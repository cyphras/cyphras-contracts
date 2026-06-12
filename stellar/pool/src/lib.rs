#![no_std]

use soroban_poseidon::poseidon_hash;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, crypto::bn254::Fr, crypto::BnScalar,
    token, vec, Address, Bytes, BytesN, Env, Vec, U256,
};

const MERKLE_LEVELS: u32 = 20;
const ROOT_HISTORY_SIZE: u32 = 1000;

// Fees and amounts are range-checked to 64 bits in the circuit; reject anything larger so
// escrowed XLM can never become unspendable (no valid proof could ever match it).
const MAX_FEE: i128 = 1i128 << 64;

// The relayer fee must be a multiple of this tier (0.01 XLM). Quantizing it on-chain keeps the fee
// from becoming a fingerprint that links a deposit to its withdrawal: within a pool every note pays
// the same denomination, so a unique fee would otherwise single one out of the anonymity set.
const FEE_TIER: i128 = 100_000;

// BN254 scalar field modulus r, big-endian. The commitment is hashed with Poseidon, whose host
// implementation traps on an input at or above r; reject a non-canonical value up front so an
// invalid deposit fails with a clear error instead of an opaque host panic.
const FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

// One instance TTL bump keeps the whole commit working set alive: config plus the zero hashes and
// filled subtrees. Spent nullifiers are bumped when written. An off-chain keeper extends the bulk
// persistent root state (root history and known-root flags) periodically.
const TTL_THRESHOLD: u32 = 100_000;
const TTL_BUMP: u32 = 518_400;

#[contracttype]
enum DataKey {
    Token,
    XlmToken,
    Verifier,
    Denomination,
    NextIndex,
    RootIndex,
    FilledSubtree(u32),
    RootHistory(u32),
    KnownRoot(BytesN<32>),
    Zero(u32),
    NullifierUsed(BytesN<32>),
}

#[contractevent]
pub struct CommitEvent {
    #[topic]
    pub leaf: BytesN<32>,
    pub leaf_index: u32,
    pub root: BytesN<32>,
}

#[contractevent]
pub struct RevealEvent {
    #[topic]
    pub nullifier_hash: BytesN<32>,
    pub recipient: Address,
    pub denomination: i128,
    pub relayer_xlm_fee: i128,
}

#[contract]
pub struct PoolContract;

#[contractimpl]
impl PoolContract {
    // Runs once at deploy. Using a constructor means the pool can never exist in an
    // uninitialized state, closing the front-run window an unauthenticated init would open.
    pub fn __constructor(
        env: Env,
        token: Address,
        xlm_token: Address,
        verifier: Address,
        denomination: i128,
    ) {
        if denomination <= 0 {
            panic!("invalid denomination");
        }
        // token may equal xlm_token: an XLM pool sends XLM as the asset and also pays the
        // relayer fee in XLM. The pool still pays out exactly the denomination plus the
        // proven fee, so the shared XLM balance stays correct.

        env.storage().instance().set(&DataKey::Token, &token);
        env.storage().instance().set(&DataKey::XlmToken, &xlm_token);
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        env.storage()
            .instance()
            .set(&DataKey::Denomination, &denomination);
        env.storage().instance().set(&DataKey::NextIndex, &0u32);
        env.storage().instance().set(&DataKey::RootIndex, &0u32);

        let zeros = Self::compute_zeros(&env);
        // The zero hashes and filled subtrees are the fixed working set every commit reads. Keeping
        // them in instance storage means a single instance TTL bump keeps the whole commit path
        // alive, so the tree can never break by having individual structural entries archive.
        for i in 0..=MERKLE_LEVELS {
            env.storage()
                .instance()
                .set(&DataKey::Zero(i), &zeros.get(i).unwrap());
        }
        for i in 0..MERKLE_LEVELS {
            env.storage()
                .instance()
                .set(&DataKey::FilledSubtree(i), &zeros.get(i).unwrap());
        }
        let initial_root = zeros.get(MERKLE_LEVELS).unwrap();
        env.storage()
            .persistent()
            .set(&DataKey::RootHistory(0), &initial_root);
        env.storage()
            .persistent()
            .set(&DataKey::KnownRoot(initial_root), &true);
    }

    // Deposit a note: transfer the pool's fixed denomination plus the note's relayer fee (escrowed
    // in XLM). The fee is bound into the tree leaf, so the escrowed amount is provably the fee the
    // note pays at reveal and cannot be under-escrowed then over-withdrawn against the shared pool.
    pub fn commit(env: Env, sender: Address, inner_commitment: BytesN<32>, relayer_fee: i128) {
        sender.require_auth();
        if relayer_fee < 0 || relayer_fee >= MAX_FEE {
            panic!("invalid relayer fee");
        }
        if relayer_fee % FEE_TIER != 0 {
            panic!("fee must be a multiple of the fee tier");
        }
        if inner_commitment.to_array() >= FR_MODULUS {
            panic!("invalid commitment");
        }

        let denomination: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Denomination)
            .unwrap();
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        token::TokenClient::new(&env, &token_addr).transfer(
            &sender,
            &env.current_contract_address(),
            &denomination,
        );
        let xlm_addr: Address = env.storage().instance().get(&DataKey::XlmToken).unwrap();
        token::TokenClient::new(&env, &xlm_addr).transfer(
            &sender,
            &env.current_contract_address(),
            &relayer_fee,
        );

        let leaf = Self::hash_leaf(&env, &inner_commitment, relayer_fee);
        let leaf_index = Self::insert_leaf(&env, &leaf);
        let root = Self::last_root(&env);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        CommitEvent {
            leaf,
            leaf_index,
            root,
        }
        .publish(&env);
    }

    // Withdraw a note to the recipient and pay the relayer. All public inputs are derived
    // from on-chain truth (the recipient/relayer addresses, the fee paid, and the pool's
    // own token) so a relayer cannot redirect funds, inflate the fee, or spend a note in
    // the wrong pool - any mismatch makes the proof fail to verify.
    pub fn reveal(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier_hash: BytesN<32>,
        amount_hash: BytesN<32>,
        recipient: Address,
        relayer: Address,
        xlm_fee: i128,
    ) {
        if xlm_fee < 0 || xlm_fee >= MAX_FEE {
            panic!("invalid xlm fee");
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::NullifierUsed(nullifier_hash.clone()))
        {
            panic!("nullifier already used");
        }
        if !Self::root_is_known(&env, &root) {
            panic!("unknown root");
        }

        let recipient_field = Self::address_to_field(&env, &recipient);
        let relayer_field = Self::address_to_field(&env, &relayer);
        let relayer_fee_field = Self::i128_to_field(&env, xlm_fee);
        let token_addr: Address = env.storage().instance().get(&DataKey::Token).unwrap();
        let asset_id_field = Self::address_to_field(&env, &token_addr);

        let verifier_addr: Address = env.storage().instance().get(&DataKey::Verifier).unwrap();
        let valid = verifier::VerifierClient::new(&env, &verifier_addr).verify(
            &proof,
            &root,
            &nullifier_hash,
            &recipient_field,
            &relayer_field,
            &relayer_fee_field,
            &amount_hash,
            &asset_id_field,
        );
        if !valid {
            panic!("invalid proof");
        }

        env.storage()
            .persistent()
            .set(&DataKey::NullifierUsed(nullifier_hash.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::NullifierUsed(nullifier_hash.clone()),
            TTL_BUMP,
            TTL_BUMP,
        );
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);

        let denomination: i128 = env
            .storage()
            .instance()
            .get(&DataKey::Denomination)
            .unwrap();
        token::TokenClient::new(&env, &token_addr).transfer(
            &env.current_contract_address(),
            &recipient,
            &denomination,
        );
        if xlm_fee > 0 {
            let xlm_addr: Address = env.storage().instance().get(&DataKey::XlmToken).unwrap();
            token::TokenClient::new(&env, &xlm_addr).transfer(
                &env.current_contract_address(),
                &relayer,
                &xlm_fee,
            );
        }

        RevealEvent {
            nullifier_hash,
            recipient,
            denomination,
            relayer_xlm_fee: xlm_fee,
        }
        .publish(&env);
    }

    pub fn is_known_root(env: Env, root: BytesN<32>) -> bool {
        Self::root_is_known(&env, &root)
    }

    pub fn get_last_root(env: Env) -> BytesN<32> {
        Self::last_root(&env)
    }

    pub fn next_index(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::NextIndex)
            .unwrap_or(0)
    }

    pub fn get_denomination(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Denomination)
            .unwrap()
    }

    fn root_is_known(env: &Env, root: &BytesN<32>) -> bool {
        env.storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::KnownRoot(root.clone()))
            .unwrap_or(false)
    }

    fn last_root(env: &Env) -> BytesN<32> {
        let ri: u32 = env
            .storage()
            .instance()
            .get(&DataKey::RootIndex)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .get(&DataKey::RootHistory(ri))
            .unwrap()
    }

    fn insert_leaf(env: &Env, leaf: &BytesN<32>) -> u32 {
        let next_index: u32 = env
            .storage()
            .instance()
            .get(&DataKey::NextIndex)
            .unwrap_or(0);
        if next_index >= 2u32.pow(MERKLE_LEVELS) {
            panic!("merkle tree full");
        }

        let mut current_index = next_index;
        let mut current_hash = leaf.clone();
        let zeros = Self::get_zeros(env);

        for level in 0..MERKLE_LEVELS {
            let (l, r) = if current_index % 2 == 0 {
                env.storage()
                    .instance()
                    .set(&DataKey::FilledSubtree(level), &current_hash);
                (current_hash.clone(), zeros.get(level).unwrap())
            } else {
                let l: BytesN<32> = env
                    .storage()
                    .instance()
                    .get(&DataKey::FilledSubtree(level))
                    .unwrap();
                (l, current_hash.clone())
            };
            current_hash = Self::hash_pair(env, &l, &r);
            current_index /= 2;
        }

        let ri: u32 = env
            .storage()
            .instance()
            .get(&DataKey::RootIndex)
            .unwrap_or(0);
        let new_ri = (ri + 1) % ROOT_HISTORY_SIZE;
        env.storage()
            .persistent()
            .set(&DataKey::RootHistory(new_ri), &current_hash);
        env.storage()
            .persistent()
            .set(&DataKey::KnownRoot(current_hash.clone()), &true);
        env.storage().instance().set(&DataKey::RootIndex, &new_ri);
        env.storage()
            .instance()
            .set(&DataKey::NextIndex, &(next_index + 1));

        next_index
    }

    fn hash_pair(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        let l = U256::from_be_bytes(env, &left.clone().into());
        let r = U256::from_be_bytes(env, &right.clone().into());
        let inputs = vec![env, l, r];
        poseidon_hash::<3, BnScalar>(env, &inputs)
            .to_be_bytes()
            .try_into()
            .unwrap()
    }

    // The tree leaf binds the inner commitment to its relayer fee, matching the circuit's
    // leaf = Poseidon(innerCommitment, relayerFee). relayer_fee is non-negative and < 2^64, so it
    // is a canonical field element.
    fn hash_leaf(env: &Env, inner: &BytesN<32>, relayer_fee: i128) -> BytesN<32> {
        let mut fee_bytes = [0u8; 32];
        fee_bytes[16..32].copy_from_slice(&(relayer_fee as u128).to_be_bytes());
        let inputs = vec![
            env,
            U256::from_be_bytes(env, &inner.clone().into()),
            U256::from_be_bytes(env, &Bytes::from_array(env, &fee_bytes)),
        ];
        poseidon_hash::<3, BnScalar>(env, &inputs)
            .to_be_bytes()
            .try_into()
            .unwrap()
    }

    fn compute_zeros(env: &Env) -> Vec<BytesN<32>> {
        let mut zeros = Vec::new(env);
        let zero_leaf: BytesN<32> = BytesN::from_array(env, &[0u8; 32]);
        zeros.push_back(zero_leaf.clone());
        let mut cur = zero_leaf;
        for _ in 0..MERKLE_LEVELS {
            cur = Self::hash_pair(env, &cur, &cur);
            zeros.push_back(cur.clone());
        }
        zeros
    }

    fn get_zeros(env: &Env) -> Vec<BytesN<32>> {
        let mut zeros = Vec::new(env);
        for i in 0..=MERKLE_LEVELS {
            zeros.push_back(env.storage().instance().get(&DataKey::Zero(i)).unwrap());
        }
        zeros
    }

    // Extracts the 32-byte identifier from an address (ed25519 public key for a G account,
    // contract hash for a C contract) and reduces it mod the BN254 scalar field to a
    // canonical field element. Matches the client's address-to-field derivation. Parsing
    // mirrors the XDR layout of ScVal::Address (ScVal discriminant + ScAddress).
    fn address_to_field(env: &Env, addr: &Address) -> BytesN<32> {
        let xdr = addr.to_xdr(env);
        let addr_type: BytesN<4> = xdr.slice(4..8).try_into().unwrap();
        let raw: BytesN<32> = match addr_type.to_array() {
            // ScAddress::Account -> skip PublicKey type (4 bytes), then 32-byte ed25519 key
            [0, 0, 0, 0] => xdr.slice(12..44).try_into().unwrap(),
            // ScAddress::Contract -> 32-byte contract hash
            [0, 0, 0, 1] => xdr.slice(8..40).try_into().unwrap(),
            _ => panic!("unsupported address type"),
        };
        Fr::from_bytes(raw).to_bytes()
    }

    fn i128_to_field(env: &Env, v: i128) -> BytesN<32> {
        let mut buf = [0u8; 32];
        buf[16..].copy_from_slice(&(v as u128).to_be_bytes());
        BytesN::from_array(env, &buf)
    }
}

mod verifier {
    use soroban_sdk::{contractclient, Bytes, BytesN, Env};

    #[allow(dead_code)]
    #[contractclient(name = "VerifierClient")]
    pub trait Verifier {
        fn verify(
            env: Env,
            proof: Bytes,
            root: BytesN<32>,
            nullifier_hash: BytesN<32>,
            recipient: BytesN<32>,
            relayer: BytesN<32>,
            relayer_fee: BytesN<32>,
            amount_hash: BytesN<32>,
            asset_id: BytesN<32>,
        ) -> bool;
    }
}

mod test;
