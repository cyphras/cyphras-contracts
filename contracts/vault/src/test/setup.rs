use std::{cell::Cell, fmt::Debug, rc::Rc};

use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token::TokenClient,
    vec,
    xdr::{self, ScAddress},
    Address, Bytes, Env, InvokeError, MuxedAddress, TryFromVal, U256,
};
use types::{ExtData, TxProof};

use super::{fixtures, trapdoor};
use crate::{proof, Error, Limits, Vault, VaultClient};

pub const XLM: i128 = 10_000_000;
pub const DAY: u64 = 86_400;
pub const DELAY_SMALL: u64 = 3_600;
pub const DELAY_LARGE: u64 = 86_400;
// One hour into a UTC day.
pub const T0: u64 = 20_000 * DAY + 3_600;
pub const SEQ0: u32 = 1_000;
pub const TESTNET: &str = "Test SDF Network ; September 2015";
pub const MAINNET: &str = "Public Global Stellar Network ; September 2015";

/// The proposed initial limits of the mainnet XLM vault, with the lowest minimum deposit.
pub fn limits() -> Limits {
    Limits {
        min_deposit: 1,
        max_deposit: 2_500 * XLM,
        max_daily_per_depositor: 5_000 * XLM,
        tvl_cap: 25_000 * XLM,
        max_daily_outflow: 5_000 * XLM,
        max_fee: 5 * XLM,
        large_deposit_threshold: 500 * XLM,
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Flattens a `try_` client call: a contract error becomes `Err`, and anything the host aborts
/// for any other reason fails the test.
pub fn outcome<T, C: Debug, I: Debug>(
    result: Result<Result<T, C>, Result<Error, I>>,
) -> Result<T, Error> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Err(Ok(error)) => Err(error),
        Ok(Err(e)) => panic!("cannot convert the result: {e:?}"),
        Err(Err(e)) => panic!("the host aborted the call: {e:?}"),
    }
}

/// True when the host itself aborted the call rather than the vault returning an error.
pub fn host_aborted<T, C, E: Debug>(result: Result<Result<T, C>, Result<E, InvokeError>>) -> bool {
    matches!(result, Err(Err(_)))
}

pub struct Setup {
    pub env: Env,
    pub vault: VaultClient<'static>,
    pub token: TokenClient<'static>,
    pub guardian: Address,
    pub asp: Address,
    pub empty_root: U256,
    rng: Cell<u64>,
    _trapdoor: Option<trapdoor::Guard>,
}

pub fn env(passphrase: &str) -> Env {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.sequence_number = SEQ0;
        l.timestamp = T0;
        l.network_id = sha256(passphrase.as_bytes());
    });
    env
}

/// The Stellar Asset Contract of XLM.
pub fn native_asset(env: &Env) -> Address {
    asset_contract(env, xdr::Asset::Native)
}

pub fn asset_contract(env: &Env, asset: xdr::Asset) -> Address {
    let id = env
        .host()
        .invoke_function(xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
            contract_id_preimage: xdr::ContractIdPreimage::Asset(asset),
            executable: xdr::ContractExecutable::StellarAsset,
        }))
        .unwrap();
    Address::try_from_val(env, &id).unwrap()
}

/// Creates the classic account behind a G address, holding `balance` stroops of XLM.
pub fn create_account(env: &Env, address: &Address, balance: i128) {
    let ScAddress::Account(account_id) = ScAddress::from(address) else {
        panic!("not an account address");
    };
    let key = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id: account_id.clone(),
    }));
    let entry = Rc::new(xdr::LedgerEntry {
        data: xdr::LedgerEntryData::Account(xdr::AccountEntry {
            account_id,
            balance: balance.try_into().unwrap(),
            flags: 0,
            home_domain: Default::default(),
            inflation_dest: None,
            num_sub_entries: 0,
            seq_num: xdr::SequenceNumber(0),
            thresholds: xdr::Thresholds([1; 4]),
            signers: Default::default(),
            ext: xdr::AccountEntryExt::V0,
        }),
        last_modified_ledger_seq: 0,
        ext: xdr::LedgerEntryExt::V0,
    });
    env.host().add_ledger_entry(&key, &entry, None).unwrap();
}

pub fn account_address(env: &Env, tag: &str) -> Address {
    let id = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(sha256(
        tag.as_bytes(),
    ))));
    Address::try_from_val(env, &ScAddress::Account(id)).unwrap()
}

impl Setup {
    /// A testnet XLM vault that verifies with the trapdoor key.
    pub fn new() -> Self {
        Self::build(limits(), true)
    }

    /// A testnet XLM vault that verifies with the embedded testnet-forgeable key.
    pub fn real() -> Self {
        Self::build(limits(), false)
    }

    pub fn with_limits(limits: Limits) -> Self {
        Self::build(limits, true)
    }

    fn build(limits: Limits, trapdoor: bool) -> Self {
        let trapdoor = trapdoor.then(trapdoor::enable);
        let env = env(TESTNET);
        let token = native_asset(&env);
        let guardian = Address::generate(&env);
        let asp = Address::generate(&env);
        let id = env.register_at(
            &fixtures::vault_address(&env),
            Vault,
            (
                token.clone(),
                guardian.clone(),
                asp.clone(),
                DELAY_SMALL,
                DELAY_LARGE,
                limits,
            ),
        );
        let vault = VaultClient::new(&env, &id);
        Setup {
            empty_root: vault.current_root(),
            vault,
            token: TokenClient::new(&env, &token),
            env,
            guardian,
            asp,
            rng: Cell::new(0x9e37_79b9_7f4a_7c15),
            _trapdoor: trapdoor,
        }
    }

    /// A funded G account named by `tag`.
    pub fn account(&self, tag: &str, balance: i128) -> Address {
        let address = account_address(&self.env, tag);
        create_account(&self.env, &address, balance);
        address
    }

    pub fn balance(&self, address: &Address) -> i128 {
        self.token.balance(address)
    }

    pub fn now(&self) -> u64 {
        self.env.ledger().timestamp()
    }

    /// Moves time forward, with the ledger sequence following at five seconds a ledger.
    pub fn advance(&self, seconds: u64) {
        self.env.ledger().with_mut(|l| {
            l.timestamp += seconds;
            l.sequence_number += (seconds / 5).max(1) as u32;
        });
    }

    pub fn next_u64(&self) -> u64 {
        // splitmix64
        let mut z = self.rng.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
        self.rng.set(z);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    /// A uniformly random canonical field element, below 2^253.
    pub fn field(&self) -> U256 {
        U256::from_parts(
            &self.env,
            self.next_u64() >> 3,
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
        )
    }

    pub fn ciphertext(&self, len: u32) -> Bytes {
        let mut out = Bytes::new(&self.env);
        for _ in 0..len {
            out.push_back(self.next_u64() as u8);
        }
        out
    }

    /// ExtData for this vault and network, with fresh ciphertexts and a deadline 120 ledgers out.
    pub fn ext(
        &self,
        ext_amount: i128,
        fee: i128,
        recipient: impl Into<MuxedAddress>,
        relayer: &Address,
    ) -> ExtData {
        ExtData {
            vault: self.vault.address.clone(),
            network_id: self.env.ledger().network_id(),
            deadline: self.env.ledger().sequence() + 120,
            ext_amount,
            fee,
            recipient: recipient.into(),
            relayer: relayer.clone(),
            encrypted_output0: self.ciphertext(proof::CIPHERTEXT_LEN),
            encrypted_output1: self.ciphertext(proof::CIPHERTEXT_LEN),
        }
    }

    /// A trapdoor proof of `ext` against `root`, spending `nullifiers` into `commitments`.
    pub fn prove_with(
        &self,
        ext: &ExtData,
        root: U256,
        nullifiers: [U256; 2],
        commitments: [U256; 2],
    ) -> TxProof {
        let env = &self.env;
        let public_amount = proof::public_amount(env, ext.ext_amount, ext.fee).unwrap();
        let ext_data_hash = proof::ext_data_hash(env, ext);
        let inputs = [
            root.clone(),
            public_amount.clone(),
            ext_data_hash.clone(),
            self.vault.config().domain,
            nullifiers[0].clone(),
            nullifiers[1].clone(),
            commitments[0].clone(),
            commitments[1].clone(),
        ];
        TxProof {
            proof: trapdoor::forge(env, &inputs),
            root,
            public_amount,
            ext_data_hash,
            input_nullifiers: vec![env, nullifiers[0].clone(), nullifiers[1].clone()],
            output_commitments: vec![env, commitments[0].clone(), commitments[1].clone()],
        }
    }

    /// A trapdoor proof of `ext` with fresh nullifiers and commitments, against the empty root
    /// for a deposit and the current root otherwise.
    pub fn prove(&self, ext: &ExtData) -> TxProof {
        let root = if ext.ext_amount > 0 {
            self.empty_root.clone()
        } else {
            self.vault.current_root()
        };
        self.prove_with(
            ext,
            root,
            [self.field(), self.field()],
            [self.field(), self.field()],
        )
    }

    pub fn shield(&self, depositor: &Address, amount: i128) -> Result<u64, Error> {
        let ext = self.ext(amount, 0, depositor, depositor);
        let proof = self.prove_with(
            &ext,
            self.empty_root.clone(),
            [self.field(), self.field()],
            [self.field(), self.field()],
        );
        outcome(self.vault.try_shield(&proof, &ext, depositor))
    }

    pub fn transact(&self, submitter: &Address, ext: &ExtData) -> Result<(), Error> {
        outcome(self.vault.try_transact(&self.prove(ext), ext, submitter))
    }

    /// Attests every deposit so far and moves past the long delay.
    pub fn attest_all_and_wait(&self) {
        let last = self.vault.status().next_deposit_id - 1;
        if last > self.vault.status().attested_up_to {
            self.vault.attest(&last);
        }
        self.advance(DELAY_LARGE);
    }

    pub fn pending_ids(&self) -> soroban_sdk::Vec<u64> {
        let mut ids = soroban_sdk::Vec::new(&self.env);
        for id in 1..self.vault.status().next_deposit_id {
            if self.vault.pending(&id).is_some() {
                ids.push_back(id);
            }
        }
        ids
    }

    /// Shields `amount` from a new account and admits it, so the pool holds spendable value.
    pub fn fund_pool(&self, tag: &str, amount: i128) {
        let depositor = self.account(tag, amount);
        let id = self.shield(&depositor, amount).unwrap();
        self.attest_all_and_wait();
        let admitted = self.vault.admit(&vec![&self.env, id]);
        assert_eq!(admitted, vec![&self.env, id]);
    }
}
