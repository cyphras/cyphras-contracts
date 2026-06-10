#![cfg(test)]
extern crate std;

use super::{PoolContract, PoolContractClient};
use num_bigint::BigUint;
use soroban_poseidon::poseidon_hash;
use soroban_sdk::crypto::BnScalar;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, vec, Address, Bytes, BytesN, Env, U256};

// Poseidon compatibility: the host Poseidon must match circomlib for the tree to work.

fn dec_to_bytes32(s: &str) -> [u8; 32] {
    let n = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
    let be = n.to_bytes_be();
    let mut buf = [0u8; 32];
    buf[32 - be.len()..].copy_from_slice(&be);
    buf
}

fn u256_dec(env: &Env, s: &str) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &dec_to_bytes32(s)))
}

fn want(env: &Env, s: &str) -> BytesN<32> {
    BytesN::from_array(env, &dec_to_bytes32(s))
}

#[test]
fn poseidon_arity2_matches_circomlib() {
    let env = Env::default();
    let inputs = vec![&env, u256_dec(&env, "1"), u256_dec(&env, "2")];
    let got: BytesN<32> = poseidon_hash::<3, BnScalar>(&env, &inputs)
        .to_be_bytes()
        .try_into()
        .unwrap();
    assert_eq!(
        got,
        want(
            &env,
            "7853200120776062878684798364095072458815029376092732009249414926327459813530"
        )
    );
}

#[test]
fn poseidon_arity3_matches_circomlib() {
    let env = Env::default();
    let inputs = vec![
        &env,
        u256_dec(&env, "1"),
        u256_dec(&env, "2"),
        u256_dec(&env, "3"),
    ];
    let got: BytesN<32> = poseidon_hash::<4, BnScalar>(&env, &inputs)
        .to_be_bytes()
        .try_into()
        .unwrap();
    assert_eq!(
        got,
        want(
            &env,
            "6542985608222806190361240322586112750744169038454362455181422643027100751666"
        )
    );
}

#[test]
fn poseidon_arity4_matches_circomlib() {
    let env = Env::default();
    let inputs = vec![
        &env,
        u256_dec(&env, "1"),
        u256_dec(&env, "2"),
        u256_dec(&env, "3"),
        u256_dec(&env, "4"),
    ];
    let got: BytesN<32> = poseidon_hash::<5, BnScalar>(&env, &inputs)
        .to_be_bytes()
        .try_into()
        .unwrap();
    assert_eq!(
        got,
        want(
            &env,
            "18821383157269793795438455681495246036402687001665670618754263018637548127333"
        )
    );
}

const DENOM: i128 = 1000;
const FEE: i128 = 100;

struct Fixture {
    env: Env,
    pool: PoolContractClient<'static>,
    token: Address,
    xlm: Address,
}

fn setup() -> Fixture {
    let env = Env::default();
    env.mock_all_auths();

    let issuer = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(issuer.clone())
        .address();
    let xlm = env
        .register_stellar_asset_contract_v2(issuer.clone())
        .address();
    let verifier = Address::generate(&env);

    let pool_id = env.register(PoolContract, (token.clone(), xlm.clone(), verifier, DENOM));
    let pool = PoolContractClient::new(&env, &pool_id);

    Fixture {
        env,
        pool,
        token,
        xlm,
    }
}

fn fund(env: &Env, token: &Address, to: &Address, amount: i128) {
    token::StellarAssetClient::new(env, token).mint(to, &amount);
}

#[test]
fn commit_moves_funds_and_advances_tree() {
    let f = setup();
    let sender = Address::generate(&f.env);
    fund(&f.env, &f.token, &sender, DENOM);
    fund(&f.env, &f.xlm, &sender, FEE);

    let root_before = f.pool.get_last_root();
    assert_eq!(f.pool.next_index(), 0);

    let commitment = BytesN::from_array(&f.env, &[7u8; 32]);
    f.pool.commit(&sender, &commitment, &FEE);

    // funds escrowed in the pool
    let pool_id = f.pool.address.clone();
    assert_eq!(
        token::TokenClient::new(&f.env, &f.token).balance(&pool_id),
        DENOM
    );
    assert_eq!(
        token::TokenClient::new(&f.env, &f.xlm).balance(&pool_id),
        FEE
    );
    assert_eq!(
        token::TokenClient::new(&f.env, &f.token).balance(&sender),
        0
    );

    // tree advanced to a new, known root
    assert_eq!(f.pool.next_index(), 1);
    let root_after = f.pool.get_last_root();
    assert_ne!(root_before, root_after);
    assert!(f.pool.is_known_root(&root_after));
}

#[test]
fn multiple_commits_increment_index_and_change_root() {
    let f = setup();
    let sender = Address::generate(&f.env);
    fund(&f.env, &f.token, &sender, DENOM * 3);
    fund(&f.env, &f.xlm, &sender, FEE * 3);

    let mut last = f.pool.get_last_root();
    for i in 0..3u8 {
        let commitment = BytesN::from_array(&f.env, &[i + 1; 32]);
        f.pool.commit(&sender, &commitment, &FEE);
        let r = f.pool.get_last_root();
        assert_ne!(last, r);
        assert!(f.pool.is_known_root(&r));
        last = r;
    }
    assert_eq!(f.pool.next_index(), 3);
    assert_eq!(
        token::TokenClient::new(&f.env, &f.token).balance(&f.pool.address),
        DENOM * 3
    );
}

#[test]
#[should_panic(expected = "unknown root")]
fn reveal_rejects_unknown_root() {
    let f = setup();
    let zero = BytesN::from_array(&f.env, &[0u8; 32]);
    let fake_root = BytesN::from_array(&f.env, &[9u8; 32]);
    let proof = Bytes::from_array(&f.env, &[0u8; 256]);
    f.pool.reveal(
        &proof,
        &fake_root,
        &zero,
        &zero,
        &Address::generate(&f.env),
        &Address::generate(&f.env),
        &0i128,
    );
}

#[test]
#[should_panic(expected = "invalid xlm fee")]
fn commit_rejects_fee_at_or_above_64_bits() {
    let f = setup();
    let sender = Address::generate(&f.env);
    fund(&f.env, &f.token, &sender, DENOM);
    let huge_fee = 1i128 << 64;
    fund(&f.env, &f.xlm, &sender, huge_fee);
    let commitment = BytesN::from_array(&f.env, &[7u8; 32]);
    f.pool.commit(&sender, &commitment, &huge_fee);
}
