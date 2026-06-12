#![cfg(test)]

use super::{FactoryContract, FactoryContractClient};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, BytesN, Env};

// The real compiled pool contract, so the factory deploys a genuine pool.
mod pool_contract {
    soroban_sdk::contractimport!(file = "../target/wasm32v1-none/release/cyphras_pool.wasm");
}

const DENOM: i128 = 1000;

struct Fixture {
    env: Env,
    factory: FactoryContractClient<'static>,
    token: Address,
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
    let admin = Address::generate(&env);

    let pool_wasm_hash = env.deployer().upload_contract_wasm(pool_contract::WASM);
    let factory_id = env.register(
        FactoryContract,
        (admin, verifier, xlm.clone(), pool_wasm_hash),
    );
    let factory = FactoryContractClient::new(&env, &factory_id);

    Fixture {
        env,
        factory,
        token,
    }
}

#[test]
fn creates_and_registers_a_constructed_pool() {
    let f = setup();
    let pool_addr = f.factory.create_pool(&f.token, &DENOM);

    // registry reflects the new pool
    assert_eq!(
        f.factory.get_pool(&f.token, &DENOM),
        Some(pool_addr.clone())
    );
    assert_eq!(f.factory.get_generation(&f.token, &DENOM), 0);
    assert_eq!(f.factory.get_pools().len(), 1);

    // the deployed pool was constructed atomically with the right config
    let pool = pool_contract::Client::new(&f.env, &pool_addr);
    assert_eq!(pool.get_denomination(), DENOM);
    assert_eq!(pool.next_index(), 0);
}

#[test]
fn pools_are_deterministic_and_distinct_per_denomination() {
    let f = setup();
    let a = f.factory.create_pool(&f.token, &DENOM);
    let b = f.factory.create_pool(&f.token, &(DENOM * 10));
    assert_ne!(a, b);
    assert_eq!(f.factory.get_pools().len(), 2);
}

#[test]
#[should_panic(expected = "pool already exists")]
fn create_pool_is_unique_per_token_denomination() {
    let f = setup();
    f.factory.create_pool(&f.token, &DENOM);
    f.factory.create_pool(&f.token, &DENOM);
}

#[test]
#[should_panic(expected = "current pool not full")]
fn rotate_requires_full_tree() {
    let f = setup();
    f.factory.create_pool(&f.token, &DENOM);
    // tree is empty, so rotation must be refused
    f.factory.rotate_pool(&f.token, &DENOM);
}

#[test]
#[should_panic(expected = "pool does not exist")]
fn rotate_requires_existing_pool() {
    let f = setup();
    f.factory.rotate_pool(&f.token, &DENOM);
}

#[test]
#[should_panic(expected = "no pending pool wasm")]
fn set_pool_wasm_requires_a_proposal() {
    let f = setup();
    let new_hash = BytesN::from_array(&f.env, &[9u8; 32]);
    f.factory.set_pool_wasm(&new_hash);
}

#[test]
#[should_panic(expected = "wasm timelock not elapsed")]
fn set_pool_wasm_blocked_before_timelock() {
    let f = setup();
    let new_hash = BytesN::from_array(&f.env, &[9u8; 32]);
    f.factory.propose_pool_wasm(&new_hash);
    f.factory.set_pool_wasm(&new_hash);
}

#[test]
fn set_pool_wasm_enacts_after_timelock() {
    let f = setup();
    let new_hash = BytesN::from_array(&f.env, &[9u8; 32]);
    f.factory.propose_pool_wasm(&new_hash);
    f.env.ledger().with_mut(|li| li.sequence_number += 17_280);
    f.factory.set_pool_wasm(&new_hash);
}

#[test]
fn set_admin_transfers_control() {
    let f = setup();
    let new_admin = Address::generate(&f.env);
    f.factory.set_admin(&new_admin);
    f.factory.create_pool(&f.token, &DENOM);
}

#[test]
#[should_panic]
fn create_pool_requires_admin_auth() {
    // No mock_all_auths here, so the admin's require_auth in create_pool must fail.
    let env = Env::default();
    let issuer = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(issuer.clone())
        .address();
    let xlm = env
        .register_stellar_asset_contract_v2(issuer.clone())
        .address();
    let verifier = Address::generate(&env);
    let admin = Address::generate(&env);

    let pool_wasm_hash = env.deployer().upload_contract_wasm(pool_contract::WASM);
    let factory_id = env.register(FactoryContract, (admin, verifier, xlm, pool_wasm_hash));
    let factory = FactoryContractClient::new(&env, &factory_id);

    factory.create_pool(&token, &DENOM);
}
