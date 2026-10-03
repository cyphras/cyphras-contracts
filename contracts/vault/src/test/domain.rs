use std::panic::{catch_unwind, AssertUnwindSafe};

use soroban_sdk::{testutils::Address as _, xdr, Address, Env, String, U256};

use super::{
    fixtures,
    setup::{
        asset_contract, create_account, env, limits, native_asset, DELAY_LARGE, DELAY_SMALL,
        MAINNET, TESTNET, XLM,
    },
};
use crate::{tree, Config, Limits, Status, Vault, VaultClient};

fn deploy(env: &Env, token: &Address, delays: (u64, u64), limits: Limits) -> Address {
    env.register(
        Vault,
        (
            token.clone(),
            Address::generate(env),
            Address::generate(env),
            delays.0,
            delays.1,
            limits,
        ),
    )
}

/// The asset contract for `native` or `CODE:ISSUER`, with the issuer's account in place.
fn asset(env: &Env, asset: &str) -> Address {
    let Some((code, issuer)) = asset.split_once(':') else {
        return native_asset(env);
    };
    let issuer_address = Address::from_str(env, issuer);
    create_account(env, &issuer_address, XLM);
    let xdr::ScAddress::Account(issuer) = xdr::ScAddress::from(&issuer_address) else {
        panic!("the issuer is not an account");
    };
    let mut asset_code = [0u8; 4];
    asset_code[..code.len()].copy_from_slice(code.as_bytes());
    asset_contract(
        env,
        xdr::Asset::CreditAlphanum4(xdr::AlphaNum4 {
            asset_code: xdr::AssetCode4(asset_code),
            issuer,
        }),
    )
}

#[test]
fn the_domain_matches_the_reference_vectors() {
    let vectors = fixtures::domains();
    let cases = vectors["domains"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for case in cases {
        let network = case["network"].as_str().unwrap();
        let env = env(if network == "mainnet" {
            MAINNET
        } else {
            TESTNET
        });
        let token = asset(&env, case["asset"].as_str().unwrap());
        assert_eq!(
            soroban_sdk::token::TokenClient::new(&env, &token).name(),
            String::from_str(&env, case["asset"].as_str().unwrap())
        );
        let vault = VaultClient::new(
            &env,
            &deploy(&env, &token, (DELAY_SMALL, DELAY_LARGE), limits()),
        );
        assert_eq!(
            vault.config().domain,
            fixtures::field(&env, &case["domain"]),
            "{case}"
        );
    }
}

#[test]
fn any_network_other_than_mainnet_takes_the_testnet_label() {
    let env = env("Standalone Network ; February 2017");
    let token = native_asset(&env);
    let vault = VaultClient::new(
        &env,
        &deploy(&env, &token, (DELAY_SMALL, DELAY_LARGE), limits()),
    );
    let testnet = &fixtures::domains()["domains"][1];
    assert_eq!(testnet["preimage"], "cyphras/v2/domain/testnet/native");
    assert_eq!(
        vault.config().domain,
        fixtures::field(&env, &testnet["domain"])
    );
}

#[test]
fn the_constructor_stores_the_configuration_and_an_empty_tree() {
    let env = env(TESTNET);
    let token = native_asset(&env);
    let guardian = Address::generate(&env);
    let asp = Address::generate(&env);
    let id = env.register(
        Vault,
        (
            token.clone(),
            guardian.clone(),
            asp.clone(),
            60u64,
            120u64,
            limits(),
        ),
    );
    let vault = VaultClient::new(&env, &id);
    let domain = vault.config().domain;
    assert_eq!(
        vault.config(),
        Config {
            token,
            domain: domain.clone(),
            guardian,
            asp,
            delay_small: 60,
            delay_large: 120,
        }
    );
    assert_ne!(domain, U256::from_u32(&env, 0));
    assert_eq!(vault.limits(), limits());
    assert_eq!(vault.queued_limits(), None);
    assert_eq!(
        vault.status(),
        Status {
            deposits_paused: false,
            transfers_paused: false,
            halted_until: 0,
            next_halt_at: 0,
            next_deposit_id: 1,
            attested_up_to: 0,
            tvl: 0,
            outflow_day: 0,
            outflow: 0,
        }
    );
    assert_eq!(vault.next_leaf_index(), 0);
    assert_eq!(vault.pending(&1), None);
    assert!(vault.is_known_root(&vault.current_root()));
    assert_eq!(tree::ROOT_HISTORY, 256);
}

fn refused(delays: (u64, u64), limits: Limits) -> bool {
    let env = env(TESTNET);
    let token = native_asset(&env);
    catch_unwind(AssertUnwindSafe(|| deploy(&env, &token, delays, limits))).is_err()
}

#[test]
fn the_constructor_refuses_an_unsafe_configuration() {
    let ok = limits();
    assert!(!refused((DELAY_SMALL, DELAY_LARGE), ok.clone()));
    assert!(!refused((DELAY_LARGE, DELAY_LARGE), ok.clone()));
    assert!(refused((DELAY_LARGE, DELAY_SMALL), ok.clone()));

    // A full pool must be able to leave within seven days of outflow.
    assert!(!refused(
        (DELAY_SMALL, DELAY_LARGE),
        Limits {
            tvl_cap: 7 * ok.max_daily_outflow,
            ..ok.clone()
        }
    ));
    assert!(refused(
        (DELAY_SMALL, DELAY_LARGE),
        Limits {
            tvl_cap: 7 * ok.max_daily_outflow + 1,
            ..ok.clone()
        }
    ));
    for negative in [
        Limits {
            max_deposit: -1,
            ..ok.clone()
        },
        Limits {
            max_daily_per_depositor: -1,
            ..ok.clone()
        },
        Limits {
            tvl_cap: -1,
            ..ok.clone()
        },
        Limits {
            max_daily_outflow: -1,
            tvl_cap: 0,
            ..ok.clone()
        },
        Limits {
            max_fee: -1,
            ..ok.clone()
        },
        Limits {
            large_deposit_threshold: -1,
            ..ok.clone()
        },
    ] {
        assert!(refused((DELAY_SMALL, DELAY_LARGE), negative));
    }
}
