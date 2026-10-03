use std::panic::{catch_unwind, AssertUnwindSafe};

use soroban_sdk::{
    testutils::Address as _,
    xdr::{self, ContractEventBody, ScError, ScVal},
    Address, Env, String, U256,
};

use super::{
    fixtures,
    setup::{
        asset_contract, create_account, env, limits, native_asset, DELAY_LARGE, DELAY_SMALL,
        MAINNET, TESTNET, XLM,
    },
};
use crate::{tree, Config, Error, Limits, Status, Vault, VaultClient};

/// Deploys a vault, or returns the error its constructor refused the deployment with.
fn deploy(env: &Env, token: &Address, delays: (u64, u64), limits: Limits) -> Result<Address, u32> {
    let args = (
        token.clone(),
        Address::generate(env),
        Address::generate(env),
        delays.0,
        delays.1,
        limits,
    );
    match catch_unwind(AssertUnwindSafe(|| env.register(Vault, args))) {
        Ok(id) => Ok(id),
        Err(_) => Err(constructor_error(env)),
    }
}

// The host reports a failed deployment as an invalid action; the constructor's own error is in a
// diagnostic event.
fn constructor_error(env: &Env) -> u32 {
    let events = env.host().get_events().unwrap().0;
    events
        .iter()
        .rev()
        .find_map(|e| match &e.event.body {
            ContractEventBody::V0(body) => match body.topics.as_slice() {
                [ScVal::Symbol(topic), ScVal::Error(ScError::Contract(code))]
                    if topic.to_utf8_string_lossy() == "error" =>
                {
                    Some(*code)
                }
                _ => None,
            },
        })
        .expect("the deployment failed without a contract error")
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
        let mainnet = case["network"] == "mainnet";
        let env = env(if mainnet { MAINNET } else { TESTNET });
        let token = asset(&env, case["asset"].as_str().unwrap());
        assert_eq!(
            soroban_sdk::token::TokenClient::new(&env, &token).name(),
            String::from_str(&env, case["asset"].as_str().unwrap())
        );
        let expected = fixtures::field(&env, &case["domain"]);
        assert_eq!(crate::domain(&env, &token), expected, "{case}");
        // A build with the forgeable key cannot deploy on mainnet, so only testnet deploys here.
        if !mainnet {
            let id = deploy(&env, &token, (DELAY_SMALL, DELAY_LARGE), limits()).unwrap();
            assert_eq!(VaultClient::new(&env, &id).config().domain, expected);
        }
    }
}

#[test]
fn any_network_other_than_mainnet_takes_the_testnet_label() {
    let env = env("Standalone Network ; February 2017");
    let token = native_asset(&env);
    let id = deploy(&env, &token, (DELAY_SMALL, DELAY_LARGE), limits()).unwrap();
    let testnet = &fixtures::domains()["domains"][1];
    assert_eq!(testnet["preimage"], "cyphras/v2/domain/testnet/native");
    assert_eq!(
        VaultClient::new(&env, &id).config().domain,
        fixtures::field(&env, &testnet["domain"])
    );
}

#[test]
fn a_build_with_the_forgeable_key_refuses_to_deploy_on_mainnet() {
    const { assert!(verifier::FORGEABLE) };
    let env = env(MAINNET);
    let token = native_asset(&env);
    let result = deploy(&env, &token, (DELAY_SMALL, DELAY_LARGE), limits());
    assert_eq!(result, Err(Error::ForgeableKey as u32));
}

#[test]
fn a_build_with_the_forgeable_key_deploys_on_any_other_network() {
    for passphrase in [TESTNET, "Standalone Network ; February 2017"] {
        let env = env(passphrase);
        let token = native_asset(&env);
        assert!(deploy(&env, &token, (DELAY_SMALL, DELAY_LARGE), limits()).is_ok());
    }
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
            pending_total: 0,
            queued_total: 0,
            exit_head: 1,
            exit_tail: 1,
            outflow_day: 0,
            outflow: 0,
        }
    );
    assert_eq!(vault.next_leaf_index(), 0);
    assert_eq!(vault.pending(&1), None);
    assert_eq!(vault.exit(&1), None);
    assert!(vault.is_known_root(&vault.current_root()));
    assert_eq!(tree::ROOT_HISTORY, 256);
}

#[test]
fn the_constructor_refuses_an_unsafe_configuration() {
    let env = env(TESTNET);
    let token = native_asset(&env);
    let ok = limits();
    let delays = (DELAY_SMALL, DELAY_LARGE);
    let bad_limits = Err(Error::BadLimits as u32);
    assert!(deploy(&env, &token, delays, ok.clone()).is_ok());
    assert!(deploy(&env, &token, (DELAY_LARGE, DELAY_LARGE), ok.clone()).is_ok());
    assert_eq!(
        deploy(&env, &token, (DELAY_LARGE, DELAY_SMALL), ok.clone()),
        Err(Error::BadConfig as u32)
    );

    // A full pool must be able to leave within seven days of outflow.
    let week = 7 * ok.max_daily_outflow;
    let at_the_bound = Limits {
        tvl_cap: week,
        ..ok.clone()
    };
    assert!(deploy(&env, &token, delays, at_the_bound).is_ok());
    let past_the_bound = Limits {
        tvl_cap: week + 1,
        ..ok.clone()
    };
    assert_eq!(deploy(&env, &token, delays, past_the_bound), bad_limits);
    // Deposits can start stopped: min_deposit may exceed a zero max_deposit.
    let stopped = Limits {
        min_deposit: XLM,
        max_deposit: 0,
        ..ok.clone()
    };
    assert!(deploy(&env, &token, delays, stopped).is_ok());
    for negative in [
        Limits {
            min_deposit: 0,
            ..ok.clone()
        },
        Limits {
            min_deposit: -1,
            ..ok.clone()
        },
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
        assert_eq!(deploy(&env, &token, delays, negative), bad_limits);
    }
}
