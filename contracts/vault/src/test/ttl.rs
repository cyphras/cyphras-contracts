use soroban_sdk::{
    testutils::storage::{Instance as _, Persistent as _, Temporary as _},
    Vec,
};

use super::{
    queue::authorizers,
    setup::{outcome, Setup, DAY, DELAY_SMALL, XLM},
};
use crate::{DataKey, Error};

// 30 days and one hour of five-second ledgers.
const WRITE_TTL: u32 = 30 * 17_280 + 720;
const DAY_TOTAL_TTL: u32 = 86_400;

fn persistent_ttl(s: &Setup, key: &DataKey) -> u32 {
    s.env.as_contract(&s.vault.address, || {
        s.env.storage().persistent().get_ttl(key)
    })
}

fn instance_ttl(s: &Setup) -> u32 {
    s.env
        .as_contract(&s.vault.address, || s.env.storage().instance().get_ttl())
}

fn max_ttl(s: &Setup) -> u32 {
    s.env
        .as_contract(&s.vault.address, || s.env.storage().max_ttl())
}

const TREE: [DataKey; 4] = [
    DataKey::Roots,
    DataKey::Frontier,
    DataKey::Zeros,
    DataKey::NextLeaf,
];

#[test]
fn every_write_keeps_its_entry_alive_for_thirty_days() {
    let s = Setup::new();
    assert_eq!(instance_ttl(&s), WRITE_TTL);
    for key in &TREE {
        assert_eq!(persistent_ttl(&s, key), WRITE_TTL);
    }

    let depositor = s.account("depositor", 100 * XLM);
    let ext = s.ext(XLM, 0, &depositor, &depositor);
    let proof = s.prove(&ext);
    s.vault.shield(&proof, &ext, &depositor);
    assert_eq!(persistent_ttl(&s, &DataKey::Pending(1)), WRITE_TTL);
    for nullifier in proof.input_nullifiers.iter() {
        assert_eq!(
            persistent_ttl(&s, &DataKey::Nullifier(nullifier)),
            WRITE_TTL
        );
    }
    let day = DataKey::DepositorDay(depositor.clone(), s.now() / DAY);
    let day_ttl = s.env.as_contract(&s.vault.address, || {
        s.env.storage().temporary().get_ttl(&day)
    });
    assert_eq!(day_ttl, DAY_TOTAL_TTL);

    // Past the threshold a write extends the entry again, by a small step.
    s.advance(5 * DAY);
    s.vault.attest(&1);
    s.vault.admit(&Vec::from_slice(&s.env, &[1]));
    assert_eq!(instance_ttl(&s), WRITE_TTL);
    for key in [DataKey::Roots, DataKey::Frontier, DataKey::NextLeaf] {
        assert_eq!(persistent_ttl(&s, &key), WRITE_TTL);
    }
    // Zeros is never written after construction, so only the keeper extends it.
    assert_eq!(persistent_ttl(&s, &DataKey::Zeros), WRITE_TTL - 5 * 17_280);
}

#[test]
fn bump_ttl_extends_the_instance_the_tree_and_the_listed_deposits_to_the_maximum() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    s.advance(DELAY_SMALL);

    s.vault.bump_ttl(&Vec::from_slice(&s.env, &[1, 7]));
    assert!(authorizers(&s).is_empty());
    let max = max_ttl(&s);
    assert_eq!(instance_ttl(&s), max);
    for key in &TREE {
        assert_eq!(persistent_ttl(&s, key), max);
    }
    assert_eq!(persistent_ttl(&s, &DataKey::Pending(1)), max);
    // Unlisted deposits keep their TTL.
    assert!(persistent_ttl(&s, &DataKey::Pending(2)) < max);

    // A later write does not shorten an entry the keeper extended.
    s.vault.flag(&1, &1);
    assert_eq!(persistent_ttl(&s, &DataKey::Pending(1)), max);
}

#[test]
fn the_reentrancy_lock_is_released_after_every_guarded_call() {
    let s = Setup::new();
    s.fund_pool("funder", 10 * XLM);
    let depositor = s.account("depositor", 100 * XLM);
    let relayer = s.account("relayer", 0);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    let id = s.vault.status().next_deposit_id - 1;
    s.vault.flag(&id, &1);
    let held = || {
        s.env.as_contract(&s.vault.address, || {
            s.env.storage().temporary().has(&DataKey::Lock)
        })
    };
    assert!(!held());
    s.transact(&relayer, &s.ext(-XLM, 0, &relayer, &relayer))
        .unwrap();
    assert!(!held());
    s.vault.cancel(&(id - 1));
    assert!(!held());
    s.vault.refund(&id);
    assert!(!held());
}

#[test]
fn a_held_lock_refuses_every_entry_point_that_calls_out() {
    let s = Setup::new();
    s.fund_pool("funder", 10 * XLM);
    let depositor = s.account("depositor", 100 * XLM);
    let relayer = s.account("relayer", 0);
    s.shield(&depositor, XLM).unwrap();
    let id = s.vault.status().next_deposit_id - 1;
    s.vault.flag(&id, &1);
    s.env.as_contract(&s.vault.address, || {
        s.env.storage().temporary().set(&DataKey::Lock, &())
    });

    assert_eq!(s.shield(&depositor, XLM), Err(Error::Reentered));
    assert_eq!(
        s.transact(&relayer, &s.ext(-XLM, 0, &relayer, &relayer)),
        Err(Error::Reentered)
    );
    assert_eq!(outcome(s.vault.try_cancel(&id)), Err(Error::Reentered));
    assert_eq!(outcome(s.vault.try_refund(&id)), Err(Error::Reentered));
    // Entry points that move no funds do not take the lock.
    s.vault.unflag(&id);
}
