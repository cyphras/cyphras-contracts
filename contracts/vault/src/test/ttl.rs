use soroban_sdk::{
    testutils::storage::{Instance as _, Persistent as _, Temporary as _},
    Vec,
};

use super::{
    queue::authorizers,
    setup::{limits, Setup, DAY, DELAY_SMALL, XLM},
};
use crate::{DataKey, Limits};

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

const TREE: [DataKey; 3] = [DataKey::Roots, DataKey::Frontier, DataKey::NextLeaf];

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
    for key in &TREE {
        assert_eq!(persistent_ttl(&s, key), WRITE_TTL);
    }
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
fn each_call_writes_only_the_entries_it_changes() {
    let s = Setup::new();
    s.fund_pool("funder", 100 * XLM);
    let relayer = s.account("relayer", 0);
    let user = s.account("user", 0);
    let depositor = s.account("depositor", 100 * XLM);
    let writes = || s.env.cost_estimate().resources().write_entries;

    // A call that needs an authorization also writes the signer's nonce. A relayed unshield
    // writes the instance, two nullifiers, three tree entries and three balances.
    s.transact(&relayer, &s.ext(-XLM, XLM, &user, &relayer))
        .unwrap();
    assert_eq!(writes(), 10);
    // A transfer without a fee moves no balance.
    s.transact(&relayer, &s.ext(0, 0, &relayer, &relayer))
        .unwrap();
    assert_eq!(writes(), 7);
    // The instance, two nullifiers, the deposit, the day total and two balances.
    s.shield(&depositor, XLM).unwrap();
    assert_eq!(writes(), 8);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    s.vault.attest(&4);
    s.advance(DELAY_SMALL);
    // The instance, the deposit and three tree entries.
    s.vault.admit(&Vec::from_slice(&s.env, &[2]));
    assert_eq!(writes(), 5);
    // The instance, the deposit and two balances.
    s.vault.cancel(&3);
    assert_eq!(writes(), 5);
    s.vault.flag(&4, &1);
    s.advance(DAY);
    s.vault.refund(&4);
    assert_eq!(writes(), 4);
}

#[test]
fn the_exit_queue_writes_only_the_entries_it_changes() {
    let s = Setup::with_limits(Limits {
        max_daily_outflow: 10 * XLM,
        tvl_cap: 70 * XLM,
        ..limits()
    });
    s.fund_pool("funder", 50 * XLM);
    let relayer = s.account("relayer", 0);
    let user = s.account("user", 0);
    let writes = || s.env.cost_estimate().resources().write_entries;
    s.transact(&relayer, &s.ext(-10 * XLM, 0, &relayer, &relayer))
        .unwrap();

    // A queued unshield writes the instance, two nullifiers, three tree entries, the exit and
    // the submitter's nonce, and moves no balance.
    s.transact(&relayer, &s.ext(-XLM, XLM, &user, &relayer))
        .unwrap();
    assert_eq!(writes(), 8);
    assert_eq!(persistent_ttl(&s, &DataKey::Exit(1)), WRITE_TTL);
    // Releasing it writes the instance, the exit and three balances.
    s.advance(DAY);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(writes(), 5);
}
