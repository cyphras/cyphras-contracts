//! The test environment archives an entry once the ledger passes its TTL and restores it when a
//! call touches it, as a transaction does when the entry is in its footprint.

use std::rc::Rc;

use soroban_sdk::{
    testutils::Ledger,
    xdr::{self, ScAddress, ScVal},
    Env, IntoVal, TryFromVal, U256,
};

use super::{
    e2e::Flow,
    fixtures,
    setup::{limits, outcome, Setup, DAY, XLM},
};
use crate::{DataKey, Error, Limits};

fn ledger_key(env: &Env, contract: &soroban_sdk::Address, key: &DataKey) -> Rc<xdr::LedgerKey> {
    let ScAddress::Contract(contract) = ScAddress::from(contract) else {
        panic!("not a contract");
    };
    Rc::new(xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
        contract: ScAddress::Contract(contract),
        key: ScVal::try_from_val(env, &IntoVal::<Env, soroban_sdk::Val>::into_val(key, env))
            .unwrap(),
        durability: xdr::ContractDataDurability::Persistent,
    }))
}

fn live_until(env: &Env, contract: &soroban_sdk::Address, key: &DataKey) -> u32 {
    let (_, live_until) = env
        .host()
        .get_ledger_entry(&ledger_key(env, contract, key))
        .unwrap()
        .unwrap();
    live_until.unwrap()
}

/// Moves the ledger past the end of the entry's life, so it is archived. Reading the entry would
/// restore it, so it is not read again here.
fn archive(env: &Env, contract: &soroban_sdk::Address, key: &DataKey) -> u32 {
    let end = live_until(env, contract, key);
    assert!(end >= env.ledger().sequence());
    env.ledger().set_sequence_number(end + 1);
    end
}

#[test]
fn a_spent_nullifier_still_refuses_a_double_spend_after_archival_and_restore() {
    let flow = Flow::at("unshield_self");
    let s = &flow.s;
    let env = &s.env;
    let step = fixtures::step("unshield_muxed");
    let spent: U256 = fixtures::proof(env, &step)
        .input_nullifiers
        .get_unchecked(0);
    let key = DataKey::Nullifier(spent.clone());
    let end = archive(env, &s.vault.address, &key);

    // The vault's read restores it, with the network's minimum TTL.
    assert!(s.vault.is_spent(&spent));
    assert!(env.cost_estimate().resources().disk_read_entries > 0);
    let restored_until = live_until(env, &s.vault.address, &key);
    assert!(restored_until > end);
    assert_eq!(restored_until, env.ledger().sequence() + 4_096 - 1);

    // Archive it again and replay the transaction that spent it.
    archive(env, &s.vault.address, &key);
    assert_eq!(flow.run(&step), Err(Error::NullifierSpent));

    // The tree entries were archived too, and the next transaction still settles.
    flow.run(&fixtures::step("unshield_self")).unwrap();
    assert_eq!(
        s.vault.current_root(),
        fixtures::field(env, &fixtures::step("unshield_self")["root_after"])
    );
}

#[test]
fn an_archived_pending_deposit_can_still_be_cancelled_or_refunded() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, 10 * XLM).unwrap();
    s.shield(&depositor, 20 * XLM).unwrap();
    s.vault.flag(&2, &4);
    s.advance(DAY);
    archive(&s.env, &s.vault.address, &DataKey::Pending(1));
    archive(&s.env, &s.vault.address, &DataKey::Pending(2));

    s.vault.cancel(&1);
    s.vault.refund(&2);
    assert_eq!(s.balance(&depositor), 100 * XLM);
    assert_eq!(outcome(s.vault.try_cancel(&1)), Err(Error::UnknownDeposit));
}

#[test]
fn an_archived_queued_or_stranded_exit_is_still_paid() {
    let s = Setup::with_limits(Limits {
        max_daily_outflow: 10 * XLM,
        tvl_cap: 70 * XLM,
        ..limits()
    });
    s.fund_pool("funder", 50 * XLM);
    let user = s.account("user", 0);
    let poor = s.account("poor", 0);
    s.transact(&user, &s.ext(-10 * XLM, 0, &user, &user))
        .unwrap();
    s.transact(&user, &s.ext(-XLM / 2, 0, &poor, &user))
        .unwrap();
    s.transact(&user, &s.ext(-XLM, 0, &user, &user)).unwrap();
    // Both exits were written in the same ledger, so they are archived together.
    archive(&s.env, &s.vault.address, &DataKey::Exit(1));
    s.advance(DAY);

    // The base reserve rises, and the first exit would leave its account below it, so it strands;
    // the second is paid.
    s.env.ledger().with_mut(|l| l.base_reserve = 5_000_000);
    assert_eq!(s.vault.release(&2), 2);
    assert_eq!(s.balance(&user), 11 * XLM);
    archive(&s.env, &s.vault.address, &DataKey::Stranded(1));
    s.account("poor", XLM);
    s.vault.claim(&1);
    assert_eq!(s.balance(&poor), XLM + XLM / 2);
    assert_eq!(s.vault.status().queued_total, 0);
}
