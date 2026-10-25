//! The test environment archives an entry once the ledger passes its TTL and restores it when a
//! call touches it, as a transaction does when the entry is in its footprint. The vault runs
//! natively here, so its code entry is touched only through the instance's TTL extension, which
//! extends the code with it.

use std::rc::Rc;

use soroban_sdk::{
    testutils::Ledger,
    xdr::{self, ScAddress, ScVal},
    Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec, U256,
};

use super::{
    e2e::Flow,
    fixtures,
    setup::{limits, outcome, Setup, DAY, XLM},
};
use crate::{DataKey, Error, Limits};

// The mainnet network settings: a restored entry lives 120 days, no entry lives past 180 days.
const MIN_PERSISTENT_TTL: u32 = 2_073_600;
const MAX_ENTRY_TTL: u32 = 3_110_400;
const LEDGERS_PER_DAY: u32 = 17_280;
const LEDGERS_PER_HOUR: u32 = 720;
// The vault's own writes extend an entry with this many ledgers left or fewer, to WRITE_TTL.
const THRESHOLD: u32 = 30 * LEDGERS_PER_DAY;
const WRITE_TTL: u32 = THRESHOLD + LEDGERS_PER_HOUR;

const TREE: [DataKey; 3] = [DataKey::Roots, DataKey::Frontier, DataKey::NextLeaf];

fn contract_data(contract: &Address, key: ScVal) -> Rc<xdr::LedgerKey> {
    let ScAddress::Contract(contract) = ScAddress::from(contract) else {
        panic!("not a contract");
    };
    Rc::new(xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
        contract: ScAddress::Contract(contract),
        key,
        durability: xdr::ContractDataDurability::Persistent,
    }))
}

fn ledger_key(env: &Env, contract: &Address, key: &DataKey) -> Rc<xdr::LedgerKey> {
    let key = ScVal::try_from_val(env, &IntoVal::<Env, Val>::into_val(key, env)).unwrap();
    contract_data(contract, key)
}

fn instance_key(s: &Setup) -> Rc<xdr::LedgerKey> {
    contract_data(&s.vault.address, ScVal::LedgerKeyContractInstance)
}

/// The code entry the vault's instance names, read while the instance is live.
fn code_key(s: &Setup) -> Rc<xdr::LedgerKey> {
    let (entry, _) = s
        .env
        .host()
        .get_ledger_entry(&instance_key(s))
        .unwrap()
        .unwrap();
    let xdr::LedgerEntryData::ContractData(data) = &entry.data else {
        panic!("not contract data");
    };
    let ScVal::ContractInstance(instance) = &data.val else {
        panic!("not an instance");
    };
    let xdr::ContractExecutable::Wasm(hash) = &instance.executable else {
        panic!("not a wasm contract");
    };
    Rc::new(xdr::LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
        hash: hash.clone(),
    }))
}

/// The asset contract's entry for the balance of `holder`, a contract.
fn balance_key(s: &Setup, holder: &Address) -> Rc<xdr::LedgerKey> {
    let key: Val = (Symbol::new(&s.env, "Balance"), holder.clone()).into_val(&s.env);
    contract_data(&s.token.address, ScVal::try_from_val(&s.env, &key).unwrap())
}

/// The code, the instance, the tree and the vault's balance: what an unshield touches.
fn vault_keys(s: &Setup) -> std::vec::Vec<Rc<xdr::LedgerKey>> {
    let mut keys = std::vec![code_key(s), instance_key(s)];
    keys.extend(TREE.iter().map(|k| ledger_key(&s.env, &s.vault.address, k)));
    keys.push(balance_key(s, &s.vault.address));
    keys
}

/// The entry's live-until ledger as stored, read without restoring it.
fn stored_live_until(env: &Env, key: &xdr::LedgerKey) -> u32 {
    env.host()
        .get_stored_entries()
        .unwrap()
        .into_iter()
        .find(|(k, _)| k.as_ref() == key)
        .and_then(|(_, entry)| entry)
        .and_then(|(_, live_until)| live_until)
        .unwrap()
}

fn mainnet_ttls(env: &Env) {
    env.ledger().with_mut(|l| {
        l.min_persistent_entry_ttl = MIN_PERSISTENT_TTL;
        l.max_entry_ttl = MAX_ENTRY_TTL;
    });
}

/// The first ledger at which every listed entry is archived.
fn all_archived_at(env: &Env, keys: &[Rc<xdr::LedgerKey>]) -> u32 {
    let last = keys
        .iter()
        .map(|key| stored_live_until(env, key))
        .max()
        .unwrap();
    (last + 1).max(env.ledger().sequence())
}

/// Moves time forward to `sequence`, at five seconds a ledger.
fn move_to(s: &Setup, sequence: u32) {
    let ledgers = sequence - s.env.ledger().sequence();
    s.advance(ledgers as u64 * 5);
    assert_eq!(s.env.ledger().sequence(), sequence);
}

/// Moves to the first ledger at which every listed entry is archived.
fn archive_all(s: &Setup, keys: &[Rc<xdr::LedgerKey>]) {
    move_to(s, all_archived_at(&s.env, keys));
    assert_archived(&s.env, keys);
}

fn assert_archived(env: &Env, keys: &[Rc<xdr::LedgerKey>]) {
    for key in keys {
        assert!(
            stored_live_until(env, key) < env.ledger().sequence(),
            "{key:?}"
        );
    }
}

/// A restored entry lives for the network's minimum persistent TTL, counting the current ledger.
/// That is above the vault's 30-day threshold, so the call's own writes do not extend it further.
fn assert_restored(env: &Env, keys: &[Rc<xdr::LedgerKey>]) {
    let restored_until = env.ledger().sequence() + MIN_PERSISTENT_TTL - 1;
    for key in keys {
        assert_eq!(stored_live_until(env, key), restored_until, "{key:?}");
    }
}

/// Proves a transaction for the first ledger at which every listed entry is archived, as a user
/// would whose proof was made before, moves there and submits it.
fn transact_once_archived(
    s: &Setup,
    keys: &[Rc<xdr::LedgerKey>],
    submitter: &Address,
    ext_amount: i128,
    fee: i128,
    recipient: &Address,
) -> Result<(), Error> {
    let at = all_archived_at(&s.env, keys);
    let mut ext = s.ext(ext_amount, fee, recipient, submitter);
    ext.deadline = at + 120;
    let proof = s.prove(&ext);
    move_to(s, at);
    assert_archived(&s.env, keys);
    outcome(s.vault.try_transact(&proof, &ext, submitter))
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
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&poor), XLM + XLM / 2);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn every_call_goes_through_once_the_code_instance_and_tree_are_archived() {
    let s = Setup::with_limits(Limits {
        max_daily_outflow: 10 * XLM,
        tvl_cap: 70 * XLM,
        ..limits()
    });
    mainnet_ttls(&s.env);
    s.fund_pool("funder", 50 * XLM);
    let user = s.account("user", 0);
    let relayer = s.account("relayer", 0);
    let depositor = s.account("depositor", 10 * XLM);
    let id = s.shield(&depositor, 10 * XLM).unwrap();
    let vault = vault_keys(&s);
    let (code, instance, tree, balance) = (&vault[0], &vault[1], &vault[2..5], &vault[5]);
    let shared = [code.clone(), instance.clone(), balance.clone()];
    let with = |more: &[Rc<xdr::LedgerKey>]| [vault.as_slice(), more].concat();

    // A self-relayed unshield restores every entry it touches.
    transact_once_archived(&s, &vault, &user, -5 * XLM, 0, &user).unwrap();
    assert_restored(&s.env, &vault);
    assert_eq!(s.balance(&user), 5 * XLM);

    // So does a relayed transfer, which pays the relayer its fee.
    transact_once_archived(&s, &vault, &relayer, 0, XLM / 10, &relayer).unwrap();
    assert_restored(&s.env, &vault);
    assert_eq!(s.balance(&relayer), XLM / 10);

    // A cancel restores only what it touches: the tree stays archived.
    let pending = ledger_key(&s.env, &s.vault.address, &DataKey::Pending(id));
    archive_all(&s, &with(&[pending]));
    s.vault.cancel(&id);
    assert_restored(&s.env, &shared);
    assert_archived(&s.env, tree);
    assert_eq!(s.balance(&depositor), 10 * XLM);

    // Today's window filled, two exits queue.
    let poor = s.account("poor", 0);
    s.transact(&user, &s.ext(-10 * XLM, 0, &user, &user))
        .unwrap();
    s.transact(&user, &s.ext(-XLM / 2, 0, &poor, &user))
        .unwrap();
    s.transact(&user, &s.ext(-XLM, 0, &user, &user)).unwrap();
    let exits = [1, 2].map(|id| ledger_key(&s.env, &s.vault.address, &DataKey::Exit(id)));
    archive_all(&s, &with(&exits));
    // The base reserve rises, and the first exit would leave its account below it, so it strands;
    // the second is paid.
    s.env.ledger().with_mut(|l| l.base_reserve = 5_000_000);
    assert_eq!(s.vault.release(&2), 2);
    assert_restored(&s.env, &shared);
    assert_archived(&s.env, tree);
    assert_eq!(s.balance(&user), 16 * XLM);

    let stranded = ledger_key(&s.env, &s.vault.address, &DataKey::Stranded(1));
    archive_all(&s, &with(&[stranded]));
    s.account("poor", XLM);
    assert_eq!(s.vault.claim(&1), 3);
    assert_restored(&s.env, &[code.clone(), instance.clone()]);
    assert_archived(&s.env, tree);
    assert_eq!(s.vault.release(&1), 1);
    assert_restored(&s.env, &shared);
    assert_eq!(s.balance(&poor), XLM + XLM / 2);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn under_thirty_days_a_write_extends_the_vaults_entries_by_the_time_since_the_last_one() {
    let s = Setup::new();
    mainnet_ttls(&s.env);
    s.fund_pool("funder", 50 * XLM);
    let relayer = s.account("relayer", 0);
    let keys = vault_keys(&s)[..5].to_vec();
    // A transfer without a fee writes the instance and the tree, and moves no balance.
    let write = || {
        s.transact(&relayer, &s.ext(0, 0, &relayer, &relayer))
            .unwrap()
    };
    let lives = || {
        keys.iter()
            .map(|k| stored_live_until(&s.env, k))
            .collect::<std::vec::Vec<_>>()
    };

    // A write leaves the code, the instance and the tree 30 days and an hour.
    write();
    let written = s.env.ledger().sequence();
    assert_eq!(lives(), std::vec![written + WRITE_TTL; 5]);

    // Half an hour later they have more than 30 days left, and a write extends nothing.
    s.advance(1_800);
    write();
    assert_eq!(lives(), std::vec![written + WRITE_TTL; 5]);

    // Three days after the last extension, a write extends them by those three days.
    move_to(&s, written + 3 * LEDGERS_PER_DAY);
    write();
    assert_eq!(
        lives(),
        std::vec![written + 3 * LEDGERS_PER_DAY + WRITE_TTL; 5]
    );

    // After a longer extension, as the keeper makes, a write pays nothing until they fall to 30
    // days left; two days after that, it extends them by two days and an hour.
    s.vault.bump_ttl(&Vec::new(&s.env), &Vec::new(&s.env));
    let bumped = lives();
    assert_eq!(bumped, std::vec![bumped[0]; 5]);
    assert!(bumped[0] - s.env.ledger().sequence() > THRESHOLD);
    move_to(&s, bumped[0] - THRESHOLD - LEDGERS_PER_HOUR);
    write();
    assert_eq!(lives(), bumped);
    let gap = 2 * LEDGERS_PER_DAY;
    move_to(&s, bumped[0] - THRESHOLD + gap);
    write();
    assert_eq!(lives(), std::vec![bumped[0] + gap + LEDGERS_PER_HOUR; 5]);
}
