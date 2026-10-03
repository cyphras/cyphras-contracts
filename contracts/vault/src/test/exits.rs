//! The exit queue: an exit that does not fit today's outflow window waits in ID order, and anyone
//! releases the queue as the window allows.

use std::{collections::VecDeque, rc::Rc};

use soroban_sdk::{
    testutils::{Events as _, MuxedAddress as _},
    token::StellarAssetClient,
    xdr, Address, Env, Event, MuxedAddress,
};

use super::{
    queue::authorizers,
    setup::{
        account_address, asset_contract, create_account, env, limits, outcome, Setup, DAY,
        DELAY_SMALL, TESTNET, XLM,
    },
};
use crate::{events, storage, Error, Exit, Status};

const HALT: u64 = 72 * 3_600;

/// A vault holding six admitted deposits of 2,500 XLM, three days of outflow.
pub fn funded() -> Setup {
    let s = Setup::new();
    for i in 0..6 {
        s.fund_pool(&std::format!("funder {i}"), 2_500 * XLM);
    }
    s
}

pub fn to_midnight(s: &Setup) {
    s.advance(DAY - s.now() % DAY);
}

/// The outflow paid so far today.
pub fn used(s: &Setup) -> i128 {
    let status = s.vault.status();
    if status.outflow_day == s.now() / DAY {
        status.outflow
    } else {
        0
    }
}

/// Takes what is left of today's window with a self-relayed exit to `to`, paid at once.
pub fn fill_window(s: &Setup, to: &Address) {
    let room = s.vault.limits().max_daily_outflow - used(s);
    let ext = s.ext(-room, 0, to, to);
    assert_eq!(s.transact(to, &ext), Ok(()));
    assert_eq!(used(s), s.vault.limits().max_daily_outflow);
}

/// Submits an unshield that must wait in the queue, and returns its exit ID.
pub fn queue(
    s: &Setup,
    payout: i128,
    fee: i128,
    recipient: impl Into<MuxedAddress>,
    relayer: &Address,
) -> u64 {
    let id = s.vault.status().exit_tail;
    let ext = s.ext(-payout, fee, recipient, relayer);
    assert_eq!(s.transact(relayer, &ext), Ok(()));
    assert_eq!(s.vault.status().exit_tail, id + 1);
    id
}

#[test]
fn an_exit_that_does_not_fit_todays_window_waits_in_the_queue() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    let relayer = s.account("relayer", 0);
    fill_window(&s, &filler);
    let status = s.vault.status();
    let leaf = s.vault.next_leaf_index();

    let ext = s.ext(-10 * XLM, XLM, &user, &relayer);
    let proof = s.prove(&ext);
    s.vault.transact(&proof, &ext, &relayer);

    let vault = s.vault.address.clone();
    let all = s.env.events().all();
    let nf = |i| proof.input_nullifiers.get_unchecked(i);
    let cm = |i| proof.output_commitments.get_unchecked(i);
    assert_eq!(
        all.filter_by_contract(&vault),
        std::vec![
            events::NewNullifier { nullifier: nf(0) }.to_xdr(&s.env, &vault),
            events::NewNullifier { nullifier: nf(1) }.to_xdr(&s.env, &vault),
            events::NewCommitment {
                index: leaf,
                commitment: cm(0),
                encrypted_output: ext.encrypted_output0.clone()
            }
            .to_xdr(&s.env, &vault),
            events::NewCommitment {
                index: leaf + 1,
                commitment: cm(1),
                encrypted_output: ext.encrypted_output1.clone()
            }
            .to_xdr(&s.env, &vault),
            events::ExitQueued {
                id: 1,
                ext_amount: -10 * XLM,
                fee: XLM,
                recipient: user.clone().into(),
                relayer: relayer.clone()
            }
            .to_xdr(&s.env, &vault),
        ]
    );
    // The notes are spent and the outputs inserted, but nothing is paid yet: the payout and the
    // fee are owed by the vault, which still holds them.
    assert!(all.filter_by_contract(&s.token.address).events().is_empty());
    assert_eq!((s.balance(&user), s.balance(&relayer)), (0, 0));
    assert!(s.vault.is_spent(&nf(0)) && s.vault.is_spent(&nf(1)));
    assert_eq!(s.vault.next_leaf_index(), leaf + 2);
    assert_eq!(
        s.vault.exit(&1),
        Some(Exit {
            recipient: user.clone().into(),
            payout: 10 * XLM,
            relayer: relayer.clone(),
            fee: XLM,
            queued_at: s.now(),
        })
    );
    assert_eq!(
        s.vault.status(),
        Status {
            queued_total: 11 * XLM,
            exit_tail: 2,
            ..status
        }
    );
    assert_eq!(s.balance(&vault), s.vault.status().tvl);
}

#[test]
fn anyone_releases_queued_exits_in_order_once_the_window_has_room() {
    let s = funded();
    let filler = s.account("filler", 0);
    let relayer = s.account("relayer", 0);
    let users: std::vec::Vec<Address> = (0..3)
        .map(|i| s.account(&std::format!("user {i}"), 0))
        .collect();
    fill_window(&s, &filler);
    for (i, user) in users.iter().enumerate() {
        queue(&s, (i as i128 + 1) * 100 * XLM, XLM, user, &relayer);
    }
    // The window stays full until midnight.
    let status = s.vault.status();
    assert_eq!(s.vault.release(&10), 0);
    assert_eq!(s.vault.status(), status);

    to_midnight(&s);
    s.env.set_auths(&[]);
    assert_eq!(s.vault.release(&10), 3);
    assert!(authorizers(&s).is_empty());
    let vault = s.vault.address.clone();
    let settled = |id: u64, payout: i128| {
        events::Settled {
            ext_amount: -payout,
            fee: XLM,
            recipient: users[id as usize - 1].clone().into(),
            relayer: relayer.clone(),
            exit_id: Some(id),
        }
        .to_xdr(&s.env, &vault)
    };
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            settled(1, 100 * XLM),
            settled(2, 200 * XLM),
            settled(3, 300 * XLM)
        ]
    );
    for (i, user) in users.iter().enumerate() {
        assert_eq!(s.balance(user), (i as i128 + 1) * 100 * XLM);
        assert_eq!(s.vault.exit(&(i as u64 + 1)), None);
    }
    assert_eq!(s.balance(&relayer), 3 * XLM);
    assert_eq!(
        s.vault.status(),
        Status {
            tvl: status.tvl - 603 * XLM,
            queued_total: 0,
            exit_head: 4,
            outflow_day: s.now() / DAY,
            outflow: 603 * XLM,
            ..status
        }
    );
    assert_eq!(s.balance(&vault), s.vault.status().tvl);
}

#[test]
fn release_pays_what_fits_of_an_exit_and_keeps_the_rest_at_the_head() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    let relayer = s.account("relayer", 0);
    fill_window(&s, &filler);
    let a = queue(&s, 3_000 * XLM, 0, &user, &user);
    let b = queue(&s, 3_000 * XLM, 2 * XLM, &user, &relayer);
    let c = queue(&s, XLM, 0, &user, &user);
    let queued_at = s.now();

    // The second exit does not fit beside the first, so what fits of it is paid and the rest
    // waits at the head, still ahead of the third.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            events::Settled {
                ext_amount: -3_000 * XLM,
                fee: 0,
                recipient: user.clone().into(),
                relayer: user.clone(),
                exit_id: Some(a)
            }
            .to_xdr(&s.env, &vault),
            events::ExitPaid {
                id: b,
                payout_paid: 2_000 * XLM,
                fee_paid: 0,
                payout_left: 1_000 * XLM,
                fee_left: 2 * XLM
            }
            .to_xdr(&s.env, &vault),
        ]
    );
    assert_eq!(
        s.vault.exit(&b),
        Some(Exit {
            recipient: user.clone().into(),
            payout: 1_000 * XLM,
            relayer: relayer.clone(),
            fee: 2 * XLM,
            queued_at,
        })
    );
    assert!(s.vault.exit(&c).is_some());
    let status = s.vault.status();
    assert_eq!(status.exit_head, b);
    assert_eq!(used(&s), s.vault.limits().max_daily_outflow);
    assert_eq!(status.queued_total, 1_003 * XLM);
    assert_eq!(s.balance(&user), 5_000 * XLM);

    // The next day pays the rest of the second exit, then the third.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            events::Settled {
                ext_amount: -1_000 * XLM,
                fee: 2 * XLM,
                recipient: user.clone().into(),
                relayer: relayer.clone(),
                exit_id: Some(b)
            }
            .to_xdr(&s.env, &vault),
            events::Settled {
                ext_amount: -XLM,
                fee: 0,
                recipient: user.clone().into(),
                relayer: user.clone(),
                exit_id: Some(c)
            }
            .to_xdr(&s.env, &vault),
        ]
    );
    assert_eq!(
        (s.balance(&user), s.balance(&relayer)),
        (6_001 * XLM, 2 * XLM)
    );
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn a_fee_is_paid_in_part_like_a_payout() {
    let s = Setup::with_limits(crate::Limits {
        max_daily_outflow: 10 * XLM,
        tvl_cap: 70 * XLM,
        ..limits()
    });
    s.fund_pool("funder", 50 * XLM);
    let user = s.account("user", 0);
    let relayer = s.account("relayer", 0);
    fill_window(&s, &user);
    queue(&s, 2 * XLM, 0, &user, &user);
    let id = queue(&s, 7 * XLM, 2 * XLM, &user, &relayer);

    // Two units go to the first exit and seven to the payout, which leaves one for the fee.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env
            .events()
            .all()
            .filter_by_contract(&vault)
            .events()
            .last(),
        Some(
            &events::ExitPaid {
                id,
                payout_paid: 7 * XLM,
                fee_paid: XLM,
                payout_left: 0,
                fee_left: XLM
            }
            .to_xdr(&s.env, &vault)
        )
    );
    assert_eq!(s.balance(&relayer), XLM);
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 1);
    assert_eq!(s.balance(&relayer), 2 * XLM);
    assert_eq!(s.balance(&user), 19 * XLM);
    assert_eq!(used(&s), XLM);
}

#[test]
fn release_stops_after_max_exits() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    fill_window(&s, &filler);
    for _ in 0..3 {
        queue(&s, XLM, 0, &user, &user);
    }
    to_midnight(&s);
    assert_eq!(s.vault.release(&0), 0);
    assert_eq!(s.vault.release(&2), 2);
    assert_eq!(s.vault.status().exit_head, 3);
    assert_eq!(s.vault.release(&5), 1);
    // An empty queue releases nothing.
    assert_eq!(s.vault.release(&5), 0);
    assert_eq!(s.balance(&user), 3 * XLM);
}

#[test]
fn a_waiting_exit_makes_every_later_one_wait_even_when_it_would_fit() {
    let s = funded();
    let filler = s.account("filler", 0);
    let first = s.account("first", 0);
    let second = s.account("second", 0);
    fill_window(&s, &filler);
    queue(&s, 10 * XLM, 0, &first, &first);

    // The new day's window is empty, but the first exit has not been released yet.
    to_midnight(&s);
    assert_eq!(used(&s), 0);
    assert_eq!(queue(&s, XLM, 0, &second, &second), 2);
    assert_eq!(s.balance(&second), 0);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!((s.balance(&first), s.balance(&second)), (10 * XLM, XLM));
    // With the queue empty again, an exit that fits is paid at once.
    let ext = s.ext(-XLM, 0, &second, &second);
    assert_eq!(s.transact(&second, &ext), Ok(()));
    assert_eq!(s.balance(&second), 2 * XLM);
}

#[test]
fn a_transfers_fee_waits_behind_queued_exits() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    let relayer = s.account("relayer", 0);
    fill_window(&s, &filler);
    queue(&s, 10 * XLM, 0, &user, &user);
    to_midnight(&s);

    let ext = s.ext(0, 2 * XLM, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
    let vault = s.vault.address.clone();
    let all = s.env.events().all();
    assert_eq!(
        all.filter_by_contract(&vault).events().last(),
        Some(
            &events::ExitQueued {
                id: 2,
                ext_amount: 0,
                fee: 2 * XLM,
                recipient: relayer.clone().into(),
                relayer: relayer.clone()
            }
            .to_xdr(&s.env, &vault)
        )
    );
    assert!(all.filter_by_contract(&s.token.address).events().is_empty());
    let exit = s.vault.exit(&2).unwrap();
    assert_eq!((exit.payout, exit.fee), (0, 2 * XLM));

    assert_eq!(s.vault.release(&10), 2);
    assert_eq!((s.balance(&user), s.balance(&relayer)), (10 * XLM, 2 * XLM));
}

#[test]
fn a_transfer_without_a_fee_never_waits() {
    let s = funded();
    let filler = s.account("filler", 0);
    let relayer = s.account("relayer", 0);
    fill_window(&s, &filler);
    queue(&s, XLM, 0, &relayer, &relayer);
    let status = s.vault.status();

    let ext = s.ext(0, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
    let vault = s.vault.address.clone();
    let all = s.env.events().all();
    assert_eq!(
        all.filter_by_contract(&vault).events().last(),
        Some(
            &events::Settled {
                ext_amount: 0,
                fee: 0,
                recipient: relayer.clone().into(),
                relayer: relayer.clone(),
                exit_id: None
            }
            .to_xdr(&s.env, &vault)
        )
    );
    assert!(all.filter_by_contract(&s.token.address).events().is_empty());
    assert_eq!(s.vault.status(), status);
}

#[test]
fn the_queue_takes_a_full_window_a_day_and_no_more() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    let max = s.vault.limits().max_daily_outflow;
    fill_window(&s, &filler);
    // Seven exits of 700 XLM and part of an eighth fill a day's window.
    for _ in 0..14 {
        queue(&s, 700 * XLM, 0, &user, &user);
    }
    let mut paid_per_day = std::vec::Vec::new();
    while s.vault.status().exit_head < s.vault.status().exit_tail {
        to_midnight(&s);
        let before = s.balance(&user);
        // However often the keeper calls, the window caps the day.
        for max in [3, 50, 50] {
            s.vault.release(&max);
        }
        let paid = s.balance(&user) - before;
        assert_eq!(used(&s), paid);
        assert!(paid <= max);
        paid_per_day.push(paid);
    }
    assert_eq!(paid_per_day, std::vec![max, 9_800 * XLM - max]);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn release_works_while_paused_and_waits_out_a_halt() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    fill_window(&s, &filler);
    queue(&s, XLM, 0, &user, &user);
    queue(&s, XLM, 0, &user, &user);
    s.vault.set_pause(&true, &true);
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);

    s.vault.halt();
    assert_eq!(outcome(s.vault.try_release(&1)), Err(Error::Halted));
    s.advance(HALT - 1);
    assert_eq!(outcome(s.vault.try_release(&1)), Err(Error::Halted));
    s.advance(1);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&user), 2 * XLM);
}

#[test]
fn value_owed_to_queued_exits_cannot_leave_twice() {
    // The trapdoor key stands in for a broken proof system: it forges any spend.
    let s = Setup::with_limits(crate::Limits {
        max_daily_outflow: 100 * XLM,
        tvl_cap: 700 * XLM,
        ..limits()
    });
    s.fund_pool("admitted", 150 * XLM);
    let depositor = s.account("pending depositor", 100 * XLM);
    let id = s.shield(&depositor, 50 * XLM).unwrap();
    let user = s.account("user", 0);
    let forger = s.account("forger", 0);
    fill_window(&s, &user);
    queue(&s, 40 * XLM, 0, &user, &user);
    let status = s.vault.status();
    assert_eq!(
        (status.tvl, status.pending_total, status.queued_total),
        (100 * XLM, 50 * XLM, 40 * XLM)
    );

    // Of the 100 XLM the vault holds, only the 10 XLM of unspent notes can still leave.
    let ext = s.ext(-10 * XLM - 1, 0, &forger, &forger);
    assert_eq!(s.transact(&forger, &ext), Err(Error::ExceedsAdmittedValue));
    let ext = s.ext(-10 * XLM, 0, &forger, &forger);
    assert_eq!(s.transact(&forger, &ext), Ok(()));
    let ext = s.ext(-1, 0, &forger, &forger);
    assert_eq!(s.transact(&forger, &ext), Err(Error::ExceedsAdmittedValue));

    // The queued exits and the pending deposit are still paid in full.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    s.vault.cancel(&id);
    assert_eq!(s.balance(&user), 140 * XLM);
    assert_eq!(s.balance(&forger), 10 * XLM);
    assert_eq!(s.balance(&depositor), 100 * XLM);
    assert_eq!(s.balance(&s.vault.address), 0);
    let status = s.vault.status();
    assert_eq!(
        (status.tvl, status.pending_total, status.queued_total),
        (0, 0, 0)
    );
}

/// The days after the first day boundary within which an exit is paid in full when every day's
/// window is used in full until it is: `ahead`, at least what the exits queued before it still
/// owe, and `own`, its own outflow, must pass through windows of `window` each.
pub fn wait_bound(ahead: i128, own: i128, window: i128) -> u64 {
    ((ahead + own) as u64).div_ceil(window as u64)
}

/// An honest exit waiting in the queue.
pub struct Waiting {
    pub id: u64,
    pub day: u64,
    pub ahead: i128,
    pub own: i128,
}

/// Pops every honest exit the queue has paid in full, checking that it went in its turn and in
/// time.
pub fn check_paid(s: &Setup, waiting: &mut VecDeque<Waiting>) {
    let status = s.vault.status();
    let window = s.vault.limits().max_daily_outflow;
    while let Some(exit) = waiting.front() {
        if s.vault.exit(&exit.id).is_some() {
            break;
        }
        // Every exit queued before it left the queue first.
        assert!(status.exit_head > exit.id);
        let days = s.now() / DAY - exit.day;
        let bound = wait_bound(exit.ahead, exit.own, window);
        assert!(
            days <= bound,
            "exit {} waited {days} days, more than {bound}",
            exit.id
        );
        waiting.pop_front();
    }
}

/// Submits an honest exit that must wait, and records what is ahead of it.
pub fn queue_honest(s: &Setup, payout: i128, honest: &Address, waiting: &mut VecDeque<Waiting>) {
    let ahead = s.vault.status().queued_total;
    let id = queue(s, payout, 0, honest, honest);
    waiting.push_back(Waiting {
        id,
        day: s.now() / DAY,
        ahead,
        own: payout,
    });
}

#[test]
fn one_funded_account_recycling_capital_cannot_keep_an_honest_exit_waiting_past_its_turn() {
    let s = Setup::new();
    let limits = s.vault.limits();
    let window = limits.max_daily_outflow;
    for i in 0..4 {
        s.fund_pool(&std::format!("honest {i}"), 2_500 * XLM);
    }
    let honest = s.account("honest exit", 0);
    let attacker = s.account("attacker", 0);
    let attacker_source = s.account("attacker source", window);
    // Below the large-deposit threshold a deposit waits only the short delay, so the attacker
    // can deposit what it got back and have it admitted within the day.
    let chunk = limits.large_deposit_threshold - XLM;
    let deposit = |s: &Setup, amount: i128| {
        let mut left = amount;
        let mut last = 0;
        while left > 0 {
            last = s.shield(&attacker_source, left.min(chunk)).unwrap();
            left -= left.min(chunk);
        }
        s.vault.attest(&last);
        s.advance(DELAY_SMALL);
        let pending = s.pending_ids();
        let mut start = 0;
        while start < pending.len() {
            let batch = pending.slice(start..(start + 5).min(pending.len()));
            assert_eq!(s.vault.admit(&batch), batch);
            start += batch.len();
        }
    };
    deposit(&s, window);
    let mut attacker_notes = window;

    let mut waiting = VecDeque::new();
    for day in 0..12 {
        to_midnight(&s);
        // The attacker races for each new window before anyone else with all it holds. Once an
        // exit waits, the attacker's exit waits behind it.
        if day < 8 && attacker_notes > 0 {
            let ext = s.ext(-attacker_notes, 0, &attacker, &attacker);
            assert_eq!(s.transact(&attacker, &ext), Ok(()));
            attacker_notes = 0;
        }
        // An honest exit follows and waits its turn.
        if day < 8 {
            queue_honest(&s, 100 * XLM, &honest, &mut waiting);
        }
        // The keeper releases at the start of the day until the window is full.
        s.vault.release(&50);
        s.vault.release(&50);
        assert!(used(&s) <= window);
        check_paid(&s, &mut waiting);
        // Whatever reached the attacker goes straight back into the pool.
        let back = s.balance(&attacker);
        if back > 0 {
            s.token.transfer(&attacker, &attacker_source, &back);
            deposit(&s, back);
            attacker_notes = back;
        }
    }
    assert!(waiting.is_empty());
    assert_eq!(s.balance(&honest), 800 * XLM);
    assert_eq!(s.vault.status().exit_head, s.vault.status().exit_tail);
}

#[test]
fn exits_sized_to_waste_the_window_still_use_all_of_it() {
    let s = Setup::new();
    for i in 0..9 {
        s.fund_pool(&std::format!("funder {i}"), 2_500 * XLM);
    }
    let window = s.vault.limits().max_daily_outflow;
    let filler = s.account("filler", 0);
    let attacker = s.account("attacker", 0);
    let honest = s.account("honest", 0);
    fill_window(&s, &filler);
    // Two of these never fit one window whole, but the second is paid in part.
    let wasteful = window / 2 + 1;
    for _ in 0..6 {
        queue(&s, wasteful, 0, &attacker, &attacker);
    }
    let mut waiting = VecDeque::new();
    queue_honest(&s, 100 * XLM, &honest, &mut waiting);
    let bound = wait_bound(6 * wasteful, 100 * XLM, window);
    assert_eq!(bound, 4);

    let mut days = 0;
    while !waiting.is_empty() {
        to_midnight(&s);
        days += 1;
        s.vault.release(&50);
        check_paid(&s, &mut waiting);
        if !waiting.is_empty() {
            assert_eq!(used(&s), window);
        }
    }
    // A little over three windows in front and its own small outflow take exactly the bound.
    assert_eq!(days, bound);
    assert_eq!(s.balance(&honest), 100 * XLM);
    assert_eq!(s.balance(&attacker), 6 * wasteful);
}

#[test]
fn exits_of_any_size_are_paid_in_exactly_their_share_of_full_windows() {
    let s = Setup::new();
    for i in 0..10 {
        s.fund_pool(&std::format!("funder {i}"), 2_500 * XLM);
    }
    let window = s.vault.limits().max_daily_outflow;
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    fill_window(&s, &filler);
    // Exits of random sizes, worth four windows in all, wait together.
    let mut waiting = VecDeque::new();
    let mut notes = 20_000 * XLM;
    while notes > 0 {
        let size = (1 + s.below(window as u64) as i128).min(notes);
        queue_honest(&s, size, &user, &mut waiting);
        notes -= size;
    }
    let bounds: std::vec::Vec<(u64, u64)> = waiting
        .iter()
        .map(|w| (w.id, wait_bound(w.ahead, w.own, window)))
        .collect();
    assert_eq!(bounds.last().unwrap().1, 4);

    let mut day = 0;
    while !waiting.is_empty() {
        to_midnight(&s);
        day += 1;
        s.vault.release(&50);
        // With every window used in full, each exit is paid on the very day its bound names.
        for (id, bound) in &bounds {
            assert_eq!(s.vault.exit(id).is_none(), *bound <= day, "exit {id}");
        }
        check_paid(&s, &mut waiting);
    }
    assert_eq!(day, 4);
    assert_eq!(s.balance(&user), 20_000 * XLM);
}

// The live network's per-transaction limits on instructions and on event bytes. The test
// environment also enforces its limits on written and accessed ledger entries by default.
const TX_INSTRUCTIONS: i64 = 400_000_000;
const TX_EVENTS: u32 = 16_384;

/// A classic asset with a twelve-letter code, the longest name its transfer events can carry.
fn long_asset(env: &Env) -> xdr::AlphaNum12 {
    let issuer = account_address(env, "issuer");
    let xdr::ScAddress::Account(issuer) = xdr::ScAddress::from(&issuer) else {
        panic!("the issuer is not an account");
    };
    xdr::AlphaNum12 {
        asset_code: xdr::AssetCode12(*b"ABCDEFGHIJKL"),
        issuer,
    }
}

/// An account with an authorized trustline to `asset`, written straight into the ledger.
fn trusting(env: &Env, asset: &xdr::AlphaNum12, tag: &str) -> Address {
    let address = account_address(env, tag);
    create_account(env, &address, 0);
    let xdr::ScAddress::Account(account_id) = xdr::ScAddress::from(&address) else {
        panic!("not an account address");
    };
    let asset = xdr::TrustLineAsset::CreditAlphanum12(asset.clone());
    let key = Rc::new(xdr::LedgerKey::Trustline(xdr::LedgerKeyTrustLine {
        account_id: account_id.clone(),
        asset: asset.clone(),
    }));
    let entry = Rc::new(xdr::LedgerEntry {
        data: xdr::LedgerEntryData::Trustline(xdr::TrustLineEntry {
            account_id,
            asset,
            balance: 0,
            limit: i64::MAX,
            flags: xdr::TrustLineFlags::AuthorizedFlag as u32,
            ext: xdr::TrustLineEntryExt::V0,
        }),
        last_modified_ledger_seq: 0,
        ext: xdr::LedgerEntryExt::V0,
    });
    env.host().add_ledger_entry(&key, &entry, None).unwrap();
    address
}

/// A vault of the long-named asset holding `n` exits, written into its storage as `transact`
/// queues them. Each pays 100 units to a muxed address of an account of its own and a fee of one
/// unit to its relayer, which is the same account for every exit when `shared_relayer` is set.
fn queued_exits(n: u64, shared_relayer: bool) -> Setup {
    let env = env(TESTNET);
    let asset = long_asset(&env);
    create_account(&env, &account_address(&env, "issuer"), XLM);
    let token = asset_contract(&env, xdr::Asset::CreditAlphanum12(asset.clone()));
    let s = Setup::with_token(
        env,
        token.clone(),
        crate::Limits {
            max_daily_outflow: 1_000_000 * XLM,
            tvl_cap: 7_000_000 * XLM,
            ..limits()
        },
    );
    let total = 101 * XLM * n as i128;
    StellarAssetClient::new(&s.env, &token).mint(&s.vault.address, &total);
    let shared = trusting(&s.env, &asset, "relayer");
    let exits: std::vec::Vec<Exit> = (0..n)
        .map(|i| Exit {
            recipient: MuxedAddress::new(
                trusting(&s.env, &asset, &std::format!("recipient {i}")),
                u64::MAX - i,
            ),
            payout: 100 * XLM,
            relayer: if shared_relayer {
                shared.clone()
            } else {
                trusting(&s.env, &asset, &std::format!("relayer {i}"))
            },
            fee: XLM,
            queued_at: s.now(),
        })
        .collect();
    s.env.as_contract(&s.vault.address, || {
        let mut status = storage::status(&s.env);
        for exit in &exits {
            storage::set_exit(&s.env, status.exit_tail, exit);
            status.exit_tail += 1;
        }
        status.tvl = total;
        status.queued_total = total;
        storage::set_status(&s.env, &status);
    });
    s
}

#[test]
fn fifteen_releases_fit_every_limit_of_one_transaction() {
    // Each exit has a recipient and a relayer of its own, so it writes three entries and emits a
    // settled event and two transfers naming the long asset. The budget is lifted so that only
    // the network's limits, checked here and by the test environment, apply.
    let s = queued_exits(15, false);
    s.env.cost_estimate().budget().reset_unlimited();
    assert_eq!(s.vault.release(&15), 15);
    let resources = s.env.cost_estimate().resources();
    std::println!(
        "release of 15: cpu {} mem {} writes {} entries {} events {}",
        resources.instructions,
        resources.mem_bytes,
        resources.write_entries,
        resources.disk_read_entries + resources.memory_read_entries + resources.write_entries,
        resources.contract_events_size_bytes,
    );
    assert!(resources.instructions <= TX_INSTRUCTIONS);
    assert!(resources.contract_events_size_bytes <= TX_EVENTS);
    assert_eq!(resources.write_entries, 3 * 15 + 2);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn the_event_limit_caps_a_release_at_eighteen_exits() {
    let s = queued_exits(19, true);
    s.env.cost_estimate().budget().reset_unlimited();
    assert_eq!(s.vault.release(&1), 1);
    let one = s.env.cost_estimate().resources().contract_events_size_bytes;
    s.env.cost_estimate().budget().reset_unlimited();
    assert_eq!(s.vault.release(&18), 18);
    let eighteen = s.env.cost_estimate().resources().contract_events_size_bytes;
    assert_eq!(eighteen, 18 * one);
    assert!(eighteen <= TX_EVENTS && 19 * one > TX_EVENTS);
}
