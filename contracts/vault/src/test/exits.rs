//! The exit queue: an exit that does not fit today's outflow window waits in ID order, and anyone
//! releases the queue as the window allows.

use soroban_sdk::{testutils::Events as _, Address, Event};

use super::{
    queue::authorizers,
    setup::{limits, outcome, Setup, DAY, XLM},
};
use crate::{events, Error, Exit, Status};

const HALT: u64 = 72 * 3_600;

/// A vault holding six admitted deposits of 2,500 XLM, three days of outflow.
fn funded() -> Setup {
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
pub fn queue(s: &Setup, payout: i128, fee: i128, recipient: &Address, relayer: &Address) -> u64 {
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
fn release_stops_at_the_first_exit_that_does_not_fit_and_never_skips_it() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    fill_window(&s, &filler);
    let a = queue(&s, 3_000 * XLM, 0, &user, &user);
    let b = queue(&s, 3_000 * XLM, 0, &user, &user);
    let c = queue(&s, XLM, 0, &user, &user);

    // The last exit would fit beside the first, but it does not pass the second.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 1);
    assert_eq!(s.vault.exit(&a), None);
    assert!(s.vault.exit(&b).is_some() && s.vault.exit(&c).is_some());
    assert_eq!(s.vault.status().exit_head, b);
    assert_eq!(s.balance(&user), 3_000 * XLM);
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!(s.balance(&user), 6_001 * XLM);
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
fn released_exits_never_take_more_than_a_window_a_day() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    let max = s.vault.limits().max_daily_outflow;
    fill_window(&s, &filler);
    // Seven exits of 700 XLM fit a day's window and an eighth does not.
    for _ in 0..14 {
        queue(&s, 700 * XLM, 0, &user, &user);
    }
    let mut days = 0;
    while s.vault.status().exit_head < s.vault.status().exit_tail {
        to_midnight(&s);
        let before = s.balance(&user);
        // However often the keeper calls, the window caps the day.
        for max in [3, 50, 50] {
            s.vault.release(&max);
        }
        let paid = s.balance(&user) - before;
        assert_eq!(paid, 4_900 * XLM);
        assert_eq!(used(&s), paid);
        assert!(paid <= max);
        days += 1;
    }
    assert_eq!(days, 2);
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
