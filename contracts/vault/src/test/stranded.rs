//! Exits whose recipient or relayer can no longer receive the asset when they are released. A
//! part the asset contract refuses is set aside as a stranded exit, the queue moves on, and once
//! the party can receive, anyone moves the part back to the tail of the queue.

use std::collections::VecDeque;

use soroban_sdk::{
    testutils::{Events as _, Ledger, MuxedAddress as _},
    Event, MuxedAddress,
};

use super::{
    exits::{
        check_paid, fill_window, funded, queue, queue_honest, to_midnight, used, wait_bound,
        Waiting,
    },
    queue::authorizers,
    setup::{limits, outcome, Classic, DAY, XLM},
};
use crate::{events, Error, Exit, Limits, Status};

const HALT: u64 = 72 * 3_600;

/// A vault of a classic asset whose issuer can revoke authorization, holding 15,000 units of
/// admitted notes.
fn classic() -> Classic {
    let c = Classic::new(limits());
    c.fund(6, 2_500 * XLM);
    c
}

#[test]
fn an_exit_whose_recipient_loses_the_right_to_hold_the_asset_strands_and_the_queue_moves_on() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let relayer = c.holder("relayer", 0);
    let honest = c.holder("honest", 0);
    let flaky = c.holder("flaky", 0);
    fill_window(s, &filler);
    let stuck = queue(s, 10 * XLM, XLM, &flaky, &relayer);
    let queued_at = s.now();
    let next = queue(s, 20 * XLM, XLM, &honest, &relayer);
    // The issuer revokes the recipient's right to hold the asset after its exit was queued.
    c.asset.set_authorized(&flaky, &false);
    to_midnight(s);
    let status = s.vault.status();

    assert_eq!(s.vault.release(&10), 2);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            events::ExitStranded {
                id: stuck,
                payout: 10 * XLM,
                fee: 0
            }
            .to_xdr(&s.env, &vault),
            events::Settled {
                ext_amount: -20 * XLM,
                fee: XLM,
                recipient: honest.clone().into(),
                relayer: relayer.clone(),
                exit_id: Some(next)
            }
            .to_xdr(&s.env, &vault),
        ]
    );
    // The fee of the stranded exit reached its relayer; the payout stays owed and reserved.
    assert_eq!(s.vault.exit(&stuck), None);
    assert_eq!(
        s.vault.stranded(&stuck),
        Some(Exit {
            recipient: flaky.clone().into(),
            payout: 10 * XLM,
            relayer: relayer.clone(),
            fee: 0,
            queued_at,
        })
    );
    assert_eq!(s.balance(&relayer), 2 * XLM);
    assert_eq!(s.balance(&honest), 20 * XLM);
    let released = Status {
        tvl: status.tvl - 22 * XLM,
        queued_total: 10 * XLM,
        exit_head: next + 1,
        outflow_day: s.now() / DAY,
        outflow: 22 * XLM,
        ..status
    };
    assert_eq!(s.vault.status(), released);
    assert_eq!(s.balance(&vault), released.tvl);

    // While the recipient still cannot receive, nothing can move back into the queue.
    assert_eq!(
        outcome(s.vault.try_claim(&stuck)),
        Err(Error::NothingClaimable)
    );
    assert_eq!(s.vault.status(), released);

    // Once it can, anyone moves the payout to the tail of the queue. The value stays owed and
    // nothing is paid yet, so no total and no window changes.
    c.asset.set_authorized(&flaky, &true);
    s.env.set_auths(&[]);
    let requeued = s.vault.claim(&stuck);
    assert!(authorizers(s).is_empty());
    assert_eq!(requeued, released.exit_tail);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitRequeued {
            id: stuck,
            new_id: requeued,
            payout: 10 * XLM,
            fee: 0
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.vault.stranded(&stuck), None);
    assert_eq!(
        s.vault.exit(&requeued),
        Some(Exit {
            recipient: flaky.clone().into(),
            payout: 10 * XLM,
            relayer: relayer.clone(),
            fee: 0,
            queued_at: s.now(),
        })
    );
    assert_eq!(
        s.vault.status(),
        Status {
            exit_tail: requeued + 1,
            ..released
        }
    );

    // release pays it in turn, under its new ID.
    assert_eq!(s.vault.release(&10), 1);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Settled {
            ext_amount: -10 * XLM,
            fee: 0,
            recipient: flaky.clone().into(),
            relayer: relayer.clone(),
            exit_id: Some(requeued)
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&flaky), 10 * XLM);
    assert_eq!(
        s.vault.status(),
        Status {
            tvl: released.tvl - 10 * XLM,
            queued_total: 0,
            exit_head: requeued + 1,
            exit_tail: requeued + 1,
            outflow: 32 * XLM,
            ..released
        }
    );
    assert_eq!(s.balance(&vault), s.vault.status().tvl);
}

#[test]
fn a_refused_part_payment_strands_all_the_exit_still_owes_and_the_window_moves_on() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let frozen = c.holder("frozen", 0);
    let relayer = c.holder("relayer", 0);
    fill_window(s, &filler);
    let first = queue(s, 3_000 * XLM, 0, &filler, &filler);
    let stuck = queue(s, 3_000 * XLM, XLM, &frozen, &relayer);
    let last = queue(s, 1_000 * XLM, 0, &filler, &filler);
    c.asset.set_authorized(&frozen, &false);
    to_midnight(s);

    // What fits of the second exit is refused, so all it owes strands and the third is paid.
    assert_eq!(s.vault.release(&10), 3);
    let vault = s.vault.address.clone();
    let settled = |id: u64, payout: i128| {
        events::Settled {
            ext_amount: -payout,
            fee: 0,
            recipient: filler.clone().into(),
            relayer: filler.clone(),
            exit_id: Some(id),
        }
        .to_xdr(&s.env, &vault)
    };
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            settled(first, 3_000 * XLM),
            events::ExitStranded {
                id: stuck,
                payout: 3_000 * XLM,
                fee: XLM
            }
            .to_xdr(&s.env, &vault),
            settled(last, 1_000 * XLM),
        ]
    );
    let stranded = s.vault.stranded(&stuck).unwrap();
    assert_eq!((stranded.payout, stranded.fee), (3_000 * XLM, XLM));
    assert_eq!(used(s), 4_000 * XLM);
    assert_eq!(s.vault.status().queued_total, 3_001 * XLM);
    assert_eq!(s.balance(&filler), 9_000 * XLM);
}

#[test]
fn a_deauthorized_recipient_strands_and_is_paid_once_authorized_again() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let frozen = c.holder("frozen", 0);
    fill_window(s, &filler);
    let id = queue(s, 10 * XLM, 0, &frozen, &frozen);
    c.asset.set_authorized(&frozen, &false);
    to_midnight(s);

    assert_eq!(s.vault.release(&1), 1);
    let stranded = s.vault.stranded(&id).unwrap();
    assert_eq!((stranded.payout, stranded.fee), (10 * XLM, 0));
    // Nothing was paid, so nothing was taken from the window.
    assert_eq!(used(s), 0);
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );
    assert_eq!(s.vault.stranded(&id), Some(stranded));

    c.asset.set_authorized(&frozen, &true);
    s.vault.claim(&id);
    // A claim pays nothing; release does.
    assert_eq!((s.balance(&frozen), used(s)), (0, 0));
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&frozen), 10 * XLM);
    assert_eq!(used(s), 10 * XLM);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn a_fee_its_relayer_cannot_receive_strands_alone() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let exchange = c.holder("exchange", 0);
    let relayer = c.holder("relayer", 0);
    fill_window(s, &filler);
    let deposit_address = MuxedAddress::new(exchange.clone(), 7);
    let id = queue(s, 10 * XLM, XLM, deposit_address.clone(), &relayer);
    c.asset.set_authorized(&relayer, &false);
    to_midnight(s);

    assert_eq!(s.vault.release(&1), 1);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitStranded {
            id,
            payout: 0,
            fee: XLM
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&exchange), 10 * XLM);
    assert_eq!(used(s), 10 * XLM);
    let status = s.vault.status();
    assert_eq!(status.queued_total, XLM);
    assert_eq!(s.balance(&vault), status.tvl);

    c.asset.set_authorized(&relayer, &true);
    let requeued = s.vault.claim(&id);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitRequeued {
            id,
            new_id: requeued,
            payout: 0,
            fee: XLM
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Settled {
            ext_amount: 0,
            fee: XLM,
            recipient: deposit_address,
            relayer: relayer.clone(),
            exit_id: Some(requeued)
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&relayer), XLM);
    assert_eq!(s.balance(&exchange), 10 * XLM);
    assert_eq!(used(s), 11 * XLM);
}

#[test]
fn a_requeued_exit_waits_behind_every_exit_queued_before_its_claim() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let flaky = c.holder("flaky", 0);
    let other = c.holder("other", 0);
    fill_window(s, &filler);
    let stuck = queue(s, 10 * XLM, 0, &flaky, &flaky);
    c.asset.set_authorized(&flaky, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    assert!(s.vault.stranded(&stuck).is_some());

    // Two exits join the queue after the strand and before the claim, behind a full window.
    fill_window(s, &filler);
    let first = queue(s, 100 * XLM, 0, &other, &other);
    let second = queue(s, 200 * XLM, 0, &other, &other);
    c.asset.set_authorized(&flaky, &true);
    // The claim needs no room in the full window, and the exit goes behind both.
    let requeued = s.vault.claim(&stuck);
    assert!(requeued > second && second > first);
    assert_eq!(s.vault.release(&10), 0);

    to_midnight(s);
    assert_eq!(s.vault.release(&10), 3);
    let vault = s.vault.address.clone();
    let settled = |id: u64, payout: i128, to: &soroban_sdk::Address| {
        events::Settled {
            ext_amount: -payout,
            fee: 0,
            recipient: to.clone().into(),
            relayer: to.clone(),
            exit_id: Some(id),
        }
        .to_xdr(&s.env, &vault)
    };
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            settled(first, 100 * XLM, &other),
            settled(second, 200 * XLM, &other),
            settled(requeued, 10 * XLM, &flaky),
        ]
    );
}

#[test]
fn a_party_that_can_never_receive_cannot_hold_up_the_others_part() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let relayer = c.holder("relayer", 0);
    let flaky = c.holder("flaky", 0);
    fill_window(s, &filler);
    let id = queue(s, 10 * XLM, XLM, &flaky, &relayer);
    let queued_at = s.now();
    // The recipient loses the right to hold the asset for a while, the relayer for good.
    c.asset.set_authorized(&flaky, &false);
    c.asset.set_authorized(&relayer, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    let stranded = s.vault.stranded(&id).unwrap();
    assert_eq!((stranded.payout, stranded.fee), (10 * XLM, XLM));
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );

    // Once the recipient can receive, its payout moves back into the queue on its own.
    c.asset.set_authorized(&flaky, &true);
    let requeued = s.vault.claim(&id);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitRequeued {
            id,
            new_id: requeued,
            payout: 10 * XLM,
            fee: 0
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(
        s.vault.stranded(&id),
        Some(Exit {
            recipient: flaky.clone().into(),
            payout: 0,
            relayer: relayer.clone(),
            fee: XLM,
            queued_at,
        })
    );
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&flaky), 10 * XLM);
    // The relayer's fee stays stranded and reserved.
    assert_eq!(s.vault.status().queued_total, XLM);
}

#[test]
fn a_claim_is_refused_while_halted_and_works_while_paused() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let flaky = c.holder("flaky", 0);
    fill_window(s, &filler);
    let first = queue(s, XLM, 0, &flaky, &flaky);
    let second = queue(s, XLM, 0, &flaky, &flaky);
    c.asset.set_authorized(&flaky, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&2), 2);
    c.asset.set_authorized(&flaky, &true);

    s.vault.set_pause(&true, &true);
    s.vault.claim(&first);
    s.vault.halt();
    assert_eq!(outcome(s.vault.try_claim(&second)), Err(Error::Halted));
    s.advance(HALT);
    s.vault.claim(&second);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!(s.balance(&flaky), 2 * XLM);
}

#[test]
fn only_a_stranded_exit_can_be_claimed() {
    let s = funded();
    let filler = s.account("filler", 0);
    let user = s.account("user", 0);
    fill_window(&s, &filler);
    let id = queue(&s, XLM, 0, &user, &user);
    for unknown in [0, id, id + 1, u64::MAX] {
        assert_eq!(
            outcome(s.vault.try_claim(&unknown)),
            Err(Error::NotStranded)
        );
    }
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(outcome(s.vault.try_claim(&id)), Err(Error::NotStranded));
    assert_eq!(s.balance(&user), XLM);
}

#[test]
fn a_payment_that_would_leave_its_account_below_the_reserve_strands() {
    let s = funded();
    let filler = s.account("filler", 0);
    let poor = s.account("poor", 0);
    fill_window(&s, &filler);
    let id = queue(&s, XLM / 2, 0, &poor, &filler);
    // The base reserve rises, and an account must hold two of them after any payment it takes.
    s.env.ledger().with_mut(|l| l.base_reserve = 5_000_000);
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&id).map(|e| e.payout), Some(XLM / 2));

    s.account("poor", XLM);
    s.vault.claim(&id);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&poor), XLM + XLM / 2);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn a_vault_the_issuer_deauthorizes_neither_strands_nor_reorders_the_queue() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let a = c.holder("a", 0);
    let b = c.holder("b", 0);
    fill_window(s, &filler);
    let first = queue(s, 10 * XLM, 0, &a, &a);
    let second = queue(s, 20 * XLM, 0, &b, &b);
    // The issuer revokes the vault's own right to hold the asset.
    c.asset.set_authorized(&s.vault.address, &false);
    to_midnight(s);
    let status = s.vault.status();

    assert_eq!(
        outcome(s.vault.try_release(&10)),
        Err(Error::VaultCannotPay)
    );
    assert_eq!(s.vault.status(), status);
    assert!(s.vault.exit(&first).is_some() && s.vault.exit(&second).is_some());
    assert!(s.vault.stranded(&first).is_none() && s.vault.stranded(&second).is_none());

    // Once it is authorized again, the queue is paid in its order.
    c.asset.set_authorized(&s.vault.address, &true);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!((s.balance(&a), s.balance(&b)), (10 * XLM, 0));
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&b), 20 * XLM);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn a_vault_short_of_funds_pays_what_it_can_in_order_and_keeps_the_rest_queued() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let a = c.holder("a", 0);
    let b = c.holder("b", 0);
    fill_window(s, &filler);
    let first = queue(s, 10 * XLM, 0, &a, &a);
    let second = queue(s, 20 * XLM, 0, &b, &b);
    // The issuer claws back all but 15 units of what the vault holds.
    let held = s.balance(&s.vault.address);
    c.asset.clawback(&s.vault.address, &(held - 15 * XLM));
    to_midnight(s);

    // The first exit is paid; the second waits at the head instead of stranding.
    assert_eq!(s.vault.release(&10), 1);
    assert_eq!(s.balance(&a), 10 * XLM);
    assert_eq!(s.vault.status().exit_head, second);
    assert!(s.vault.exit(&first).is_none() && s.vault.stranded(&second).is_none());
    assert_eq!(
        outcome(s.vault.try_release(&10)),
        Err(Error::VaultCannotPay)
    );

    // Once the vault holds enough again, the second exit is paid.
    c.asset.mint(&s.vault.address, &(15 * XLM));
    assert_eq!(s.vault.release(&10), 1);
    assert_eq!(s.balance(&b), 20 * XLM);
}

#[test]
fn release_needs_nothing_from_the_vault_when_there_is_nothing_to_pay() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let a = c.holder("a", 0);
    c.asset.set_authorized(&s.vault.address, &false);
    // An empty queue, and a queue behind a full window, release nothing and fail nothing.
    assert_eq!(s.vault.release(&10), 0);
    c.asset.set_authorized(&s.vault.address, &true);
    fill_window(s, &filler);
    queue(s, 10 * XLM, 0, &a, &a);
    c.asset.set_authorized(&s.vault.address, &false);
    assert_eq!(s.vault.release(&10), 0);
}

#[test]
fn a_requeued_exit_is_paid_in_its_share_of_full_windows_however_busy_the_queue() {
    let c = Classic::new(Limits {
        tvl_cap: 35_000 * XLM,
        ..limits()
    });
    c.fund(14, 2_500 * XLM);
    let s = &c.s;
    let window = s.vault.limits().max_daily_outflow;
    let filler = c.holder("filler", 0);
    let honest = c.holder("honest", 0);
    let flaky = c.holder("flaky", 0);
    fill_window(s, &filler);
    // A whole window strands on its recipient.
    let stuck = queue(s, window, 0, &flaky, &flaky);
    c.asset.set_authorized(&flaky, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&stuck).map(|e| e.payout), Some(window));
    c.asset.set_authorized(&flaky, &true);
    fill_window(s, &filler);

    // Honest demand of a whole window a day keeps the queue busy, and the first call of each day
    // is the keeper's release. The stranded window still goes out within its bound, counted from
    // the day it was moved back into the queue.
    let mut waiting = VecDeque::new();
    for day in 0..6 {
        if day < 4 {
            queue_honest(s, window / 2, &honest, &mut waiting);
            queue_honest(s, window / 2, &honest, &mut waiting);
        }
        if day == 0 {
            let ahead = s.vault.status().queued_total - window;
            let id = s.vault.claim(&stuck);
            assert_eq!(wait_bound(ahead, window, window), 2);
            waiting.push_back(Waiting {
                id,
                day: s.now() / DAY,
                ahead,
                own: window,
            });
        }
        to_midnight(s);
        s.vault.release(&50);
        assert!(used(s) <= window);
        check_paid(s, &mut waiting);
    }
    assert!(waiting.is_empty());
    assert_eq!(s.balance(&flaky), window);
    assert_eq!(s.balance(&honest), 4 * window);
}

#[test]
fn exits_ahead_that_strand_and_are_claimed_go_behind_and_never_delay_an_honest_exit() {
    let c = Classic::new(limits());
    c.fund(10, 2_500 * XLM);
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let flaky = c.holder("flaky", 0);
    let honest = c.holder("honest", 0);
    fill_window(s, &filler);

    // Exits ahead, two of them to a party that loses its authorization before they are released,
    // so they strand and are claimed again at day boundaries, before the keeper's release.
    for (i, payout) in [3_000 * XLM, 2_000 * XLM, 4_000 * XLM, 1_500 * XLM]
        .into_iter()
        .enumerate()
    {
        let to = if i % 2 == 0 { &flaky } else { &filler };
        queue(s, payout, 0, to, to);
    }
    let mut waiting = VecDeque::new();
    for payout in [700 * XLM, 2_600 * XLM, 100 * XLM] {
        queue_honest(s, payout, &honest, &mut waiting);
    }
    c.asset.set_authorized(&flaky, &false);

    let mut stranded: std::vec::Vec<u64> = std::vec::Vec::new();
    for day in 1..=8 {
        to_midnight(s);
        if day >= 2 {
            c.asset.set_authorized(&flaky, &true);
            stranded.retain(|id| outcome(s.vault.try_claim(id)).is_err());
        }
        let head = s.vault.status().exit_head;
        s.vault.release(&50);
        for id in head..s.vault.status().exit_head {
            if s.vault.stranded(&id).is_some() {
                stranded.push(id);
            }
        }
        check_paid(s, &mut waiting);
    }
    assert!(waiting.is_empty());
    assert!(stranded.is_empty());
    assert_eq!(s.balance(&honest), 3_400 * XLM);
    assert_eq!(s.balance(&flaky), 7_000 * XLM);
}
