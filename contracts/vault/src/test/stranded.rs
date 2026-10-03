//! Exits whose recipient or relayer cannot receive the asset. A part the asset contract refuses
//! is set aside as a stranded exit, the queue moves on, and anyone claims it once the party can
//! receive.

use soroban_sdk::{
    testutils::{Events as _, Ledger, MuxedAddress as _},
    Event, MuxedAddress,
};

use super::{
    exits::{fill_window, funded, queue, to_midnight, used},
    queue::authorizers,
    setup::{account_address, limits, outcome, Classic, DAY, XLM},
};
use crate::{events, Error, Exit, Status};

const HALT: u64 = 72 * 3_600;

/// A vault of a classic asset whose issuer can revoke authorization, holding 15,000 units of
/// admitted notes.
fn classic() -> Classic {
    let c = Classic::new(limits());
    c.fund(6, 2_500 * XLM);
    c
}

#[test]
fn an_exit_to_a_recipient_without_a_trustline_strands_and_the_queue_moves_on() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let relayer = c.holder("relayer", 0);
    let honest = c.holder("honest", 0);
    let untrusting = s.account("untrusting", 0);
    fill_window(s, &filler);
    let stuck = queue(s, 10 * XLM, XLM, &untrusting, &relayer);
    let queued_at = s.now();
    let next = queue(s, 20 * XLM, XLM, &honest, &relayer);
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
            recipient: untrusting.clone().into(),
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

    // While the recipient still cannot receive, a claim pays nothing, so it fails.
    assert_eq!(
        outcome(s.vault.try_claim(&stuck)),
        Err(Error::NothingClaimable)
    );
    assert_eq!(s.vault.status(), released);
    assert!(s.vault.stranded(&stuck).is_some());

    // Once it can, anyone claims it.
    c.asset.trust(&untrusting);
    s.env.set_auths(&[]);
    s.vault.claim(&stuck);
    assert!(authorizers(s).is_empty());
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Settled {
            ext_amount: -10 * XLM,
            fee: 0,
            recipient: untrusting.clone().into(),
            relayer: relayer.clone(),
            exit_id: Some(stuck)
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&untrusting), 10 * XLM);
    assert_eq!(s.vault.stranded(&stuck), None);
    assert_eq!(
        s.vault.status(),
        Status {
            tvl: released.tvl - 10 * XLM,
            queued_total: 0,
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
    s.vault.claim(&id);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Settled {
            ext_amount: 0,
            fee: XLM,
            recipient: deposit_address,
            relayer: relayer.clone(),
            exit_id: Some(id)
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&relayer), XLM);
    assert_eq!(s.balance(&exchange), 10 * XLM);
    assert_eq!(used(s), 11 * XLM);
}

#[test]
fn a_claimed_part_is_paid_whole_within_what_is_left_of_todays_window() {
    let c = classic();
    let s = &c.s;
    let window = s.vault.limits().max_daily_outflow;
    let filler = c.holder("filler", 0);
    let relayer = c.holder("relayer", 0);
    let untrusting = s.account("untrusting", 0);
    fill_window(s, &filler);
    let id = queue(s, 10 * XLM, XLM, &untrusting, &relayer);
    c.asset.set_authorized(&relayer, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    c.asset.trust(&untrusting);
    c.asset.set_authorized(&relayer, &true);

    // With no exit queued, an exit paid at once leaves room for the fee but not the payout.
    let ext = s.ext(-(window - 5 * XLM), 0, &filler, &filler);
    assert_eq!(s.transact(&filler, &ext), Ok(()));
    s.vault.claim(&id);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitPaid {
            id,
            payout_paid: 0,
            fee_paid: XLM,
            payout_left: 10 * XLM,
            fee_left: 0
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(used(s), window - 4 * XLM);
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );

    to_midnight(s);
    s.vault.claim(&id);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Settled {
            ext_amount: -10 * XLM,
            fee: 0,
            recipient: untrusting.clone().into(),
            relayer: relayer.clone(),
            exit_id: Some(id)
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(used(s), 10 * XLM);
    assert_eq!(
        (s.balance(&untrusting), s.balance(&relayer)),
        (10 * XLM, XLM)
    );
    assert_eq!(s.vault.status().queued_total, 0);
    assert_eq!(outcome(s.vault.try_claim(&id)), Err(Error::NotStranded));
}

#[test]
fn a_party_that_can_never_receive_cannot_hold_up_the_others_part() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let relayer = c.holder("relayer", 0);
    let untrusting = s.account("untrusting", 0);
    fill_window(s, &filler);
    let id = queue(s, 10 * XLM, XLM, &untrusting, &relayer);
    let queued_at = s.now();
    // The relayer loses the right to hold the asset for good.
    c.asset.set_authorized(&relayer, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    let stranded = s.vault.stranded(&id).unwrap();
    assert_eq!((stranded.payout, stranded.fee), (10 * XLM, XLM));
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );

    // Once the recipient can receive, its payout is claimed on its own.
    c.asset.trust(&untrusting);
    s.vault.claim(&id);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitPaid {
            id,
            payout_paid: 10 * XLM,
            fee_paid: 0,
            payout_left: 0,
            fee_left: XLM
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&untrusting), 10 * XLM);
    assert_eq!(
        s.vault.stranded(&id),
        Some(Exit {
            recipient: untrusting.clone().into(),
            payout: 0,
            relayer: relayer.clone(),
            fee: XLM,
            queued_at,
        })
    );
    assert_eq!(s.vault.status().queued_total, XLM);
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );
}

#[test]
fn a_claim_is_refused_while_halted_and_works_while_paused() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let untrusting = s.account("untrusting", 0);
    fill_window(s, &filler);
    let first = queue(s, XLM, 0, &untrusting, &untrusting);
    let second = queue(s, XLM, 0, &untrusting, &untrusting);
    to_midnight(s);
    assert_eq!(s.vault.release(&2), 2);
    c.asset.trust(&untrusting);

    s.vault.set_pause(&true, &true);
    s.vault.claim(&first);
    s.vault.halt();
    assert_eq!(outcome(s.vault.try_claim(&second)), Err(Error::Halted));
    s.advance(HALT);
    s.vault.claim(&second);
    assert_eq!(s.balance(&untrusting), 2 * XLM);
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
fn a_payment_too_small_to_create_its_missing_account_strands() {
    let s = funded();
    // Paying a missing account creates it, which needs two base reserves.
    s.env.ledger().with_mut(|l| l.base_reserve = 5_000_000);
    let filler = s.account("filler", 0);
    let missing = account_address(&s.env, "missing");
    fill_window(&s, &filler);
    let id = queue(&s, XLM / 2, 0, &missing, &filler);
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&id).map(|e| e.payout), Some(XLM / 2));

    // An account must hold its two base reserves to receive anything.
    s.account("missing", XLM);
    s.vault.claim(&id);
    assert_eq!(s.balance(&missing), XLM + XLM / 2);
    assert_eq!(s.vault.status().queued_total, 0);
}
