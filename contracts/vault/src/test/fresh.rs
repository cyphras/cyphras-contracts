//! An unshield of XLM may pay an account that does not exist yet: the asset contract creates it
//! from a payment of two base reserves, 1 XLM while the reserve is 0.5 XLM. Such a payout is
//! accepted from 1 XLM up, and release never pays it in a part too small to create the account.

use soroban_sdk::{
    testutils::{Events as _, Ledger},
    token::StellarAssetClient,
    xdr, Address, Event, InvokeError,
};

use super::{
    exits::{fill_window, funded, queue, to_midnight, used, wait_bound},
    receive::exit,
    setup::{
        account_address, asset_contract, create_account, env, limits, outcome, Classic, Setup, DAY,
        TESTNET, XLM,
    },
};
use crate::{events, storage, Error, Exit, Limits};

// The base reserve of the live networks, in stroops.
const RESERVE: u32 = 5_000_000;

/// A vault holding six admitted deposits of 2,500 XLM, on a network whose base reserve is 0.5 XLM.
fn native() -> Setup {
    let s = funded();
    s.env.ledger().with_mut(|l| l.base_reserve = RESERVE);
    s
}

/// A vault whose window is 10 XLM, holding `notes` of admitted notes, on a network whose base
/// reserve is 0.5 XLM.
fn small(notes: i128) -> Setup {
    let s = Setup::with_limits(Limits {
        max_daily_outflow: 10 * XLM,
        tvl_cap: 70 * XLM,
        ..limits()
    });
    s.fund_pool("funder", notes);
    s.env.ledger().with_mut(|l| l.base_reserve = RESERVE);
    s
}

/// Takes all of today's window but `room` with an exit to `to`, paid at once.
fn leave_room(s: &Setup, to: &Address, room: i128) {
    let take = s.vault.limits().max_daily_outflow - used(s) - room;
    assert_eq!(s.transact(to, &s.ext(-take, 0, to, to)), Ok(()));
}

/// The days after the first day boundary within which an exit is paid in full when payouts to
/// new accounts may be queued with it, given the same full windows as `wait_bound`. Release stops
/// short of a full window only for such a payout with less than 1 XLM of room left, so every day
/// pays at least the window less 1 XLM. As no more than seven windows are ever owed, this is at
/// most one day past `wait_bound` for any window of 8 XLM or more.
fn wait_bound_creating(ahead: i128, own: i128, window: i128) -> u64 {
    ((ahead + own) as u64).div_ceil((window - XLM + 1) as u64)
}

/// Replaces queued exit `id` with what `merge` makes of it, which names an account that does not
/// exist. This is what the vault sees when a party merges its account away after the exit was
/// queued.
fn merge_away(s: &Setup, id: u64, merge: impl FnOnce(Exit) -> Exit) {
    s.env.as_contract(&s.vault.address, || {
        let exit = merge(storage::exit(&s.env, id).unwrap());
        storage::set_exit(&s.env, id, &exit);
    });
}

#[test]
fn an_xlm_payout_of_one_xlm_or_more_creates_its_recipients_account_paid_at_once_or_queued() {
    let s = native();
    let filler = s.account("filler", 0);
    let relayer = s.account("relayer", 10 * XLM);
    let fresh = |tag: &str| account_address(&s.env, tag);

    // Less than 1 XLM could not create the account, so the exit is refused before anything is
    // spent.
    assert_eq!(
        exit(&s, XLM - 1, 0, fresh("a").into(), &relayer),
        Err(Error::CannotReceive)
    );
    assert_eq!(exit(&s, XLM, 0, fresh("a").into(), &relayer), Ok(()));
    assert_eq!(exit(&s, 25 * XLM, 0, fresh("b").into(), &relayer), Ok(()));
    assert_eq!(
        (s.balance(&fresh("a")), s.balance(&fresh("b"))),
        (XLM, 25 * XLM)
    );

    // Queued, the same payouts are judged alike, and release creates the accounts.
    fill_window(&s, &filler);
    assert_eq!(
        exit(&s, XLM - 1, 0, fresh("c").into(), &relayer),
        Err(Error::CannotReceive)
    );
    queue(&s, XLM, 0, fresh("c"), &relayer);
    queue(&s, 25 * XLM, 0, fresh("d"), &relayer);
    assert!(!fresh("c").exists() && !fresh("d").exists());
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!(
        (s.balance(&fresh("c")), s.balance(&fresh("d"))),
        (XLM, 25 * XLM)
    );
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn any_other_asset_still_needs_an_existing_account_whatever_the_payout() {
    let c = Classic::new(limits());
    c.fund(3, 2_500 * XLM);
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let holder = c.holder("holder", 0);
    let missing = account_address(&s.env, "missing");
    assert_eq!(
        exit(s, 100 * XLM, 0, missing.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    leave_room(s, &filler, XLM / 2);
    assert_eq!(
        exit(s, 100 * XLM, 0, missing.clone().into(), &filler),
        Err(Error::CannotReceive)
    );

    // No payment of any size reaches an account that was merged away, so release does not wait
    // for room and the exit strands at once.
    let id = queue(s, 100 * XLM, 0, &holder, &filler);
    merge_away(s, id, |exit| Exit {
        recipient: missing.into(),
        ..exit
    });
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&id).map(|e| e.payout), Some(100 * XLM));
}

#[test]
fn the_issuer_of_another_asset_must_exist_too_though_a_payment_to_it_burns() {
    let env = env(TESTNET);
    let issuer = account_address(&env, "issuer");
    let xdr::ScAddress::Account(account_id) = xdr::ScAddress::from(&issuer) else {
        panic!("not an account address");
    };
    let token = asset_contract(
        &env,
        xdr::Asset::CreditAlphanum4(xdr::AlphaNum4 {
            asset_code: xdr::AssetCode4(*b"USDC"),
            issuer: account_id,
        }),
    );
    let asset = StellarAssetClient::new(&env, &token);
    // The asset contract lets its issuer hold the asset whether its account exists or not.
    assert!(asset.authorized(&issuer));
    assert!(!crate::can_receive(&env, &asset, &issuer, 100 * XLM));
    create_account(&env, &issuer, XLM);
    assert!(crate::can_receive(&env, &asset, &issuer, 100 * XLM));
}

#[test]
fn a_relayer_must_exist_whatever_its_fee() {
    let s = native();
    let user = s.account("user", 10 * XLM);
    let relayer = account_address(&s.env, "relayer");
    assert_eq!(
        exit(&s, 10 * XLM, 5 * XLM, user.clone().into(), &relayer),
        Err(Error::CannotReceive)
    );
    s.account("relayer", 0);
    assert_eq!(exit(&s, 10 * XLM, 5 * XLM, user.into(), &relayer), Ok(()));
    assert_eq!(s.balance(&relayer), 5 * XLM);
}

#[test]
fn a_part_payment_of_one_xlm_creates_the_account_and_the_rest_follows() {
    let s = native();
    let filler = s.account("filler", 0);
    let relayer = s.account("relayer", 10 * XLM);
    let fresh = account_address(&s.env, "fresh");
    leave_room(&s, &filler, XLM);
    let id = queue(&s, 10 * XLM, XLM / 2, &fresh, &relayer);

    assert_eq!(s.vault.release(&10), 1);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::ExitPaid {
            id,
            payout_paid: XLM,
            fee_paid: 0,
            payout_left: 9 * XLM,
            fee_left: XLM / 2
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&fresh), XLM);

    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 1);
    assert_eq!(s.balance(&fresh), 10 * XLM);
    assert_eq!(s.balance(&relayer), 10 * XLM + XLM / 2);
}

#[test]
fn once_its_account_exists_a_recipient_takes_parts_of_any_size() {
    let s = small(30 * XLM);
    let user = s.account("user", 10 * XLM);
    let fresh = account_address(&s.env, "fresh");
    fill_window(&s, &user);
    queue(&s, 96 * XLM / 10, 0, &fresh, &user);
    let second = queue(&s, 5 * XLM, 0, &fresh, &user);

    // The first exit creates the account, after which the second takes what is left of the
    // window, far less than 1 XLM.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!(s.vault.exit(&second).map(|e| e.payout), Some(46 * XLM / 10));
    assert_eq!(s.balance(&fresh), 10 * XLM);
}

#[test]
fn a_payout_that_would_create_its_account_waits_at_the_head_for_a_window_with_room_for_one_xlm() {
    let s = native();
    let filler = s.account("filler", 0);
    let user = s.account("user", 10 * XLM);
    let relayer = s.account("relayer", 10 * XLM);
    let fresh = account_address(&s.env, "fresh");
    leave_room(&s, &filler, XLM - 1);
    let first = queue(&s, XLM, XLM / 2, &fresh, &relayer);
    let queued = s.vault.exit(&first);
    // The second exit would fit what is left of the window, but it waits behind the first.
    let second = queue(&s, XLM / 10, 0, &user, &user);
    let status = s.vault.status();

    // A part of less than 1 XLM could not create the account and would strand the exit, so
    // release stops and nothing changes.
    assert_eq!(s.vault.release(&10), 0);
    assert!(s
        .env
        .events()
        .all()
        .filter_by_contract(&s.vault.address)
        .events()
        .is_empty());
    assert_eq!(s.vault.status(), status);
    assert_eq!(s.vault.exit(&first), queued);
    assert_eq!(s.vault.stranded(&first), None);
    assert!(!fresh.exists());

    // The next window pays the payout whole and creates the account.
    to_midnight(&s);
    assert_eq!(s.vault.release(&10), 2);
    assert_eq!(s.vault.exit(&second), None);
    assert_eq!(s.balance(&fresh), XLM);
    assert_eq!(s.balance(&relayer), 10 * XLM + XLM / 2);
    assert_eq!(s.balance(&user), 10 * XLM + XLM / 10);
}

#[test]
fn an_exit_behind_payouts_that_create_accounts_waits_at_most_one_day_past_its_bound() {
    let s = small(40 * XLM);
    let window = s.vault.limits().max_daily_outflow;
    let user = s.account("user", 10 * XLM);
    let fresh = |tag: &str| account_address(&s.env, tag);
    fill_window(&s, &user);
    // Each of these leaves less than 1 XLM of its day's window, too little to start the next.
    queue(&s, 95 * XLM / 10, 0, fresh("one"), &user);
    queue(&s, 95 * XLM / 10, 0, fresh("two"), &user);
    let ahead = s.vault.status().queued_total;
    let id = queue(&s, XLM, 0, &user, &user);
    let bound = wait_bound(ahead, XLM, window);
    assert_eq!(bound, 2);
    assert_eq!(wait_bound_creating(ahead, XLM, window), bound + 1);

    let mut used_per_day = std::vec::Vec::new();
    while s.vault.exit(&id).is_some() {
        to_midnight(&s);
        s.vault.release(&10);
        used_per_day.push(used(&s));
    }
    // Half an XLM of the first window goes unused, so the exit takes a third day.
    assert_eq!(used_per_day, std::vec![95 * XLM / 10, window, XLM / 2]);
    assert_eq!(used_per_day.len() as u64, bound + 1);
}

#[test]
fn no_exit_waits_more_than_one_day_past_its_bound_whichever_payouts_create_accounts() {
    // Payouts to new accounts are sized to leave less than 1 XLM of a window when one opens it,
    // which is when they waste the most.
    let s = small(60 * XLM);
    let window = s.vault.limits().max_daily_outflow;
    let user = s.account("user", 10 * XLM);
    let mut worst = 0;
    let mut created = 0;
    for round in 0..8 {
        if round > 0 {
            // A deposit empties its funder's account, which the reserve would not allow.
            s.env.ledger().with_mut(|l| l.base_reserve = 0);
            s.fund_pool(&std::format!("funder {round}"), 60 * XLM);
            s.env.ledger().with_mut(|l| l.base_reserve = RESERVE);
        }
        fill_window(&s, &user);
        let day = s.now() / DAY;
        let mut waiting = std::vec::Vec::new();
        let mut notes = 60 * XLM - window;
        while notes >= XLM {
            let fresh = s.below(2) == 0;
            let (recipient, size) = if fresh {
                created += 1;
                let tag = std::format!("fresh {created}");
                (
                    account_address(&s.env, &tag),
                    9 * XLM + s.below(XLM as u64) as i128,
                )
            } else {
                (user.clone(), XLM + s.below(9 * XLM as u64) as i128)
            };
            let size = size.min(notes);
            let ahead = s.vault.status().queued_total;
            let id = queue(&s, size, 0, &recipient, &user);
            waiting.push((
                id,
                wait_bound(ahead, size, window),
                wait_bound_creating(ahead, size, window),
            ));
            notes -= size;
        }
        while !waiting.is_empty() {
            to_midnight(&s);
            s.vault.release(&50);
            let days = s.now() / DAY - day;
            waiting.retain(|(id, bound, creating)| {
                if s.vault.exit(id).is_some() {
                    return true;
                }
                assert!(days <= *creating, "exit {id} waited {days} days");
                assert!(days <= bound + 1, "exit {id} waited {days} days");
                worst = worst.max(days.saturating_sub(*bound));
                false
            });
        }
        assert_eq!(s.vault.status().queued_total, 0);
    }
    assert_eq!(worst, 1);
}

#[test]
fn a_payout_below_two_raised_reserves_strands_and_is_requeued_until_it_can_create_the_account() {
    let s = native();
    let filler = s.account("filler", 0);
    let relayer = s.account("relayer", 10 * XLM);
    let fresh = account_address(&s.env, "fresh");
    let payout = 3 * XLM / 2;
    // The base reserve rises to 1 XLM, so creating an account takes 2 XLM.
    s.env.ledger().with_mut(|l| l.base_reserve = 2 * RESERVE);

    // Paid at once, the asset contract refuses the payout with its own error and the whole call
    // fails, so nothing is spent.
    let ext = s.ext(-payout, 0, &fresh, &relayer);
    let proof = s.prove(&ext);
    let status = s.vault.status();
    assert!(matches!(
        s.vault.try_transact(&proof, &ext, &relayer),
        Err(Err(InvokeError::Contract(14)))
    ));
    assert!(!s.vault.is_spent(&proof.input_nullifiers.get_unchecked(0)));
    assert_eq!(s.vault.status(), status);

    // Queued, it strands, and claim moves it back while the account is still missing, as the
    // vault cannot read the reserve.
    fill_window(&s, &filler);
    let id = queue(&s, payout, 0, &fresh, &relayer);
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&id).map(|e| e.payout), Some(payout));
    let id = s.vault.claim(&id);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&id).map(|e| e.payout), Some(payout));
    assert!(!fresh.exists());

    // Back at 0.5 XLM, the payout creates the account.
    s.env.ledger().with_mut(|l| l.base_reserve = RESERVE);
    s.vault.claim(&id);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&fresh), payout);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn a_payout_too_small_to_create_a_merged_away_account_strands_until_the_account_exists_again() {
    let s = native();
    let filler = s.account("filler", 0);
    let user = s.account("user", 10 * XLM);
    let payout = 8 * XLM / 10;
    leave_room(&s, &filler, XLM / 2);
    let id = queue(&s, payout, 0, &user, &filler);
    let gone = account_address(&s.env, "gone");
    merge_away(&s, id, |exit| Exit {
        recipient: gone.clone().into(),
        ..exit
    });

    // Waiting for a fuller window would not help, as the whole payout is too small to create
    // the account too, so the refused part strands at once.
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.vault.stranded(&id).map(|e| e.payout), Some(payout));
    // Claim judges the missing account as transact does.
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );

    s.account("gone", XLM);
    s.vault.claim(&id);
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&gone), XLM + payout);
    assert_eq!(s.vault.status().queued_total, 0);
}

#[test]
fn claim_moves_a_fee_only_to_a_relayer_that_exists_whatever_the_fee() {
    let s = native();
    let filler = s.account("filler", 0);
    let user = s.account("user", 10 * XLM);
    let relayer = s.account("relayer", 10 * XLM);
    fill_window(&s, &filler);
    let id = queue(&s, 10 * XLM, 2 * XLM, &user, &relayer);
    let gone = account_address(&s.env, "gone");
    merge_away(&s, id, |exit| Exit {
        relayer: gone.clone(),
        ..exit
    });
    // At a base reserve of 1.5 XLM the fee is too small to create the relayer's account.
    s.env.ledger().with_mut(|l| l.base_reserve = 3 * RESERVE);
    to_midnight(&s);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(
        s.vault.stranded(&id).map(|e| (e.payout, e.fee)),
        Some((0, 2 * XLM))
    );
    assert_eq!(
        outcome(s.vault.try_claim(&id)),
        Err(Error::NothingClaimable)
    );

    s.account("gone", 5 * XLM);
    s.vault.claim(&id);
    assert_eq!(s.vault.release(&1), 1);
    assert_eq!(s.balance(&gone), 7 * XLM);
}
