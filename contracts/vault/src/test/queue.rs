use soroban_sdk::{testutils::Events as _, Address, Event, Vec};

use super::setup::{outcome, Setup, DAY, DELAY_LARGE, DELAY_SMALL, XLM};
use crate::{events, Error};

/// The addresses whose authorization the last call required.
pub fn authorizers(s: &Setup) -> std::vec::Vec<Address> {
    s.env
        .auths()
        .into_iter()
        .map(|(address, _)| address)
        .collect()
}

fn ids(s: &Setup, ids: &[u64]) -> Vec<u64> {
    Vec::from_slice(&s.env, ids)
}

#[test]
fn only_the_asp_attests_flags_and_unflags() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.vault.attest(&1);
    assert_eq!(authorizers(&s), std::vec![s.asp.clone()]);
    s.vault.flag(&1, &2);
    assert_eq!(authorizers(&s), std::vec![s.asp.clone()]);
    s.vault.unflag(&1);
    assert_eq!(authorizers(&s), std::vec![s.asp.clone()]);
}

#[test]
fn attestations_only_move_forward_and_never_past_the_last_deposit() {
    let s = Setup::new();
    assert_eq!(outcome(s.vault.try_attest(&1)), Err(Error::BadAttestation));
    let depositor = s.account("depositor", 100 * XLM);
    for _ in 0..3 {
        s.shield(&depositor, XLM).unwrap();
    }
    assert_eq!(outcome(s.vault.try_attest(&0)), Err(Error::BadAttestation));
    assert_eq!(outcome(s.vault.try_attest(&4)), Err(Error::BadAttestation));
    s.vault.attest(&2);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Attested { up_to: 2 }.to_xdr(&s.env, &vault)]
    );
    assert_eq!(outcome(s.vault.try_attest(&2)), Err(Error::BadAttestation));
    assert_eq!(outcome(s.vault.try_attest(&1)), Err(Error::BadAttestation));
    s.vault.attest(&3);
    assert_eq!(s.vault.status().attested_up_to, 3);
}

#[test]
fn attestation_waits_out_a_halt() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.vault.halt();
    assert_eq!(outcome(s.vault.try_attest(&1)), Err(Error::Halted));
    s.vault.resume();
    s.vault.attest(&1);
}

#[test]
fn a_flag_refuses_a_pending_deposit_and_a_second_flag_replaces_the_reason() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    let vault = s.vault.address.clone();

    s.vault.flag(&1, &1);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::DepositFlagged { id: 1, reason: 1 }.to_xdr(&s.env, &vault)]
    );
    let flagged_at = s.now();
    let flag = |s: &Setup| {
        let deposit = s.vault.pending(&1).unwrap();
        (deposit.flag, deposit.flagged_at)
    };
    assert_eq!(flag(&s), (Some(1), flagged_at));
    // A new reason keeps the time of the first flag.
    s.advance(3_600);
    s.vault.flag(&1, &99);
    assert_eq!(flag(&s), (Some(99), flagged_at));

    assert_eq!(outcome(s.vault.try_flag(&1, &0)), Err(Error::BadReason));
    assert_eq!(
        outcome(s.vault.try_flag(&2, &1)),
        Err(Error::UnknownDeposit)
    );
}

#[test]
fn unflag_clears_a_mistaken_flag_while_the_deposit_is_pending() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    let vault = s.vault.address.clone();
    assert_eq!(outcome(s.vault.try_unflag(&1)), Err(Error::NotFlagged));
    assert_eq!(outcome(s.vault.try_unflag(&9)), Err(Error::UnknownDeposit));
    s.vault.flag(&1, &5);
    s.vault.unflag(&1);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::DepositUnflagged { id: 1, reason: 5 }.to_xdr(&s.env, &vault)]
    );
    let deposit = s.vault.pending(&1).unwrap();
    assert_eq!((deposit.flag, deposit.flagged_at), (None, 0));

    s.vault.attest(&1);
    s.advance(DELAY_SMALL);
    s.vault.admit(&ids(&s, &[1]));
    assert_eq!(
        outcome(s.vault.try_flag(&1, &1)),
        Err(Error::UnknownDeposit)
    );
    assert_eq!(outcome(s.vault.try_unflag(&1)), Err(Error::UnknownDeposit));
}

#[test]
fn flags_and_unflags_work_while_halted() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.vault.halt();
    s.vault.flag(&1, &3);
    s.vault.unflag(&1);
    s.vault.flag(&1, &4);
    let deposit = s.vault.pending(&1).unwrap();
    assert_eq!((deposit.flag, deposit.flagged_at), (Some(4), s.now()));
}

#[test]
fn admission_needs_attestation_no_flag_and_the_delay_of_the_amount() {
    let s = Setup::new();
    let depositor = s.account("depositor", 10_000 * XLM);
    let threshold = s.vault.limits().large_deposit_threshold;
    let start = s.now();
    s.shield(&depositor, 100 * XLM).unwrap(); // 1: small
    s.shield(&depositor, threshold).unwrap(); // 2: large at the threshold
    s.shield(&depositor, 100 * XLM).unwrap(); // 3: flagged
    s.shield(&depositor, 100 * XLM).unwrap(); // 4: not attested
    s.vault.flag(&3, &1);
    s.vault.attest(&3);
    let all = ids(&s, &[1, 2, 3, 4]);

    s.advance(DELAY_SMALL - 1);
    assert_eq!(s.vault.admit(&all), ids(&s, &[]));
    s.advance(1);
    assert_eq!(s.now(), start + DELAY_SMALL);
    assert_eq!(s.vault.admit(&all), ids(&s, &[1]));

    s.advance(DELAY_LARGE - DELAY_SMALL - 1);
    assert_eq!(s.vault.admit(&all), ids(&s, &[]));
    s.advance(1);
    assert_eq!(s.vault.admit(&all), ids(&s, &[2]));

    s.vault.unflag(&3);
    assert_eq!(s.vault.admit(&all), ids(&s, &[3]));
    assert_eq!(s.vault.admit(&all), ids(&s, &[]));
    s.vault.attest(&4);
    assert_eq!(s.vault.admit(&all), ids(&s, &[4]));
    assert_eq!(s.vault.next_leaf_index(), 8);
}

#[test]
fn the_delay_follows_the_current_large_deposit_threshold() {
    let s = Setup::new();
    let depositor = s.account("depositor", 10_000 * XLM);
    s.shield(&depositor, 300 * XLM).unwrap();
    s.vault.attest(&1);
    let mut tighter = s.vault.limits();
    tighter.large_deposit_threshold = 300 * XLM;
    s.vault.set_limits(&tighter);
    s.advance(DELAY_SMALL);
    assert_eq!(s.vault.admit(&ids(&s, &[1])), ids(&s, &[]));
    s.advance(DELAY_LARGE - DELAY_SMALL);
    assert_eq!(s.vault.admit(&ids(&s, &[1])), ids(&s, &[1]));
}

#[test]
fn admit_inserts_each_deposit_as_one_pair_in_id_order() {
    let s = Setup::new();
    let depositor = s.account("depositor", 10_000 * XLM);
    for _ in 0..3 {
        s.shield(&depositor, XLM).unwrap();
    }
    let pending: std::vec::Vec<_> = (1..=3).map(|id| s.vault.pending(&id).unwrap()).collect();
    s.vault.attest(&3);
    s.advance(DELAY_SMALL);
    assert_eq!(s.vault.admit(&ids(&s, &[1, 3])), ids(&s, &[1, 3]));

    let vault = s.vault.address.clone();
    let mut expected = std::vec::Vec::new();
    for (index, (id, deposit)) in [(1, &pending[0]), (3, &pending[2])].into_iter().enumerate() {
        let leaf = 2 * index as u64;
        expected.push(
            events::NewCommitment {
                index: leaf,
                commitment: deposit.commitment0.clone(),
                encrypted_output: deposit.encrypted_output0.clone(),
            }
            .to_xdr(&s.env, &vault),
        );
        expected.push(
            events::NewCommitment {
                index: leaf + 1,
                commitment: deposit.commitment1.clone(),
                encrypted_output: deposit.encrypted_output1.clone(),
            }
            .to_xdr(&s.env, &vault),
        );
        expected.push(
            events::DepositAdmitted {
                id,
                leaf_index0: leaf,
                leaf_index1: leaf + 1,
            }
            .to_xdr(&s.env, &vault),
        );
    }
    assert_eq!(s.env.events().all().filter_by_contract(&vault), expected);
    assert!(s.vault.pending(&1).is_none() && s.vault.pending(&3).is_none());
    assert!(s.vault.pending(&2).is_some());
    let leaves = [
        pending[0].commitment0.clone(),
        pending[0].commitment1.clone(),
        pending[2].commitment0.clone(),
        pending[2].commitment1.clone(),
    ];
    assert_eq!(
        s.vault.current_root(),
        super::tree::reference_root(&s.env, &leaves)
    );
    // Admission moves no funds: the value was counted at shield time.
    assert_eq!(s.vault.status().tvl, 3 * XLM);
}

#[test]
fn admit_ids_must_be_strictly_ascending() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    s.vault.attest(&2);
    s.advance(DELAY_SMALL);
    for bad in [&[2, 1][..], &[1, 1][..], &[1, 2, 2][..]] {
        assert_eq!(
            outcome(s.vault.try_admit(&ids(&s, bad))),
            Err(Error::BadIds)
        );
    }
    assert_eq!(s.vault.admit(&ids(&s, &[1, 2])), ids(&s, &[1, 2]));
}

#[test]
fn admit_skips_ids_that_are_not_pending_and_needs_no_authorization() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    s.vault.cancel(&1);
    s.vault.attest(&2);
    s.advance(DELAY_SMALL);
    assert_eq!(s.vault.admit(&ids(&s, &[0, 1, 2, 7])), ids(&s, &[2]));
    assert!(authorizers(&s).is_empty());
    assert_eq!(s.vault.admit(&ids(&s, &[])), ids(&s, &[]));
}

#[test]
fn admit_is_refused_while_halted() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.vault.attest(&1);
    s.advance(DELAY_SMALL);
    s.vault.halt();
    assert_eq!(
        outcome(s.vault.try_admit(&ids(&s, &[1]))),
        Err(Error::Halted)
    );
    s.advance(72 * 3_600);
    assert_eq!(s.vault.admit(&ids(&s, &[1])), ids(&s, &[1]));
}

#[test]
fn the_depositor_cancels_a_deposit_that_is_not_admitted() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, 40 * XLM).unwrap();
    s.shield(&depositor, 10 * XLM).unwrap();
    s.vault.flag(&2, &4);

    s.vault.cancel(&1);
    assert_eq!(authorizers(&s), std::vec![depositor.clone()]);
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::DepositRefunded { id: 1, reason: 0 }.to_xdr(&s.env, &vault)]
    );
    // A flagged deposit can be cancelled too; the event says the depositor cancelled it.
    s.vault.cancel(&2);
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::DepositRefunded { id: 2, reason: 0 }.to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&depositor), 100 * XLM);
    assert_eq!(s.vault.status().tvl, 0);
    assert_eq!(outcome(s.vault.try_cancel(&1)), Err(Error::UnknownDeposit));
}

#[test]
fn anyone_refunds_a_deposit_flagged_a_day_ago_and_only_to_its_depositor() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, 30 * XLM).unwrap();
    assert_eq!(outcome(s.vault.try_refund(&1)), Err(Error::NotFlagged));
    s.vault.flag(&1, &3);
    assert_eq!(outcome(s.vault.try_refund(&1)), Err(Error::RefundTooEarly));
    s.advance(DAY - 1);
    assert_eq!(outcome(s.vault.try_refund(&1)), Err(Error::RefundTooEarly));
    s.advance(1);

    s.vault.refund(&1);
    assert!(authorizers(&s).is_empty());
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::DepositRefunded { id: 1, reason: 3 }.to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.balance(&depositor), 100 * XLM);
    assert_eq!(s.vault.status().tvl, 0);
    assert_eq!(outcome(s.vault.try_refund(&1)), Err(Error::UnknownDeposit));
    assert_eq!(outcome(s.vault.try_refund(&2)), Err(Error::UnknownDeposit));
}

#[test]
fn a_pending_deposit_can_always_leave_while_halted_or_paused() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, 10 * XLM).unwrap();
    s.shield(&depositor, 10 * XLM).unwrap();
    s.vault.set_pause(&true, &true);
    s.vault.halt();
    s.vault.flag(&2, &5);
    s.vault.cancel(&1);
    s.advance(DAY);
    s.vault.refund(&2);
    assert_eq!(s.balance(&depositor), 100 * XLM);
}

#[test]
fn a_deposit_is_resolved_at_most_once() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    for _ in 0..3 {
        s.shield(&depositor, XLM).unwrap();
    }
    s.vault.attest(&3);
    s.advance(DELAY_SMALL);
    s.vault.admit(&ids(&s, &[1]));
    s.vault.cancel(&2);
    s.vault.flag(&3, &1);
    s.advance(DAY);
    s.vault.refund(&3);
    for id in 1..=3 {
        assert_eq!(outcome(s.vault.try_cancel(&id)), Err(Error::UnknownDeposit));
        assert_eq!(outcome(s.vault.try_refund(&id)), Err(Error::UnknownDeposit));
    }
    assert_eq!(s.vault.admit(&ids(&s, &[1, 2, 3])), ids(&s, &[]));
    assert_eq!(s.vault.next_leaf_index(), 2);
    assert_eq!(s.balance(&depositor), 99 * XLM);
}

#[test]
fn a_mistaken_flag_can_be_corrected_before_anyone_else_refunds_it() {
    let s = Setup::new();
    let depositor = s.account("depositor", 10_000 * XLM);
    let limits = s.vault.limits();
    s.shield(&depositor, limits.max_deposit).unwrap();
    s.vault.flag(&1, &5);

    // A third party cannot refund it in the same ledger, before the ASP can look again.
    s.env.set_auths(&[]);
    assert_eq!(outcome(s.vault.try_refund(&1)), Err(Error::RefundTooEarly));
    s.env.mock_all_auths();
    s.advance(DAY - 1);
    s.vault.unflag(&1);
    s.advance(1);
    assert_eq!(outcome(s.vault.try_refund(&1)), Err(Error::NotFlagged));
    s.vault.attest(&1);
    s.advance(DELAY_LARGE);
    assert_eq!(s.vault.admit(&ids(&s, &[1])), ids(&s, &[1]));
}

#[test]
fn a_batch_of_sixteen_admissions_fits_the_network_limits() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    for _ in 0..17 {
        s.shield(&depositor, XLM).unwrap();
    }
    s.vault.attest(&17);
    s.advance(DELAY_SMALL);
    // The test budget defaults to 100M instructions; the network allows more per transaction.
    // Its other limits, such as 16 KiB of events, are enforced by default.
    s.env
        .cost_estimate()
        .budget()
        .reset_limits(600_000_000, 41_943_040);
    let sixteen = ids(&s, &(1..=16).collect::<std::vec::Vec<_>>());
    assert_eq!(s.vault.admit(&sixteen), sixteen);
    let resources = s.env.cost_estimate().resources();
    assert!(resources.contract_events_size_bytes <= 16_384);
    assert_eq!(s.vault.next_leaf_index(), 32);
}
