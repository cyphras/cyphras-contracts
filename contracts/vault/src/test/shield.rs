use soroban_sdk::{
    testutils::{AuthorizedFunction, AuthorizedInvocation, Events as _, MuxedAddress as _},
    vec, Event, IntoVal, MuxedAddress, Symbol,
};

use super::setup::{outcome, Setup, DAY, XLM};
use crate::{events, proof::CIPHERTEXT_LEN, DataKey, Error, PendingDeposit};

#[test]
fn a_shield_queues_the_deposit_and_pulls_the_funds() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    let ext = s.ext(100 * XLM, 0, &depositor, &depositor);
    let proof = s.prove(&ext);
    let root_before = s.vault.current_root();

    assert_eq!(s.vault.shield(&proof, &ext, &depositor), 1);

    assert_eq!(
        s.env.auths(),
        std::vec![(
            depositor.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    s.vault.address.clone(),
                    Symbol::new(&s.env, "shield"),
                    (proof.clone(), ext.clone(), depositor.clone()).into_val(&s.env),
                )),
                sub_invocations: std::vec![AuthorizedInvocation {
                    function: AuthorizedFunction::Contract((
                        s.token.address.clone(),
                        Symbol::new(&s.env, "transfer"),
                        (depositor.clone(), s.vault.address.clone(), 100 * XLM).into_val(&s.env),
                    )),
                    sub_invocations: std::vec![],
                }],
            }
        )]
    );
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![
            events::NewNullifier {
                nullifier: proof.input_nullifiers.get_unchecked(0)
            }
            .to_xdr(&s.env, &vault),
            events::NewNullifier {
                nullifier: proof.input_nullifiers.get_unchecked(1)
            }
            .to_xdr(&s.env, &vault),
            events::DepositPending {
                id: 1,
                depositor: depositor.clone(),
                amount: 100 * XLM,
                commitment0: proof.output_commitments.get_unchecked(0),
                commitment1: proof.output_commitments.get_unchecked(1),
                created_at: s.now(),
            }
            .to_xdr(&s.env, &vault),
        ]
    );

    assert_eq!(
        s.vault.pending(&1),
        Some(PendingDeposit {
            depositor: depositor.clone(),
            amount: 100 * XLM,
            commitment0: proof.output_commitments.get_unchecked(0),
            commitment1: proof.output_commitments.get_unchecked(1),
            encrypted_output0: ext.encrypted_output0.clone(),
            encrypted_output1: ext.encrypted_output1.clone(),
            created_at: s.now(),
            flag: None,
            flagged_at: 0,
        })
    );
    assert!(s.vault.is_spent(&proof.input_nullifiers.get_unchecked(0)));
    assert!(s.vault.is_spent(&proof.input_nullifiers.get_unchecked(1)));
    let status = s.vault.status();
    assert_eq!((status.tvl, status.next_deposit_id), (100 * XLM, 2));
    assert_eq!(s.balance(&vault), 100 * XLM);
    assert_eq!(s.balance(&depositor), 900 * XLM);
    // Deposits wait in the queue: the tree is unchanged.
    assert_eq!(s.vault.current_root(), root_before);
    assert_eq!(s.vault.next_leaf_index(), 0);
    let day = s.env.as_contract(&vault, || {
        s.env
            .storage()
            .temporary()
            .get::<_, i128>(&DataKey::DepositorDay(depositor.clone(), s.now() / DAY))
    });
    assert_eq!(day, Some(100 * XLM));
}

#[test]
fn deposit_ids_increase_by_one() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    for expected in 1..=5 {
        assert_eq!(s.shield(&depositor, XLM), Ok(expected));
    }
}

#[test]
fn a_shield_is_refused_while_halted_or_while_deposits_are_paused() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    s.vault.set_pause(&true, &false);
    assert_eq!(s.shield(&depositor, XLM), Err(Error::DepositsPaused));
    s.vault.set_pause(&false, &true);
    assert_eq!(s.shield(&depositor, XLM), Ok(1));
    s.vault.halt();
    assert_eq!(s.shield(&depositor, XLM), Err(Error::Halted));
    s.vault.resume();
    assert_eq!(s.shield(&depositor, XLM), Ok(2));
}

#[test]
fn a_shield_needs_a_positive_amount_and_no_fee() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    for (amount, fee, error) in [
        (0, 0, Error::BadAmount),
        (-XLM, 0, Error::BadAmount),
        (XLM, 1, Error::BadFee),
        (XLM, -1, Error::BadFee),
    ] {
        let ext = s.ext(amount, fee, &depositor, &depositor);
        let result = outcome(s.vault.try_shield(&s.prove(&ext), &ext, &depositor));
        assert_eq!(result, Err(error), "amount {amount} fee {fee}");
    }
}

#[test]
fn a_shield_names_the_depositor_as_recipient_and_relayer() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    let other = s.account("other", 1_000 * XLM);
    let muxed = MuxedAddress::new(depositor.clone(), 1);
    let cases: [(MuxedAddress, _); 3] = [
        (other.clone().into(), depositor.clone()),
        (depositor.clone().into(), other.clone()),
        (muxed, depositor.clone()),
    ];
    for (recipient, relayer) in cases {
        let ext = s.ext(XLM, 0, recipient, &relayer);
        let result = outcome(s.vault.try_shield(&s.prove(&ext), &ext, &depositor));
        assert_eq!(result, Err(Error::BadParties));
    }
}

#[test]
fn a_shield_is_bound_to_this_vault_and_network() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    let mut ext = s.ext(XLM, 0, &depositor, &depositor);
    ext.vault = s.token.address.clone();
    let result = outcome(s.vault.try_shield(&s.prove(&ext), &ext, &depositor));
    assert_eq!(result, Err(Error::WrongVault));

    let mut ext = s.ext(XLM, 0, &depositor, &depositor);
    ext.network_id = soroban_sdk::BytesN::from_array(&s.env, &[0; 32]);
    let result = outcome(s.vault.try_shield(&s.prove(&ext), &ext, &depositor));
    assert_eq!(result, Err(Error::WrongNetwork));
}

#[test]
fn ciphertexts_must_be_exactly_181_bytes() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    for (len0, len1) in [
        (0, 181),
        (180, 181),
        (182, 181),
        (181, 180),
        (181, 182),
        (181, 0),
    ] {
        let mut ext = s.ext(XLM, 0, &depositor, &depositor);
        ext.encrypted_output0 = s.ciphertext(len0);
        ext.encrypted_output1 = s.ciphertext(len1);
        let result = outcome(s.vault.try_shield(&s.prove(&ext), &ext, &depositor));
        assert_eq!(result, Err(Error::BadCiphertext), "{len0} and {len1} bytes");
    }
    assert_eq!(CIPHERTEXT_LEN, 181);
}

#[test]
fn a_deposit_can_reach_max_deposit_but_not_exceed_it() {
    let s = Setup::new();
    let max = s.vault.limits().max_deposit;
    let depositor = s.account("depositor", 3 * max);
    assert_eq!(s.shield(&depositor, max + 1), Err(Error::DepositTooLarge));
    assert_eq!(s.shield(&depositor, max), Ok(1));
}

#[test]
fn a_depositor_is_capped_per_utc_day() {
    let s = Setup::new();
    let limit = s.vault.limits().max_daily_per_depositor;
    let max = s.vault.limits().max_deposit;
    let depositor = s.account("depositor", 10 * limit);
    let other = s.account("other", 10 * limit);

    assert_eq!(s.shield(&depositor, max), Ok(1));
    assert_eq!(s.shield(&depositor, limit - max), Ok(2));
    assert_eq!(s.shield(&depositor, 1), Err(Error::DepositorDailyLimit));
    // The cap is per depositor.
    assert_eq!(s.shield(&other, 1), Ok(3));

    // A cancellation does not give the day's allowance back.
    s.vault.cancel(&2);
    assert_eq!(s.shield(&depositor, 1), Err(Error::DepositorDailyLimit));

    // The day in the key resets the total at the next UTC midnight, not 24 hours later.
    let to_midnight = DAY - s.now() % DAY;
    s.advance(to_midnight - 1);
    assert_eq!(s.shield(&depositor, 1), Err(Error::DepositorDailyLimit));
    s.advance(1);
    assert_eq!(s.shield(&depositor, max), Ok(4));
}

#[test]
fn deposits_fill_the_tvl_cap_and_no_further() {
    let mut limits = super::setup::limits();
    limits.tvl_cap = 300 * XLM;
    limits.max_daily_outflow = 100 * XLM;
    let s = Setup::with_limits(limits);
    let a = s.account("a", 1_000 * XLM);
    let b = s.account("b", 1_000 * XLM);
    assert_eq!(s.shield(&a, 200 * XLM), Ok(1));
    assert_eq!(s.shield(&b, 100 * XLM + 1), Err(Error::TvlCapExceeded));
    assert_eq!(s.shield(&b, 100 * XLM), Ok(2));
    // Pending deposits count toward the cap; a cancellation frees the room.
    assert_eq!(s.shield(&b, 1), Err(Error::TvlCapExceeded));
    s.vault.cancel(&1);
    assert_eq!(s.shield(&b, 200 * XLM), Ok(3));
}

#[test]
fn a_depositor_without_the_funds_cannot_shield() {
    let s = Setup::new();
    let depositor = s.account("depositor", XLM);
    let ext = s.ext(2 * XLM, 0, &depositor, &depositor);
    let proof = s.prove(&ext);
    assert!(s.vault.try_shield(&proof, &ext, &depositor).is_err());
    // Nothing of the failed call remains.
    assert!(!s.vault.is_spent(&proof.input_nullifiers.get_unchecked(0)));
    assert_eq!(s.vault.status().next_deposit_id, 1);
    assert_eq!(s.vault.status().tvl, 0);
}

#[test]
fn the_last_deposit_id_cannot_overflow() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    let vault = s.vault.address.clone();
    s.env.as_contract(&vault, || {
        let mut status = crate::storage::status(&s.env);
        status.next_deposit_id = u64::MAX - 1;
        status.attested_up_to = u64::MAX - 2;
        crate::storage::set_status(&s.env, &status);
    });
    assert_eq!(s.shield(&depositor, XLM), Ok(u64::MAX - 1));
    assert_eq!(s.vault.status().next_deposit_id, u64::MAX);
    assert_eq!(s.shield(&depositor, XLM), Err(Error::Overflow));

    // The last ID is still attested and admitted normally.
    s.vault.attest(&(u64::MAX - 1));
    assert_eq!(
        crate::test::setup::outcome(s.vault.try_attest(&u64::MAX)),
        Err(Error::BadAttestation)
    );
    s.advance(super::setup::DELAY_SMALL);
    assert_eq!(
        s.vault.admit(&vec![&s.env, u64::MAX - 1]),
        vec![&s.env, u64::MAX - 1]
    );
}

#[test]
fn a_shield_must_prove_against_the_empty_root() {
    let s = Setup::new();
    s.fund_pool("funder", 10 * XLM);
    let depositor = s.account("depositor", 100 * XLM);
    let current = s.vault.current_root();
    assert_ne!(current, s.empty_root);
    let zero = soroban_sdk::U256::from_u32(&s.env, 0);
    for root in [current, zero, s.field()] {
        let ext = s.ext(XLM, 0, &depositor, &depositor);
        let proof = s.prove_with(&ext, root, [s.field(), s.field()], [s.field(), s.field()]);
        let result = outcome(s.vault.try_shield(&proof, &ext, &depositor));
        assert_eq!(result, Err(Error::NonEmptyRoot));
    }
}

#[test]
fn a_deposit_proof_does_not_expire_with_the_root_history() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    // A proof made before 256 pairs entered the tree, so the empty root left the ring.
    let ext = s.ext(XLM, 0, &depositor, &depositor);
    let proof = s.prove(&ext);
    let pairs: std::vec::Vec<_> = (0..256).map(|_| (s.field(), s.field())).collect();
    super::tree::append(&s, &pairs);
    assert!(!s.vault.is_known_root(&s.empty_root));
    assert_eq!(s.vault.shield(&proof, &ext, &depositor), 1);
}
