use soroban_sdk::{
    testutils::{
        Address as _, AuthorizedFunction, AuthorizedInvocation, Events as _, Ledger,
        MuxedAddress as _,
    },
    Address, Event, IntoVal, MuxedAddress, Symbol,
};

use super::setup::{Setup, DAY, XLM};
use crate::{events, Error};

/// A vault holding three admitted deposits of 2,500 XLM.
fn funded() -> Setup {
    let s = Setup::new();
    for tag in ["funder a", "funder b", "funder c"] {
        s.fund_pool(tag, 2_500 * XLM);
    }
    s
}

#[test]
fn a_transfer_inserts_its_outputs_and_pays_only_the_fee() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    let ext = s.ext(0, 2 * XLM, &relayer, &relayer);
    let proof = s.prove(&ext);
    let leaf = s.vault.next_leaf_index();
    let tvl = s.vault.status().tvl;

    s.vault.transact(&proof, &ext, &relayer);

    let vault = s.vault.address.clone();
    let all = s.env.events().all();
    let cm = |i| proof.output_commitments.get_unchecked(i);
    assert_eq!(
        all.filter_by_contract(&vault),
        std::vec![
            events::NewNullifier {
                nullifier: proof.input_nullifiers.get_unchecked(0)
            }
            .to_xdr(&s.env, &vault),
            events::NewNullifier {
                nullifier: proof.input_nullifiers.get_unchecked(1)
            }
            .to_xdr(&s.env, &vault),
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
            events::Settled {
                ext_amount: 0,
                fee: 2 * XLM,
                recipient: relayer.clone().into(),
                relayer: relayer.clone()
            }
            .to_xdr(&s.env, &vault),
        ]
    );
    // One transfer, of the fee, by the asset contract.
    assert_eq!(all.filter_by_contract(&s.token.address).events().len(), 1);
    assert_eq!(s.vault.next_leaf_index(), leaf + 2);
    assert_eq!(s.vault.status().tvl, tvl - 2 * XLM);
    assert_eq!(s.balance(&relayer), 2 * XLM);
    assert_eq!(s.balance(&vault), tvl - 2 * XLM);
    assert!(s.vault.is_known_root(&s.vault.current_root()));
    assert!(s.vault.is_known_root(&proof.root));
}

#[test]
fn transact_needs_only_the_submitters_authorization() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    let submitter = Address::generate(&s.env);
    let ext = s.ext(-XLM, XLM / 10, &relayer, &relayer);
    let proof = s.prove(&ext);
    s.vault.transact(&proof, &ext, &submitter);
    assert_eq!(
        s.env.auths(),
        std::vec![(
            submitter.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    s.vault.address.clone(),
                    Symbol::new(&s.env, "transact"),
                    (proof, ext, submitter.clone()).into_val(&s.env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );
}

#[test]
fn an_unshield_pays_an_account_a_muxed_account_or_a_contract() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    let account = s.account("account", 0);
    let exchange = s.account("exchange", 0);
    let contract = Address::generate(&s.env);
    let muxed = MuxedAddress::new(exchange.clone(), u64::MAX);
    let recipients: [(MuxedAddress, &Address); 3] = [
        (account.clone().into(), &account),
        (muxed, &exchange),
        (contract.clone().into(), &contract),
    ];
    for (recipient, base) in recipients {
        let tvl = s.vault.status().tvl;
        let ext = s.ext(-10 * XLM, XLM, recipient.clone(), &relayer);
        assert_eq!(s.transact(&relayer, &ext), Ok(()));
        assert_eq!(s.balance(base), 10 * XLM);
        assert_eq!(s.vault.status().tvl, tvl - 11 * XLM);
    }
    assert_eq!(s.balance(&relayer), 3 * XLM);
    assert_eq!(s.balance(&s.vault.address), s.vault.status().tvl);
}

#[test]
fn a_self_relayed_unshield_pays_no_fee() {
    let s = funded();
    let user = s.account("user", XLM);
    let ext = s.ext(-5 * XLM, 0, &user, &user);
    assert_eq!(s.transact(&user, &ext), Ok(()));
    // A zero fee moves nothing to the relayer: one asset transfer only.
    assert_eq!(
        s.env
            .events()
            .all()
            .filter_by_contract(&s.token.address)
            .events()
            .len(),
        1
    );
    assert_eq!(s.balance(&user), 6 * XLM);
}

#[test]
fn transact_is_refused_while_halted() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    s.vault.halt();
    for amount in [0, -XLM] {
        let ext = s.ext(amount, 0, &relayer, &relayer);
        assert_eq!(s.transact(&relayer, &ext), Err(Error::Halted));
    }
}

#[test]
fn pausing_transfers_leaves_unshields_open() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    s.vault.set_pause(&true, &true);
    let ext = s.ext(0, XLM, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::TransfersPaused));
    let ext = s.ext(-XLM, XLM, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
    s.vault.set_pause(&true, &false);
    let ext = s.ext(0, XLM, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
}

#[test]
fn transact_refuses_deposits_and_fees_outside_the_cap() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    let max_fee = s.vault.limits().max_fee;
    for (amount, fee, error) in [
        (1, 0, Error::BadAmount),
        (-XLM, -1, Error::BadFee),
        (-XLM, max_fee + 1, Error::BadFee),
        (0, max_fee + 1, Error::BadFee),
    ] {
        let ext = s.ext(amount, fee, &relayer, &relayer);
        assert_eq!(
            s.transact(&relayer, &ext),
            Err(error),
            "amount {amount} fee {fee}"
        );
    }
    let ext = s.ext(-XLM, max_fee, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
}

#[test]
fn ciphertexts_and_binding_are_checked_for_transact_too() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    let mut ext = s.ext(-XLM, 0, &relayer, &relayer);
    ext.encrypted_output1 = s.ciphertext(180);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::BadCiphertext));
    let mut ext = s.ext(-XLM, 0, &relayer, &relayer);
    ext.vault = relayer.clone();
    assert_eq!(s.transact(&relayer, &ext), Err(Error::WrongVault));
    let mut ext = s.ext(-XLM, 0, &relayer, &relayer);
    ext.network_id = soroban_sdk::BytesN::from_array(&s.env, &[1; 32]);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::WrongNetwork));
}

#[test]
fn the_daily_outflow_counts_payouts_and_fees_and_resets_at_midnight() {
    let s = funded();
    let relayer = s.account("relayer", 0);
    let max = s.vault.limits().max_daily_outflow;

    let ext = s.ext(-(max - 3 * XLM), 3 * XLM, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
    assert_eq!(s.vault.status().outflow, max);
    let ext = s.ext(-1, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::OutflowLimit));
    let ext = s.ext(0, 1, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::OutflowLimit));
    // A transfer without a fee moves nothing out.
    let ext = s.ext(0, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));

    let to_midnight = DAY - s.now() % DAY;
    s.advance(to_midnight - 1);
    let ext = s.ext(-1, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::OutflowLimit));
    s.advance(1);
    let ext = s.ext(-1, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
    let status = s.vault.status();
    assert_eq!((status.outflow_day, status.outflow), (s.now() / DAY, 1));
}

#[test]
fn more_than_the_vault_holds_can_never_leave() {
    // Only a forged proof could ask for this; the vault still refuses it.
    let s = Setup::new();
    s.fund_pool("funder", 100 * XLM);
    let relayer = s.account("relayer", 0);
    let ext = s.ext(-100 * XLM, 1, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::ExceedsAdmittedValue));
    let ext = s.ext(-100 * XLM, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Ok(()));
    assert_eq!(s.vault.status().tvl, 0);
}

#[test]
fn a_forged_spend_cannot_take_pending_deposits() {
    // The trapdoor key stands in for a broken proof system: it forges any spend.
    let s = Setup::new();
    s.fund_pool("admitted", 100 * XLM);
    let depositor = s.account("pending depositor", 1_000 * XLM);
    let id = s.shield(&depositor, 100 * XLM).unwrap();
    let forger = s.account("forger", 0);
    let status = s.vault.status();
    assert_eq!((status.tvl, status.pending_total), (200 * XLM, 100 * XLM));

    // Only 100 XLM was ever admitted, so no more than that can leave.
    let ext = s.ext(-100 * XLM - 1, 0, &forger, &forger);
    assert_eq!(s.transact(&forger, &ext), Err(Error::ExceedsAdmittedValue));
    let ext = s.ext(-100 * XLM, 0, &forger, &forger);
    assert_eq!(s.transact(&forger, &ext), Ok(()));
    let ext = s.ext(-1, 0, &forger, &forger);
    assert_eq!(s.transact(&forger, &ext), Err(Error::ExceedsAdmittedValue));

    // The pending deposit is untouched and its depositor takes it back.
    s.vault.cancel(&id);
    assert_eq!(s.balance(&depositor), 1_000 * XLM);
    assert_eq!(s.balance(&s.vault.address), 0);
    let status = s.vault.status();
    assert_eq!((status.tvl, status.pending_total), (0, 0));
}

#[test]
fn a_transact_is_atomic_when_its_payout_fails() {
    let s = funded();
    // Paying a missing account creates it, which needs two base reserves; one stroop fails after
    // every check and effect has run.
    s.env.ledger().with_mut(|l| l.base_reserve = 5_000_000);
    let missing = super::setup::account_address(&s.env, "missing");
    let relayer = s.account("relayer", 0);
    let ext = s.ext(-1, 0, &missing, &relayer);
    let proof = s.prove(&ext);
    let leaf = s.vault.next_leaf_index();
    let status = s.vault.status();
    assert!(s.vault.try_transact(&proof, &ext, &relayer).is_err());
    assert!(!s.vault.is_spent(&proof.input_nullifiers.get_unchecked(0)));
    assert_eq!(s.vault.next_leaf_index(), leaf);
    assert_eq!(s.vault.status(), status);
}
