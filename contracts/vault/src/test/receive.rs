//! An exit is refused before anything is spent when a party it would pay cannot receive the asset
//! now, the same whether it would be paid at once or wait in the queue.

use soroban_sdk::{
    testutils::{Address as _, MuxedAddress as _},
    xdr::{self, ScAddress},
    Address, MuxedAddress, TryFromVal,
};

use super::{
    exits::{fill_window, funded, used},
    setup::{account_address, limits, outcome, Classic, Setup, XLM},
};
use crate::Error;

/// A vault of a classic asset whose issuer can revoke authorization, holding 10,000 units.
fn classic() -> Classic {
    let c = Classic::new(limits());
    c.fund(4, 2_500 * XLM);
    c
}

/// Submits an unshield and returns its result, checking that a refused one spent nothing.
fn exit(
    s: &Setup,
    payout: i128,
    fee: i128,
    recipient: MuxedAddress,
    relayer: &Address,
) -> Result<(), Error> {
    let ext = s.ext(-payout, fee, recipient, relayer);
    let proof = s.prove(&ext);
    let status = s.vault.status();
    let result = outcome(s.vault.try_transact(&proof, &ext, relayer));
    if result.is_err() {
        assert!(!s.vault.is_spent(&proof.input_nullifiers.get_unchecked(0)));
        assert_eq!(s.vault.status(), status);
    }
    result
}

#[test]
fn an_exit_to_a_party_that_cannot_receive_is_refused_alike_paid_at_once_or_queued() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let untrusting = s.account("untrusting", 0);

    // With the queue empty and the window open the exit would be paid at once.
    assert_eq!(
        exit(s, 10 * XLM, 0, untrusting.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    // With the window full it would wait in the queue, and it is refused all the same.
    fill_window(s, &filler);
    assert_eq!(
        exit(s, 10 * XLM, 0, untrusting.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    assert_eq!(s.vault.status().exit_tail, 1);

    // Once the account trusts the asset, the exit waits its turn.
    c.asset.trust(&untrusting);
    assert_eq!(exit(s, 10 * XLM, 0, untrusting.into(), &filler), Ok(()));
    assert_eq!(s.vault.status().exit_tail, 2);
}

#[test]
fn a_recipient_whose_authorization_is_revoked_is_refused_until_it_is_restored() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let frozen = c.holder("frozen", 0);
    c.asset.set_authorized(&frozen, &false);
    assert_eq!(
        exit(s, 10 * XLM, 0, frozen.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    c.asset.set_authorized(&frozen, &true);
    assert_eq!(exit(s, 10 * XLM, 0, frozen.clone().into(), &filler), Ok(()));
    assert_eq!(s.balance(&frozen), 10 * XLM);
}

#[test]
fn a_native_account_that_does_not_exist_yet_is_refused() {
    let s = funded();
    let filler = s.account("filler", 0);
    let missing = account_address(&s.env, "missing");
    // Two base reserves would create the account, but an exit only pays existing accounts.
    assert_eq!(
        exit(&s, 10 * XLM, 0, missing.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    fill_window(&s, &filler);
    assert_eq!(
        exit(&s, 10 * XLM, 0, missing.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    s.account("missing", 0);
    assert_eq!(exit(&s, 10 * XLM, 0, missing.into(), &filler), Ok(()));
}

#[test]
fn a_contract_recipient_is_paid_unless_its_balance_is_deauthorized() {
    // The asset contract credits any contract address, deployed or not.
    let s = funded();
    let filler = s.account("filler", 0);
    let contract = Address::generate(&s.env);
    assert_eq!(
        exit(&s, 10 * XLM, 0, contract.clone().into(), &filler),
        Ok(())
    );
    assert_eq!(s.balance(&contract), 10 * XLM);

    // The issuer of a classic asset can deauthorize a contract's balance too.
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let contract = Address::generate(&s.env);
    assert_eq!(
        exit(s, 10 * XLM, 0, contract.clone().into(), &filler),
        Ok(())
    );
    c.asset.set_authorized(&contract, &false);
    assert_eq!(
        exit(s, 10 * XLM, 0, contract.clone().into(), &filler),
        Err(Error::CannotReceive)
    );
    assert_eq!(s.balance(&contract), 10 * XLM);
}

#[test]
fn a_muxed_recipient_is_judged_by_its_base_account() {
    let c = classic();
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let exchange = c.holder("exchange", 0);
    let deposit_address = MuxedAddress::new(exchange.clone(), 42);
    assert_eq!(
        exit(s, 10 * XLM, 0, deposit_address.clone(), &filler),
        Ok(())
    );
    c.asset.set_authorized(&exchange, &false);
    assert_eq!(
        exit(s, 10 * XLM, 0, deposit_address, &filler),
        Err(Error::CannotReceive)
    );
    let untrusting = s.account("untrusting", 0);
    assert_eq!(
        exit(s, 10 * XLM, 0, MuxedAddress::new(untrusting, 1), &filler),
        Err(Error::CannotReceive)
    );
    assert_eq!(s.balance(&exchange), 10 * XLM);
}

#[test]
fn a_relayer_that_cannot_receive_is_refused_only_when_it_has_a_fee_to_take() {
    let c = classic();
    let s = &c.s;
    let user = c.holder("user", 0);
    let relayer = c.holder("relayer", 0);
    c.asset.set_authorized(&relayer, &false);
    assert_eq!(
        exit(s, 10 * XLM, XLM, user.clone().into(), &relayer),
        Err(Error::CannotReceive)
    );
    // Without a fee the relayer is paid nothing, so it need not be able to receive.
    assert_eq!(exit(s, 10 * XLM, 0, user.clone().into(), &relayer), Ok(()));
    assert_eq!(s.balance(&user), 10 * XLM);
    assert_eq!(used(s), 10 * XLM);
}

#[test]
fn only_an_account_or_a_contract_can_be_named_as_a_party() {
    // The host builds an address object only for an account or a contract, so a call naming a
    // liquidity pool or a claimable balance fails before the vault runs, and the check of
    // whether a party can receive never meets one.
    let s = funded();
    let pool = ScAddress::LiquidityPool(xdr::PoolId(xdr::Hash([7; 32])));
    let balance = ScAddress::ClaimableBalance(xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(
        xdr::Hash([9; 32]),
    ));
    for address in [pool, balance] {
        assert!(
            Address::try_from_val(&s.env, &address).is_err(),
            "{address:?}"
        );
    }
}
