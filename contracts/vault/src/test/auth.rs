use soroban_sdk::{
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    vec, Address, IntoVal, Val, Vec,
};

use super::setup::{host_aborted, outcome, Setup, DAY, XLM};
use crate::Error;

#[test]
fn every_privileged_entry_point_refuses_a_call_without_authorization() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    s.vault.flag(&2, &1);
    let mut looser = s.vault.limits();
    looser.max_fee += 1;
    let mut tighter = s.vault.limits();
    tighter.max_fee -= 1;
    s.vault.set_limits(&looser);
    s.vault.halt();
    let status = s.vault.status();
    let limits = s.vault.limits();

    // From here on no signature is mocked.
    s.env.set_auths(&[]);
    assert!(host_aborted(s.vault.try_attest(&1)), "attest");
    assert!(host_aborted(s.vault.try_flag(&1, &1)), "flag");
    assert!(host_aborted(s.vault.try_unflag(&2)), "unflag");
    assert!(
        host_aborted(s.vault.try_set_pause(&true, &true)),
        "set_pause"
    );
    assert!(host_aborted(s.vault.try_resume()), "resume");
    assert!(host_aborted(s.vault.try_set_limits(&tighter)), "tighten");
    assert!(host_aborted(s.vault.try_set_limits(&looser)), "loosen");
    assert!(host_aborted(s.vault.try_cancel_limits()), "cancel_limits");
    assert!(host_aborted(s.vault.try_cancel(&1)), "cancel");
    let ext = s.ext(XLM, 0, &depositor, &depositor);
    let proof = s.prove(&ext);
    assert!(
        host_aborted(s.vault.try_shield(&proof, &ext, &depositor)),
        "shield"
    );
    let relayer = Address::generate(&s.env);
    let ext = s.ext(0, 0, &relayer, &relayer);
    let proof = s.prove(&ext);
    assert!(
        host_aborted(s.vault.try_transact(&proof, &ext, &relayer)),
        "transact"
    );
    // The cooldown would refuse a second halt anyway, but the authorization is checked first.
    assert!(host_aborted(s.vault.try_halt()), "halt");
    assert_eq!(s.vault.status(), status);
    assert_eq!(s.vault.limits(), limits);
    assert!(s.vault.queued_limits().is_some());

    // The permissionless entry points need nobody.
    s.vault.bump_ttl(&Vec::from_slice(&s.env, &[1, 2]));
    assert_eq!(
        outcome(s.vault.try_apply_limits()),
        Err(Error::LimitsNotReady)
    );
    s.advance(DAY);
    s.vault.refund(&2);
    assert_eq!(s.balance(&depositor), 99 * XLM);
}

fn mock(s: &Setup, who: &Address, function: &'static str, args: Vec<Val>) {
    s.env.mock_auths(&[MockAuth {
        address: who,
        invoke: &MockAuthInvoke {
            contract: &s.vault.address,
            fn_name: function,
            args,
            sub_invokes: &[],
        },
    }]);
}

#[test]
fn the_wrong_role_cannot_stand_in_for_the_right_one() {
    let s = Setup::new();
    let depositor = s.account("depositor", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    let env = &s.env;
    let stranger = Address::generate(env);

    // The ASP signs guardian calls, the guardian signs ASP calls, and others sign a cancel.
    mock(&s, &s.asp, "halt", vec![env]);
    assert!(host_aborted(s.vault.try_halt()));
    mock(&s, &s.asp, "set_pause", (true, true).into_val(env));
    assert!(host_aborted(s.vault.try_set_pause(&true, &true)));
    let mut tighter = s.vault.limits();
    tighter.max_fee = 0;
    mock(&s, &s.asp, "set_limits", (tighter.clone(),).into_val(env));
    assert!(host_aborted(s.vault.try_set_limits(&tighter)));
    mock(&s, &s.guardian, "attest", (1u64,).into_val(env));
    assert!(host_aborted(s.vault.try_attest(&1)));
    mock(&s, &s.guardian, "flag", (1u64, 1u32).into_val(env));
    assert!(host_aborted(s.vault.try_flag(&1, &1)));
    mock(&s, &stranger, "cancel", (1u64,).into_val(env));
    assert!(host_aborted(s.vault.try_cancel(&1)));
    mock(&s, &s.guardian, "cancel", (1u64,).into_val(env));
    assert!(host_aborted(s.vault.try_cancel(&1)));
    assert!(s.vault.pending(&1).is_some());
    assert_eq!(s.vault.status().attested_up_to, 0);
}
