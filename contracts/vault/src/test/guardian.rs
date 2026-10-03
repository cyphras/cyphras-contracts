use soroban_sdk::{testutils::Events as _, Event, Vec};

use super::{
    queue::authorizers,
    setup::{outcome, Setup, DAY, DELAY_LARGE, XLM},
};
use crate::{events, storage, Error, Limits, QueuedLimits};

const HALT: u64 = 72 * 3_600;
const WEEK: u64 = 7 * DAY;

#[test]
fn only_the_guardian_pauses_halts_resumes_and_changes_limits() {
    let s = Setup::new();
    let guardian = std::vec![s.guardian.clone()];
    s.vault.set_pause(&true, &true);
    assert_eq!(authorizers(&s), guardian);
    s.vault.halt();
    assert_eq!(authorizers(&s), guardian);
    s.vault.resume();
    assert_eq!(authorizers(&s), guardian);
    let mut looser = s.vault.limits();
    looser.max_fee += 1;
    s.vault.set_limits(&looser);
    assert_eq!(authorizers(&s), guardian);
    s.vault.cancel_limits();
    assert_eq!(authorizers(&s), guardian);
}

#[test]
fn set_pause_sets_both_flags() {
    let s = Setup::new();
    let vault = s.vault.address.clone();
    for (deposits, transfers) in [(true, false), (false, true), (true, true), (false, false)] {
        s.vault.set_pause(&deposits, &transfers);
        assert_eq!(
            s.env.events().all().filter_by_contract(&vault),
            std::vec![events::Paused {
                deposits,
                transfers
            }
            .to_xdr(&s.env, &vault)]
        );
        let status = s.vault.status();
        assert_eq!(
            (status.deposits_paused, status.transfers_paused),
            (deposits, transfers)
        );
    }
}

#[test]
fn a_halt_stops_shield_transact_and_admit_for_72_hours() {
    let s = Setup::new();
    s.fund_pool("funder", 100 * XLM);
    let depositor = s.account("depositor", 100 * XLM);
    let relayer = s.account("relayer", 0);
    s.shield(&depositor, XLM).unwrap();
    let id = s.vault.status().next_deposit_id - 1;
    s.vault.attest(&id);
    s.advance(DELAY_LARGE);

    s.vault.halt();
    let until = s.now() + HALT;
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Halted { until }.to_xdr(&s.env, &vault)]
    );
    let status = s.vault.status();
    assert_eq!(
        (status.halted_until, status.next_halt_at),
        (until, until + WEEK)
    );

    s.advance(HALT - 1);
    assert_eq!(s.shield(&depositor, XLM), Err(Error::Halted));
    assert_eq!(
        s.transact(&relayer, &s.ext(-XLM, 0, &relayer, &relayer)),
        Err(Error::Halted)
    );
    let ids = Vec::from_slice(&s.env, &[id]);
    assert_eq!(outcome(s.vault.try_admit(&ids)), Err(Error::Halted));

    s.advance(1);
    assert_eq!(s.now(), until);
    assert_eq!(s.vault.admit(&ids), ids);
    assert!(s.shield(&depositor, XLM).is_ok());
    assert_eq!(
        s.transact(&relayer, &s.ext(-XLM, 0, &relayer, &relayer)),
        Ok(())
    );
}

#[test]
fn halts_are_seven_days_apart_counted_from_the_end_of_the_last() {
    let s = Setup::new();
    s.vault.halt();
    let end = s.now() + HALT;
    // No second halt while halted, which would extend it.
    assert_eq!(outcome(s.vault.try_halt()), Err(Error::HaltCooldown));
    s.advance(HALT);
    assert_eq!(s.now(), end);
    s.advance(WEEK - 1);
    assert_eq!(outcome(s.vault.try_halt()), Err(Error::HaltCooldown));
    s.advance(1);
    s.vault.halt();
    assert_eq!(s.vault.status().halted_until, end + WEEK + HALT);
}

#[test]
fn resume_ends_a_halt_early_and_the_cooldown_runs_from_then() {
    let s = Setup::new();
    assert_eq!(outcome(s.vault.try_resume()), Err(Error::NotHalted));
    s.vault.halt();
    s.advance(3_600);
    s.vault.resume();
    let resumed_at = s.now();
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::Resumed {
            next_halt_at: resumed_at + WEEK
        }
        .to_xdr(&s.env, &vault)]
    );
    let status = s.vault.status();
    assert_eq!(
        (status.halted_until, status.next_halt_at),
        (resumed_at, resumed_at + WEEK)
    );
    assert_eq!(outcome(s.vault.try_resume()), Err(Error::NotHalted));
    s.advance(WEEK - 1);
    assert_eq!(outcome(s.vault.try_halt()), Err(Error::HaltCooldown));
    s.advance(1);
    s.vault.halt();
}

#[test]
fn a_halt_that_expired_cannot_be_resumed() {
    let s = Setup::new();
    s.vault.halt();
    s.advance(HALT);
    assert_eq!(outcome(s.vault.try_resume()), Err(Error::NotHalted));
}

#[test]
fn the_guardian_keeps_its_other_powers_while_halted() {
    let s = Setup::new();
    s.vault.halt();
    s.vault.set_pause(&true, &true);
    let mut tighter = s.vault.limits();
    tighter.max_fee = 0;
    s.vault.set_limits(&tighter);
    assert_eq!(s.vault.limits(), tighter);
}

fn each_field(limits: &Limits, delta: i128) -> std::vec::Vec<Limits> {
    let mut out = std::vec::Vec::new();
    for i in 0..6 {
        let mut l = limits.clone();
        match i {
            0 => l.max_deposit += delta,
            1 => l.max_daily_per_depositor += delta,
            2 => l.tvl_cap += delta,
            3 => l.max_daily_outflow += delta,
            4 => l.max_fee += delta,
            _ => l.large_deposit_threshold += delta,
        }
        out.push(l);
    }
    out
}

#[test]
fn a_tightening_applies_at_once() {
    let s = Setup::new();
    let vault = s.vault.address.clone();
    for field in [0, 1, 2, 4, 5] {
        let tighter = each_field(&s.vault.limits(), -1).swap_remove(field);
        s.vault.set_limits(&tighter);
        assert_eq!(
            s.env.events().all().filter_by_contract(&vault),
            std::vec![events::LimitsApplied {
                limits: tighter.clone(),
                ready_at: s.now()
            }
            .to_xdr(&s.env, &vault)]
        );
        assert_eq!(s.vault.limits(), tighter);
        assert_eq!(s.vault.queued_limits(), None);
    }
    // Setting the same limits again is a tightening of nothing.
    let same = s.vault.limits();
    s.vault.set_limits(&same);
    assert_eq!(s.vault.limits(), same);
}

#[test]
fn max_daily_outflow_never_decreases() {
    let s = Setup::new();
    let mut lower = s.vault.limits();
    lower.max_daily_outflow -= 1;
    lower.tvl_cap = 7 * lower.max_daily_outflow;
    assert_eq!(
        outcome(s.vault.try_set_limits(&lower)),
        Err(Error::OutflowDecrease)
    );
    lower.max_daily_outflow = 0;
    lower.tvl_cap = 0;
    assert_eq!(
        outcome(s.vault.try_set_limits(&lower)),
        Err(Error::OutflowDecrease)
    );
}

#[test]
fn limits_always_let_a_full_pool_exit_within_seven_days() {
    let s = Setup::new();
    let mut l = s.vault.limits();
    l.tvl_cap = 7 * l.max_daily_outflow + 1;
    assert_eq!(outcome(s.vault.try_set_limits(&l)), Err(Error::BadLimits));
    l.tvl_cap = 7 * l.max_daily_outflow;
    s.vault.set_limits(&l);
    assert_eq!(s.vault.queued_limits().map(|q| q.limits), Some(l.clone()));

    let current = s.vault.limits();
    for negative in [
        Limits {
            max_deposit: -1,
            ..current.clone()
        },
        Limits {
            max_daily_per_depositor: -1,
            ..current.clone()
        },
        Limits {
            tvl_cap: -1,
            ..current.clone()
        },
        Limits {
            max_fee: -1,
            ..current.clone()
        },
        Limits {
            large_deposit_threshold: -1,
            ..current.clone()
        },
    ] {
        assert_eq!(
            outcome(s.vault.try_set_limits(&negative)),
            Err(Error::BadLimits)
        );
    }
}

#[test]
fn a_loosening_waits_seven_days_and_then_anyone_applies_it() {
    let s = Setup::new();
    let before = s.vault.limits();
    let vault = s.vault.address.clone();
    for looser in each_field(&before, 1) {
        s.vault.set_limits(&looser);
        let ready_at = s.now() + WEEK;
        assert_eq!(
            s.env.events().all().filter_by_contract(&vault),
            std::vec![events::LimitsQueued {
                limits: looser.clone(),
                ready_at
            }
            .to_xdr(&s.env, &vault)]
        );
        assert_eq!(s.vault.limits(), before);
        assert_eq!(
            s.vault.queued_limits(),
            Some(QueuedLimits {
                limits: looser.clone(),
                ready_at
            })
        );
        s.vault.cancel_limits();
    }

    let mut looser = before.clone();
    looser.max_deposit *= 2;
    looser.tvl_cap = 35_000 * XLM;
    s.vault.set_limits(&looser);
    let ready_at = s.now() + WEEK;
    s.advance(WEEK - 1);
    assert_eq!(
        outcome(s.vault.try_apply_limits()),
        Err(Error::LimitsNotReady)
    );
    s.advance(1);
    s.vault.apply_limits();
    assert!(authorizers(&s).is_empty());
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::LimitsApplied {
            limits: looser.clone(),
            ready_at
        }
        .to_xdr(&s.env, &vault)]
    );
    assert_eq!(s.vault.limits(), looser);
    assert_eq!(s.vault.queued_limits(), None);
    assert_eq!(
        outcome(s.vault.try_apply_limits()),
        Err(Error::NoQueuedLimits)
    );
}

#[test]
fn a_change_that_raises_any_field_is_queued_whole() {
    let s = Setup::new();
    let before = s.vault.limits();
    let mut mixed = before.clone();
    mixed.max_deposit -= 1;
    mixed.max_fee += 1;
    s.vault.set_limits(&mixed);
    assert_eq!(s.vault.limits(), before);
    assert_eq!(s.vault.queued_limits().unwrap().limits, mixed);
}

#[test]
fn a_new_loosening_replaces_the_queued_one_and_restarts_the_clock() {
    let s = Setup::new();
    let mut first = s.vault.limits();
    first.max_fee += 1;
    s.vault.set_limits(&first);
    s.advance(3 * DAY);
    let mut second = s.vault.limits();
    second.max_deposit += 1;
    s.vault.set_limits(&second);
    assert_eq!(
        s.vault.queued_limits(),
        Some(QueuedLimits {
            limits: second.clone(),
            ready_at: s.now() + WEEK
        })
    );
    s.advance(4 * DAY);
    assert_eq!(
        outcome(s.vault.try_apply_limits()),
        Err(Error::LimitsNotReady)
    );
    s.advance(3 * DAY);
    s.vault.apply_limits();
    assert_eq!(s.vault.limits(), second);
}

#[test]
fn a_tightening_leaves_a_queued_loosening_in_place() {
    let s = Setup::new();
    let mut looser = s.vault.limits();
    looser.max_fee += 1;
    s.vault.set_limits(&looser);
    let mut tighter = s.vault.limits();
    tighter.max_deposit -= 1;
    s.vault.set_limits(&tighter);
    assert_eq!(s.vault.limits(), tighter);
    assert_eq!(s.vault.queued_limits().unwrap().limits, looser);
}

#[test]
fn cancel_limits_drops_the_queued_loosening() {
    let s = Setup::new();
    assert_eq!(
        outcome(s.vault.try_cancel_limits()),
        Err(Error::NoQueuedLimits)
    );
    let before = s.vault.limits();
    let mut looser = before.clone();
    looser.max_fee += 1;
    s.vault.set_limits(&looser);
    let ready_at = s.now() + WEEK;
    s.vault.cancel_limits();
    let vault = s.vault.address.clone();
    assert_eq!(
        s.env.events().all().filter_by_contract(&vault),
        std::vec![events::LimitsCancelled {
            limits: looser,
            ready_at
        }
        .to_xdr(&s.env, &vault)]
    );
    s.advance(WEEK);
    assert_eq!(
        outcome(s.vault.try_apply_limits()),
        Err(Error::NoQueuedLimits)
    );
    assert_eq!(s.vault.limits(), before);
}

#[test]
fn a_queued_change_is_checked_again_when_it_applies() {
    let s = Setup::new();
    let current = s.vault.limits();
    for (limits, error) in [
        (
            Limits {
                max_daily_outflow: current.max_daily_outflow - 1,
                tvl_cap: 0,
                ..current.clone()
            },
            Error::OutflowDecrease,
        ),
        (
            Limits {
                tvl_cap: 7 * current.max_daily_outflow + 1,
                ..current.clone()
            },
            Error::BadLimits,
        ),
    ] {
        s.env.as_contract(&s.vault.address, || {
            storage::set_queued_limits(
                &s.env,
                &QueuedLimits {
                    limits,
                    ready_at: 0,
                },
            );
        });
        assert_eq!(outcome(s.vault.try_apply_limits()), Err(error));
    }
}

#[test]
fn a_stolen_guardian_key_cannot_keep_a_full_pool_from_leaving_within_a_halt_and_a_week() {
    let s = Setup::new();
    let limits = s.vault.limits();
    // Fill the pool to its cap.
    let mut tvl = 0;
    let mut n = 0;
    while tvl < limits.tvl_cap {
        let depositor = s.account(&std::format!("depositor {n}"), limits.max_deposit);
        s.shield(&depositor, limits.max_deposit).unwrap();
        tvl += limits.max_deposit;
        n += 1;
    }
    s.attest_all_and_wait();
    // Each admitted pair costs about 12M instructions, so the keeper admits in batches.
    let ids = s.pending_ids();
    for batch in [ids.slice(0..5), ids.slice(5..ids.len())] {
        assert_eq!(s.vault.admit(&batch), batch);
    }
    assert_eq!(s.vault.status().tvl, limits.tvl_cap);

    // Everything the guardian can do at once.
    s.vault.set_pause(&true, &true);
    let tightest = Limits {
        max_deposit: 0,
        max_daily_per_depositor: 0,
        tvl_cap: 0,
        max_daily_outflow: limits.max_daily_outflow,
        max_fee: 0,
        large_deposit_threshold: 0,
    };
    s.vault.set_limits(&tightest);
    s.vault.halt();
    s.advance(HALT);
    assert_eq!(outcome(s.vault.try_halt()), Err(Error::HaltCooldown));

    // Self-relayed, fee-free unshields drain the pool one daily window at a time.
    let user = s.account("user", 0);
    let mut days = 0;
    while s.vault.status().tvl > 0 {
        let amount = s.vault.status().tvl.min(tightest.max_daily_outflow);
        let ext = s.ext(-amount, 0, &user, &user);
        assert_eq!(s.transact(&user, &ext), Ok(()));
        s.advance(DAY);
        days += 1;
    }
    assert!(days <= 7);
    assert_eq!(s.balance(&user), limits.tvl_cap);
}
