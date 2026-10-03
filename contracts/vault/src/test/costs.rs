//! Metered cost of the calls, printed with `cargo test costs -- --nocapture`. The contract runs
//! natively here, so the guest's own instructions are not counted; the host functions it calls,
//! which dominate, are.

use soroban_sdk::Env;

use super::{
    e2e::Flow,
    exits::{fill_window, queue, to_midnight},
    fixtures,
    setup::{limits, Classic, XLM},
};
use crate::Limits;

// The default test budget, stricter than the network's per-transaction limit.
const BUDGET: u64 = 100_000_000;

/// Prints the metered cost of the last call and checks that it stays well inside the budget.
fn report(env: &Env, name: &str) {
    let budget = env.cost_estimate().budget();
    let resources = env.cost_estimate().resources();
    std::println!(
        "{name:<16} cpu {:>11} mem {:>9} writes {:>2} write bytes {:>6} events {:>5}",
        budget.cpu_instruction_cost(),
        budget.memory_bytes_cost(),
        resources.write_entries,
        resources.write_bytes,
        resources.contract_events_size_bytes,
    );
    assert!(budget.cpu_instruction_cost() < BUDGET / 2);
}

#[test]
fn costs_of_the_real_proof_calls() {
    let flow = Flow::new();
    let s = &flow.s;
    for step in fixtures::proofs()["steps"].as_array().unwrap() {
        flow.run(step).unwrap();
        report(&s.env, step["name"].as_str().unwrap());
    }
    assert_eq!(s.vault.status().tvl, 9 * XLM);
}

#[test]
fn costs_of_a_queued_exit_its_release_and_a_claim() {
    // A window too small for the transfer's fee and the muxed unshield on the same day.
    let window = 710_000_000;
    let flow = Flow::with_limits(Limits {
        max_daily_outflow: window,
        tvl_cap: 7 * window,
        ..limits()
    });
    flow.run_until("unshield_muxed");
    flow.run(&fixtures::step("unshield_muxed")).unwrap();
    report(&flow.s.env, "queued unshield");
    assert_eq!(flow.s.vault.status().exit_tail, 2);
    to_midnight(&flow.s);
    assert_eq!(flow.s.vault.release(&1), 1);
    report(&flow.s.env, "release");

    // Both parts of this exit strand, so the claim makes both transfers.
    let c = Classic::new(limits());
    c.fund(3, 2_500 * XLM);
    let s = &c.s;
    let filler = c.holder("filler", 0);
    let relayer = c.holder("relayer", 0);
    let flaky = c.holder("flaky", 0);
    fill_window(s, &filler);
    let id = queue(s, 10 * XLM, XLM, &flaky, &relayer);
    c.asset.set_authorized(&flaky, &false);
    c.asset.set_authorized(&relayer, &false);
    to_midnight(s);
    assert_eq!(s.vault.release(&1), 1);
    report(&s.env, "stranded release");
    c.asset.set_authorized(&flaky, &true);
    c.asset.set_authorized(&relayer, &true);
    s.vault.claim(&id);
    report(&s.env, "claim");
    assert_eq!((s.balance(&flaky), s.balance(&relayer)), (10 * XLM, XLM));
}
