//! Metered cost of the real-proof calls, printed with `cargo test costs -- --nocapture`. The
//! contract runs natively here, so the guest's own instructions are not counted; the host
//! functions it calls, which dominate, are.

use super::{e2e::Flow, fixtures, setup::XLM};

// The default test budget, stricter than the network's per-transaction limit.
const BUDGET: u64 = 100_000_000;

#[test]
fn costs_of_the_real_proof_calls() {
    let flow = Flow::new();
    let s = &flow.s;
    for step in fixtures::proofs()["steps"].as_array().unwrap() {
        flow.run(step).unwrap();
        let budget = s.env.cost_estimate().budget();
        let resources = s.env.cost_estimate().resources();
        std::println!(
            "{:<15} cpu {:>11} mem {:>9} write bytes {:>6} events {:>5}",
            step["name"].as_str().unwrap(),
            budget.cpu_instruction_cost(),
            budget.memory_bytes_cost(),
            resources.write_bytes,
            resources.contract_events_size_bytes,
        );
        assert!(budget.cpu_instruction_cost() < BUDGET / 2);
    }
    assert_eq!(s.vault.status().tvl, 9 * XLM);
}
