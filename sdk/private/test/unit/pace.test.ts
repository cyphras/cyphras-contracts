import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { updatePace } from "../../src/wallet/pace.ts";
import { emptyState } from "../../src/wallet/state.ts";

const at = (ledger: number, seconds: number) => ({ ledger, at: 1_700_000_000 + seconds });

describe("ledger pace", () => {
  it("takes five seconds a ledger until close times span 60 ledgers", () => {
    const state = emptyState(1);
    assert.equal(updatePace(state, []), 5);
    assert.equal(updatePace(state, [at(100, 0), at(159, 59 * 2)]), 5);
    assert.equal(updatePace(state, [at(100, 0), at(160, 60 * 4)]), 4);
  });

  it("takes the fastest pace over the spans the close times give, but never slower than five seconds", () => {
    const state = emptyState(1);
    // A week at six seconds, then the last hour at four.
    const times = [at(1_000, 0), at(101_800, 604_800), at(102_700, 604_800 + 3_600)];
    assert.equal(updatePace(state, times), 4);
    assert.equal(updatePace(emptyState(1), [at(1_000, 0), at(2_000, 6_000)]), 5);
    // A reply whose times run backwards gives a pace no faster than a second.
    assert.equal(updatePace(emptyState(1), [at(1_000, 600), at(2_000, 0)]), 1);
  });

  it("keeps the close times of the last hour, spaced by 60 ledgers, for the next sync", () => {
    const state = emptyState(1);
    updatePace(state, [at(1_000, 0), at(10_000, 40_000)]);
    assert.deepEqual(state.ledgerTimes, [at(10_000, 40_000)]);
    updatePace(state, [at(10_030, 40_120)]);
    assert.deepEqual(state.ledgerTimes, [at(10_000, 40_000)]);
    // A later sync, whose reply alone spans too few ledgers, takes the pace from the kept time.
    assert.equal(updatePace(state, [at(10_100, 40_000 + 100 * 4)]), 4);
    assert.deepEqual(state.ledgerTimes, [at(10_000, 40_000), at(10_100, 40_400)]);
    updatePace(state, [at(11_000, 40_400 + 3_601)]);
    assert.deepEqual(state.ledgerTimes, [at(11_000, 44_001)]);
  });
});
