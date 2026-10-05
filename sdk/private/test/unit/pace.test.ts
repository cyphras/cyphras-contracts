import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { closedBy, recordCloseTimes, updatePace } from "../../src/wallet/pace.ts";
import {
  type OwnedNote,
  type Plan,
  type SentNote,
  type Staging,
  emptyState,
} from "../../src/wallet/state.ts";

const at = (ledger: number, seconds: number) => ({ ledger, at: 1_700_000_000 + seconds });
// A close time as kept: read when the wallet's clock showed `seen` seconds past the same moment.
const kept = (ledger: number, seconds: number, seen = seconds) => ({
  ...at(ledger, seconds),
  seen: 1_700_000_000 + seen,
});
const SEEN = 1_700_000_000;

describe("ledger pace", () => {
  it("takes five seconds a ledger until close times span 60 ledgers", () => {
    const state = emptyState(1);
    assert.equal(updatePace(state, [], SEEN), 5);
    assert.equal(updatePace(state, [at(100, 0), at(159, 59 * 2)], SEEN), 5);
    assert.equal(updatePace(state, [at(100, 0), at(160, 60 * 4)], SEEN), 4);
  });

  it("takes the fastest pace over the spans the close times give, but never slower than five seconds", () => {
    const state = emptyState(1);
    // A week at six seconds, then the last hour at four.
    const times = [at(1_000, 0), at(101_800, 604_800), at(102_700, 604_800 + 3_600)];
    assert.equal(updatePace(state, times, SEEN), 4);
    assert.equal(updatePace(emptyState(1), [at(1_000, 0), at(2_000, 6_000)], SEEN), 5);
    // Close times that claim faster ledgers than half the fallback, or that run backwards, give a
    // pace no faster than that.
    assert.equal(updatePace(emptyState(1), [at(1_000, 0), at(2_000, 1_000)], SEEN), 2.5);
    assert.equal(updatePace(emptyState(1), [at(1_000, 600), at(2_000, 0)], SEEN), 2.5);
  });

  it("keeps the close times of the last hour, spaced by 60 ledgers, with when each sync read them", () => {
    const state = emptyState(1);
    updatePace(state, [at(1_000, 0), at(10_000, 40_000)], SEEN + 40_010);
    assert.deepEqual(state.ledgerTimes, [kept(10_000, 40_000, 40_010)]);
    updatePace(state, [at(10_030, 40_120)], SEEN + 40_130);
    assert.deepEqual(state.ledgerTimes, [kept(10_000, 40_000, 40_010)]);
    // A later sync, whose reply alone spans too few ledgers, takes the pace from the kept time.
    assert.equal(updatePace(state, [at(10_100, 40_000 + 100 * 4)], SEEN + 40_405), 4);
    assert.deepEqual(state.ledgerTimes, [
      kept(10_000, 40_000, 40_010),
      kept(10_100, 40_400, 40_405),
    ]);
    updatePace(state, [at(11_000, 40_400 + 3_601)], SEEN + 44_002);
    assert.deepEqual(state.ledgerTimes, [kept(11_000, 44_001, 44_002)]);
  });

  it("tells by when a ledger closes, at the slowest pace kept and never faster than five seconds", () => {
    const state = emptyState(1);
    assert.equal(closedBy(state, 100), undefined);
    // Four seconds a ledger, then six.
    state.ledgerTimes = [kept(1_000, 0), kept(1_060, 240), kept(1_120, 600)];
    assert.equal(closedBy(state, 1_220), at(1_120, 600 + 100 * 6).at);
    // A ledger before the newest kept had closed by then.
    assert.equal(closedBy(state, 1_100), at(1_120, 600).at);
    state.ledgerTimes = [kept(1_000, 0), kept(1_060, 240)];
    assert.equal(closedBy(state, 1_160), at(1_060, 240 + 100 * 5).at);
  });

  it("tells it from when the wallet read the newest close time, when that is later than RPC said", () => {
    const state = emptyState(1);
    // RPC said the newest ledger closed an hour before the wallet read it.
    state.ledgerTimes = [kept(1_000, 0), kept(1_060, 300, 3_900)];
    assert.equal(closedBy(state, 1_160), at(1_060, 3_900 + 100 * 5).at);
    assert.equal(closedBy(state, 1_000), at(1_060, 3_900).at);
    // A clock behind RPC's times leaves them as RPC said.
    state.ledgerTimes = [kept(1_000, 0), kept(1_060, 300, 200)];
    assert.equal(closedBy(state, 1_160), at(1_060, 300 + 100 * 5).at);
  });

  it("keeps the close times of the ledgers the history names or will name, the first told of each", () => {
    const state = emptyState(1);
    const note = (ledger: number, spent?: number) =>
      ({
        ledger,
        spent: spent === undefined ? undefined : { txHash: "t", ledger: spent },
      }) as OwnedNote;
    state.notes = [note(10, 12), note(11)];
    state.sent = [{ ledger: 14 } as SentNote];
    state.plans = [{ evidence: [{ ledger: 16 }] } as unknown as Plan];
    state.staging = {
      notes: [note(18, 19)],
      sent: [{ ledger: 20 } as SentNote],
      found: [{ ledger: 22 }],
    } as unknown as Staging;
    const reported = Array.from({ length: 15 }, (_, i) => at(10 + i, i * 5));
    recordCloseTimes(state, [...reported].reverse());
    const named = [10, 11, 12, 14, 16, 18, 19, 20, 22];
    assert.deepEqual(
      state.closeTimes,
      named.map((l) => at(l, (l - 10) * 5)),
    );
    // A time already kept stands, and so does the first of two reports of one ledger.
    state.notes.push(note(30));
    recordCloseTimes(state, [at(10, 999), at(30, 100), at(30, 200)]);
    assert.deepEqual(
      state.closeTimes,
      [...named, 30].map((l) => at(l, l === 30 ? 100 : (l - 10) * 5)),
    );
  });
});
