import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { emptyState, loadState, saveState } from "../../src/wallet/state.ts";
import { testBytes } from "../helpers.ts";

describe("stored state", () => {
  it("round-trips bigints of either sign and bytes exactly", async () => {
    const store = new SealedStore(new MemoryStore(), testBytes("state/key", 0, 32));
    const state = emptyState(10);
    const values = [0n, 1n, -1n, 2n ** 255n, -(2n ** 127n)];
    state.nullifierBuffer = values.map((nf, i) => ({ nf, ledger: i, txHash: "ab".repeat(32) }));
    await saveState(store, state);
    const loaded = await loadState(store);
    assert.deepEqual(
      loaded?.nullifierBuffer.map((n) => n.nf),
      values,
    );
  });

  it("loads a state from before close times, checked ledgers, digests and counts of providers", async () => {
    const store = new SealedStore(new MemoryStore(), testBytes("state/key", 2, 32));
    const state = emptyState(10);
    state.unchecked = [
      { from: 20, to: 30, leaves: { first: 0, end: 4, ledger: 15, chunks: [] }, lost: false },
    ];
    await saveState(store, state);
    const text = new TextDecoder().decode((await store.read("state")) as Uint8Array);
    const older = JSON.parse(text);
    delete older.ledgerTimes;
    delete older.checkedLeafLedger;
    delete older.unchecked[0].leaves.chunks;
    // Only what the load reads of a staging and of plans.
    older.staging = { unchecked: { first: 4, ledger: 31 } };
    older.plans = [{ evidence: [{ outputs: [3, null] }, { outputs: [null, null] }] }];
    await store.write("state", new TextEncoder().encode(JSON.stringify(older)));
    const loaded = await loadState(store);
    assert.deepEqual(loaded?.ledgerTimes, []);
    assert.equal(loaded?.checkedLeafLedger, 0);
    // Leaves kept without the digests a recheck compares can no longer be checked, and leaves
    // staged without them are taken again.
    assert.equal(loaded?.unchecked[0]?.lost, true);
    assert.equal(loaded?.staging, undefined);
    // A landing kept without the count of providers that confirmed it rests on the first alone.
    assert.deepEqual(
      loaded?.plans[0]?.evidence.map((e) => e.providers),
      [1, 0],
    );
  });

  it("refuses a number without its sign", async () => {
    const backend = new MemoryStore();
    const store = new SealedStore(backend, testBytes("state/key", 1, 32));
    const state = emptyState(10);
    state.nullifierBuffer = [{ nf: 5n, ledger: 1, txHash: "ab".repeat(32) }];
    await saveState(store, state);
    const text = new TextDecoder().decode((await store.read("state")) as Uint8Array);
    await store.write("state", new TextEncoder().encode(text.replace('"+5"', '"5"')));
    await assert.rejects(loadState(store), /malformed number/);
  });
});
