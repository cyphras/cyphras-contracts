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

  it("loads a state from before close times, checked ledgers, digests, counts of providers, range statuses and confirmed exits", async () => {
    const store = new SealedStore(new MemoryStore(), testBytes("state/key", 2, 32));
    const state = emptyState(10);
    state.unchecked = [
      {
        from: 20,
        to: 30,
        leaves: { first: 0, end: 4, ledger: 15, chunks: [] },
        status: "open",
        askedAt: undefined,
      },
      { from: 31, to: 40, leaves: undefined, status: "open", askedAt: undefined },
      { from: 41, to: 50, leaves: undefined, status: "open", askedAt: undefined },
    ];
    await saveState(store, state);
    const text = new TextDecoder().decode((await store.read("state")) as Uint8Array);
    const older = JSON.parse(text);
    delete older.ledgerTimes;
    delete older.checkedLeafLedger;
    older.unchecked.forEach((range: Record<string, unknown>, i: number) => {
      delete range["status"];
      range["lost"] = i === 1;
    });
    delete older.unchecked[0].leaves.chunks;
    // A partial range of leaves kept without their digests.
    older.unchecked.push({
      from: 51,
      to: 60,
      leaves: { first: 8, end: 10, ledger: 55, chunks: [] },
      status: "partial",
    });
    // Only what the load reads of a staging and of plans.
    older.staging = { unchecked: { first: 4, ledger: 31 } };
    older.plans = [
      { evidence: [{ outputs: [3, null] }, { outputs: [null, null] }], exit: { id: 1, parts: [] } },
    ];
    older.deposits = [{ state: "admitted" }];
    await store.write("state", new TextEncoder().encode(JSON.stringify(older)));
    const loaded = await loadState(store);
    assert.deepEqual(loaded?.ledgerTimes, []);
    assert.equal(loaded?.checkedLeafLedger, 0);
    // A range kept as lost on the first provider's word is open again; leaves kept without the
    // digests a recheck compares can no longer be checked, and leaves staged without them are
    // taken again.
    assert.deepEqual(
      loaded?.unchecked.map((r) => r.status),
      ["lost", "open", "open", "lost"],
    );
    assert.equal(
      loaded?.unchecked.some((r) => "lost" in r),
      false,
    );
    assert.equal(loaded?.staging, undefined);
    // A landing kept without the count of providers that confirmed it rests on the first alone.
    assert.deepEqual(
      loaded?.plans[0]?.evidence.map((e) => e.providers),
      [1, 0],
    );
    // Exits and deposits kept without what they rest on count as the indexer's word.
    assert.equal(loaded?.plans[0]?.exit?.confirmed, false);
    assert.equal(loaded?.deposits[0]?.confirmed, false);
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
