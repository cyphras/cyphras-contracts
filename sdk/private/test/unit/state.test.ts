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
