import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { StrKey } from "@stellar/stellar-base";
import { type Deployment, PINNED_DEPLOYMENTS } from "../../src/deployments.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import {
  type Deposit,
  type Plan,
  type WalletState,
  emptyState,
  loadState,
  saveState,
  unscopedFit,
} from "../../src/wallet/state.ts";
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
    older.deposits = [{ state: "admitted" }, { state: "cancelled" }];
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
    // Exits and deposits kept without what they rest on count as the indexer's word; a deposit
    // then cancelled was its depositor's cancel.
    assert.equal(loaded?.plans[0]?.exit?.confirmed, false);
    assert.deepEqual(loaded?.plans[0]?.exit?.known, []);
    assert.deepEqual(
      loaded?.deposits.map((d) => [d.confirmed, d.ownReturn]),
      [
        [false, undefined],
        [false, "cancelled"],
      ],
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

describe("a state in the unscoped records", () => {
  const pinned = PINNED_DEPLOYMENTS["testnet/xlm"] as Deployment;
  const other = StrKey.encodeContract(Buffer.alloc(32, 9));
  const at = (deployLedger: number, vault = pinned.vault): Deployment => ({
    ...pinned,
    vault,
    deployLedger,
  });
  const deposit = { builtAt: 0 } as unknown as Deposit;
  const plan = { id: "p", builtAt: 0, ext: { vault: "" } } as unknown as Plan;
  // A state synced from `ledger`, with a deposit built then and plans for `vaults` built then.
  function state(ledger: number, vaults: readonly string[] = []): WalletState {
    const s = emptyState(ledger);
    s.deposits = [{ ...deposit, builtAt: ledger }];
    s.plans = vaults.map((vault, i) => ({
      ...plan,
      id: `p${i}`,
      builtAt: ledger,
      ext: { ...plan.ext, vault },
    }));
    return s;
  }

  it("is nothing to keep when it records no note, payment, operation or deposit", () => {
    assert.equal(unscopedFit(emptyState(100), at(50), [at(50)]), "empty");
  });

  it("goes to the vault its plans name alone, and to no other", () => {
    const named = state(100, [pinned.vault]);
    assert.equal(unscopedFit(named, at(50), []), "ours");
    assert.equal(unscopedFit(named, at(50, other), []), "theirs");
    // The vault it names, deployed after the state's ledgers, cannot be it.
    assert.equal(unscopedFit(named, at(150), []), "unassigned");
    assert.equal(unscopedFit(state(100, [pinned.vault, other]), at(50), [at(50)]), "unassigned");
  });

  it("goes, with no plan, only to the one pinned vault its ledgers fit", () => {
    const bare = state(100);
    assert.equal(unscopedFit(bare, at(50), [at(50)]), "ours");
    assert.equal(unscopedFit(bare, at(50), [at(50), at(60, other)]), "unassigned");
    assert.equal(unscopedFit(bare, at(50), [at(50), at(150, other)]), "ours");
    assert.equal(unscopedFit(bare, at(50, other), [at(50)]), "unassigned");
    assert.equal(unscopedFit(bare, at(150), [at(150)]), "theirs");
  });

  it("is not this vault's when any ledger it records is from before this one", () => {
    const early: [string, (s: WalletState) => void][] = [
      ["synced from", (s) => (s.nullifierSince = 10)],
      ["a leaf", (s) => (s.lastLeafLedger = 10)],
      ["a deposit", (s) => (s.deposits[0] = { ...deposit, builtAt: 10 })],
    ];
    for (const [what, edit] of early) {
      const s = state(100);
      edit(s);
      assert.equal(unscopedFit(s, at(50), [at(50)]), "theirs", what);
    }
    // A plan that names this vault yet was built before it was deployed leaves it in doubt.
    const s = state(100, [pinned.vault]);
    s.plans = [{ ...(s.plans[0] as Plan), builtAt: 10 }];
    assert.equal(unscopedFit(s, at(50), [at(50)]), "unassigned");
  });
});
