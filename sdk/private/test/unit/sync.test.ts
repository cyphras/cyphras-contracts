import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { P } from "../../src/field.ts";
import { CommitmentTree, EMPTY_ROOT } from "../../src/merkle.ts";
import type { ChainView, RootHistory } from "../../src/vault/state.ts";
import {
  type Evidence,
  type OwnedNote,
  type Plan,
  type WalletState,
  emptyState,
} from "../../src/wallet/state.ts";
import { advancePlans, checkRoot, recordEvents } from "../../src/wallet/sync.ts";
import { testScalar } from "../helpers.ts";

const leaf = (i: number): bigint => testScalar("sync/leaf", i, P);

function treeOf(count: number): CommitmentTree {
  const tree = CommitmentTree.empty();
  tree.append(Array.from({ length: count }, (_, i) => leaf(i)));
  return tree;
}

// The root history of a vault whose tree holds `count` leaves of the same sequence, one root per
// inserted pair, newest last.
function historyOf(count: number): RootHistory {
  const roots: bigint[] = Array.from({ length: 256 }, () => 0n);
  roots[0] = EMPTY_ROOT;
  let newest = 0;
  const tree = CommitmentTree.empty();
  for (let i = 0; i < count; i += 2) {
    tree.append([leaf(i), leaf(i + 1)]);
    newest = (newest + 1) % 256;
    roots[newest] = tree.root();
  }
  return { roots, newest, nextLeaf: count, ledger: 100 };
}

describe("root check", () => {
  it("confirms a tree whose root is the vault's current one or in its history", () => {
    assert.equal(checkRoot(treeOf(4), historyOf(4)).state, "verified");
    assert.equal(checkRoot(treeOf(2), historyOf(8)).state, "verified");
  });

  it("finds a mismatch when the vault is ahead and its history lacks the root", () => {
    const forged = CommitmentTree.empty();
    forged.append([leaf(0), leaf(1) ^ 1n]);
    assert.equal(checkRoot(forged, historyOf(8)).state, "mismatch");
    assert.equal(checkRoot(forged, historyOf(2)).state, "mismatch");
  });

  it("cannot judge a tree the vault's view is behind, or one past its history", () => {
    assert.equal(checkRoot(treeOf(6), historyOf(4)).state, "behind");
    assert.equal(checkRoot(treeOf(2), historyOf(2 + 2 * 256)).state, "behind");
  });
});

describe("plan fate", () => {
  // A wallet whose tree holds `count` leaves, the vault's own as of ledger 200, with one submitted
  // plan built then, whose proof the vault accepts up to ledger 320. The plan spends the note at
  // position 0, whose nullifier is 101, and a dummy input whose nullifier is 102.
  function walletWith(
    count: number,
    root = treeOf(count).root(),
  ): { state: WalletState; plan: Plan; note: OwnedNote } {
    const state = emptyState(1);
    state.tree = treeOf(count).snapshot();
    const note: OwnedNote = {
      pos: 0,
      cm: leaf(0),
      value: 11n,
      d: new Uint8Array(11),
      rcm: 1n,
      nf: 101n,
      ledger: 100,
      txHash: "00".repeat(32),
      pagePath: undefined,
      spent: undefined,
      built: false,
    };
    state.notes.push(note);
    const plan: Plan = {
      id: "plan",
      kind: "send",
      state: "submitted",
      createdAt: 0,
      route: { kind: "relayer", url: "http://relayer.test" },
      amount: 10n,
      fee: 1n,
      to: "recipient",
      createsAccount: false,
      inputs: [{ pos: 0, nf: 101n, value: 11n }],
      nullifiers: [101n, 102n],
      commitments: [201n, 202n],
      outputs: [],
      root,
      builtAt: 200,
      deadline: 320,
      ext: {} as Plan["ext"],
      proof: {} as Plan["proof"],
      notBefore: undefined,
      operationId: undefined,
      retryOf: undefined,
      txHash: undefined,
      heldId: undefined,
      ledger: undefined,
      evidence: [],
      relayerStatus: undefined,
      exit: undefined,
      error: undefined,
    };
    state.plans.push(plan);
    return { state, plan, note };
  }

  const viewAt = (ledger: number, count: number): ChainView => ({
    ledger,
    instance: {} as ChainView["instance"],
    roots: { ...historyOf(count), ledger },
  });

  const evidence = (fields: Partial<Evidence>): Evidence => ({
    txHash: "ab".repeat(32),
    ledger: 210,
    outputs: [undefined, undefined],
    nullifiers: [false, false],
    foreign: false,
    checked: false,
    ...fields,
  });

  it("keeps a plan alive on a lagging node's view from before the plan was built", () => {
    const { state, plan } = walletWith(40);
    // The node's tree is older than the wallet's: its history may well lack the plan's root.
    advancePlans(state, viewAt(150, 38));
    assert.equal(plan.state, "submitted");
    advancePlans(state, viewAt(150, 38 - 2 * 256));
    assert.equal(plan.state, "submitted");
  });

  it("declares a plan dead only with the vault's whole tree, at or past its deadline", () => {
    const { state, plan } = walletWith(40);
    advancePlans(state, viewAt(319, 40));
    assert.equal(plan.state, "submitted");
    // Leaves the wallet does not hold yet may be the plan's.
    advancePlans(state, viewAt(320, 42));
    assert.equal(plan.state, "submitted");
    advancePlans(state, viewAt(320, 40));
    assert.equal(plan.state, "dead");
  });

  it("declares a plan dead once the checked spends up to its deadline show its notes unspent", () => {
    const { state, plan, note } = walletWith(40);
    // The vault holds leaves the wallet does not, so it lacks the whole tree.
    const view = viewAt(400, 42);
    state.nullifierSince = 320;
    advancePlans(state, view);
    assert.equal(plan.state, "submitted");
    state.nullifierSince = 321;
    state.unchecked = [{ from: 300, to: 310, leaves: undefined, lost: false }];
    advancePlans(state, view);
    assert.equal(plan.state, "submitted");
    state.unchecked = [];
    // A spend of its note by the deadline, or a leaf of its, may be its own landing.
    note.spent = { txHash: "cd".repeat(32), ledger: 320 };
    advancePlans(state, view);
    assert.equal(plan.state, "submitted");
    note.spent = undefined;
    plan.evidence = [evidence({ outputs: [41, undefined] })];
    advancePlans(state, view);
    assert.equal(plan.state, "submitted");
    plan.evidence = [];
    note.spent = { txHash: "cd".repeat(32), ledger: 321 };
    advancePlans(state, view);
    assert.equal(plan.state, "dead");
  });

  it("declares a plan dead once its root has left the history of the vault's whole tree", () => {
    const kept = walletWith(40, treeOf(38).root());
    advancePlans(kept.state, viewAt(250, 40));
    assert.equal(kept.plan.state, "submitted");
    const evicted = walletWith(40, 7n);
    advancePlans(evicted.state, viewAt(250, 40));
    assert.equal(evicted.plan.state, "dead");
  });

  it("confirms a plan once both its commitments are in leaves, whatever transaction they name", () => {
    const { state, plan } = walletWith(40);
    plan.evidence = [evidence({ txHash: "aa".repeat(32), outputs: [40, undefined] })];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    plan.evidence = [
      evidence({ txHash: "aa".repeat(32), outputs: [40, undefined] }),
      evidence({ txHash: "bb".repeat(32), outputs: [undefined, 41] }),
    ];
    advancePlans(state, viewAt(400, 40));
    assert.equal(plan.state, "confirmed");
    assert.equal(plan.txHash, "aa".repeat(32));
  });

  it("takes where a plan landed from leaves only, never from the vault's events", () => {
    const { state, plan } = walletWith(40);
    const tx = "cc".repeat(32);
    const at = (index: number, commitment: bigint) => ({
      index,
      commitment,
      ciphertext: new Uint8Array(181),
      ledger: 211,
      txHash: tx,
    });
    recordEvents(state.plans, {
      leaves: [at(40, 201n), at(41, 202n)],
      nullifiers: [{ nullifier: 101n, ledger: 211, txHash: tx }],
    });
    assert.deepEqual(plan.evidence[0]?.outputs, [undefined, undefined]);
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
  });

  it("supersedes a plan only on the vault's checked events of another transaction spending its notes", () => {
    const { state, plan, note } = walletWith(40);
    const tx = "ab".repeat(32);
    const spend = (nullifier: bigint) => ({ nullifier, ledger: 210, txHash: tx });
    const foreign = { index: 40, commitment: 7n, ciphertext: new Uint8Array(181), ledger: 210 };
    // A spend of the dummy input says nothing of the plan's notes.
    recordEvents(state.plans, { leaves: [{ ...foreign, txHash: tx }], nullifiers: [spend(102n)] });
    assert.equal(plan.evidence.length, 0);
    // The indexer's word alone, or a spend whose leaves are unknown, proves nothing.
    plan.evidence = [evidence({ nullifiers: [true, false], foreign: true })];
    note.spent = { txHash: tx, ledger: 210 };
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    plan.evidence = [evidence({ nullifiers: [true, false], checked: true })];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    // Nor does a spend the note's own record does not show.
    plan.evidence = [evidence({ nullifiers: [true, false], foreign: true, checked: true })];
    note.spent = undefined;
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    note.spent = { txHash: tx, ledger: 210 };
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "superseded");
  });

  it("takes a landed plan's transaction again from the leaves a rescan finds", () => {
    const { state, plan } = walletWith(40);
    Object.assign(plan, { state: "settled", txHash: "aa".repeat(32), ledger: 205 });
    plan.exit = { id: 3, parts: [], ledger: 205, event: undefined };
    plan.evidence = [evidence({ txHash: "bb".repeat(32), ledger: 206, outputs: [38, 39] })];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "confirmed");
    assert.equal(plan.txHash, "bb".repeat(32));
    assert.equal(plan.ledger, 206);
    assert.equal(plan.exit, undefined);
  });

  it("starts a landed plan over once the checked spends of its ledger refute its landing", () => {
    const { state, plan, note } = walletWith(40);
    Object.assign(plan, { state: "settled", txHash: "aa".repeat(32), ledger: 205 });
    // Until the spends of its ledger are checked, nothing refutes it.
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "settled");
    state.nullifierSince = 230;
    state.unchecked = [{ from: 200, to: 229, leaves: undefined, lost: false }];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "settled");
    state.unchecked = [];
    note.spent = { txHash: "aa".repeat(32), ledger: 205 };
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "settled");
    note.spent = undefined;
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    assert.equal(plan.ledger, undefined);
  });

  it("supersedes a plan whose notes a landed plan of the same wallet spent", () => {
    const { state, plan } = walletWith(40);
    const retry: Plan = { ...plan, id: "retry", nullifiers: [101n, 103n], state: "settled" };
    state.plans.push(retry);
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "superseded");
  });
});
