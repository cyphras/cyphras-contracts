import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { P } from "../../src/field.ts";
import { CommitmentTree, EMPTY_ROOT } from "../../src/merkle.ts";
import type { ChainView, RootHistory } from "../../src/vault/state.ts";
import { type Evidence, type Plan, type WalletState, emptyState } from "../../src/wallet/state.ts";
import { advancePlans, checkRoot } from "../../src/wallet/sync.ts";
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
  // plan built then, whose proof the vault accepts up to ledger 320.
  function walletWith(
    count: number,
    root = treeOf(count).root(),
  ): { state: WalletState; plan: Plan } {
    const state = emptyState(1);
    state.tree = treeOf(count).snapshot();
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
      inputs: [],
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
    return { state, plan };
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
    plan.evidence = [
      evidence({ txHash: "aa".repeat(32), outputs: [40, undefined] }),
      evidence({ txHash: "bb".repeat(32), outputs: [undefined, 41] }),
    ];
    advancePlans(state, viewAt(400, 40));
    assert.equal(plan.state, "confirmed");
    assert.equal(plan.txHash, "aa".repeat(32));
  });

  it("takes the landing transaction the vault's events name over the indexer's", () => {
    const { state, plan } = walletWith(40);
    plan.evidence = [
      evidence({ txHash: "aa".repeat(32), outputs: [40, 41] }),
      evidence({ txHash: "cc".repeat(32), ledger: 211, outputs: [40, 41], checked: true }),
    ];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.txHash, "cc".repeat(32));
    assert.equal(plan.ledger, 211);
  });

  it("supersedes a plan only on the vault's events of another transaction spending its notes", () => {
    const { state, plan } = walletWith(40);
    // The indexer's word alone, or a spend whose leaves are unknown, proves nothing.
    plan.evidence = [evidence({ nullifiers: [true, false], foreign: true })];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    plan.evidence = [evidence({ nullifiers: [true, false], checked: true })];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "submitted");
    plan.evidence = [evidence({ nullifiers: [true, false], foreign: true, checked: true })];
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "superseded");
  });

  it("supersedes a plan whose notes a landed plan of the same wallet spent", () => {
    const { state, plan } = walletWith(40);
    const retry: Plan = { ...plan, id: "retry", nullifiers: [101n, 103n], state: "settled" };
    state.plans.push(retry);
    advancePlans(state, viewAt(250, 40));
    assert.equal(plan.state, "superseded");
  });
});
