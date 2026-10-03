import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { P } from "../../src/field.ts";
import { CommitmentTree, EMPTY_ROOT } from "../../src/merkle.ts";
import type { RootHistory } from "../../src/vault/state.ts";
import { checkRoot } from "../../src/wallet/sync.ts";
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
