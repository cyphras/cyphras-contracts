import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { sha256 } from "@noble/hashes/sha2";
import { StrKey, nativeToScVal, xdr } from "@stellar/stellar-base";
import { bytesToHex, utf8 } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import { P } from "../../src/field.ts";
import type { IncomingKeys } from "../../src/keys.ts";
import { CommitmentTree, EMPTY_ROOT } from "../../src/merkle.ts";
import type { Leaf } from "../../src/net/indexer.ts";
import { SorobanRpc } from "../../src/net/rpc.ts";
import type { ChainView, RootHistory } from "../../src/vault/state.ts";
import {
  type Evidence,
  type LeafChunk,
  type OwnedNote,
  type Plan,
  type UncheckedRange,
  type WalletState,
  emptyState,
} from "../../src/wallet/state.ts";
import {
  type ScanKeys,
  advancePlans,
  applyDownload,
  checkRoot,
  checkedBetween,
  recheck,
  recordEvents,
} from "../../src/wallet/sync.ts";
import { testScalar } from "../helpers.ts";
import { map } from "../support/vault.ts";

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
    providers: 1,
    nullifiers: [false, false],
    foreign: false,
    checked: false,
    ...fields,
  });

  it("keeps a plan alive on a lagging node's view from before the plan was built", () => {
    const { state, plan } = walletWith(40);
    // The node's tree is older than the wallet's: its history may well lack the plan's root.
    advancePlans(state, [viewAt(150, 38)]);
    assert.equal(plan.state, "submitted");
    advancePlans(state, [viewAt(150, 38 - 2 * 256)]);
    assert.equal(plan.state, "submitted");
  });

  it("declares a plan dead only with the vault's whole tree, at or past its deadline", () => {
    const { state, plan } = walletWith(40);
    advancePlans(state, [viewAt(319, 40)]);
    assert.equal(plan.state, "submitted");
    // Leaves the wallet does not hold yet may be the plan's.
    advancePlans(state, [viewAt(320, 42)]);
    assert.equal(plan.state, "submitted");
    advancePlans(state, [viewAt(320, 40)]);
    assert.equal(plan.state, "dead");
  });

  it("declares a plan dead once the checked spends up to its deadline show its notes unspent", () => {
    const { state, plan, note } = walletWith(40);
    // The vault holds leaves the wallet does not, so it lacks the whole tree.
    const view = viewAt(400, 42);
    state.nullifierSince = 320;
    advancePlans(state, [view]);
    assert.equal(plan.state, "submitted");
    state.nullifierSince = 321;
    state.unchecked = [{ from: 300, to: 310, leaves: undefined, status: "open" }];
    advancePlans(state, [view]);
    assert.equal(plan.state, "submitted");
    state.unchecked = [];
    // A spend of its note by the deadline, or a leaf of its, may be its own landing.
    note.spent = { txHash: "cd".repeat(32), ledger: 320 };
    advancePlans(state, [view]);
    assert.equal(plan.state, "submitted");
    note.spent = undefined;
    plan.evidence = [evidence({ outputs: [41, undefined] })];
    advancePlans(state, [view]);
    assert.equal(plan.state, "submitted");
    plan.evidence = [];
    note.spent = { txHash: "cd".repeat(32), ledger: 321 };
    advancePlans(state, [view]);
    assert.equal(plan.state, "dead");
  });

  it("declares a plan dead once the tree it holds has a leaf from past its deadline", () => {
    const { state, plan } = walletWith(40);
    // The vault holds leaves the wallet does not, and no spend was checked.
    const view = viewAt(400, 42);
    state.checkedLeafLedger = 320;
    advancePlans(state, [view]);
    assert.equal(plan.state, "submitted");
    state.checkedLeafLedger = 321;
    plan.evidence = [evidence({ outputs: [undefined, 39] })];
    advancePlans(state, [view]);
    assert.equal(plan.state, "submitted");
    // Nor while a provider's view is from before the deadline.
    plan.evidence = [];
    advancePlans(state, [view, viewAt(319, 42)]);
    assert.equal(plan.state, "submitted");
    advancePlans(state, [view]);
    assert.equal(plan.state, "dead");
  });

  it("declares a plan dead once its root has left the history of the vault's whole tree", () => {
    const kept = walletWith(40, treeOf(38).root());
    advancePlans(kept.state, [viewAt(250, 40)]);
    assert.equal(kept.plan.state, "submitted");
    const evicted = walletWith(40, 7n);
    advancePlans(evicted.state, [viewAt(250, 40)]);
    assert.equal(evicted.plan.state, "dead");
  });

  it("confirms a plan once both its commitments are in leaves, whatever transaction they name", () => {
    const { state, plan } = walletWith(40);
    plan.evidence = [evidence({ txHash: "aa".repeat(32), outputs: [40, undefined] })];
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "submitted");
    plan.evidence = [
      evidence({ txHash: "aa".repeat(32), outputs: [40, undefined] }),
      evidence({ txHash: "bb".repeat(32), outputs: [undefined, 41] }),
    ];
    advancePlans(state, [viewAt(400, 40)]);
    assert.equal(plan.state, "confirmed");
    assert.equal(plan.txHash, "aa".repeat(32));
  });

  it("takes the transaction that added both of a plan's commitments over one that copied one", () => {
    const { state, plan } = walletWith(44);
    // The recipient of the first output knows its opening, and so can add its commitment again.
    plan.evidence = [
      evidence({ txHash: "aa".repeat(32), ledger: 205, outputs: [40, undefined] }),
      evidence({ txHash: "bb".repeat(32), ledger: 206, outputs: [42, 43] }),
    ];
    advancePlans(state, [viewAt(250, 44)]);
    assert.equal(plan.state, "confirmed");
    assert.equal(plan.txHash, "bb".repeat(32));
    assert.equal(plan.ledger, 206);
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
    advancePlans(state, [viewAt(250, 40)]);
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
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "submitted");
    plan.evidence = [evidence({ nullifiers: [true, false], checked: true })];
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "submitted");
    // Nor does a spend the note's own record does not show.
    plan.evidence = [evidence({ nullifiers: [true, false], foreign: true, checked: true })];
    note.spent = undefined;
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "submitted");
    note.spent = { txHash: tx, ledger: 210 };
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "superseded");
  });

  it("takes a landed plan's transaction again from the leaves a rescan finds", () => {
    const { state, plan } = walletWith(40);
    Object.assign(plan, { state: "settled", txHash: "aa".repeat(32), ledger: 205 });
    plan.exit = { id: 3, parts: [], ledger: 205, event: undefined };
    plan.evidence = [evidence({ txHash: "bb".repeat(32), ledger: 206, outputs: [38, 39] })];
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "confirmed");
    assert.equal(plan.txHash, "bb".repeat(32));
    assert.equal(plan.ledger, 206);
    assert.equal(plan.exit, undefined);
  });

  it("starts a landed plan over once the checked spends of its ledger refute its landing", () => {
    const { state, plan, note } = walletWith(40);
    Object.assign(plan, { state: "settled", txHash: "aa".repeat(32), ledger: 205 });
    plan.exit = { id: 3, parts: [], ledger: 205, event: undefined };
    // Until the spends of its ledger are checked, nothing refutes it.
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "settled");
    state.nullifierSince = 230;
    state.unchecked = [{ from: 200, to: 229, leaves: undefined, status: "open" }];
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "settled");
    state.unchecked = [];
    note.spent = { txHash: "aa".repeat(32), ledger: 205 };
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "settled");
    note.spent = undefined;
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "submitted");
    assert.equal(plan.ledger, undefined);
    assert.equal(plan.exit, undefined);
  });

  it("supersedes a plan whose notes a landed plan of the same wallet spent", () => {
    const { state, plan } = walletWith(40);
    const retry: Plan = { ...plan, id: "retry", nullifiers: [101n, 103n], state: "settled" };
    state.plans.push(retry);
    advancePlans(state, [viewAt(250, 40)]);
    assert.equal(plan.state, "superseded");
  });
});

describe("unchecked ranges", () => {
  const VAULT = StrKey.encodeContract(Buffer.alloc(32, 9));
  const TX = "ab".repeat(32);

  // The leaf at a position as the vault added it, in ledger 60, or as a sync took it.
  const leafAt = (index: number, ledger = 60): Leaf => ({
    index,
    commitment: leaf(index),
    ciphertext: new Uint8Array(181).fill(index),
    ledger,
    txHash: TX,
  });

  // A run of leaves as an unchecked sync keeps it: a digest of what it took of each.
  const chunk = (leaves: readonly Leaf[]): LeafChunk => ({
    end: (leaves[leaves.length - 1] as Leaf).index + 1,
    digest: bytesToHex(
      sha256(
        utf8(
          leaves
            .map(
              (l) =>
                `${l.index}/${l.commitment}/${bytesToHex(l.ciphertext)}/${l.ledger}/${l.txHash}`,
            )
            .join("\n"),
        ),
      ),
    ),
  });

  // A deposit the vault took into its entry queue at a ledger, as getEvents shows it.
  const depositAt = (ledger: number, id: number) => ({
    type: "contract",
    ledger,
    ledgerClosedAt: "2026-10-04T00:00:00Z",
    contractId: VAULT,
    id: `${String(ledger).padStart(12, "0")}-${String(900).padStart(8, "0")}`,
    txHash: TX,
    inSuccessfulContractCall: true,
    topic: [xdr.ScVal.scvSymbol("deposit_pending").toXDR("base64")],
    value: map([
      ["id", xdr.ScVal.scvU64(new xdr.Uint64(BigInt(id)))],
      ["commitment0", nativeToScVal(1n, { type: "u256" })],
      ["commitment1", nativeToScVal(2n, { type: "u256" })],
    ]).toXDR("base64"),
  });

  // An RPC whose getEvents shows the vault adding these leaves, and any other events, up to the
  // ledger `latest`.
  function showing(
    leaves: readonly Leaf[],
    latest = 70,
    others: readonly object[] = [],
  ): SorobanRpc {
    const added = leaves.map((l, i) => ({
      type: "contract",
      ledger: l.ledger,
      ledgerClosedAt: "2026-10-04T00:00:00Z",
      contractId: VAULT,
      id: `${String(l.ledger).padStart(12, "0")}-${String(i).padStart(8, "0")}`,
      txHash: l.txHash,
      inSuccessfulContractCall: true,
      topic: [xdr.ScVal.scvSymbol("new_commitment").toXDR("base64")],
      value: map([
        ["index", xdr.ScVal.scvU64(new xdr.Uint64(BigInt(l.index)))],
        ["commitment", nativeToScVal(l.commitment, { type: "u256" })],
        ["encrypted_output", xdr.ScVal.scvBytes(Buffer.from(l.ciphertext))],
      ]).toXDR("base64"),
    }));
    const events = [...added, ...others];
    return new SorobanRpc("http://rpc", async (_input, init) => {
      const { id } = JSON.parse(String(init?.body));
      const result = { events, latestLedger: latest, oldestLedger: 1 };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id, result }));
    });
  }

  // An RPC that answers getEvents with a JSON-RPC error: -32600 as one that no longer holds the
  // ledgers asked for, -32603 as a busy one.
  function refusing(code: number): SorobanRpc {
    return new SorobanRpc("http://rpc", async (_input, init) => {
      const { id } = JSON.parse(String(init?.body));
      return new Response(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message: "no" } }));
    });
  }
  const isFault = (err: unknown): boolean =>
    err instanceof CyphrasError && err.code === "indexer_fault";

  // A wallet that took the leaves at positions 4 to 7 unchecked, in two runs, the first of them
  // added at ledger 60, in a sync whose spends, from ledger 100 on, were checked.
  function walletAfter(taken: readonly Leaf[]): WalletState {
    const state = emptyState(1);
    state.nullifierSince = 120;
    const chunks = [chunk(taken.slice(0, 2)), chunk(taken.slice(2))];
    state.unchecked = [
      { from: 100, to: 99, leaves: { first: 4, end: 8, ledger: 60, chunks }, status: "open" },
    ];
    return state;
  }
  const four = [4, 5, 6, 7].map((i) => leafAt(i));

  it("counts a range of leaves alone as no unchecked ledger", () => {
    const state = walletAfter(four);
    assert.equal(checkedBetween(state, 50, 110), true);
  });

  it("checks every leaf of a range by its runs, clears it and takes the ledgers as checked", async () => {
    const state = walletAfter(four);
    await recheck(state, [showing(four)], VAULT, 1);
    assert.deepEqual(state.unchecked, []);
    assert.equal(state.checkedLeafLedger, 60);
  });

  it("checks the runs RPC shows in full and keeps the rest of the range", async () => {
    const state = walletAfter(four);
    await recheck(state, [showing(four.slice(0, 3))], VAULT, 1);
    const [rest] = state.unchecked;
    assert.equal(rest?.leaves?.first, 6);
    assert.equal(rest?.leaves?.ledger, 60);
    assert.equal(rest?.leaves?.chunks.length, 1);
    // A range whose leaves were added before its spends' ledgers keeps those ledgers whole when RPC
    // reaches none of them yet.
    const spends = walletAfter(four);
    spends.unchecked = [{ ...(spends.unchecked[0] as UncheckedRange), to: 110 }];
    await recheck(spends, [showing(four.slice(0, 3), 80)], VAULT, 1);
    assert.deepEqual(
      spends.unchecked.map((r) => [r.from, r.to]),
      [[100, 110]],
    );
  });

  it("refuses a leaf whose ledger or transaction the sync took otherwise", async () => {
    const forged = [...four.slice(0, 3), { ...leafAt(7), ledger: 400 }];
    await assert.rejects(
      recheck(walletAfter(forged), [showing(four)], VAULT, 1),
      (err: unknown) => err instanceof CyphrasError && err.code === "indexer_fault",
    );
    const renamed = [...four.slice(0, 3), { ...leafAt(7), txHash: "cd".repeat(32) }];
    await assert.rejects(
      recheck(walletAfter(renamed), [showing(four)], VAULT, 1),
      (err: unknown) => err instanceof CyphrasError && err.code === "indexer_fault",
    );
  });

  it("takes a range's spends as checked only up to the ledger every RPC provider reaches", async () => {
    const state = emptyState(1);
    state.nullifierSince = 120;
    state.unchecked = [{ from: 60, to: 100, leaves: undefined, status: "open" }];
    await recheck(state, [showing([], 90), showing([], 80)], VAULT, 1);
    assert.deepEqual(
      state.unchecked.map((r) => [r.from, r.to]),
      [[81, 100]],
    );
  });

  it("checks a range against every RPC provider, as far as the one that reaches least", async () => {
    const state = walletAfter(four);
    await recheck(state, [showing(four), showing(four.slice(0, 3))], VAULT, 1);
    assert.equal(state.unchecked[0]?.leaves?.first, 6);
    await recheck(state, [showing(four), showing(four)], VAULT, 1);
    assert.deepEqual(state.unchecked, []);
    // A provider whose events differ from what the sync took is as much a fault as the first.
    const forged = [...four.slice(0, 3), { ...leafAt(7), ledger: 400 }];
    await assert.rejects(
      recheck(walletAfter(forged), [showing(forged), showing(four)], VAULT, 1),
      (err: unknown) => err instanceof CyphrasError && err.code === "indexer_fault",
    );
  });

  // Keys for downloads with nothing to scan, which never use them.
  const NO_KEYS: ScanKeys = {
    network: "testnet",
    incoming: {} as IncomingKeys,
    ovk: undefined,
    nkFold: undefined,
  };

  it("starts a new range for an unchecked sync that follows one kept as partial", () => {
    const state = emptyState(1);
    state.nullifierSince = 121;
    state.unchecked = [{ from: 100, to: 120, leaves: undefined, status: "partial" }];
    const tree = CommitmentTree.empty();
    const data = { since: 121, completeTo: 130, horizon: 130, nullifiers: [], firstIndex: 0 };
    applyDownload(state, NO_KEYS, { ...data, leaves: [], tree, pages: [] }, false, 1);
    assert.deepEqual(
      state.unchecked.map((r) => [r.from, r.to, r.status]),
      [
        [100, 120, "partial"],
        [121, 130, "open"],
      ],
    );
  });

  it("takes no checked ledger from staged unchecked leaves that a checked sync with no new leaves applies", () => {
    const state = emptyState(1);
    state.tree = treeOf(4).snapshot();
    state.nullifierSince = 120;
    // An earlier sync staged the leaves at positions 4 to 7 while RPC could not check them, the
    // last one labelled with a ledger far past the vault's.
    const staged = [4, 5, 6, 7].map((i) => leafAt(i, i === 7 ? 9_999 : 60));
    state.staging = {
      tree: treeOf(8).snapshot(),
      lastLeafLedger: 9_999,
      notes: [],
      sent: [],
      paths: [],
      found: [],
      unchecked: { first: 4, ledger: 60, chunks: [chunk(staged)] },
    };
    const tree = treeOf(8);
    const data = { since: 120, completeTo: 130, horizon: 130, nullifiers: [], firstIndex: 8 };
    applyDownload(state, NO_KEYS, { ...data, leaves: [], tree, pages: [] }, true, 1);
    assert.equal(state.tree.leafCount, 8);
    assert.equal(state.checkedLeafLedger, 0);
    assert.deepEqual(
      state.unchecked.map((r) => [r.leaves?.first, r.leaves?.end, r.status]),
      [[4, 8, "open"]],
    );
  });

  it("clears a range only when every RPC provider shows the vault's exits and deposits in it alike", async () => {
    const spends = (): WalletState => {
      const state = emptyState(1);
      state.nullifierSince = 120;
      state.unchecked = [{ from: 60, to: 100, leaves: undefined, status: "open" }];
      return state;
    };
    await assert.rejects(
      recheck(spends(), [showing([], 110), showing([], 110, [depositAt(80, 3)])], VAULT, 1),
      isFault,
    );
    const state = spends();
    const both = showing([], 110, [depositAt(80, 3)]);
    const events = await recheck(state, [both, both], VAULT, 1);
    assert.deepEqual(state.unchecked, []);
    assert.deepEqual(
      events?.deposits.map((d) => d.id),
      [3],
    );
    assert.equal(events?.from, 60);
    // The events of a range of leaves alone cover no ledger's exits or deposits.
    const leavesOnly = await recheck(walletAfter(four), [showing(four), showing(four)], VAULT, 1);
    assert.ok((leavesOnly?.from as number) > (leavesOnly?.latest as number));
  });

  it("checks a range against the RPC providers that still hold it when another no longer does", async () => {
    const hidden = [...four.slice(0, 3), { ...leafAt(7), ciphertext: new Uint8Array(181) }];
    await assert.rejects(
      recheck(walletAfter(hidden), [refusing(-32600), showing(four)], VAULT, 1),
      isFault,
    );
    await assert.rejects(
      recheck(walletAfter(hidden), [showing(four), refusing(-32600)], VAULT, 1),
      isFault,
    );
  });

  it("keeps what the providers that still hold a range show alike as partial, never cleared", async () => {
    const state = walletAfter(four);
    state.unchecked.push({ from: 130, to: 140, leaves: undefined, status: "open" });
    assert.equal(await recheck(state, [refusing(-32600), showing(four)], VAULT, 1), undefined);
    assert.deepEqual(
      state.unchecked.map((r) => r.status),
      ["partial", "open"],
    );
    assert.equal(state.checkedLeafLedger, 0);
    // The next recheck goes on with the next open range.
    await recheck(state, [showing([], 150), refusing(-32600)], VAULT, 1);
    assert.deepEqual(
      state.unchecked.map((r) => [r.from, r.to, r.status]),
      [
        [100, 70, "partial"],
        [130, 140, "partial"],
      ],
    );
    assert.equal(checkedBetween(state, 130, 140), false);
  });

  it("keeps a range as lost only once no RPC provider holds it, and moves nothing while one is busy", async () => {
    const state = walletAfter(four);
    await recheck(state, [refusing(-32600), refusing(-32603)], VAULT, 1);
    await recheck(state, [refusing(-32603), showing(four)], VAULT, 1);
    assert.deepEqual(
      state.unchecked.map((r) => [r.leaves?.first, r.status]),
      [[4, "open"]],
    );
    const hidden = [...four.slice(0, 3), { ...leafAt(7), ciphertext: new Uint8Array(181) }];
    await assert.rejects(
      recheck(walletAfter(hidden), [refusing(-32603), showing(four)], VAULT, 1),
      isFault,
    );
    await recheck(state, [refusing(-32600), refusing(-32600)], VAULT, 1);
    assert.equal(state.unchecked[0]?.status, "lost");
    const alone = walletAfter(four);
    await recheck(alone, [refusing(-32600)], VAULT, 1);
    assert.equal(alone.unchecked[0]?.status, "lost");
  });

  it("refuses leaves RPC shows with a gap after the range's first, in full runs or not", async () => {
    for (const shown of [four.slice(2), four.slice(1, 2)]) {
      await assert.rejects(
        recheck(walletAfter(four), [showing(shown)], VAULT, 1),
        (err: unknown) => err instanceof CyphrasError && err.code === "indexer_fault",
      );
    }
  });
});
