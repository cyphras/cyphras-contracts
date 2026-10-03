import { encodeAddress } from "../address.ts";
import { bytesToHex } from "../bytes.ts";
import { AddressCache, decryptIncoming, recoverOutgoing } from "../encryption.ts";
import { CyphrasError, fail } from "../errors.ts";
import type { IncomingKeys, Network } from "../keys.ts";
import { CommitmentTree, PAGE_SIZE, pagePath } from "../merkle.ts";
import type { Leaf, SpentNullifier } from "../net/indexer.ts";
import type { SorobanRpc } from "../net/rpc.ts";
import { nullifier } from "../notes.ts";
import type { ChainView, RootHistory, VaultReader } from "../vault/state.ts";
import { type ChainSource, type DepositEvent, type ExitEvents, RpcEventSource } from "./sources.ts";
import {
  ACTIVE_STATES,
  type Evidence,
  type OwnedNote,
  type Plan,
  type PlanState,
  type RootCheck,
  type Staging,
  type WalletState,
} from "./state.ts";

// What a wallet can see with its keys: incoming notes always; outgoing notes with ovk; spends
// with nkFold.
export interface ScanKeys {
  readonly network: Network;
  readonly incoming: IncomingKeys;
  readonly ovk: Uint8Array | undefined;
  readonly nkFold: bigint | undefined;
}

// What one sync downloaded, before anything of it is checked or applied.
export interface Download {
  // The first ledger of nullifiers asked for, the ledger the source claims to be complete to, and
  // the ledger up to which they are used: no later than the vault was read at.
  readonly since: number;
  readonly completeTo: number;
  readonly horizon: number;
  readonly nullifiers: readonly SpentNullifier[];
  // The leaves after the local tree's last one, up to the vault's NextLeaf at most.
  readonly firstIndex: number;
  readonly leaves: readonly Leaf[];
  // The local tree extended by those leaves, and the pages they completed.
  readonly tree: CommitmentTree;
  readonly pages: readonly { readonly page: number; readonly leaves: readonly bigint[] }[];
}

// Downloads the nullifiers spent since the last sync, then reads the vault, then the leaves after
// the local tree's last one, staged or confirmed, up to the vault's NextLeaf. A leaf past NextLeaf
// cannot be checked against the vault yet, so the next sync takes it. Nullifiers count only up to
// the ledger the vault was read at, so every transaction whose nullifiers are kept has its leaves
// below NextLeaf; and when the page cap stops the leaves short, only up to the ledger before the
// last leaf taken.
export async function downloadChain(
  state: WalletState,
  source: ChainSource,
  vault: VaultReader,
  maxPages: number,
): Promise<{ readonly view: ChainView; readonly data: Download }> {
  const since = state.nullifierSince;
  const served = await source.nullifiers(since);
  const view = await vault.view();
  const tree = CommitmentTree.fromSnapshot(state.staging?.tree ?? state.tree);
  const firstIndex = tree.leafCount;
  const nextLeaf = view.roots.nextLeaf;
  const leaves: Leaf[] = [];
  const pages: { page: number; leaves: readonly bigint[] }[] = [];
  let capped = false;
  for (let fetched = 0; tree.leafCount < nextLeaf; fetched++) {
    if (fetched === maxPages) {
      capped = true;
      break;
    }
    const batch = await source.nextLeaves(tree);
    const accepted = batch.leaves.slice(0, nextLeaf - tree.leafCount);
    if ((tree.leafCount + accepted.length) % 2 !== 0) {
      fail("indexer_fault", "the leaves end in the middle of an inserted pair");
    }
    pages.push(...tree.append(accepted.map((l) => l.commitment)));
    leaves.push(...accepted);
    if (batch.done || accepted.length < batch.leaves.length) break;
  }
  let horizon = Math.min(served.completeToLedger, view.ledger);
  const last = leaves[leaves.length - 1];
  if (capped && last !== undefined) horizon = Math.min(horizon, last.ledger - 1);
  return {
    view,
    data: {
      since,
      completeTo: served.completeToLedger,
      horizon,
      nullifiers: served.nullifiers.filter((n) => n.ledger <= horizon),
      firstIndex,
      leaves,
      tree,
      pages,
    },
  };
}

export interface CrossCheck {
  // RPC covered the range and agreed with the indexer.
  readonly verified: boolean;
  // The exit and deposit events RPC returned for the range and after it, if it held them.
  readonly exits: ExitEvents | undefined;
  readonly deposits: readonly DepositEvent[];
}

const leafKey = (l: Leaf): string =>
  `${l.index}/${l.commitment}/${bytesToHex(l.ciphertext)}/${l.ledger}/${l.txHash}`;
const nfKey = (n: SpentNullifier): string => `${n.nullifier}/${n.ledger}/${n.txHash}`;

// Compares what the indexer served with the vault's events from RPC since the same ledger. Every
// served leaf is compared by its index, whatever ledger the indexer gave it; only a leaf added
// before that ledger, which RPC no longer shows, rests on the root check alone. Unverified when
// RPC cannot cover the range; a difference raises indexer_fault, since either the indexer or the
// RPC is wrong, and neither is trusted until it is resolved.
export async function crossCheck(
  rpc: SorobanRpc,
  vault: string,
  data: Download,
  maxPages: number,
): Promise<CrossCheck> {
  let events;
  try {
    events = await new RpcEventSource(rpc, vault, data.since, maxPages).events();
  } catch (err) {
    if (err instanceof CyphrasError) return { verified: false, exits: undefined, deposits: [] };
    throw err;
  }
  if (data.completeTo > Math.max(events.head, data.horizon)) {
    fail("indexer_fault", "the indexer claims to be complete past the chain's latest ledger");
  }
  // RPC stopped short of the horizon, at its page cap or behind the indexer: nothing is proven.
  const exits = { from: events.from, to: events.latest, events: events.exits };
  if (events.latest < data.horizon) {
    return { verified: false, exits, deposits: events.deposits };
  }
  const differ = (): never =>
    fail("indexer_fault", "the indexer's leaves or nullifiers differ from the vault's events");
  const onChain = new Map(events.leaves.map((l) => [l.index, l]));
  const first = events.leaves[0]?.index ?? Number.POSITIVE_INFINITY;
  for (const leaf of data.leaves) {
    if (leaf.index < first) continue;
    const chain = onChain.get(leaf.index);
    if (chain === undefined || leafKey(chain) !== leafKey(leaf)) differ();
  }
  // Every leaf added up to the horizon must have been served.
  const end = data.firstIndex + data.leaves.length;
  if (events.leaves.some((l) => l.index >= end && l.ledger <= data.horizon)) differ();
  const within = (n: SpentNullifier): boolean => n.ledger <= data.horizon;
  const served = new Set(data.nullifiers.map(nfKey));
  const chainNfs = new Set(events.nullifiers.filter(within).map(nfKey));
  if (served.size !== chainNfs.size || [...served].some((k) => !chainNfs.has(k))) differ();
  return { verified: true, exits, deposits: events.deposits };
}

// F-27: the local root must be one of the vault's last 256 roots, read from the ledger.
export function checkRoot(tree: CommitmentTree, history: RootHistory): RootCheck {
  const root = tree.root();
  const known = history.roots.filter((r) => r !== 0n);
  const base = { ledger: history.ledger, root, roots: known };
  if (history.nextLeaf < tree.leafCount) return { ...base, state: "behind" };
  if (history.nextLeaf === tree.leafCount) {
    const current = history.roots[history.newest];
    return { ...base, state: current === root ? "verified" : "mismatch" };
  }
  if (known.includes(root)) return { ...base, state: "verified" };
  // More than 255 pairs behind: the root has left the history, which says nothing about its
  // correctness. The wallet syncs further before it spends.
  const pairsBehind = (history.nextLeaf - tree.leafCount) / 2;
  return { ...base, state: pairsBehind >= history.roots.length ? "behind" : "mismatch" };
}

function scanLeaf(state: WalletState, leaf: Leaf, keys: ScanKeys, cache: AddressCache): boolean {
  const incoming = decryptIncoming(keys.incoming, leaf.commitment, leaf.ciphertext, cache);
  const outgoing =
    keys.ovk === undefined
      ? undefined
      : recoverOutgoing(keys.ovk, leaf.commitment, leaf.ciphertext);
  // Zero-value outputs are the padding of two-output transactions and carry nothing to spend.
  if (incoming !== undefined && incoming.value > 0n) {
    if (state.notes.some((n) => n.pos === leaf.index)) return false;
    const note: OwnedNote = {
      pos: leaf.index,
      cm: leaf.commitment,
      value: incoming.value,
      d: incoming.d,
      rcm: incoming.rcm,
      nf:
        keys.nkFold === undefined ? undefined : nullifier(leaf.commitment, leaf.index, keys.nkFold),
      ledger: leaf.ledger,
      txHash: leaf.txHash,
      pagePath: undefined,
      spent: undefined,
      built: outgoing !== undefined,
    };
    state.notes.push(note);
    return true;
  }
  if (incoming === undefined && outgoing !== undefined && outgoing.value > 0n) {
    if (!state.sent.some((s) => s.pos === leaf.index)) {
      state.sent.push({
        pos: leaf.index,
        cm: leaf.commitment,
        value: outgoing.value,
        rcm: outgoing.rcm,
        esk: outgoing.esk,
        address: encodeAddress(keys.network, outgoing.d, outgoing.pkd),
        ledger: leaf.ledger,
        txHash: leaf.txHash,
      });
    }
  }
  return false;
}

function evidenceOf(plan: Plan, txHash: string, ledger: number): Evidence {
  let e = plan.evidence.find((x) => x.txHash === txHash);
  if (e === undefined) {
    e = { txHash, ledger, nullifiers: [false, false], outputs: [undefined, undefined] };
    plan.evidence.push(e);
  }
  return e;
}

// Records, per transaction, which of a plan's commitments the new leaves add and which of its
// nullifiers the new nullifiers spend.
function recordEvidence(
  plans: readonly Plan[],
  leaves: readonly Leaf[],
  nullifiers: readonly { readonly nf: bigint; readonly ledger: number; readonly txHash: string }[],
): void {
  for (const plan of plans) {
    for (const leaf of leaves) {
      const slot = plan.commitments.indexOf(leaf.commitment);
      if (slot >= 0) evidenceOf(plan, leaf.txHash, leaf.ledger).outputs[slot] = leaf.index;
    }
    for (const n of nullifiers) {
      const slot = plan.nullifiers.indexOf(n.nf);
      if (slot >= 0) evidenceOf(plan, n.txHash, n.ledger).nullifiers[slot] = true;
    }
  }
}

// The notes and outgoing outputs this wallet finds in new leaves, with the paths of notes in the
// pages those leaves completed.
function scanDownload(
  state: WalletState,
  keys: ScanKeys,
  data: Download,
): { readonly staging: Staging; readonly newNotes: number } {
  const staged = state.staging;
  const found: WalletState = {
    ...state,
    notes: [...(staged?.notes ?? [])],
    sent: [...(staged?.sent ?? [])],
  };
  const cache = new AddressCache(keys.incoming);
  let newNotes = 0;
  for (const leaf of data.leaves) {
    if (state.notes.some((n) => n.pos === leaf.index)) continue;
    if (scanLeaf(found, leaf, keys, cache)) newNotes++;
  }
  const paths = [...(staged?.paths ?? [])];
  for (const page of data.pages) {
    const start = page.page * PAGE_SIZE;
    const inPage = (pos: number): boolean => pos >= start && pos < start + PAGE_SIZE;
    for (const note of found.notes) {
      if (note.pagePath === undefined && inPage(note.pos)) {
        note.pagePath = pagePath(page.leaves, note.pos - start);
      }
    }
    for (const note of state.notes) {
      if (note.pagePath === undefined && inPage(note.pos)) {
        paths.push({ pos: note.pos, pagePath: pagePath(page.leaves, note.pos - start) });
      }
    }
  }
  return {
    staging: {
      tree: data.tree.snapshot(),
      lastLeafLedger:
        data.leaves[data.leaves.length - 1]?.ledger ??
        staged?.lastLeafLedger ??
        state.lastLeafLedger,
      notes: found.notes,
      sent: found.sent,
      paths,
    },
    newNotes,
  };
}

// Holds a download whose tree the vault's root history cannot confirm yet, because it stopped at
// its page cap far behind the vault. None of it counts; the next sync continues from it.
export function stageDownload(state: WalletState, keys: ScanKeys, data: Download): void {
  if (data.leaves.length > 0) state.staging = scanDownload(state, keys, data).staging;
}

// Applies a download whose tree the vault's root history has confirmed, with anything staged
// before it: the notes found count from now, spent notes are marked, and the evidence of plans is
// recorded, only from data the cross-check confirmed, since it decides whether a payment failed.
// Returns how many notes this sync found.
export function applyDownload(
  state: WalletState,
  keys: ScanKeys,
  data: Download,
  checked: boolean,
): number {
  const { staging, newNotes } = scanDownload(state, keys, data);
  for (const { pos, pagePath: path } of staging.paths) {
    const note = state.notes.find((n) => n.pos === pos);
    if (note !== undefined) note.pagePath = path;
  }
  state.notes.push(...staging.notes);
  state.sent.push(...staging.sent);
  state.tree = staging.tree;
  state.lastLeafLedger = staging.lastLeafLedger;
  state.staging = undefined;

  const buffer = [
    ...state.nullifierBuffer,
    ...data.nullifiers.map((n) => ({ nf: n.nullifier, ledger: n.ledger, txHash: n.txHash })),
  ];
  const spent = new Map(buffer.map((n) => [n.nf, n]));
  for (const note of state.notes) {
    if (note.nf === undefined || note.spent !== undefined) continue;
    const hit = spent.get(note.nf);
    if (hit !== undefined) note.spent = { txHash: hit.txHash, ledger: hit.ledger };
  }
  if (checked) recordEvidence(state.plans, data.leaves, buffer);
  else state.checkedFrom = data.horizon + 1;
  state.nullifierSince = data.horizon + 1;
  // A leaf not yet scanned lies at or after the last scanned one, and so does any spend of it.
  state.nullifierBuffer = buffer.filter((n) => n.ledger >= state.lastLeafLedger);
  return newNotes;
}

export function isActive(plan: Plan): boolean {
  return ACTIVE_STATES.includes(plan.state);
}

// Moves each plan that has not landed along the submission state machine, with data the root
// check and the cross-check both confirmed. `horizon` is the ledger up to which the cross-checked
// nullifiers are complete; it is never past the ledger the vault was read at. A dead plan is
// reconsidered too: if its own transaction turns out to have landed, it is confirmed.
export function advancePlans(state: WalletState, horizon: number, view: ChainView): void {
  for (const plan of state.plans) {
    if (!isActive(plan) && plan.state !== "dead") continue;
    const landed = plan.evidence.find(
      (e) => e.nullifiers.every(Boolean) && e.outputs.every((pos) => pos !== undefined),
    );
    if (landed !== undefined) {
      plan.state = "confirmed";
      plan.txHash = landed.txHash;
      plan.ledger = landed.ledger;
      continue;
    }
    // A nullifier spent by a transaction that did not add this plan's outputs: another plan won.
    if (plan.evidence.some((e) => e.nullifiers.some(Boolean))) {
      plan.state = "superseded";
      continue;
    }
    // A plan is declared dead only when every spend since it was built is known and checked.
    if (plan.state === "dead" || state.checkedFrom > plan.builtAt) continue;
    // The vault refuses the proof after its deadline.
    if (horizon >= plan.deadline) {
      plan.state = "dead";
      continue;
    }
    // The root left the vault's history, as read at or after the ledger the plan was built at.
    const roots = view.roots;
    if (
      roots.ledger >= plan.builtAt &&
      horizon >= roots.ledger &&
      !roots.roots.includes(plan.root)
    ) {
      plan.state = "dead";
    }
  }
}

// A full rescan rebuilds the evidence of every plan the chain has not shown to land, so nothing
// recorded from an earlier sync decides its fate.
export function resetUnlanded(plans: readonly Plan[]): void {
  const unlanded: readonly PlanState[] = ["prepared", "submitted", "superseded", "dead"];
  for (const plan of plans) {
    if (!unlanded.includes(plan.state)) continue;
    plan.evidence = [];
    plan.state = plan.txHash === undefined ? "prepared" : "submitted";
  }
}
