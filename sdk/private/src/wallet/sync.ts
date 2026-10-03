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
import { type ChainSource, RpcEventSource, type VaultEvents } from "./sources.ts";
import {
  ACTIVE_STATES,
  type Evidence,
  type FoundLeaf,
  LANDED_STATES,
  type OwnedNote,
  type Plan,
  type RootCheck,
  type Staging,
  type UncheckedRange,
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
  // The vault's events RPC returned for the range and after it, if it held them.
  readonly events: VaultEvents | undefined;
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
    if (err instanceof CyphrasError) return { verified: false, events: undefined };
    throw err;
  }
  if (data.completeTo > Math.max(events.head, data.horizon)) {
    fail("indexer_fault", "the indexer claims to be complete past the chain's latest ledger");
  }
  // RPC stopped short of the horizon, at its page cap or behind the indexer: nothing is proven.
  if (events.latest < data.horizon) return { verified: false, events };
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
  return { verified: true, events };
}

// The local root must be one of the vault's last 256 roots, read from the ledger.
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
    e = {
      txHash,
      ledger,
      outputs: [undefined, undefined],
      nullifiers: [false, false],
      foreign: false,
      checked: false,
    };
    plan.evidence.push(e);
  }
  return e;
}

// Each of the plan's two commitments is in the vault's tree, in whatever transaction.
const landed = (plan: Plan): boolean =>
  [0, 1].every((slot) => plan.evidence.some((e) => e.outputs[slot] !== undefined));

// Records where the plans' output commitments landed, among leaves the vault's root confirmed:
// those positions hold the commitments whatever transaction the source names for them. Only these
// leaves show where a plan landed; a plan already shown to land takes none again.
function recordOutputs(plans: readonly Plan[], found: readonly FoundLeaf[]): void {
  for (const plan of plans.filter((p) => !landed(p))) {
    for (const leaf of found) {
      const slot = plan.commitments.indexOf(leaf.commitment);
      if (slot >= 0) evidenceOf(plan, leaf.txHash, leaf.ledger).outputs[slot] = leaf.index;
    }
  }
}

// Records what the vault's own events show of each plan that has not landed, transaction by
// transaction: whether it spent one of the plan's notes, its dummy inputs aside, and whether it
// added a leaf that is not the plan's. The caller passes only events the wallet checked: those a
// cross-check matched with the indexer's data, up to its horizon, and those a recheck matched with
// what the wallet kept.
export function recordEvents(
  plans: readonly Plan[],
  events: Pick<VaultEvents, "leaves" | "nullifiers">,
): void {
  const txs = new Map<string, { ledger: number; leaves: FoundLeaf[]; nullifiers: bigint[] }>();
  const tx = (hash: string, ledger: number) => {
    let t = txs.get(hash);
    if (t === undefined) {
      t = { ledger, leaves: [], nullifiers: [] };
      txs.set(hash, t);
    }
    return t;
  };
  for (const leaf of events.leaves) tx(leaf.txHash, leaf.ledger).leaves.push(leaf);
  for (const n of events.nullifiers) tx(n.txHash, n.ledger).nullifiers.push(n.nullifier);
  for (const plan of plans.filter((p) => !LANDED_STATES.includes(p.state))) {
    const notes = plan.inputs.map((input) => input.nf);
    for (const [hash, t] of txs) {
      const spends = plan.nullifiers.map((nf) => notes.includes(nf) && t.nullifiers.includes(nf));
      if (!spends.some(Boolean)) continue;
      const e = evidenceOf(plan, hash, t.ledger);
      e.checked = true;
      e.nullifiers = [e.nullifiers[0] || spends[0] === true, e.nullifiers[1] || spends[1] === true];
      e.foreign ||= t.leaves.some((l) => !plan.commitments.includes(l.commitment));
    }
  }
}

// The vault's events of the ledgers up to `ledger`.
export function eventsUpTo(
  events: Pick<VaultEvents, "leaves" | "nullifiers">,
  ledger: number,
): Pick<VaultEvents, "leaves" | "nullifiers"> {
  return {
    leaves: events.leaves.filter((l) => l.ledger <= ledger),
    nullifiers: events.nullifiers.filter((n) => n.ledger <= ledger),
  };
}

// The notes and outgoing outputs this wallet finds in new leaves, with the paths of notes in the
// pages those leaves completed. `checked` says whether a cross-check confirmed the new leaves.
function scanDownload(
  state: WalletState,
  keys: ScanKeys,
  data: Download,
  checked: boolean,
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
  const commitments = new Set(state.plans.filter((p) => !landed(p)).flatMap((p) => p.commitments));
  const planLeaves = data.leaves
    .filter((l) => commitments.has(l.commitment))
    .map((l) => ({ index: l.index, commitment: l.commitment, ledger: l.ledger, txHash: l.txHash }));
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
      found: [...(staged?.found ?? []), ...planLeaves],
      unchecked:
        staged?.unchecked ??
        (checked || data.leaves[0] === undefined
          ? undefined
          : { first: data.leaves[0].index, ledger: data.leaves[0].ledger }),
    },
    newNotes,
  };
}

// Holds a download whose tree the vault's root history cannot confirm yet, because it stopped at
// its page cap far behind the vault. None of it counts; the next sync continues from it.
export function stageDownload(
  state: WalletState,
  keys: ScanKeys,
  data: Download,
  checked: boolean,
): void {
  if (data.leaves.length > 0) state.staging = scanDownload(state, keys, data, checked).staging;
}

// Applies a download whose tree the vault's root history has confirmed, with anything staged
// before it: the notes found count from now, spent notes are marked, and where plans' commitments
// landed is recorded. Spends and leaves the cross-check did not confirm stay unchecked. Returns how
// many notes this sync found.
export function applyDownload(
  state: WalletState,
  keys: ScanKeys,
  data: Download,
  checked: boolean,
): number {
  const { staging, newNotes } = scanDownload(state, keys, data, checked);
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
  recordOutputs(state.plans, staging.found);
  const leaves =
    staging.unchecked === undefined
      ? undefined
      : { ...staging.unchecked, end: staging.tree.leafCount };
  const to = checked ? data.since - 1 : data.horizon;
  if (to >= data.since || leaves !== undefined) {
    addUnchecked(state, { from: data.since, to, leaves, lost: false });
  }
  state.nullifierSince = data.horizon + 1;
  // A leaf not yet scanned lies at or after the last scanned one, and so does any spend of it.
  state.nullifierBuffer = buffer.filter((n) => n.ledger >= state.lastLeafLedger);
  return newNotes;
}

// Joins a range to the last one when their ledgers touch, so a run of unchecked syncs is one range.
function addUnchecked(state: WalletState, range: UncheckedRange): void {
  const at = state.unchecked.length - 1;
  const last = state.unchecked[at];
  if (last === undefined || last.lost || last.to + 1 < range.from) {
    state.unchecked.push(range);
    return;
  }
  const [a, b] = [last.leaves, range.leaves];
  state.unchecked[at] = {
    from: last.from,
    to: Math.max(last.to, range.to),
    leaves:
      a === undefined || b === undefined
        ? (a ?? b)
        : { first: a.first, end: Math.max(a.end, b.end), ledger: a.ledger },
    lost: false,
  };
}

// Checks what the wallet kept from the oldest range a sync took unchecked, against the vault's own
// events while RPC still holds them: the wallet's notes and outgoing outputs at the range's leaves,
// found again by trial decryption with the transaction and ledger of each, where the plans'
// commitments landed among those leaves, and the spends of its notes in the range's ledgers. A
// difference is the indexer's. Returns the events of the ledgers whose spends were checked; what
// RPC does not reach yet stays in the range, and a range RPC no longer holds is kept, as lost.
export async function recheck(
  state: WalletState,
  keys: ScanKeys,
  rpc: SorobanRpc,
  vault: string,
  maxPages: number,
): Promise<VaultEvents | undefined> {
  const at = state.unchecked.findIndex((r) => !r.lost);
  const range = state.unchecked[at];
  if (range === undefined) return undefined;
  const start = Math.min(
    range.from <= range.to ? range.from : Number.POSITIVE_INFINITY,
    range.leaves?.ledger ?? Number.POSITIVE_INFINITY,
  );
  let events: VaultEvents;
  try {
    events = await new RpcEventSource(rpc, vault, start, maxPages).events();
  } catch (err) {
    if (!(err instanceof CyphrasError)) throw err;
    // A busy RPC is asked again in the next sync.
    if (err.code === "history_unavailable") state.unchecked[at] = { ...range, lost: true };
    return undefined;
  }
  const differ = (): never =>
    fail("indexer_fault", "the vault's events contradict what an unchecked sync took");
  let leaves = range.leaves;
  if (leaves !== undefined) {
    const { first, end } = leaves;
    // The leaves RPC shows follow one another from the range's first, up to the last ledger it
    // covers.
    const shown = events.leaves.filter((l) => l.index >= first && l.index < end);
    if (shown.some((l, i) => l.index !== first + i)) differ();
    const covered = (pos: number): boolean => pos >= first && pos < first + shown.length;
    const found: WalletState = { ...state, notes: [], sent: [] };
    const cache = new AddressCache(keys.incoming);
    for (const leaf of shown) scanLeaf(found, leaf, keys, cache);
    const where = (x: { pos: number; txHash: string; ledger: number }): string =>
      `${x.pos}/${x.txHash}/${x.ledger}`;
    for (const [kept, chain] of [
      [state.notes, found.notes],
      [state.sent, found.sent],
    ] as const) {
      const ours = kept.filter((x) => covered(x.pos)).map(where);
      const theirs = chain.map(where);
      if (ours.length !== theirs.length || ours.some((x) => !theirs.includes(x))) differ();
    }
    for (const plan of state.plans) {
      for (const e of plan.evidence) {
        e.outputs.forEach((pos, slot) => {
          const chain = pos === undefined || !covered(pos) ? undefined : shown[pos - first];
          if (
            chain !== undefined &&
            (chain.commitment !== plan.commitments[slot] ||
              chain.txHash !== e.txHash ||
              chain.ledger !== e.ledger)
          ) {
            differ();
          }
        });
      }
    }
    const next = first + shown.length;
    leaves =
      next === end
        ? undefined
        : { first: next, end, ledger: shown.length === 0 ? leaves.ledger : events.latest + 1 };
  }
  const to = Math.min(range.to, events.latest);
  const within = <T extends { readonly ledger: number }>(xs: readonly T[]): T[] =>
    xs.filter((x) => x.ledger >= range.from && x.ledger <= to);
  const spends = new Map(within(events.nullifiers).map((n) => [n.nullifier, n]));
  for (const note of state.notes) {
    if (note.nf === undefined) continue;
    const chain = spends.get(note.nf);
    const kept =
      note.spent !== undefined && note.spent.ledger >= range.from && note.spent.ledger <= to;
    if (chain === undefined ? kept : chain.txHash !== note.spent?.txHash) differ();
  }
  const rest: UncheckedRange = {
    from: range.from <= range.to ? to + 1 : range.from,
    to: range.to,
    leaves,
    lost: false,
  };
  state.unchecked.splice(at, 1, ...(rest.from <= rest.to || leaves !== undefined ? [rest] : []));
  return {
    ...events,
    leaves: within(events.leaves),
    nullifiers: within(events.nullifiers),
    deposits: within(events.deposits),
    exits: within(events.exits),
    latest: to,
  };
}

// Whether every spend of the ledgers from `from` to `to` was cross-checked.
export function checkedBetween(state: WalletState, from: number, to: number): boolean {
  return (
    to < state.nullifierSince &&
    !state.unchecked.some((r) => r.from <= r.to && r.from <= to && r.to >= from)
  );
}

export function isActive(plan: Plan): boolean {
  return ACTIVE_STATES.includes(plan.state);
}

// The transaction the plan landed in, as the source of its leaves named it.
function landing(plan: Plan): Evidence {
  const both = plan.evidence.find((e) => e.outputs.every((pos) => pos !== undefined));
  return both ?? (plan.evidence.find((e) => e.outputs[0] !== undefined) as Evidence);
}

// The vault's checked events show another transaction that spent one of the plan's notes, as the
// note's own record of its spend agrees, and added outputs that are not the plan's; or a plan of
// this wallet that spends the same notes has landed.
function superseded(state: WalletState, plan: Plan): boolean {
  const spentBy = (e: Evidence): boolean =>
    plan.inputs.some((input) => {
      const slot = plan.nullifiers.indexOf(input.nf);
      const note = state.notes.find((n) => n.pos === input.pos);
      return slot >= 0 && e.nullifiers[slot] === true && note?.spent?.txHash === e.txHash;
    });
  return (
    plan.evidence.some((e) => e.checked && e.foreign && spentBy(e)) ||
    state.plans.some(
      (q) =>
        q !== plan &&
        LANDED_STATES.includes(q.state) &&
        q.nullifiers.some((nf) => plan.nullifiers.includes(nf)),
    )
  );
}

// A plan taken for landed whose landing a rescan has not found again, where the checked spends of
// its ledger show one of its notes not spent by its transaction: it did not land there.
function landingRefuted(state: WalletState, plan: Plan): boolean {
  const at = plan.ledger;
  if (at === undefined || !checkedBetween(state, at, at)) return false;
  return plan.inputs.some((input) => {
    const note = state.notes.find((n) => n.pos === input.pos);
    const spent = note?.spent;
    return note !== undefined && (spent?.txHash !== plan.txHash || spent?.ledger !== at);
  });
}

// No sign of the plan up to its deadline: none of its commitments is known, and either the tree
// the vault's root confirmed holds a leaf added after the deadline, and so every leaf added up to
// it, or the checked spends of every ledger from the plan's building to its deadline show none of
// its notes spent, as a landing would have. It never landed, and now never will.
function missedDeadline(state: WalletState, plan: Plan): boolean {
  if (plan.evidence.some((e) => e.outputs.some((pos) => pos !== undefined))) return false;
  if (state.lastLeafLedger > plan.deadline) return true;
  if (!checkedBetween(state, plan.builtAt, plan.deadline)) return false;
  return plan.inputs.every((input) => {
    const spent = state.notes.find((n) => n.pos === input.pos)?.spent;
    return (
      state.notes.some((n) => n.pos === input.pos) &&
      (spent === undefined || spent.ledger > plan.deadline)
    );
  });
}

// Moves each plan along the submission state machine. A plan landed once both its commitments are
// in the vault's tree. It is superseded once the vault's checked events show another transaction
// spending one of its notes, or another plan of this wallet that spends the same notes landed. It
// is dead once its deadline or its root's place in the vault's history has passed with no sign of
// it, as every one of `views`, the vault read from each RPC provider, shows: either each holds the
// tree the wallet holds, without the plan's commitments in it, at or past the plan's deadline or
// with the plan's root gone from the vault's history; or each view is past the deadline, and the
// wallet's tree, or the checked spends, cover every ledger up to it with no sign of the plan. From
// then on the vault refuses its proof. A dead or superseded plan whose commitments turn up is confirmed all the
// same. A landed plan whose evidence a rescan dropped takes the transaction the rebuilt leaves
// show, or starts over once the checked spends refute its landing.
export function advancePlans(state: WalletState, views: readonly ChainView[]): void {
  for (const plan of state.plans) {
    if (!LANDED_STATES.includes(plan.state)) continue;
    if (landed(plan)) {
      const e = landing(plan);
      if (e.txHash !== plan.txHash || e.ledger !== plan.ledger) {
        // Its exit is followed again, from the transaction it landed in.
        plan.txHash = e.txHash;
        plan.ledger = e.ledger;
        plan.exit = undefined;
        plan.state = "confirmed";
      }
    } else if (landingRefuted(state, plan)) {
      plan.state =
        plan.txHash === undefined && plan.heldId === undefined ? "prepared" : "submitted";
      plan.ledger = undefined;
      plan.exit = undefined;
    }
  }
  const open = state.plans.filter(
    (p) => isActive(p) || p.state === "dead" || p.state === "superseded",
  );
  for (const plan of open) {
    if (!landed(plan)) continue;
    const e = landing(plan);
    plan.state = "confirmed";
    plan.txHash = e.txHash;
    plan.ledger = e.ledger;
  }
  // A view whose NextLeaf is the wallet's leaf count holds the wallet's tree: the sync refuses a
  // view whose root history contradicts it.
  const whole = (v: ChainView): boolean => v.roots.nextLeaf === state.tree.leafCount;
  const gone = (plan: Plan) => (v: ChainView) =>
    whole(v) && (v.roots.ledger >= plan.deadline || !v.roots.roots.includes(plan.root));
  for (const plan of open) {
    if (plan.state === "confirmed" || plan.state === "superseded") continue;
    if (superseded(state, plan)) {
      plan.state = "superseded";
    } else if (
      isActive(plan) &&
      views.length > 0 &&
      (views.every(gone(plan)) ||
        (missedDeadline(state, plan) && views.every((v) => v.ledger >= plan.deadline)))
    ) {
      plan.state = "dead";
    }
  }
}

// A full rescan rebuilds the evidence of every plan, so nothing recorded from an earlier sync
// decides its fate: a plan that has not landed starts over, and one that has keeps its state until
// the rebuilt chain shows again where it landed, or that it did not.
export function resetEvidence(plans: readonly Plan[]): void {
  for (const plan of plans) {
    plan.evidence = [];
    if (LANDED_STATES.includes(plan.state)) continue;
    plan.state = plan.txHash === undefined && plan.heldId === undefined ? "prepared" : "submitted";
  }
}
