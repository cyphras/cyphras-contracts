import { sha256 } from "@noble/hashes/sha2";
import { encodeAddress } from "../address.ts";
import { bytesToHex, utf8 } from "../bytes.ts";
import { AddressCache, decryptIncoming, recoverOutgoing } from "../encryption.ts";
import { CyphrasError, fail } from "../errors.ts";
import type { IncomingKeys, Network } from "../keys.ts";
import { CommitmentTree, PAGE_SIZE, pagePath } from "../merkle.ts";
import type { Leaf, SpentNullifier } from "../net/indexer.ts";
import type { SorobanRpc } from "../net/rpc.ts";
import { nullifier } from "../notes.ts";
import type { ChainView, RootHistory, VaultReader } from "../vault/state.ts";
import { recordCloseTimes } from "./pace.ts";
import { type ChainSource, RpcEventSource, type VaultEvents } from "./sources.ts";
import {
  ACTIVE_STATES,
  type Evidence,
  type FoundLeaf,
  LANDED_STATES,
  type LeafChunk,
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

// Downloads the nullifiers spent since the last sync, then reads the vault from each RPC provider,
// then the leaves after the local tree's last one, staged or confirmed, up to the smallest NextLeaf
// the providers that answered read. A leaf past it cannot be checked against every provider yet,
// so a later sync takes it. Nullifiers count only up to the earliest ledger those providers read
// the vault at, so every transaction whose nullifiers are kept has its leaves below that NextLeaf;
// and when the page cap stops the leaves short, only up to the ledger before the last leaf taken.
// A provider after the first that cannot answer has no view.
export async function downloadChain(
  state: WalletState,
  source: ChainSource,
  vaults: readonly VaultReader[],
  maxPages: number,
): Promise<{ readonly views: readonly (ChainView | undefined)[]; readonly data: Download }> {
  const since = state.nullifierSince;
  const served = await source.nullifiers(since);
  const views = await Promise.all(
    vaults.map((vault, i) =>
      i === 0
        ? vault.view()
        : vault.view().catch((err: unknown) => {
            if (err instanceof CyphrasError) return undefined;
            throw err;
          }),
    ),
  );
  const answered = views.filter((v): v is ChainView => v !== undefined);
  const tree = CommitmentTree.fromSnapshot(state.staging?.tree ?? state.tree);
  const firstIndex = tree.leafCount;
  const nextLeaf = Math.min(...answered.map((v) => v.roots.nextLeaf));
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
  let horizon = Math.min(served.completeToLedger, ...answered.map((v) => v.ledger));
  const last = leaves[leaves.length - 1];
  if (capped && last !== undefined) horizon = Math.min(horizon, last.ledger - 1);
  return {
    views,
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
  // RPC no longer holds the ledger the range starts at.
  readonly gone: boolean;
}

const leafKey = (l: Leaf): string =>
  `${l.index}/${l.commitment}/${bytesToHex(l.ciphertext)}/${l.ledger}/${l.txHash}`;
const nfKey = (n: SpentNullifier): string => `${n.nullifier}/${n.ledger}/${n.txHash}`;

// Fails unless every provider's events show the vault's exits and deposits from `from` to `to`
// alike: providers that differ there cannot all be right.
export function sameRecords(all: readonly VaultEvents[], from: number, to: number): void {
  const records = (e: VaultEvents): string =>
    [...e.exits, ...e.deposits]
      .filter((x) => x.ledger >= from && x.ledger <= to)
      .map((x) => JSON.stringify(x, (_key, v: unknown) => (typeof v === "bigint" ? `${v}` : v)))
      .sort()
      .join("\n");
  const [first, ...rest] = all;
  if (first !== undefined && rest.some((e) => records(e) !== records(first))) {
    fail("indexer_fault", "the RPC providers show the vault's exits or deposits differently");
  }
}

// Leaves a sync takes unchecked are kept as digests of runs of at most this many, for a recheck to
// compare with the vault's events once RPC holds them.
const CHUNK_LEAVES = 1024;

const digestOf = (leaves: readonly Leaf[]): string =>
  bytesToHex(sha256(utf8(leaves.map(leafKey).join("\n"))));

function chunksOf(leaves: readonly Leaf[]): LeafChunk[] {
  const chunks: LeafChunk[] = [];
  for (let i = 0; i < leaves.length; i += CHUNK_LEAVES) {
    const run = leaves.slice(i, i + CHUNK_LEAVES);
    chunks.push({ end: (run[run.length - 1] as Leaf).index + 1, digest: digestOf(run) });
  }
  return chunks;
}

// Compares what a source served with the vault's events from one RPC provider since the same
// ledger. Every served leaf is compared by its index, whatever ledger the source gave it; only a
// leaf added before that ledger, which RPC no longer shows, rests on the root check alone.
// Unverified when RPC cannot cover the range; a difference raises indexer_fault, since either the
// source or the RPC is wrong, and neither is trusted until it is resolved.
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
    if (err instanceof CyphrasError) {
      return { verified: false, events: undefined, gone: err.code === "history_unavailable" };
    }
    throw err;
  }
  // RPC stopped short of the horizon, at its page cap or behind the source: nothing is proven.
  if (events.latest < data.horizon) return { verified: false, events, gone: false };
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
  return { verified: true, events, gone: false };
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
      providers: 0,
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

// Records where the plans' output commitments landed, among leaves the root history of each of
// `providers` RPC providers confirmed: those positions hold the commitments whatever transaction
// the source names for them. Only these leaves show where a plan landed; a plan already shown to
// land takes none again.
function recordOutputs(
  plans: readonly Plan[],
  found: readonly FoundLeaf[],
  providers: number,
): void {
  for (const plan of plans.filter((p) => !landed(p))) {
    for (const leaf of found) {
      const slot = plan.commitments.indexOf(leaf.commitment);
      if (slot < 0) continue;
      const e = evidenceOf(plan, leaf.txHash, leaf.ledger);
      e.outputs[slot] = leaf.index;
      e.providers = providers;
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
        staged?.unchecked === undefined
          ? checked || data.leaves[0] === undefined
            ? undefined
            : {
                first: data.leaves[0].index,
                ledger: data.leaves[0].ledger,
                chunks: chunksOf(data.leaves),
              }
          : { ...staged.unchecked, chunks: [...staged.unchecked.chunks, ...chunksOf(data.leaves)] },
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

// Applies a download whose tree the root history of each of `providers` RPC providers has
// confirmed, with anything staged before it: the notes found count from now, spent notes are
// marked, and where plans' commitments landed is recorded. Spends and leaves the cross-check did
// not confirm stay unchecked. Returns how many notes this sync found.
export function applyDownload(
  state: WalletState,
  keys: ScanKeys,
  data: Download,
  checked: boolean,
  providers: number,
): number {
  const { staging, newNotes } = scanDownload(state, keys, data, checked);
  for (const { pos, pagePath: path } of staging.paths) {
    const note = state.notes.find((n) => n.pos === pos);
    if (note !== undefined) note.pagePath = path;
  }
  state.notes.push(...staging.notes);
  state.sent.push(...staging.sent);
  // The ledgers of leaves a cross-check matched with the vault's events are the vault's own.
  if (checked && staging.unchecked === undefined && staging.tree.leafCount > state.tree.leafCount) {
    state.checkedLeafLedger = Math.max(state.checkedLeafLedger, staging.lastLeafLedger);
  }
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
  recordOutputs(state.plans, staging.found, providers);
  const leaves =
    staging.unchecked === undefined
      ? undefined
      : { ...staging.unchecked, end: staging.tree.leafCount };
  const to = checked ? data.since - 1 : data.horizon;
  if (to >= data.since || leaves !== undefined) {
    addUnchecked(state, { from: data.since, to, leaves, status: "open", askedAt: undefined });
  }
  state.nullifierSince = data.horizon + 1;
  // A leaf not yet scanned lies at or after the last scanned one, and so does any spend of it.
  state.nullifierBuffer = buffer.filter((n) => n.ledger >= state.lastLeafLedger);
  return newNotes;
}

// Joins a range to the last one when their ledgers touch and their leaves follow one another, so a
// run of unchecked syncs is one range.
function addUnchecked(state: WalletState, range: UncheckedRange): void {
  const at = state.unchecked.length - 1;
  const last = state.unchecked[at];
  const [a, b] = [last?.leaves, range.leaves];
  if (
    last === undefined ||
    last.status !== "open" ||
    last.to + 1 < range.from ||
    (a !== undefined && b !== undefined && a.end !== b.first)
  ) {
    state.unchecked.push(range);
    return;
  }
  state.unchecked[at] = {
    from: last.from,
    to: Math.max(last.to, range.to),
    leaves:
      a === undefined || b === undefined
        ? (a ?? b)
        : { first: a.first, end: b.end, ledger: a.ledger, chunks: [...a.chunks, ...b.chunks] },
    status: "open",
    askedAt: undefined,
  };
}

// How far the leaves of an unchecked range are confirmed by the vault's events from one RPC
// provider, whose leaves `shown` must follow one another from the range's first: each run of them
// it shows in full must be the run the sync took. Returns the position after the last run
// confirmed.
function confirmedRuns(
  leaves: NonNullable<UncheckedRange["leaves"]>,
  shown: readonly Leaf[],
  differ: () => never,
): number {
  const { first } = leaves;
  if (shown.some((l, i) => l.index !== first + i)) differ();
  let next = first;
  for (const chunk of leaves.chunks) {
    if (chunk.end > first + shown.length) break;
    if (digestOf(shown.slice(next - first, chunk.end - first)) !== chunk.digest) differ();
    next = chunk.end;
  }
  return next;
}

// A partial range is asked about again this long after the last time, in milliseconds.
const PARTIAL_AGAIN_MS = 3_600_000;

// Checks what the wallet kept from the oldest open range a sync took unchecked, or with none open
// from the first partial range asked about an hour or more before `now`, against the vault's own
// events from every RPC provider that still holds them: every leaf the sync took, by the digests
// of runs of them, and the spends of the wallet's notes in the range's ledgers. A difference is
// the indexer's. Nothing moves while a provider is busy. What every provider shows alike is
// cleared, the ledgers of its leaves become the vault's own, and the first provider's events of
// the ledgers whose spends were cleared are returned, once every provider shows the vault's exits
// and deposits in them alike. A range some provider no longer holds cannot be confirmed by every
// one for now: what every other provider shows alike is kept as partial, and a range none of them
// holds is kept as lost.
export async function recheck(
  state: WalletState,
  rpcs: readonly SorobanRpc[],
  vault: string,
  maxPages: number,
  now: number,
): Promise<VaultEvents | undefined> {
  const open = state.unchecked.findIndex((r) => r.status === "open");
  const at =
    open >= 0
      ? open
      : state.unchecked.findIndex(
          (r) =>
            r.status === "partial" &&
            (r.askedAt === undefined || now - r.askedAt >= PARTIAL_AGAIN_MS),
        );
  const range = state.unchecked[at];
  if (range === undefined) return undefined;
  const start = Math.min(
    range.from <= range.to ? range.from : Number.POSITIVE_INFINITY,
    range.leaves?.ledger ?? Number.POSITIVE_INFINITY,
  );
  // The events of each provider that still holds the range.
  const held: VaultEvents[] = [];
  let busy = false;
  const end = { ledger: range.to, leafEnd: range.leaves?.end };
  for (const rpc of rpcs) {
    try {
      held.push(await new RpcEventSource(rpc, vault, start, maxPages, end).events());
    } catch (err) {
      if (!(err instanceof CyphrasError)) throw err;
      // A busy RPC is asked again in the next sync.
      busy ||= err.code !== "history_unavailable";
    }
  }
  recordCloseTimes(
    state,
    held.flatMap((e) => e.closeTimes),
  );
  if (held.length === 0) {
    if (!busy) state.unchecked[at] = { ...range, status: "lost" };
    return undefined;
  }
  const differ = (): never =>
    fail("indexer_fault", "the vault's events contradict what an unchecked sync took");
  const within = <T extends { readonly ledger: number }>(xs: readonly T[], to: number): T[] =>
    xs.filter((x) => x.ledger >= range.from && x.ledger <= to);
  const taken = range.leaves;
  const shownBy = (e: VaultEvents): Leaf[] =>
    taken === undefined
      ? []
      : e.leaves.filter((l) => l.index >= taken.first && l.index < taken.end);
  const confirmed: number[] = [];
  for (const e of held) {
    if (taken !== undefined) confirmed.push(confirmedRuns(taken, shownBy(e), differ));
    const to = Math.min(range.to, e.latest);
    const spends = new Map(within(e.nullifiers, to).map((n) => [n.nullifier, n]));
    for (const note of state.notes) {
      if (note.nf === undefined) continue;
      const chain = spends.get(note.nf);
      const kept =
        note.spent !== undefined && note.spent.ledger >= range.from && note.spent.ledger <= to;
      if (chain === undefined ? kept : chain.txHash !== note.spent?.txHash) differ();
    }
  }
  if (busy) return undefined;
  const events = held[0] as VaultEvents;
  const latest = Math.min(...held.map((e) => e.latest));
  const to = Math.min(range.to, latest);
  let leaves = taken;
  let done = taken;
  if (taken !== undefined) {
    const { first, end } = taken;
    const next = Math.min(...confirmed);
    const shown = shownBy(events);
    done =
      next === first
        ? undefined
        : {
            first,
            end: next,
            ledger: taken.ledger,
            chunks: taken.chunks.filter((c) => c.end <= next),
          };
    leaves =
      next === end
        ? undefined
        : {
            first: next,
            end,
            ledger: shown[next - first]?.ledger ?? (next === first ? taken.ledger : latest + 1),
            chunks: taken.chunks.filter((c) => c.end > next),
          };
    const lastChecked = shown[next - 1 - first];
    if (held.length === rpcs.length && lastChecked !== undefined) {
      state.checkedLeafLedger = Math.max(state.checkedLeafLedger, lastChecked.ledger);
    }
  }
  const rest: UncheckedRange = {
    from: range.from <= range.to ? Math.max(range.from, to + 1) : range.from,
    to: range.to,
    leaves,
    status: "open",
    askedAt: undefined,
  };
  const kept = rest.from <= rest.to || leaves !== undefined ? [rest] : [];
  if (held.length < rpcs.length) {
    const seen: UncheckedRange = {
      from: range.from,
      to,
      leaves: done,
      status: "partial",
      askedAt: now,
    };
    state.unchecked.splice(
      at,
      1,
      ...(seen.from <= seen.to || done !== undefined ? [seen] : []),
      ...kept,
    );
    return undefined;
  }
  sameRecords(held, range.from, to);
  state.unchecked.splice(at, 1, ...kept);
  return {
    ...events,
    leaves: within(events.leaves, to),
    nullifiers: within(events.nullifiers, to),
    deposits: within(events.deposits, to),
    exits: within(events.exits, to),
    from: range.from,
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

// How many RPC providers confirmed the tree that holds the plan's landing, none for a plan whose
// landing the wallet does not hold.
export function landingProviders(plan: Plan): number {
  return landed(plan) ? landing(plan).providers : 0;
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
// the vault's root confirmed holds a leaf whose ledger a check confirmed is after the deadline,
// and so every leaf added up to it, or the checked spends of every ledger from the plan's building
// to its deadline show none of its notes spent, as a landing would have. It never landed, and now
// never will.
function missedDeadline(state: WalletState, plan: Plan): boolean {
  if (plan.evidence.some((e) => e.outputs.some((pos) => pos !== undefined))) return false;
  if (state.checkedLeafLedger > plan.deadline) return true;
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
// then on the vault refuses its proof. A dead or superseded plan whose commitments turn up is
// confirmed all the same. A landed plan whose evidence a rescan dropped takes the transaction the
// rebuilt leaves show, or starts over once the checked spends refute its landing.
export function advancePlans(
  state: WalletState,
  views: readonly [ChainView, ...ChainView[]],
): void {
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
