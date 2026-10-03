import { encodeAddress } from "../address.ts";
import { bytesToHex } from "../bytes.ts";
import { AddressCache, decryptIncoming, recoverOutgoing } from "../encryption.ts";
import { CyphrasError, fail } from "../errors.ts";
import type { IncomingKeys, Network } from "../keys.ts";
import { CommitmentTree, PAGE_SIZE, pagePath } from "../merkle.ts";
import type { Leaf, SpentNullifier } from "../net/indexer.ts";
import type { SorobanRpc } from "../net/rpc.ts";
import { nullifier } from "../notes.ts";
import type { RootHistory } from "../vault/state.ts";
import { type ChainSource, type ExitEvent, RpcEventSource } from "./sources.ts";
import {
  ACTIVE_STATES,
  type Evidence,
  type OwnedNote,
  type Plan,
  type PlanState,
  type RootCheck,
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

export interface ChainUpdate {
  readonly newNotes: number;
  // The index of the first leaf and the first ledger of nullifiers this sync asked for.
  readonly firstIndex: number;
  readonly sinceLedger: number;
  readonly leaves: readonly Leaf[];
  readonly nullifiers: readonly SpentNullifier[];
  readonly completeToLedger: number;
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
export function recordEvidence(
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

// Downloads every nullifier spent since the last sync, then every leaf after the local tree's
// last one, scans the leaves and extends the tree. Nullifiers come first, so any transaction
// whose nullifiers are seen also has its leaves in the same sync.
export async function syncChain(
  state: WalletState,
  keys: ScanKeys,
  source: ChainSource,
): Promise<ChainUpdate> {
  const tree = CommitmentTree.fromSnapshot(state.tree);
  const firstIndex = tree.leafCount;
  const sinceLedger = state.nullifierSince;
  const { nullifiers, completeToLedger } = await source.nullifiers(sinceLedger);
  const cache = new AddressCache(keys.incoming);
  const fetched: Leaf[] = [];
  let newNotes = 0;
  for (;;) {
    const { leaves, done } = await source.nextLeaves(tree);
    if ((tree.leafCount + leaves.length) % 2 !== 0) {
      fail("indexer_fault", "the leaves end in the middle of an inserted pair");
    }
    for (const leaf of leaves) {
      if (scanLeaf(state, leaf, keys, cache)) newNotes++;
    }
    for (const page of tree.append(leaves.map((l) => l.commitment))) {
      const start = page.page * PAGE_SIZE;
      for (const note of state.notes) {
        if (note.pagePath === undefined && note.pos >= start && note.pos < start + PAGE_SIZE) {
          note.pagePath = pagePath(page.leaves, note.pos - start);
        }
      }
    }
    const last = leaves[leaves.length - 1];
    if (last !== undefined) state.lastLeafLedger = last.ledger;
    state.tree = tree.snapshot();
    fetched.push(...leaves);
    if (done) break;
  }

  const buffer = [
    ...state.nullifierBuffer,
    ...nullifiers.map((n) => ({ nf: n.nullifier, ledger: n.ledger, txHash: n.txHash })),
  ];
  const spent = new Map(buffer.map((n) => [n.nf, n]));
  for (const note of state.notes) {
    if (note.nf === undefined || note.spent !== undefined) continue;
    const hit = spent.get(note.nf);
    if (hit !== undefined) note.spent = { txHash: hit.txHash, ledger: hit.ledger };
  }
  recordEvidence(state.plans, fetched, buffer);
  state.nullifierSince = completeToLedger + 1;
  // A leaf not yet scanned lies at or after the last scanned one, and so does any spend of it.
  state.nullifierBuffer = buffer.filter((n) => n.ledger >= state.lastLeafLedger);
  return { newNotes, firstIndex, sinceLedger, leaves: fetched, nullifiers, completeToLedger };
}

// F-27: the local root must be one of the vault's last 256 roots, read from the ledger.
export function checkRoot(state: WalletState, history: RootHistory): RootCheck {
  const tree = CommitmentTree.fromSnapshot(state.tree);
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

export function isActive(plan: Plan): boolean {
  return ACTIVE_STATES.includes(plan.state);
}

// Moves each unconfirmed plan along the submission state machine with what the chain shows.
export function advancePlans(
  state: WalletState,
  completeToLedger: number,
  history: RootHistory | undefined,
): void {
  for (const plan of state.plans) {
    if (!isActive(plan)) continue;
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
    if (completeToLedger >= plan.deadline) {
      plan.state = "dead";
      continue;
    }
    if (
      history !== undefined &&
      completeToLedger >= history.ledger &&
      !history.roots.includes(plan.root)
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

// RPC keeps events for about a week; a cross-check looks at most a day back.
const CROSS_CHECK_LEDGERS = 17_280;

export interface CrossCheck {
  // RPC covered the range and agreed with the indexer.
  readonly verified: boolean;
  // The exit events RPC returned for the range and after it.
  readonly exits: readonly ExitEvent[];
}

// Compares what the indexer served in this sync with the vault's events from RPC for the same
// ledgers. Unverified when RPC cannot cover the range; a difference raises indexer_fault, since
// either the indexer or the RPC is wrong, and neither is trusted until it is resolved.
export async function crossCheck(
  rpc: SorobanRpc,
  vault: string,
  update: ChainUpdate,
): Promise<CrossCheck> {
  // The served data covers nullifiers from sinceLedger and every leaf after firstIndex; leaves
  // after the last scanned one lie at or after sinceLedger.
  const from = Math.max(update.sinceLedger, update.completeToLedger - CROSS_CHECK_LEDGERS);
  if (from > update.completeToLedger) return { verified: true, exits: [] };
  let events;
  try {
    events = await new RpcEventSource(rpc, vault, from).events();
  } catch (err) {
    if (err instanceof CyphrasError) return { verified: false, exits: [] };
    throw err;
  }
  const within = (ledger: number): boolean => ledger >= from && ledger <= update.completeToLedger;
  const leafKey = (l: Leaf): string =>
    `${l.index}/${l.commitment}/${bytesToHex(l.ciphertext)}/${l.txHash}`;
  const served = new Set(update.leaves.filter((l) => within(l.ledger)).map(leafKey));
  // Every leaf added after the tree's last one up to the complete ledger must have been served.
  const onChain = new Set(
    events.leaves.filter((l) => within(l.ledger) && l.index >= update.firstIndex).map(leafKey),
  );
  const nfKey = (n: SpentNullifier): string => `${n.nullifier}/${n.txHash}`;
  const servedNfs = new Set(update.nullifiers.filter((n) => within(n.ledger)).map(nfKey));
  const chainNfs = new Set(events.nullifiers.filter((n) => within(n.ledger)).map(nfKey));
  const same = (a: Set<string>, b: Set<string>): boolean =>
    a.size === b.size && [...a].every((x) => b.has(x));
  if (!same(served, onChain) || !same(servedNfs, chainNfs)) {
    fail("indexer_fault", "the indexer's leaves or nullifiers differ from the vault's events");
  }
  return { verified: true, exits: events.exits };
}
