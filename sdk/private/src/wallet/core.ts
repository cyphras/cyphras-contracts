import type { PinnedArtifacts } from "../artifacts.ts";
import { bytesToHex, randomBytes } from "../bytes.ts";
import type { Deployment } from "../deployments.ts";
import { fail } from "../errors.ts";
import type { AddressKey, SpendingKeys } from "../keys.ts";
import { CommitmentTree } from "../merkle.ts";
import type { Prover } from "../prover.ts";
import type { InvokeContext, NetworkFeeCaps } from "../vault/invoke.ts";
import type { SpendNote } from "../transaction.ts";
import type { PoolStats } from "../net/indexer.ts";
import type { ChainView } from "../vault/state.ts";
import type { Services } from "./services.ts";
import type { ScanKeys } from "./sync.ts";
import { isActive } from "./sync.ts";
import type { OwnedNote, WalletState } from "./state.ts";

// What the last sync read of the vault and the pool. Spends use these reads instead of making
// their own, so that the RPC and the indexer see the same requests whether or not a spend follows.
export interface ChainReads {
  readonly view: ChainView;
  readonly stats: PoolStats | undefined;
}

// Everything the wallet's operations share. Spend keys are absent from a view-only wallet.
export interface Core {
  readonly deployment: Deployment;
  readonly services: Services;
  readonly scan: ScanKeys;
  readonly keys: SpendingKeys | undefined;
  readonly self: AddressKey;
  readonly prover: Prover | undefined;
  readonly artifacts: PinnedArtifacts | undefined;
  readonly state: WalletState;
  // Set by every sync that succeeds.
  chain: ChainReads | undefined;
  readonly feeCaps: NetworkFeeCaps;
  save(): Promise<void>;
  now(): number;
  sleep(ms: number): Promise<void>;
}

export const newId = (): string => bytesToHex(randomBytes(16));

export function invokeContext(core: Core): InvokeContext {
  return {
    rpc: core.services.rpc,
    networkPassphrase: core.deployment.networkPassphrase,
    vault: core.deployment.vault,
    feeCaps: core.feeCaps,
    sleep: (ms: number) => core.sleep(ms),
  };
}

export function chainReads(core: Core): ChainReads {
  if (core.chain === undefined) fail("tree_unverified", "the wallet has not synced; sync first");
  return core.chain;
}

export function spendingKeys(core: Core): SpendingKeys {
  if (core.keys === undefined) fail("view_only", "a view-only wallet cannot spend");
  return core.keys;
}

// Positions of the notes that unconfirmed plans hold, which no other spend may use until those
// plans are confirmed, superseded or dead.
export function lockedPositions(state: WalletState): Set<number> {
  const locked = new Set<number>();
  for (const plan of state.plans) {
    if (isActive(plan)) for (const input of plan.inputs) locked.add(input.pos);
  }
  return locked;
}

// Inputs of a confirmed plan count as spent before the nullifier set shows it.
export function confirmedInputs(state: WalletState): Set<number> {
  const spent = new Set<number>();
  for (const plan of state.plans) {
    if (!isActive(plan) && plan.state !== "superseded" && plan.state !== "dead") {
      for (const input of plan.inputs) spent.add(input.pos);
    }
  }
  return spent;
}

export function spendableNotes(state: WalletState): OwnedNote[] {
  const locked = lockedPositions(state);
  const spent = confirmedInputs(state);
  return state.notes.filter(
    (n) => n.spent === undefined && n.value > 0n && !locked.has(n.pos) && !spent.has(n.pos),
  );
}

// The smallest single note that covers the total, else the pair with the smallest sufficient
// sum. A total that no two notes reach needs consolidation first.
export function selectNotes(notes: readonly OwnedNote[], total: bigint): OwnedNote[] {
  const sorted = [...notes].sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0));
  const single = sorted.find((n) => n.value >= total);
  if (single !== undefined) return [single];
  let best: [OwnedNote, OwnedNote] | undefined;
  let i = 0;
  let j = sorted.length - 1;
  while (i < j) {
    const a = sorted[i] as OwnedNote;
    const b = sorted[j] as OwnedNote;
    const sum = a.value + b.value;
    if (sum >= total) {
      if (best === undefined || sum < best[0].value + best[1].value) best = [a, b];
      j--;
    } else {
      i++;
    }
  }
  if (best !== undefined) return best;
  // Errors can reach logs and crash reports, so they never carry the private balance.
  const available = notes.reduce((s, n) => s + n.value, 0n);
  if (available >= total) {
    fail("needs_consolidation", "no two notes cover the amount; consolidate notes first");
  }
  return fail("insufficient_funds", "the spendable balance does not cover the amount and fee");
}

export function spendNote(state: WalletState, note: OwnedNote, address: AddressKey): SpendNote {
  const tree = CommitmentTree.fromSnapshot(state.tree);
  return {
    value: note.value,
    gd: address.gd,
    q: address.q,
    pkd: address.pkd,
    rcm: note.rcm,
    pos: note.pos,
    path: tree.path(note.pos, note.pagePath),
  };
}
