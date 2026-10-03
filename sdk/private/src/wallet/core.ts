import type { xdr } from "@stellar/stellar-base";
import type { PinnedArtifacts } from "../artifacts.ts";
import { bytesToHex, randomBytes } from "../bytes.ts";
import type { Deployment } from "../deployments.ts";
import { fail } from "../errors.ts";
import type { AddressKey, SpendingKeys } from "../keys.ts";
import { CommitmentTree } from "../merkle.ts";
import type { Prover } from "../prover.ts";
import type { Extra, InvokeContext, NetworkFeeCaps } from "../vault/invoke.ts";
import type { SpendNote } from "../transaction.ts";
import type { PoolStats } from "../net/indexer.ts";
import {
  type ChainView,
  balanceKey,
  exitKey,
  payKeys,
  queuedExit,
  strandedKey,
} from "../vault/state.ts";
import type { Services } from "./services.ts";
import type { ScanKeys } from "./sync.ts";
import { isActive } from "./sync.ts";
import type { OwnedNote, WalletState } from "./state.ts";

// What the last sync read of the vault and the pool. Spends use these reads instead of making
// their own, so that the RPC and the indexer see the same requests whether or not a spend follows.
export interface ChainReads {
  readonly view: ChainView;
  readonly stats: PoolStats | undefined;
  // Seconds per ledger, as recent close times give it.
  readonly pace: number;
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
    second: core.services.second?.rpc,
    networkPassphrase: core.deployment.networkPassphrase,
    vault: core.deployment.vault,
    feeCaps: core.feeCaps,
    sleep: (ms: number) => core.sleep(ms),
  };
}

// The vault decides in the ledger a call lands in, not at its simulation, whether an exit is paid at
// once or queued, which IDs the queue's next exits take and which exits release pays, so a call
// simulated against one state of the exit queue may need entries of another. These are the rooms
// the relayer gives its calls on the queue, given alike to the wallet's own.

// How many exits queued, or released, ahead of a call in the ledger it lands in leave it room.
const EXIT_KEYS = 4n;
// What the other path of a call on the exit queue may take beyond its simulation: an exit or
// stranded exit entry with its key, about 330 bytes; a contract's balance entry in the asset
// contract, about 225 bytes; paying an exit at once rather than queueing it, two transfers in the
// asset contract of about 200,000 instructions, with events of about 430 bytes more; and the TTL in
// ledgers the vault gives its entries when it writes them.
const EXIT_ENTRY_BYTES = 400;
const BALANCE_ENTRY_BYTES = 256;
const SWITCH_INSTRUCTIONS = 1_000_000;
const SWITCH_EVENT_BYTES = 512;
const ENTRY_TTL = 30 * 17_280 + 720;

type Room = (footprint: xdr.LedgerFootprint) => Promise<Extra>;

const exitKeys = (vault: string, first: bigint): xdr.LedgerKey[] =>
  Array.from({ length: Number(EXIT_KEYS) + 1 }, (_, i) => exitKey(vault, first + BigInt(i)));

// The other path's entries with what it may take: the bytes of an exit entry and of each of the
// asset contract's balance entries among `balances`.
const otherPath = (keys: xdr.LedgerKey[], balances: number): Extra => {
  const bytes = EXIT_ENTRY_BYTES + balances * BALANCE_ENTRY_BYTES;
  return {
    readWrite: keys,
    instructions: SWITCH_INSTRUCTIONS,
    writeBytes: bytes,
    newBytes: bytes,
    rentLedgers: ENTRY_TTL,
    eventBytes: SWITCH_EVENT_BYTES,
  };
};

const NO_ROOM: Extra = {
  readWrite: [],
  instructions: 0,
  writeBytes: 0,
  newBytes: 0,
  rentLedgers: 0,
  eventBytes: 0,
};

const isContractData = (k: xdr.LedgerKey): boolean => k.switch().name === "contractData";

// The room a transact that pays anything is given, in the order it is added: the vault's balance in
// the asset and the balances of the recipient, when it is paid, and of the relayer, when it is paid
// a fee, which paying at once writes; then the exits from the queue's tail to EXIT_KEYS past it,
// one of which queueing writes. The tail is the one the simulation queued an exit at, or the
// vault's tail now when it paid at once.
export function transactRoom(
  core: Core,
  ext: { extAmount: bigint; fee: bigint; recipient: string; relayer: string },
): Room {
  return async (footprint) => {
    const payout = -ext.extAmount;
    if (payout <= 0n && ext.fee <= 0n) return NO_ROOM;
    const { vault, asset } = core.deployment;
    const tail =
      queuedExit(vault, footprint) ?? (await core.services.vault.instance()).status.exitTail;
    const paid = [
      ...(payout > 0n ? payKeys(asset.contract, asset.name, ext.recipient) : []),
      ...(ext.fee > 0n ? payKeys(asset.contract, asset.name, ext.relayer) : []),
    ];
    const keys = [balanceKey(asset.contract, vault), ...paid, ...exitKeys(vault, tail)];
    return otherPath(keys, 1 + paid.filter(isContractData).length);
  };
}

// The room a claim is given: the exits from the tail its simulation queued it at to EXIT_KEYS past
// it, so as many exits queued ahead of it in the same ledger still leave it room.
export function claimRoom(core: Core): Room {
  return async (footprint) => {
    const tail = queuedExit(core.deployment.vault, footprint);
    return tail === undefined
      ? NO_ROOM
      : { ...NO_ROOM, readWrite: exitKeys(core.deployment.vault, tail) };
  };
}

// The room a release of up to `max` exits is given: the stranded entries of the exits it handles,
// which a payment the asset contract refuses writes, and the entries of the EXIT_KEYS exits after
// them, which it pays instead when releases of others pay as many from the head first: those exits,
// their stranded entries and their payees' balances.
export function releaseRoom(core: Core, max: number): Room {
  return async () => {
    const { vault, asset } = core.deployment;
    const { status } = await core.services.vault.instance();
    const head = status.exitHead;
    const queued = status.exitTail - head;
    const n = queued < BigInt(max) ? queued : BigInt(max);
    const keys: xdr.LedgerKey[] = [];
    for (let id = head; id < head + n; id++) keys.push(strandedKey(vault, id));
    const next: bigint[] = [];
    for (let id = head + n; id < head + n + EXIT_KEYS && id < status.exitTail; id++) next.push(id);
    const exits = await core.services.vault.exits(next);
    let balances = 0;
    for (const id of next) {
      const exit = exits.get(id);
      if (exit === undefined) continue;
      keys.push(exitKey(vault, id), strandedKey(vault, id));
      const parties = [
        ...(exit.payout > 0n ? [exit.recipient] : []),
        ...(exit.fee > 0n ? [exit.relayer] : []),
      ];
      for (const party of parties) {
        const paid = payKeys(asset.contract, asset.name, party);
        balances += paid.filter(isContractData).length;
        keys.push(...paid);
      }
    }
    return otherPath(keys, balances);
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
