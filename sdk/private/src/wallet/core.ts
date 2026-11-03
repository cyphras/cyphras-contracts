import type { xdr } from "@stellar/stellar-base";
import type { PinnedArtifacts } from "../artifacts.ts";
import { bytesToHex, randomBytes } from "../bytes.ts";
import type { Deployment } from "../deployments.ts";
import { CyphrasError, fail } from "../errors.ts";
import type { AddressKey, SpendingKeys } from "../keys.ts";
import { CommitmentTree } from "../merkle.ts";
import type { Prover } from "../prover.ts";
import type { Extra, InvokeContext, NetworkFeeCaps } from "../vault/invoke.ts";
import type { SpendNote } from "../transaction.ts";
import type { PoolStats } from "../net/indexer.ts";
import {
  type ChainView,
  type QueuedExitEntry,
  balanceKey,
  exitKey,
  payKeys,
  pendingDeposit,
  pendingKey,
  queuedExit,
  strandedKey,
} from "../vault/state.ts";
import type { Services } from "./services.ts";
import type { ScanKeys } from "./sync.ts";
import { isActive } from "./sync.ts";
import { LANDED_STATES, type OwnedNote, type Plan, type WalletState } from "./state.ts";

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

// With `caps`, checked by feeCapsOf, a call's own caps over the wallet's, as after its user agreed
// to a restore's fee.
export function invokeContext(core: Core, caps?: Partial<NetworkFeeCaps>): InvokeContext {
  return {
    rpc: core.services.rpc,
    second: core.services.second?.rpc,
    networkPassphrase: core.deployment.networkPassphrase,
    vault: core.deployment.vault,
    vaultWasmHash: core.deployment.vaultWasmHash,
    asset: core.deployment.asset.contract,
    feeCaps: { ...core.feeCaps, ...caps },
    now: () => core.now(),
    sleep: (ms: number) => core.sleep(ms),
  };
}

// The vault decides in the ledger a call lands in, not at its simulation, whether an exit is paid at
// once or queued, which IDs the queue's next exits take, which exits release pays and which ID the
// entry queue gives a deposit, so a call simulated against one state of either queue may need
// entries of another. These are the rooms the relayer gives its calls on the exit queue, given
// alike to the wallet's own and to its deposits.

// How many exits queued, or released, ahead of a call in the ledger it lands in leave it room, and
// how many deposits made ahead of a shield leave it room for the ID its own takes.
const EXIT_KEYS = 4n;
const PENDING_KEYS = 4n;
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

const pendingKeys = (vault: string, after: bigint): xdr.LedgerKey[] =>
  Array.from({ length: Number(PENDING_KEYS) }, (_, i) => pendingKey(vault, after + 1n + BigInt(i)));

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

// The room a shield is given: the entries of the PENDING_KEYS deposit IDs after the one its
// simulation took, so as many deposits made ahead of it in the same ledger still leave it room.
// Whichever ID it lands on, it writes one entry of the same size, which its simulation already
// prices; only the entries its footprint declares grow.
export function depositRoom(core: Core): Room {
  return async (footprint) => {
    const id = pendingDeposit(core.deployment.vault, footprint);
    return id === undefined
      ? NO_ROOM
      : { ...NO_ROOM, readWrite: pendingKeys(core.deployment.vault, id) };
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

// Who the exits among these IDs pay: the recipient of each payout and the relayer of each fee.
const payeesOf = (exits: Map<bigint, QueuedExitEntry>): string[] =>
  [...exits.values()].flatMap((e) => [
    ...(e.payout > 0n ? [e.recipient] : []),
    ...(e.fee > 0n ? [e.relayer] : []),
  ]);

// Who a release of up to `max` exits pays: the payees of the exits from the queue's head it handles,
// read as releaseRoom reads the queue.
export async function releasePayees(core: Core, max: number): Promise<string[]> {
  const { status } = await core.services.vault.instance();
  const head = status.exitHead;
  const queued = status.exitTail - head;
  const n = queued < BigInt(max) ? queued : BigInt(max);
  const ids: bigint[] = [];
  for (let id = head; id < head + n; id++) ids.push(id);
  return payeesOf(await core.services.vault.exits(ids));
}

// Who a claim of a stranded exit pays once it is queued again.
export async function claimPayees(core: Core, id: bigint): Promise<string[]> {
  return payeesOf(await core.services.vault.stranded([id]));
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

const keyOf = (positions: readonly number[]): string =>
  [...positions].sort((a, b) => a - b).join(",");

// The sets of note positions of the plans the vault refused as spending a note already spent, as
// every RPC provider showed.
function refusedSets(state: WalletState): Set<string> {
  const ids = new Set(state.suspects.flatMap((s) => s.plans));
  return new Set(
    state.plans.filter((p) => ids.has(p.id)).map((p) => keyOf(p.inputs.map((i) => i.pos))),
  );
}

// The spendable notes a refused plan held: one of each such plan's notes may be spent elsewhere.
// They stay spendable and only go after other notes.
export function suspectNotes(state: WalletState): OwnedNote[] {
  const marked = new Set(state.suspects.map((s) => s.pos));
  return spendableNotes(state).filter((n) => marked.has(n.pos));
}

// Notes for a total, as selectNotes chooses among the notes no refused plan held; else the single
// note or pair that is not a set of notes a refused plan held, whose most refused note was refused
// least, then with the fewest notes refused and the fewest refusals of them. A refusal happens at simulation, so going on to another
// set costs no fee. When every set that covers the total was refused, it fails with notes_refused
// and nothing is proved.
export function chooseNotes(state: WalletState, total: bigint): OwnedNote[] {
  const notes = spendableNotes(state);
  const refusals = new Map(state.suspects.map((s) => [s.pos, s.plans.length]));
  const clean = notes.filter((n) => !refusals.has(n.pos));
  try {
    return selectNotes(clean, total);
  } catch (err) {
    if (!(err instanceof CyphrasError) || clean.length === notes.length) throw err;
  }
  const refused = refusedSets(state);
  const sets = [
    ...notes.map((n) => [n]),
    ...notes.flatMap((a, i) => notes.slice(i + 1).map((b) => [a, b])),
  ].filter((set) => set.reduce((s, n) => s + n.value, 0n) >= total);
  const rank = (set: readonly OwnedNote[]): number[] => [
    Math.max(...set.map((n) => refusals.get(n.pos) ?? 0)),
    set.filter((n) => refusals.has(n.pos)).length,
    set.reduce((s, n) => s + (refusals.get(n.pos) ?? 0), 0),
    set.length,
  ];
  const order = (a: readonly OwnedNote[], b: readonly OwnedNote[]): number => {
    const [ra, rb] = [rank(a), rank(b)];
    for (let i = 0; i < ra.length; i++) {
      if (ra[i] !== rb[i]) return (ra[i] as number) - (rb[i] as number);
    }
    const [sa, sb] = [a, b].map((set) => set.reduce((s, n) => s + n.value, 0n));
    return sa === sb ? 0 : (sa as bigint) < (sb as bigint) ? -1 : 1;
  };
  const allowed = sets.filter((set) => !refused.has(keyOf(set.map((n) => n.pos)))).sort(order);
  const first = allowed[0];
  if (first !== undefined) return first;
  if (sets.length > 0) {
    fail(
      "notes_refused",
      "every set of notes that covers the amount was refused before as spending a note already spent; a later sync that shows which note is spent, or a rescan, may clear it",
    );
  }
  return selectNotes(notes, total);
}

// Whether the vault refused a plan of the same notes as spending a note already spent.
export function refusedNotes(state: WalletState, plan: Plan): boolean {
  return refusedSets(state).has(keyOf(plan.inputs.map((i) => i.pos)));
}

// The vault refused the plan as spending a note already spent, as every RPC provider showed: its
// notes are suspect, and the plan is named on each. A refusal of the same notes as an earlier one
// adds nothing; returns whether there was one.
export function markSuspects(state: WalletState, plan: Plan): boolean {
  const before = refusedNotes(state, plan);
  if (before) return true;
  for (const input of plan.inputs) {
    const at = state.suspects.findIndex((s) => s.pos === input.pos);
    const plans = state.suspects[at]?.plans ?? [];
    if (plans.includes(plan.id)) continue;
    const mark = { pos: input.pos, plans: [...plans, plan.id] };
    if (at < 0) state.suspects.push(mark);
    else state.suspects[at] = mark;
  }
  return before;
}

// Drops what a sync settled: the mark of a note it shows spent, and every mark of a refused plan
// that landed after all, or one of whose notes a transaction that is no landed plan of this wallet
// spent, which explains the refusal. A note this wallet's own landed payment spent was unspent when
// it was refused, so that explains nothing.
export function pruneSuspects(state: WalletState): void {
  const ours = new Set(
    state.plans.filter((p) => LANDED_STATES.includes(p.state)).map((p) => p.txHash),
  );
  const ids = new Set(state.suspects.flatMap((s) => s.plans));
  const explained = new Set(
    state.plans
      .filter((p) => ids.has(p.id))
      .filter(
        (p) =>
          LANDED_STATES.includes(p.state) ||
          p.inputs.some((i) => {
            const spent = state.notes.find((n) => n.pos === i.pos)?.spent;
            return spent !== undefined && !ours.has(spent.txHash);
          }),
      )
      .map((p) => p.id),
  );
  state.suspects = state.suspects
    .filter((s) => state.notes.some((n) => n.pos === s.pos && n.spent === undefined))
    .map((s) => ({ pos: s.pos, plans: s.plans.filter((id) => !explained.has(id)) }))
    .filter((s) => s.plans.length > 0);
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
