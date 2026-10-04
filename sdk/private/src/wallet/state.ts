import { bytesToHex, hexToBytes } from "../bytes.ts";
import { fail } from "../errors.ts";
import type { ExtDataJson, TxProofJson } from "../extdata.ts";
import type { TreeSnapshot } from "../merkle.ts";
import type { SealedStore } from "../storage.ts";

export interface SpentBy {
  readonly txHash: string;
  readonly ledger: number;
}

// What one transaction showed of a plan: the leaf positions at which it added the plan's two output
// commitments, which of the plan's two nullifiers it spent, and whether it added a leaf that is not
// the plan's. Positions come only from leaves the vault's root confirmed, as read from `providers`
// RPC providers; the spends of the plan's notes and the other leaves only from the vault's events
// the wallet checked, when `checked`.
export interface Evidence {
  readonly txHash: string;
  readonly ledger: number;
  outputs: [number | undefined, number | undefined];
  providers: number;
  nullifiers: [boolean, boolean];
  foreign: boolean;
  checked: boolean;
}

// A note of this wallet that is in the tree.
export interface OwnedNote {
  readonly pos: number;
  readonly cm: bigint;
  readonly value: bigint;
  readonly d: Uint8Array;
  readonly rcm: bigint;
  // Unknown to a wallet that holds only an incoming viewing key.
  readonly nf: bigint | undefined;
  readonly ledger: number;
  readonly txHash: string;
  // The siblings inside its page, captured when the page completes.
  pagePath: bigint[] | undefined;
  spent: SpentBy | undefined;
  // The outgoing key opens it too: the wallet built it, as change or a deposit of its own.
  built: boolean;
}

// An output this wallet built for another address, recovered with the outgoing viewing key.
export interface SentNote {
  readonly pos: number;
  readonly cm: bigint;
  readonly value: bigint;
  readonly rcm: bigint;
  readonly esk: bigint;
  readonly address: string;
  readonly ledger: number;
  readonly txHash: string;
}

export type PlanState =
  | "prepared"
  | "submitted"
  | "confirmed"
  | "queued"
  | "settled"
  | "stranded"
  | "superseded"
  | "dead";

export const ACTIVE_STATES: readonly PlanState[] = ["prepared", "submitted"];
export const LANDED_STATES: readonly PlanState[] = ["confirmed", "queued", "settled", "stranded"];

export interface PlanOutput {
  readonly cm: bigint;
  readonly value: bigint;
  readonly address: string;
  readonly own: boolean;
  readonly rcm: bigint;
  readonly esk: bigint;
}

export type Route =
  | { readonly kind: "relayer"; readonly url: string }
  | { readonly kind: "self"; readonly account: string };

// One exit that still owes part of an unshield's payout or fee: the exit transact queued, or one a
// claim requeued a stranded part as.
export interface ExitPart {
  readonly id: number;
  payoutLeft: bigint;
  feeLeft: bigint;
  stranded: boolean;
}

// The exit of an unshield in the vault's exit queue: the ID transact gave it, every exit known to
// hold or have held part of it, with what each still owes, and how far it follows the chain. Every
// vault event of a ledger before `ledger` is applied, and of `ledger` itself those up to `event`,
// or all of them when it is undefined, so no event is applied twice and no account older than what
// it shows is taken. `confirmed` while the parts follow the vault's events every RPC provider
// showed, from the exit's queueing on without a gap, rather than resting in part on the indexer's
// account. `account` is the indexer's account of a confirmed exit, newer than its events: what the
// plan shows, unconfirmed, until the events reach its ledger.
export interface PlanExit {
  readonly id: number;
  parts: ExitPart[];
  ledger: number;
  event: string | undefined;
  confirmed: boolean;
  account: { readonly parts: ExitPart[]; readonly ledger: number } | undefined;
}

// A spend, saved before anything is submitted.
export interface Plan {
  readonly id: string;
  readonly kind: "send" | "unshield";
  state: PlanState;
  readonly createdAt: number;
  readonly route: Route;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly to: string;
  // The unshield's destination did not exist when it was built, so its payout creates it.
  readonly createsAccount: boolean;
  readonly inputs: readonly { readonly pos: number; readonly nf: bigint; readonly value: bigint }[];
  readonly nullifiers: readonly [bigint, bigint];
  readonly commitments: readonly [bigint, bigint];
  readonly outputs: readonly PlanOutput[];
  readonly root: bigint;
  // The ledger of the vault read whose root history held `root` when the plan was built.
  readonly builtAt: number;
  readonly deadline: number;
  readonly ext: ExtDataJson;
  readonly proof: TxProofJson;
  readonly notBefore: number | undefined;
  readonly operationId: string | undefined;
  readonly retryOf: string | undefined;
  txHash: string | undefined;
  // The relayer's ID of a request it holds until not_before, until the request has a hash.
  heldId: string | undefined;
  ledger: number | undefined;
  // Keyed by transaction: the plan is confirmed only when one transaction carries both its
  // nullifiers and both its commitments.
  evidence: Evidence[];
  relayerStatus: string | undefined;
  exit: PlanExit | undefined;
  error: string | undefined;
}

export type DepositState =
  | "submitting"
  | "pending"
  | "admitted"
  | "cancelled"
  | "refunded"
  | "failed";

export interface Deposit {
  id: number | undefined;
  readonly depositor: string;
  readonly amount: bigint;
  readonly commitments: readonly [bigint, bigint];
  readonly createdAt: number;
  // The ledger the deposit was built at, and the last one at which it can land.
  readonly builtAt: number;
  readonly deadline: number;
  txHash: string | undefined;
  state: DepositState;
  attested: boolean | undefined;
  earliestAdmission: number | undefined;
  flag: { readonly reason: number; readonly flaggedAt: number | undefined } | undefined;
  leafIndices: readonly [number, number] | undefined;
  refundReason: number | undefined;
  // The state and the entry queue's details rest on every RPC provider's reads of the entry queue,
  // the wallet's own transactions every provider reports, the vault's events every provider showed
  // and the confirmed tree, rather than on the indexer's account.
  confirmed: boolean;
  // The newest ledger at which a provider showed the deposit in the entry queue; the ledger by
  // which every provider showed it gone, on reads past that and past its proof's deadline; and
  // whether this wallet sent its cancel or refund.
  seenAt: number | undefined;
  goneAt: number | undefined;
  ownReturn: "cancelled" | "refunded" | undefined;
}

// A payment spread over several transactions, each within the vault's single-exit cap and sent
// after the previous one landed and a random gap passed.
export interface Operation {
  readonly id: string;
  readonly kind: "split_unshield";
  readonly to: string;
  readonly total: bigint;
  readonly partSize: bigint;
  readonly maxFee: bigint;
  readonly route:
    | { readonly kind: "relayers"; readonly urls: readonly string[] }
    | { readonly kind: "self"; readonly account: string };
  // The part whose landing starts the gap before the next one.
  awaiting: string | undefined;
  nextAt: number;
  // Blocked by a part that did not land whose notes were spent elsewhere: sending it again with
  // other notes could pay twice, so the caller decides, unless the part lands after all. Abandoned
  // by the caller, it sends nothing more.
  state: "active" | "done" | "blocked" | "abandoned";
  blockedBy: string | undefined;
}

// Leaves taken past the confirmed tree, and what this wallet found in them, held until the vault's
// root history confirms them: a sync that stops at its page cap far behind the vault leaves its
// progress here. Nothing in it counts in the balance or the history.
export interface Staging {
  readonly tree: TreeSnapshot;
  readonly lastLeafLedger: number;
  readonly notes: OwnedNote[];
  readonly sent: SentNote[];
  // Paths of confirmed notes whose page the staged leaves completed.
  readonly paths: { readonly pos: number; readonly pagePath: bigint[] }[];
  // The staged leaves that hold a plan's output commitment.
  readonly found: readonly FoundLeaf[];
  // The first staged leaf a sync took while RPC could not confirm it, the ledger it was added at,
  // and the digests of the staged leaves from it on.
  readonly unchecked:
    | { readonly first: number; readonly ledger: number; readonly chunks: readonly LeafChunk[] }
    | undefined;
}

// A digest of the leaves from the previous chunk's end, or the range's first leaf, up to `end`:
// their positions, commitments, ciphertexts, ledgers and transactions, as a sync took them.
export interface LeafChunk {
  readonly end: number;
  readonly digest: string;
}

export interface FoundLeaf {
  readonly index: number;
  readonly commitment: bigint;
  readonly ledger: number;
  readonly txHash: string;
}

// What syncs took from the indexer while not every RPC provider could confirm it: the spends of
// the ledgers from `from` to `to`, none when `from` is past `to`, and the leaves at positions from
// `first` up to `end`, the first of them added at `ledger`, kept as digests of runs of them. "open"
// while the providers may still confirm it; "partial" while some provider no longer holds it and
// every other one showed it as the syncs took it, asked about again an hour after `askedAt`, in
// milliseconds of the wallet's clock, in case every provider holds it once more; "lost" once none
// holds it, so that nothing can check it any more.
export interface UncheckedRange {
  readonly from: number;
  readonly to: number;
  readonly leaves:
    | {
        readonly first: number;
        readonly end: number;
        readonly ledger: number;
        readonly chunks: readonly LeafChunk[];
      }
    | undefined;
  readonly status: "open" | "partial" | "lost";
  readonly askedAt: number | undefined;
}

// A ledger and the Unix second it closed at.
export interface LedgerTime {
  readonly ledger: number;
  readonly at: number;
}

export interface RootCheck {
  readonly state: "verified" | "behind" | "mismatch";
  readonly ledger: number;
  readonly root: bigint;
  readonly roots: readonly bigint[];
}

export interface WalletState {
  readonly version: 2;
  // One more at every save, so an instance can tell that another one saved since it read.
  revision: number;
  tree: TreeSnapshot;
  lastLeafLedger: number;
  // The ledger at which the newest leaf whose ledger a cross-check or a recheck confirmed was added.
  checkedLeafLedger: number;
  staging: Staging | undefined;
  nullifierSince: number;
  // Every other ledger before nullifierSince, since the wallet started, was cross-checked, and so
  // was every other leaf of the tree.
  unchecked: UncheckedRange[];
  nullifierBuffer: { readonly nf: bigint; readonly ledger: number; readonly txHash: string }[];
  notes: OwnedNote[];
  sent: SentNote[];
  plans: Plan[];
  deposits: Deposit[];
  operations: Operation[];
  rootCheck: RootCheck | undefined;
  // Close times of the last hour that RPC reported, from which the pace of ledgers is taken.
  ledgerTimes: LedgerTime[];
}

export function emptyState(deployLedger: number): WalletState {
  return {
    version: 2,
    revision: 0,
    tree: { leafCount: 0, upper: [], partial: [] },
    lastLeafLedger: 0,
    checkedLeafLedger: 0,
    staging: undefined,
    nullifierSince: deployLedger,
    unchecked: [],
    nullifierBuffer: [],
    notes: [],
    sent: [],
    plans: [],
    deposits: [],
    operations: [],
    rootCheck: undefined,
    ledgerTimes: [],
  };
}

// JSON with bigint and byte values tagged, so the state round-trips exactly. A bigint is its sign
// followed by its magnitude in hex.
function replacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") {
    return { $n: (value < 0n ? "-" : "+") + (value < 0n ? -value : value).toString(16) };
  }
  if (value instanceof Uint8Array) return { $b: bytesToHex(value) };
  return value;
}

const BIGINT = /^([+-])([0-9a-f]+)$/;

// The state never stores null, and JSON turns an undefined array element into null.
function reviver(_key: string, value: unknown): unknown {
  if (value === null) return undefined;
  if (typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value);
    const record = value as Record<string, unknown>;
    if (keys.length === 1 && typeof record["$n"] === "string") {
      const parts = BIGINT.exec(record["$n"]);
      if (parts === null) fail("storage_unreadable", "the stored state holds a malformed number");
      const magnitude = BigInt("0x" + parts[2]);
      return parts[1] === "-" ? -magnitude : magnitude;
    }
    if (keys.length === 1 && typeof record["$b"] === "string") return hexToBytes(record["$b"]);
  }
  return value;
}

const STATE_RECORD = "state";
// The last revision saved, written after the state itself.
const REVISION_RECORD = "revision";

export async function loadState(store: SealedStore): Promise<WalletState | undefined> {
  const bytes = await store.read(STATE_RECORD);
  if (bytes === undefined) return undefined;
  const state = JSON.parse(new TextDecoder().decode(bytes), reviver) as WalletState;
  if (state.version !== 2) fail("storage_unreadable", "the stored state has an unknown version");
  // A state need not hold close times yet, nor a checked leaf's ledger; its next syncs record them.
  // Leaves it took unchecked without digests a recheck compares up to the last of them can no
  // longer be checked, and leaves it staged without them the next sync takes again. A range kept
  // as lost without a status was given up on the first RPC provider's word alone, and is open again
  // for every provider to be asked.
  state.ledgerTimes ??= [];
  state.checkedLeafLedger ??= 0;
  state.unchecked = state.unchecked.map((stored) => {
    const { lost: _lost, ...range } = stored as UncheckedRange & { readonly lost?: boolean };
    const { leaves } = range;
    const undigested =
      leaves !== undefined &&
      (leaves.chunks === undefined ||
        (leaves.chunks[leaves.chunks.length - 1]?.end ?? leaves.first) !== leaves.end);
    return { ...range, status: undigested ? "lost" : (range.status ?? "open") };
  });
  if (state.staging?.unchecked !== undefined && state.staging.unchecked.chunks === undefined) {
    state.staging = undefined;
  }
  // A landing kept without the count of RPC providers that confirmed it rests on the first one's
  // root alone.
  for (const e of state.plans.flatMap((p) => p.evidence)) {
    e.providers ??= e.outputs.some((pos) => pos !== undefined) ? 1 : 0;
  }
  // Exits and deposits kept without saying what they rest on count as the indexer's word; a deposit
  // then cancelled was by its depositor.
  for (const plan of state.plans) {
    if (plan.exit !== undefined) plan.exit.confirmed ??= false;
  }
  for (const deposit of state.deposits) {
    if (deposit.confirmed === undefined && deposit.state === "cancelled") {
      deposit.ownReturn = "cancelled";
    }
    deposit.confirmed ??= false;
  }
  return state;
}

export async function saveState(store: SealedStore, state: WalletState): Promise<void> {
  await store.write(STATE_RECORD, new TextEncoder().encode(JSON.stringify(state, replacer)));
}

// The state of one account in its sealed store. A save first checks that the store still holds the
// revision this instance read, which catches an instance that saved in between. It does not stop
// two saves that interleave on an asynchronous store: only the account lock keeps instances apart.
export class StateStore {
  readonly #store: SealedStore;
  // The highest revision this instance has read or written.
  #seen = 0;

  constructor(store: SealedStore) {
    this.#store = store;
  }

  // The stored state, refused when it is older than one this instance already saw, or than the
  // last revision any instance recorded: the store was rolled back. A rollback of the whole store
  // goes unnoticed across a reopen.
  async load(): Promise<WalletState | undefined> {
    const state = await loadState(this.#store);
    const recorded = await this.#store.read(REVISION_RECORD);
    const last = recorded === undefined ? 0 : Number(new TextDecoder().decode(recorded));
    if ((state?.revision ?? 0) < Math.max(this.#seen, last)) {
      fail("state_conflict", "the stored state is older than one this wallet saw", {
        conflict: "older",
      });
    }
    if (state === undefined) return undefined;
    this.#seen = state.revision;
    return state;
  }

  // Drops a stored state that cannot be read, so that a fresh one can be saved in its place.
  async discard(): Promise<void> {
    await this.#store.remove(STATE_RECORD);
    await this.#store.remove(REVISION_RECORD);
    this.#seen = 0;
  }

  // Saves `state` as the next revision if the store still holds the revision it was read at.
  async save(state: WalletState): Promise<void> {
    const stored = (await loadState(this.#store))?.revision ?? 0;
    if (stored !== state.revision) {
      fail("state_conflict", "another instance of this wallet saved since this one read", {
        conflict: stored > state.revision ? "newer" : "older",
      });
    }
    await saveState(this.#store, { ...state, revision: state.revision + 1 });
    state.revision += 1;
    this.#seen = state.revision;
    await this.#store.write(REVISION_RECORD, new TextEncoder().encode(String(state.revision)));
  }
}
