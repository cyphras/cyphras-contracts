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
// the plan's. Positions come only from leaves the vault's root confirmed; the spends of the plan's
// notes and the other leaves only from the vault's events the wallet checked, when `checked`.
export interface Evidence {
  readonly txHash: string;
  readonly ledger: number;
  outputs: [number | undefined, number | undefined];
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

// The exit of an unshield in the vault's exit queue: the ID transact gave it, the exits that still
// owe part of it, and how far it follows the chain. Every vault event of a ledger before `ledger`
// is applied, and of `ledger` itself those up to `event`, or all of them when it is undefined, so
// no event is applied twice and no account older than what it shows is taken.
export interface PlanExit {
  readonly id: number;
  parts: ExitPart[];
  ledger: number;
  event: string | undefined;
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
  // The first staged leaf a sync took while RPC could not confirm it, and the ledger it was added at.
  readonly unchecked: { readonly first: number; readonly ledger: number } | undefined;
}

export interface FoundLeaf {
  readonly index: number;
  readonly commitment: bigint;
  readonly ledger: number;
  readonly txHash: string;
}

// What syncs took from the indexer while RPC could not confirm it: the spends of the ledgers from
// `from` to `to`, none when `from` is past `to`, and the leaves at positions from `first` up to
// `end`, the first of them added at `ledger`. `lost` once RPC no longer holds them, so that nothing
// can check them any more.
export interface UncheckedRange {
  readonly from: number;
  readonly to: number;
  readonly leaves:
    | { readonly first: number; readonly end: number; readonly ledger: number }
    | undefined;
  readonly lost: boolean;
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
}

export function emptyState(deployLedger: number): WalletState {
  return {
    version: 2,
    revision: 0,
    tree: { leafCount: 0, upper: [], partial: [] },
    lastLeafLedger: 0,
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
