import { bytesToHex, hexToBytes } from "../bytes.ts";
import { fail } from "../errors.ts";
import type { ExtDataJson, TxProofJson } from "../extdata.ts";
import type { TreeSnapshot } from "../merkle.ts";
import type { SealedStore } from "../storage.ts";

export interface SpentBy {
  readonly txHash: string;
  readonly ledger: number;
}

// What one transaction showed of a plan: which of the plan's two nullifiers it spent, and the leaf
// positions at which it added the plan's two output commitments.
export interface Evidence {
  readonly txHash: string;
  readonly ledger: number;
  readonly nullifiers: [boolean, boolean];
  readonly outputs: [number | undefined, number | undefined];
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
  | "claimed"
  | "superseded"
  | "dead";

export const ACTIVE_STATES: readonly PlanState[] = ["prepared", "submitted"];

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

// The exit of an unshield in the vault's exit queue, and what it still owes.
export interface PlanExit {
  readonly id: number;
  payoutLeft: bigint;
  feeLeft: bigint;
}

// A spend, saved before anything is submitted (sdk.md, Submission state machine).
export interface Plan {
  readonly id: string;
  readonly kind: "send" | "unshield";
  state: PlanState;
  readonly createdAt: number;
  readonly route: Route;
  readonly amount: bigint;
  readonly fee: bigint;
  readonly to: string;
  readonly inputs: readonly { readonly pos: number; readonly nf: bigint; readonly value: bigint }[];
  readonly nullifiers: readonly [bigint, bigint];
  readonly commitments: readonly [bigint, bigint];
  readonly outputs: readonly PlanOutput[];
  readonly root: bigint;
  readonly deadline: number;
  readonly ext: ExtDataJson;
  readonly proof: TxProofJson;
  readonly notBefore: number | undefined;
  readonly operationId: string | undefined;
  readonly retryOf: string | undefined;
  txHash: string | undefined;
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
  state: "active" | "done";
}

export interface RootCheck {
  readonly state: "verified" | "behind" | "mismatch";
  readonly ledger: number;
  readonly root: bigint;
  readonly roots: readonly bigint[];
}

export interface WalletState {
  readonly version: 2;
  tree: TreeSnapshot;
  lastLeafLedger: number;
  nullifierSince: number;
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
    tree: { leafCount: 0, upper: [], partial: [] },
    lastLeafLedger: 0,
    nullifierSince: deployLedger,
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
