import { CIPHERTEXT_LENGTH } from "../encryption.ts";
import { CyphrasError, fail } from "../errors.ts";
import { isAccountId, isContractId } from "../extdata.ts";
import { PAGE_SIZE } from "../merkle.ts";
import { type FetchLike, Fields, joinUrl, requestJson } from "./http.ts";

// The indexer's API, with the field names the services serve: binary values are
// lowercase hex, field elements may carry a 0x prefix, amounts are decimal strings and absent
// values are null.

export interface ServiceIdentity {
  readonly ready: boolean;
  readonly code: string | undefined;
  readonly vault: string;
  readonly networkId: string;
}

export interface IndexerHealth extends ServiceIdentity {
  readonly latestLedger: number | undefined;
  readonly ingestedLedger: number | undefined;
  readonly leafCount: number | undefined;
}

export interface Leaf {
  readonly index: number;
  readonly commitment: bigint;
  readonly ciphertext: Uint8Array;
  readonly ledger: number;
  readonly txHash: string;
}

export interface SpentNullifier {
  readonly nullifier: bigint;
  readonly ledger: number;
  readonly txHash: string;
}

export interface NullifierPage {
  readonly nullifiers: readonly SpentNullifier[];
  readonly cursor: string | undefined;
  readonly completeToLedger: number;
}

export interface QueuedDeposit {
  readonly id: number;
  readonly depositor: string;
  readonly amount: bigint;
  readonly createdAt: number;
  // Unknown until the indexer has read the deposit's delay.
  readonly earliestAdmission: number | undefined;
  readonly attested: boolean;
  readonly flag: { readonly reason: number; readonly flaggedAt: number | undefined } | undefined;
}

export interface ResolvedDeposit {
  readonly id: number;
  readonly depositor: string;
  readonly amount: bigint;
  readonly outcome: "admitted" | "cancelled" | "refunded";
  readonly reason: number | undefined;
  readonly leafIndices: readonly [number, number] | undefined;
}

export interface DepositQueue {
  readonly pending: readonly QueuedDeposit[];
  readonly resolved: readonly ResolvedDeposit[];
}

// A requeued exit is a stranded one whose claims moved all it still owed back into the queue.
export type ExitState = "queued" | "paid_in_part" | "stranded" | "requeued" | "settled";

// One exit as the indexer serves it: payoutLeft and feeLeft are what the vault still owes under
// its ID.
export interface ExitEntry {
  readonly id: number;
  readonly state: ExitState;
  // Set while the exit is in the queue: its place from the head, and the end of the UTC day by
  // which releases have paid it at the latest, in Unix seconds.
  readonly position: number | undefined;
  readonly paidBy: number | undefined;
  readonly payoutLeft: bigint;
  readonly feeLeft: bigint;
  // The transaction that queued the exit: a transact, or the claim that requeued it.
  readonly txHash: string;
  // The stranded exit a claim queued this one from, and the exits claims queued from this one.
  readonly requeuedFrom: number | undefined;
  readonly requeuedTo: readonly number[];
}

// The vault's exit queue as the indexer serves it: every queued exit from the head in order,
// every stranded one, and those paid in full or requeued lately.
export interface ExitQueue {
  readonly head: number;
  readonly tail: number;
  readonly exits: readonly ExitEntry[];
  readonly completeTo: number;
}

const EXIT_STATES: readonly ExitState[] = [
  "queued",
  "paid_in_part",
  "stranded",
  "requeued",
  "settled",
];

export interface PoolStats {
  readonly leafCount: number;
  readonly admittedDeposits: number;
  readonly distinctDepositors: number;
  readonly pendingDeposits: number;
}

export function readIdentity(f: Fields): ServiceIdentity {
  const vault = f.string("vault");
  if (!isContractId(vault)) f.fault("vault is not a contract");
  return {
    ready: f.boolean("ready"),
    code: f.has("code") ? f.string("code") : undefined,
    vault,
    networkId: f.hash("network_id"),
  };
}

const optionalInt = (f: Fields, key: string): number | undefined =>
  f.has(key) ? f.integer(key) : undefined;

export class IndexerClient {
  readonly url: string;
  readonly #fetch: FetchLike;

  constructor(url: string, fetchFn: FetchLike) {
    this.url = url;
    this.#fetch = fetchFn;
  }

  async #get(path: string): Promise<Fields> {
    const { status, body } = await requestJson(this.#fetch, "indexer", joinUrl(this.url, path));
    if (status === 503) {
      throw new CyphrasError("service_unavailable", "the indexer is not ready", {
        service: "indexer",
      });
    }
    if (status !== 200) {
      fail("service_unavailable", `the indexer answered ${status}`, { service: "indexer" });
    }
    return Fields.of(body, "indexer_fault", "indexer reply");
  }

  async health(): Promise<IndexerHealth> {
    const { body } = await requestJson(this.#fetch, "indexer", joinUrl(this.url, "/v1/health"));
    const f = Fields.of(body, "indexer_fault", "indexer health");
    return {
      ...readIdentity(f),
      latestLedger: optionalInt(f, "latest_ledger"),
      ingestedLedger: optionalInt(f, "ingested_ledger"),
      leafCount: optionalInt(f, "leaf_count"),
    };
  }

  // Leaves 1024 * page to 1024 * page + 1023 that exist, checked to be exactly that range in
  // order and to carry 181-byte ciphertexts.
  async leaves(page: number): Promise<Leaf[]> {
    const f = await this.#get(`/v1/leaves?page=${page}`);
    if (f.integer("page") !== page) f.fault("the page number differs from the request");
    const list = f.array("leaves");
    if (list.length > PAGE_SIZE) f.fault("a page holds more than 1024 leaves");
    return list.map((raw, i) => {
      const leaf = f.item(raw, i, "leaves");
      const index = leaf.integer("index");
      if (index !== page * PAGE_SIZE + i) leaf.fault("leaf indices are not contiguous");
      return {
        index,
        commitment: leaf.field("commitment"),
        ciphertext: leaf.bytes("ciphertext", CIPHERTEXT_LENGTH),
        ledger: leaf.integer("ledger", 1),
        txHash: leaf.hash("tx_hash"),
      };
    });
  }

  async nullifiers(sinceLedger: number, cursor?: string): Promise<NullifierPage> {
    const query =
      `since_ledger=${sinceLedger}` + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : "");
    const f = await this.#get(`/v1/nullifiers?${query}`);
    let previous = 0;
    const nullifiers = f.array("nullifiers").map((raw, i) => {
      const n = f.item(raw, i, "nullifiers");
      const ledger = n.integer("ledger", 1);
      if (ledger < sinceLedger || ledger < previous) n.fault("nullifiers are not in chain order");
      previous = ledger;
      return { nullifier: n.field("nullifier"), ledger, txHash: n.hash("tx_hash") };
    });
    if (nullifiers.length > 4096) f.fault("more than 4096 nullifiers in one reply");
    const next = f.has("next_cursor") ? f.string("next_cursor") : undefined;
    return {
      nullifiers,
      cursor: next === "" ? undefined : next,
      completeToLedger: f.integer("complete_to"),
    };
  }

  async deposits(): Promise<DepositQueue> {
    const f = await this.#get("/v1/deposits");
    const pending = f.array("pending").map((raw, i): QueuedDeposit => {
      const d = f.item(raw, i, "pending");
      const depositor = d.string("depositor");
      if (!isAccountId(depositor) && !isContractId(depositor)) d.fault("bad depositor");
      return {
        id: d.integer("id", 1),
        depositor,
        amount: d.amount("amount"),
        createdAt: d.integer("created_at"),
        earliestAdmission: optionalInt(d, "earliest_admission"),
        attested: d.boolean("attested"),
        flag: d.has("flag_reason")
          ? { reason: d.integer("flag_reason", 1), flaggedAt: optionalInt(d, "flagged_at") }
          : undefined,
      };
    });
    const resolved = f.array("resolved").map((raw, i): ResolvedDeposit => {
      const d: Fields = f.item(raw, i, "resolved");
      const outcome = d.string("outcome");
      if (outcome !== "admitted" && outcome !== "cancelled" && outcome !== "refunded") {
        d.fault("unknown outcome");
      }
      const first = optionalInt(d, "leaf_index0");
      const second = optionalInt(d, "leaf_index1");
      if ((first === undefined) !== (second === undefined))
        d.fault("one leaf index without the other");
      return {
        id: d.integer("id", 1),
        depositor: d.string("depositor"),
        amount: d.amount("amount"),
        outcome,
        reason: optionalInt(d, "reason"),
        leafIndices: first === undefined ? undefined : [first, second as number],
      };
    });
    return { pending, resolved };
  }

  async exits(): Promise<ExitQueue> {
    const f = await this.#get("/v1/exits");
    const head = f.integer("head", 1);
    const tail = f.integer("tail", head);
    const exits = f.array("exits").map((raw, i): ExitEntry => {
      const e: Fields = f.item(raw, i, "exits");
      const id = e.integer("id", 1);
      const state = e.string("state") as ExitState;
      if (!EXIT_STATES.includes(state)) e.fault("unknown exit state");
      const inQueue = state === "queued" || state === "paid_in_part";
      const position = inQueue ? e.integer("position") : undefined;
      if (inQueue ? id !== head + (position as number) : id >= head) {
        e.fault("an exit lies on the wrong side of the queue's head");
      }
      // A claim queues at the tail, after every exit it could come from.
      const requeuedFrom = e.has("requeued_from") ? e.integer("requeued_from", 1) : undefined;
      const requeuedTo = e.has("requeued_to") ? e.integers("requeued_to", 1) : [];
      if ((requeuedFrom ?? 0) >= id || requeuedTo.some((to) => to <= id)) {
        e.fault("an exit is requeued from a later exit");
      }
      return {
        id,
        state,
        position,
        paidBy: inQueue ? e.integer("paid_by") : undefined,
        payoutLeft: e.amount("payout_left"),
        feeLeft: e.amount("fee_left"),
        txHash: e.hash("tx_hash"),
        requeuedFrom,
        requeuedTo,
      };
    });
    const positions = exits
      .flatMap((e) => (e.position === undefined ? [] : [e.position]))
      .sort((a, b) => a - b);
    if (positions.length !== tail - head || positions.some((p, i) => p !== i)) {
      f.fault("the queue does not list every exit from its head to its tail, in order");
    }
    return { head, tail, exits, completeTo: f.integer("complete_to") };
  }

  async stats(): Promise<PoolStats> {
    const f = await this.#get("/v1/stats");
    return {
      leafCount: f.integer("leaf_count"),
      admittedDeposits: f.integer("admitted_deposits"),
      distinctDepositors: f.integer("distinct_depositors"),
      pendingDeposits: f.integer("pending_deposits"),
    };
  }
}
