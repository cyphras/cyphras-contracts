import { CIPHERTEXT_LENGTH } from "../encryption.ts";
import { CyphrasError, fail } from "../errors.ts";
import { isAccountId, isContractId } from "../extdata.ts";
import { PAGE_SIZE } from "../merkle.ts";
import { type FetchLike, Fields, joinUrl, requestJson } from "./http.ts";

// The indexer API of services.md. The JSON shapes below are this SDK's reading of it: binary
// values are lowercase hex, field elements may carry a 0x prefix, and amounts are decimal strings.

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
  readonly earliestAdmission: number;
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

export interface ExitEntry {
  readonly id: number;
  readonly payout: bigint;
  readonly fee: bigint;
  readonly recipient: string;
  // The transact that queued the exit.
  readonly txHash: string;
  readonly ledger: number;
}

export interface ResolvedExit {
  readonly id: number;
  readonly outcome: "paid" | "stranded" | "claimed";
  readonly txHash: string;
}

// The vault's FIFO exit queue. services.md does not define this endpoint yet; these are the
// fields the SDK needs to place a queued payout and estimate when it is paid.
export interface ExitQueue {
  readonly head: number;
  readonly tail: number;
  readonly queued: readonly ExitEntry[];
  readonly stranded: readonly ExitEntry[];
  readonly resolved: readonly ResolvedExit[];
  readonly completeToLedger: number;
}

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
    const next = f.has("cursor") ? f.string("cursor") : undefined;
    return {
      nullifiers,
      cursor: next === "" ? undefined : next,
      completeToLedger: f.integer("complete_to_ledger"),
    };
  }

  async deposits(): Promise<DepositQueue> {
    const f = await this.#get("/v1/deposits");
    const pending = f.array("pending").map((raw, i): QueuedDeposit => {
      const d = f.item(raw, i, "pending");
      const depositor = d.string("depositor");
      if (!isAccountId(depositor) && !isContractId(depositor)) d.fault("bad depositor");
      let flag: QueuedDeposit["flag"];
      if (d.has("flag")) {
        const fl = d.object("flag");
        flag = { reason: fl.integer("reason", 1), flaggedAt: optionalInt(fl, "flagged_at") };
      }
      return {
        id: d.integer("id", 1),
        depositor,
        amount: d.amount("amount"),
        createdAt: d.integer("created_at"),
        earliestAdmission: d.integer("earliest_admission"),
        attested: d.boolean("attested"),
        flag,
      };
    });
    const resolved = f.array("resolved").map((raw, i): ResolvedDeposit => {
      const d: Fields = f.item(raw, i, "resolved");
      const outcome = d.string("outcome");
      if (outcome !== "admitted" && outcome !== "cancelled" && outcome !== "refunded") {
        d.fault("unknown outcome");
      }
      let leafIndices: ResolvedDeposit["leafIndices"];
      if (d.has("leaf_indices")) {
        const pair = d.array("leaf_indices");
        if (pair.length !== 2 || !pair.every((x) => Number.isSafeInteger(x)))
          d.fault("bad leaf indices");
        leafIndices = [pair[0] as number, pair[1] as number];
      }
      return {
        id: d.integer("id", 1),
        depositor: d.string("depositor"),
        amount: d.amount("amount"),
        outcome,
        reason: optionalInt(d, "reason"),
        leafIndices,
      };
    });
    return { pending, resolved };
  }

  // Undefined when the indexer serves a vault without an exit queue.
  async exits(): Promise<ExitQueue | undefined> {
    const { status, body } = await requestJson(
      this.#fetch,
      "indexer",
      joinUrl(this.url, "/v1/exits"),
    );
    if (status === 404) return undefined;
    if (status !== 200) {
      fail("service_unavailable", `the indexer answered ${status}`, { service: "indexer" });
    }
    const f = Fields.of(body, "indexer_fault", "indexer exits");
    const entry = (list: string) =>
      f.array(list).map((raw, i): ExitEntry => {
        const e: Fields = f.item(raw, i, list);
        return {
          id: e.integer("id"),
          payout: e.amount("payout"),
          fee: e.amount("fee"),
          recipient: e.string("recipient"),
          txHash: e.hash("tx_hash"),
          ledger: e.integer("ledger", 1),
        };
      });
    const queued = entry("queued");
    let previous = -1;
    for (const e of queued) {
      if (e.id <= previous) f.fault("queued exits are not in ascending order");
      previous = e.id;
    }
    return {
      head: f.integer("head"),
      tail: f.integer("tail"),
      queued,
      stranded: entry("stranded"),
      resolved: f.array("resolved").map((raw, i): ResolvedExit => {
        const e: Fields = f.item(raw, i, "resolved");
        const outcome = e.string("outcome");
        if (outcome !== "paid" && outcome !== "stranded" && outcome !== "claimed") {
          e.fault("unknown exit outcome");
        }
        return { id: e.integer("id"), outcome, txHash: e.hash("tx_hash") };
      }),
      completeToLedger: f.integer("complete_to_ledger"),
    };
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
