import { StrKey, xdr } from "@stellar/stellar-base";
import { CyphrasError, fail } from "../errors.ts";
import { type FetchLike, Fields, requestJson } from "./http.ts";

export interface LedgerEntry {
  readonly key: xdr.LedgerKey;
  readonly data: xdr.LedgerEntryData;
  readonly lastModifiedLedger: number;
  readonly liveUntilLedger: number | undefined;
}

export interface LedgerEntries {
  readonly latestLedger: number;
  // Keyed by the base64 XDR of each requested key; keys with no live entry are absent.
  readonly entries: ReadonlyMap<string, LedgerEntry>;
}

export interface Simulation {
  readonly transactionData: string;
  readonly minResourceFee: bigint;
  readonly auth: readonly string[];
  readonly result: xdr.ScVal | undefined;
  readonly latestLedger: number;
  readonly needsRestore: boolean;
  // The vault error code when the simulation failed in the contract.
  readonly contractError: number | undefined;
  readonly failed: boolean;
}

export type SendStatus = "PENDING" | "DUPLICATE" | "TRY_AGAIN_LATER" | "ERROR";

// A contract event of one transaction, read from its result meta.
export interface MetaEvent {
  readonly contractId: string | undefined;
  readonly topic: readonly xdr.ScVal[];
  readonly value: xdr.ScVal;
}

export interface TransactionStatus {
  readonly status: "SUCCESS" | "FAILED" | "NOT_FOUND";
  readonly ledger: number | undefined;
  readonly latestLedger: number;
  readonly returnValue: xdr.ScVal | undefined;
  readonly events: readonly MetaEvent[];
}

export interface ContractEvent {
  readonly id: string;
  readonly ledger: number;
  // Unix seconds at which its ledger closed, when RPC says.
  readonly closedAt: number | undefined;
  readonly txHash: string;
  readonly contractId: string;
  readonly topic: readonly xdr.ScVal[];
  readonly value: xdr.ScVal;
  readonly successful: boolean;
}

export interface EventPage {
  readonly events: readonly ContractEvent[];
  readonly cursor: string | undefined;
  readonly latestLedger: number;
  readonly oldestLedger: number;
  // Unix seconds at which those two ledgers closed, when RPC says.
  readonly latestCloseTime: number | undefined;
  readonly oldestCloseTime: number | undefined;
}

// A close time, which RPC sends as a decimal string of Unix seconds.
const closeTime = (f: Fields, key: string): number | undefined =>
  f.has(key) ? Number(f.amount(key)) : undefined;

export const keyId = (key: xdr.LedgerKey): string => key.toXDR("base64");

// A Soroban RPC client over JSON-RPC 2.0. Failures carry the method and the RPC error code only.
export class SorobanRpc {
  readonly #url: string;
  readonly #fetch: FetchLike;
  #nextId = 1;

  constructor(url: string, fetchFn: FetchLike) {
    this.#url = url;
    this.#fetch = fetchFn;
  }

  async call(method: string, params?: unknown): Promise<Fields> {
    const { status, body } = await requestJson(this.#fetch, "RPC", this.#url, {
      method: "POST",
      body: { jsonrpc: "2.0", id: this.#nextId++, method, params },
    });
    const reply = Fields.of(body, "rpc_error", `RPC ${method}`);
    if (reply.has("error")) {
      const error = reply.object("error");
      const code = typeof error.raw("code") === "number" ? (error.raw("code") as number) : 0;
      throw new CyphrasError("rpc_error", `the RPC refused ${method}`, { method, code });
    }
    if (status !== 200) fail("rpc_error", `the RPC answered ${method} with ${status}`, { method });
    return reply.object("result");
  }

  async getNetworkPassphrase(): Promise<string> {
    return (await this.call("getNetwork")).string("passphrase");
  }

  async getLatestLedger(): Promise<number> {
    return (await this.call("getLatestLedger")).integer("sequence", 1);
  }

  // An entry modified after the ledger the reply claims to be of contradicts the reply.
  async getLedgerEntries(keys: readonly xdr.LedgerKey[]): Promise<LedgerEntries> {
    const wanted = new Map(keys.map((k) => [keyId(k), k]));
    const result = await this.call("getLedgerEntries", { keys: [...wanted.keys()] });
    const latestLedger = result.integer("latestLedger", 1);
    const entries = new Map<string, LedgerEntry>();
    const list = result.has("entries") ? result.array("entries") : [];
    list.forEach((raw, i) => {
      const e: Fields = result.item(raw, i, "entries");
      const id = e.string("key");
      const key = wanted.get(id);
      if (key === undefined) e.fault("an entry for a key that was not requested");
      let data: xdr.LedgerEntryData;
      try {
        data = xdr.LedgerEntryData.fromXDR(e.string("xdr"), "base64");
      } catch {
        return e.fault("an entry is not LedgerEntryData XDR");
      }
      const lastModifiedLedger = e.integer("lastModifiedLedgerSeq");
      if (lastModifiedLedger > latestLedger)
        e.fault("an entry was modified after the reply's ledger");
      entries.set(id, {
        key,
        data,
        lastModifiedLedger,
        liveUntilLedger: e.has("liveUntilLedgerSeq") ? e.integer("liveUntilLedgerSeq") : undefined,
      });
    });
    return { latestLedger, entries };
  }

  async simulateTransaction(envelope: string): Promise<Simulation> {
    const r = await this.call("simulateTransaction", { transaction: envelope });
    const latestLedger = r.integer("latestLedger", 1);
    if (r.has("error")) {
      const message = r.string("error");
      const match = /Error\(Contract, #(\d+)\)/.exec(message);
      return {
        transactionData: "",
        minResourceFee: 0n,
        auth: [],
        result: undefined,
        latestLedger,
        needsRestore: false,
        contractError: match ? Number(match[1]) : undefined,
        failed: true,
      };
    }
    const results = r.has("results") ? r.array("results") : [];
    const first = results.length > 0 ? r.item(results[0], 0, "results") : undefined;
    return {
      transactionData: r.string("transactionData"),
      minResourceFee: r.amount("minResourceFee"),
      auth: first?.has("auth") ? first.array("auth").map(String) : [],
      result: first?.has("xdr") ? xdr.ScVal.fromXDR(first.string("xdr"), "base64") : undefined,
      latestLedger,
      needsRestore: r.has("restorePreamble"),
      contractError: undefined,
      failed: false,
    };
  }

  async sendTransaction(envelope: string): Promise<{ status: SendStatus; hash: string }> {
    const r: Fields = await this.call("sendTransaction", { transaction: envelope });
    const status = r.string("status");
    if (!["PENDING", "DUPLICATE", "TRY_AGAIN_LATER", "ERROR"].includes(status)) {
      r.fault("unknown send status");
    }
    return { status: status as SendStatus, hash: r.hash("hash") };
  }

  async getTransaction(hash: string): Promise<TransactionStatus> {
    const r: Fields = await this.call("getTransaction", { hash });
    const status = r.string("status");
    if (status !== "SUCCESS" && status !== "FAILED" && status !== "NOT_FOUND") {
      r.fault("unknown transaction status");
    }
    let returnValue: xdr.ScVal | undefined;
    let events: MetaEvent[] = [];
    if (status === "SUCCESS" && r.has("resultMetaXdr")) {
      const meta = xdr.TransactionMeta.fromXDR(r.string("resultMetaXdr"), "base64");
      returnValue = sorobanReturnValue(meta);
      events = contractEvents(meta);
    }
    return {
      status,
      ledger: r.has("ledger") ? r.integer("ledger") : undefined,
      latestLedger: r.integer("latestLedger", 1),
      returnValue,
      events,
    };
  }

  async getEvents(request: {
    contractId: string;
    startLedger?: number;
    cursor?: string;
    limit?: number;
  }): Promise<EventPage> {
    const pagination: Record<string, unknown> = { limit: request.limit ?? 1000 };
    if (request.cursor !== undefined) pagination["cursor"] = request.cursor;
    const params: Record<string, unknown> = {
      filters: [{ type: "contract", contractIds: [request.contractId] }],
      pagination,
    };
    if (request.cursor === undefined) params["startLedger"] = request.startLedger;
    const r = await this.call("getEvents", params);
    const events = r.array("events").map((raw, i): ContractEvent => {
      const e = r.item(raw, i, "events");
      const closed = e.has("ledgerClosedAt") ? Date.parse(e.string("ledgerClosedAt")) : NaN;
      return {
        id: e.string("id"),
        ledger: e.integer("ledger", 1),
        closedAt: Number.isNaN(closed) ? undefined : closed / 1000,
        txHash: e.hash("txHash"),
        contractId: e.string("contractId"),
        topic: e.array("topic").map((t) => xdr.ScVal.fromXDR(String(t), "base64")),
        value: xdr.ScVal.fromXDR(e.string("value"), "base64"),
        successful: e.has("inSuccessfulContractCall")
          ? e.boolean("inSuccessfulContractCall")
          : true,
      };
    });
    return {
      events,
      cursor: r.has("cursor") ? r.string("cursor") : undefined,
      latestLedger: r.integer("latestLedger", 1),
      oldestLedger: r.has("oldestLedger") ? r.integer("oldestLedger") : 1,
      latestCloseTime: closeTime(r, "latestLedgerCloseTime"),
      oldestCloseTime: closeTime(r, "oldestLedgerCloseTime"),
    };
  }

  async sorobanInclusionFee(): Promise<bigint> {
    const r = await this.call("getFeeStats");
    return r.object("sorobanInclusionFee").amount("p90");
  }
}

function sorobanReturnValue(meta: xdr.TransactionMeta): xdr.ScVal | undefined {
  switch (meta.switch()) {
    case 3:
      return meta.v3().sorobanMeta()?.returnValue();
    case 4:
      return meta.v4().sorobanMeta()?.returnValue() ?? undefined;
    default:
      return undefined;
  }
}

function contractEvents(meta: xdr.TransactionMeta): MetaEvent[] {
  let raw: xdr.ContractEvent[] = [];
  if (meta.switch() === 3) raw = meta.v3().sorobanMeta()?.events() ?? [];
  if (meta.switch() === 4)
    raw = meta
      .v4()
      .operations()
      .flatMap((op) => op.events());
  return raw.map((e) => {
    const id = e.contractId();
    const body = e.body().v0();
    return {
      // The decoder returns the id as its own byte buffer type, which StrKey takes as is.
      contractId:
        id === null
          ? undefined
          : StrKey.encodeContract(id as unknown as Parameters<typeof StrKey.encodeContract>[0]),
      topic: body.topics(),
      value: body.data(),
    };
  });
}
