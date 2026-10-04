import { CyphrasError } from "../errors.ts";
import { type ExtDataJson, type TxProofJson, isAccountId, isContractId } from "../extdata.ts";
import { type FetchLike, Fields, joinUrl, requestJson } from "./http.ts";
import { type ServiceIdentity, readIdentity } from "./indexer.ts";

// The relayer's API, read with the same JSON conventions as the indexer's.

export interface RelayerHealth extends ServiceIdentity {
  readonly feeAddress: string;
  readonly maxFee: bigint | undefined;
  // Relaying is paused for a while after transactions failed on chain.
  readonly paused: boolean;
}

export interface Quote {
  readonly fee: bigint;
  readonly asset: string;
  readonly tier: bigint;
  readonly marginBps: number;
  // Unix seconds.
  readonly validUntil: number;
  readonly feeAddress: string;
  readonly vault: string;
  readonly networkId: string;
}

const RELAYER_ERRORS = [
  "bad_request",
  "wrong_vault",
  "fee_too_low",
  "fee_above_cap",
  "duplicate",
  "paused",
  "refused",
  "rejected",
  "rate_limited",
  "unavailable",
] as const;

export type RelayerError = (typeof RELAYER_ERRORS)[number] | "unknown";

// A request held until not_before has no hash yet: the relayer builds the transaction only when it
// sends it, and follows the request meanwhile by a random ID.
export type SubmitResult =
  | {
      readonly accepted: true;
      readonly hash: string | undefined;
      readonly heldId: string | undefined;
    }
  | { readonly accepted: false; readonly error: RelayerError; readonly reason: number | undefined };

/** A transaction the relayer submitted, as it reports it. */
export interface RelayedTx {
  readonly status: "pending" | "success" | "failed";
  readonly code: RelayerError | undefined;
  // The exit the transaction queued.
  readonly exitId: number | undefined;
}

/**
 * A request the relayer holds until its not_before: held, then once sent, the status of its
 * transaction with the hash; or failed before it was sent, with the screening's reason code when
 * the screening refused it; or cancelled by its client, never to be sent.
 */
export interface HeldRequest {
  readonly status: "held" | "cancelled" | "pending" | "success" | "failed";
  readonly hash: string | undefined;
  readonly code: RelayerError | undefined;
  readonly reason: number | undefined;
  readonly exitId: number | undefined;
}

function feeAddress(f: Fields): string {
  const address = f.string("fee_address");
  if (!isAccountId(address) && !isContractId(address)) f.fault("fee_address is not an address");
  return address;
}

const errorCode = (code: string): RelayerError =>
  (RELAYER_ERRORS as readonly string[]).includes(code) ? (code as RelayerError) : "unknown";

function oneOf<T extends string>(f: Fields, key: string, values: readonly T[]): T {
  const value = f.string(key);
  if (!(values as readonly string[]).includes(value)) f.fault(`${key} is not a known value`);
  return value as T;
}

export class RelayerClient {
  readonly url: string;
  readonly #fetch: FetchLike;

  constructor(url: string, fetchFn: FetchLike) {
    this.url = url;
    this.#fetch = fetchFn;
  }

  async health(timeoutMs?: number): Promise<RelayerHealth> {
    const { body } = await requestJson(this.#fetch, "relayer", joinUrl(this.url, "/v1/health"), {
      ...(timeoutMs === undefined ? {} : { timeoutMs }),
    });
    const f = Fields.of(body, "service_unavailable", "relayer health");
    return {
      ...readIdentity(f),
      feeAddress: feeAddress(f),
      maxFee: f.has("max_fee") ? f.amount("max_fee") : undefined,
      paused: f.has("paused") && f.boolean("paused"),
    };
  }

  async quote(): Promise<Quote> {
    const { status, body } = await requestJson(
      this.#fetch,
      "relayer",
      joinUrl(this.url, "/v1/quote"),
    );
    if (status !== 200) {
      // "unavailable" here means the quote would exceed the vault's max_fee.
      const reply = Fields.of(body ?? {}, "service_rejected", "relayer error");
      const code = reply.has("error") ? reply.string("error") : `http_${status}`;
      throw new CyphrasError("service_rejected", "the relayer gave no quote", { code });
    }
    const f = Fields.of(body, "quote_invalid", "relayer quote");
    return {
      fee: f.amount("fee"),
      asset: f.string("asset"),
      tier: f.amount("tier"),
      marginBps: f.integer("margin_bps"),
      validUntil: f.integer("valid_until"),
      feeAddress: feeAddress(f),
      vault: f.string("vault"),
      networkId: f.hash("network_id"),
    };
  }

  async submit(proof: TxProofJson, ext: ExtDataJson, notBefore?: number): Promise<SubmitResult> {
    const body: Record<string, unknown> = { proof, ext };
    if (notBefore !== undefined) body["not_before"] = notBefore;
    const reply = await requestJson(this.#fetch, "relayer", joinUrl(this.url, "/v1/submit"), {
      method: "POST",
      body,
    });
    if (reply.status === 202 || reply.status === 200) {
      const f = Fields.of(reply.body, "service_rejected", "relayer submission");
      if (f.has("hash")) return { accepted: true, hash: f.hash("hash"), heldId: undefined };
      if (notBefore === undefined || !f.has("held") || !f.boolean("held")) {
        f.fault("an accepted submission has no hash");
      }
      const id = f.string("id");
      if (!/^[0-9a-f]{32}$/.test(id)) f.fault("id is not 16 bytes of lowercase hex");
      return { accepted: true, hash: undefined, heldId: id };
    }
    const f = Fields.of(reply.body ?? {}, "service_rejected", "relayer error");
    return {
      accepted: false,
      error: errorCode(f.has("error") ? f.string("error") : ""),
      reason: f.has("reason") ? f.integer("reason") : undefined,
    };
  }

  // Asks only the relayer that submitted the transaction, which already knows its hash. A
  // transaction it does not know is undefined.
  async tx(hash: string): Promise<RelayedTx | undefined> {
    const { status, body } = await requestJson(
      this.#fetch,
      "relayer",
      joinUrl(this.url, `/v1/tx/${hash}`),
    );
    if (status === 404) return undefined;
    if (status !== 200) {
      throw new CyphrasError("service_unavailable", "the relayer gave no status", {
        service: "relayer",
      });
    }
    const f = Fields.of(body, "service_rejected", "relayer status");
    return {
      status: oneOf(f, "status", ["pending", "success", "failed"] as const),
      code: f.has("code") ? errorCode(f.string("code")) : undefined,
      exitId: f.has("exit_id") ? f.integer("exit_id", 1) : undefined,
    };
  }

  // Asks the relayer not to send a request it holds. False when it holds no such request to
  // cancel: it sent, refused or cancelled it, or, after a restart, does not know it.
  async cancelHeld(id: string): Promise<boolean> {
    const { status, body } = await requestJson(
      this.#fetch,
      "relayer",
      joinUrl(this.url, `/v1/held/${id}`),
      { method: "DELETE" },
    );
    if (status === 404) return false;
    if (status !== 200) {
      throw new CyphrasError("service_unavailable", "the relayer gave no answer", {
        service: "relayer",
      });
    }
    const f = Fields.of(body, "service_rejected", "cancelled request");
    oneOf(f, "status", ["cancelled"] as const);
    return true;
  }

  // Asks the relayer about a request it holds, by the ID its reply gave. The relayer keeps held
  // requests in memory only, so one it does not know, after a restart, is undefined.
  async held(id: string): Promise<HeldRequest | undefined> {
    const { status, body } = await requestJson(
      this.#fetch,
      "relayer",
      joinUrl(this.url, `/v1/held/${id}`),
    );
    if (status === 404) return undefined;
    if (status !== 200) {
      throw new CyphrasError("service_unavailable", "the relayer gave no status", {
        service: "relayer",
      });
    }
    const f = Fields.of(body, "service_rejected", "held request");
    const state = oneOf(f, "status", [
      "held",
      "cancelled",
      "pending",
      "success",
      "failed",
    ] as const);
    const hash = f.has("hash") ? f.hash("hash") : undefined;
    const unsent = state === "held" || state === "cancelled";
    if (unsent !== (hash === undefined) && state !== "failed") {
      f.fault("a held request has a hash only once it is sent");
    }
    return {
      status: state,
      hash,
      code: f.has("code") ? errorCode(f.string("code")) : undefined,
      reason: f.has("reason") ? f.integer("reason") : undefined,
      exitId: f.has("exit_id") ? f.integer("exit_id", 1) : undefined,
    };
  }
}
