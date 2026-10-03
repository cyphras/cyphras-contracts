import { CyphrasError } from "../errors.ts";
import { type ExtDataJson, type TxProofJson, isAccountId, isContractId } from "../extdata.ts";
import { type FetchLike, Fields, joinUrl, requestJson } from "./http.ts";
import { type ServiceIdentity, readIdentity } from "./indexer.ts";

// The relayer API of services.md, read with the same JSON conventions as the indexer's.

export interface RelayerHealth extends ServiceIdentity {
  readonly feeAddress: string;
  readonly maxFee: bigint | undefined;
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
// sends it.
export type SubmitResult =
  | { readonly accepted: true; readonly hash: string | undefined }
  | { readonly accepted: false; readonly error: RelayerError; readonly reason: number | undefined };

export type RelayedStatus = "pending" | "success" | "failed" | "unknown";

function feeAddress(f: Fields): string {
  const address = f.string("fee_address");
  if (!isAccountId(address) && !isContractId(address)) f.fault("fee_address is not an address");
  return address;
}

export class RelayerClient {
  readonly url: string;
  readonly #fetch: FetchLike;

  constructor(url: string, fetchFn: FetchLike) {
    this.url = url;
    this.#fetch = fetchFn;
  }

  async health(): Promise<RelayerHealth> {
    const { body } = await requestJson(this.#fetch, "relayer", joinUrl(this.url, "/v1/health"));
    const f = Fields.of(body, "service_unavailable", "relayer health");
    return {
      ...readIdentity(f),
      feeAddress: feeAddress(f),
      maxFee: f.has("max_fee") ? f.amount("max_fee") : undefined,
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
      if (f.has("hash")) return { accepted: true, hash: f.hash("hash") };
      if (notBefore === undefined || !f.has("held") || !f.boolean("held")) {
        f.fault("an accepted submission has no hash");
      }
      return { accepted: true, hash: undefined };
    }
    const f = Fields.of(reply.body ?? {}, "service_rejected", "relayer error");
    const code = f.has("error") ? f.string("error") : "";
    const error = (RELAYER_ERRORS as readonly string[]).includes(code)
      ? (code as RelayerError)
      : "unknown";
    return { accepted: false, error, reason: f.has("reason") ? f.integer("reason") : undefined };
  }

  // Asks only the relayer that submitted the transaction, which already knows its hash.
  async status(hash: string): Promise<RelayedStatus> {
    const { status, body } = await requestJson(
      this.#fetch,
      "relayer",
      joinUrl(this.url, `/v1/tx/${hash}`),
    );
    if (status === 404) return "unknown";
    if (status !== 200) return "unknown";
    const state = Fields.of(body, "service_rejected", "relayer status").string("status");
    return state === "pending" || state === "success" || state === "failed" ? state : "unknown";
  }
}
