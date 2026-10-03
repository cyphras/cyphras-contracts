import { CyphrasError, type ErrorCode, fail } from "../errors.ts";
import { P } from "../field.ts";
import { hexToBytes } from "../bytes.ts";

/** The fetch function the SDK sends every request through, so a caller can route it via a proxy. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const DEFAULT_TIMEOUT_MS = 30_000;

export interface JsonResponse {
  readonly status: number;
  readonly body: unknown;
}

// One JSON request. No cookies, credentials or referrer go out, and the reply is read as JSON or
// refused. A transport failure raises service_unavailable naming only the service.
export async function requestJson(
  fetchFn: FetchLike,
  service: string,
  url: string,
  init: { method?: "GET" | "POST"; body?: unknown; timeoutMs?: number } = {},
): Promise<JsonResponse> {
  const headers: Record<string, string> = { accept: "application/json" };
  if (init.body !== undefined) headers["content-type"] = "application/json";
  let response: Response;
  try {
    response = await fetchFn(url, {
      method: init.method ?? "GET",
      headers,
      body: init.body === undefined ? null : JSON.stringify(init.body),
      credentials: "omit",
      referrerPolicy: "no-referrer",
      redirect: "error",
      signal: AbortSignal.timeout(init.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
  } catch {
    return fail("service_unavailable", `the ${service} could not be reached`, { service });
  }
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }
  return { status: response.status, body };
}

// Strict readers for service replies. Every malformed field raises the given error code, so a
// lying or broken service can stop an operation but never feed it a value of the wrong shape.
export class Fields {
  readonly #value: Readonly<Record<string, unknown>>;
  readonly #code: ErrorCode;
  readonly #what: string;

  private constructor(value: Readonly<Record<string, unknown>>, code: ErrorCode, what: string) {
    this.#value = value;
    this.#code = code;
    this.#what = what;
  }

  static of(value: unknown, code: ErrorCode, what: string): Fields {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new CyphrasError(code, `${what} is not a JSON object`);
    }
    return new Fields(value as Record<string, unknown>, code, what);
  }

  fault(detail: string): never {
    throw new CyphrasError(this.#code, `${this.#what}: ${detail}`);
  }

  has(key: string): boolean {
    return this.#value[key] !== undefined && this.#value[key] !== null;
  }

  raw(key: string): unknown {
    return this.#value[key];
  }

  string(key: string): string {
    const v = this.#value[key];
    if (typeof v !== "string") this.fault(`${key} is not a string`);
    return v;
  }

  boolean(key: string): boolean {
    const v = this.#value[key];
    if (typeof v !== "boolean") this.fault(`${key} is not a boolean`);
    return v;
  }

  integer(key: string, min = 0): number {
    const v = this.#value[key];
    if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) {
      this.fault(`${key} is not an integer of at least ${min}`);
    }
    return v;
  }

  amount(key: string): bigint {
    const v = this.#value[key];
    if (typeof v !== "string" || !/^(0|-?[1-9][0-9]{0,38})$/.test(v)) {
      this.fault(`${key} is not a decimal amount`);
    }
    return BigInt(v);
  }

  field(key: string): bigint {
    const v = this.#value[key];
    if (typeof v !== "string" || !/^(0x)?[0-9a-f]{64}$/.test(v)) {
      this.fault(`${key} is not a 32-byte field element`);
    }
    const x = BigInt(v.startsWith("0x") ? v : "0x" + v);
    if (x >= P) this.fault(`${key} is not a canonical field element`);
    return x;
  }

  bytes(key: string, length: number): Uint8Array {
    const v = this.#value[key];
    if (typeof v !== "string" || v.length !== 2 * length || !/^[0-9a-f]*$/.test(v)) {
      this.fault(`${key} is not ${length} bytes of lowercase hex`);
    }
    return hexToBytes(v);
  }

  hash(key: string): string {
    const v = this.#value[key];
    if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v)) this.fault(`${key} is not a hash`);
    return v;
  }

  array(key: string): readonly unknown[] {
    const v = this.#value[key];
    if (!Array.isArray(v)) this.fault(`${key} is not an array`);
    return v;
  }

  object(key: string): Fields {
    return Fields.of(this.#value[key], this.#code, `${this.#what}.${key}`);
  }

  item(value: unknown, index: number, key: string): Fields {
    return Fields.of(value, this.#code, `${this.#what}.${key}[${index}]`);
  }
}

export function joinUrl(base: string, path: string): string {
  return base.replace(/\/+$/, "") + path;
}
