import { CyphrasError, type ErrorCode, fail } from "../errors.ts";
import { P } from "../field.ts";
import { hexToBytes } from "../bytes.ts";

/** The fetch function the SDK sends every request through, so a caller can route it via a proxy. */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const DEFAULT_TIMEOUT_MS = 30_000;
// Several times the largest reply a service sends: a page of 1,024 leaves or 4,096 nullifiers,
// or 1,000 contract events.
export const MAX_REPLY_BYTES = 4 * 1024 * 1024;

export interface JsonResponse {
  readonly status: number;
  readonly body: unknown;
}

// Reads a reply body no larger than `limit`, and stops reading as soon as it is larger.
async function readBody(response: Response, limit: number): Promise<string | undefined> {
  const reader = response.body?.getReader();
  if (reader === undefined) return undefined;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      return undefined;
    }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    all.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(all);
}

// One JSON request. No cookies, credentials or referrer go out, the reply is read as JSON or
// refused, and the request is abandoned past its timeout or once its reply grows too large. A
// transport failure raises service_unavailable naming only the service.
export async function requestJson(
  fetchFn: FetchLike,
  service: string,
  url: string,
  init: { method?: "GET" | "POST" | "DELETE"; body?: unknown; timeoutMs?: number } = {},
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
  let text: string | undefined;
  try {
    text = await readBody(response, MAX_REPLY_BYTES);
  } catch {
    return fail("service_unavailable", `the ${service} could not be reached`, { service });
  }
  if (text === undefined && response.body !== null) {
    fail("service_unavailable", `the ${service} sent a reply that is too large`, { service });
  }
  let body: unknown;
  try {
    body = text === undefined ? undefined : JSON.parse(text);
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

  integers(key: string, min = 0): readonly number[] {
    return this.array(key).map((v) => {
      if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min) {
        this.fault(`${key} holds a value that is not an integer of at least ${min}`);
      }
      return v;
    });
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
