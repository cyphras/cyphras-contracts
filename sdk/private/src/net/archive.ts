import { sha256 } from "@noble/hashes/sha2";
import { StrKey, scValToBigInt, xdr } from "@stellar/stellar-base";
import { bytesToHex } from "../bytes.ts";
import { CyphrasError, fail } from "../errors.ts";
import { P } from "../field.ts";
import { decodeVaultEvent } from "../vault/events.ts";
import type { FetchLike } from "./http.ts";
import type { Leaf, SpentNullifier } from "./indexer.ts";

// The published form of a vault's event history, cyphras-vault-archive/1: a manifest and one gzip
// file of canonical JSON lines per closed window of ledgers. Every rule here is the one the
// archive tool's reader applies, so a file it writes is read here and a file it refuses is refused
// here; what the archive says is still only taken once the chain confirms it.
export const ARCHIVE_FORMAT = "cyphras-vault-archive/1";
export const WINDOW_LEDGERS = 17_280;
export const MAX_MANIFEST_BYTES = 4 << 20;
export const MAX_WINDOW_BYTES = 64 << 20;
const MAX_LINE_BYTES = 1 << 20;
// The network limits the events of a transaction to 16 KiB, about 21.9 KB in base64.
const MAX_EVENT_BYTES = 32 << 10;
const MAX_PRODUCER_BYTES = 128;
const TREE_CAPACITY = 2 ** 32;
const UINT32_MAX = 0xffffffff;
const MANIFEST_TIMEOUT_MS = 30_000;
const WINDOW_TIMEOUT_MS = 120_000;

// Every topic the vault emits, with the fields of its data, as the archive tool's decoder reads
// them. A window may hold only these, each with exactly these fields.
const VAULT_TOPICS: ReadonlyMap<string, readonly string[]> = new Map([
  ["deposit_pending", ["id", "depositor", "amount", "commitment0", "commitment1", "created_at"]],
  ["deposit_flagged", ["id", "reason"]],
  ["deposit_unflagged", ["id", "reason"]],
  ["attested", ["up_to"]],
  ["deposit_admitted", ["id", "leaf_index0", "leaf_index1"]],
  ["deposit_refunded", ["id", "reason"]],
  ["new_commitment", ["index", "commitment", "encrypted_output"]],
  ["new_nullifier", ["nullifier"]],
  ["settled", ["ext_amount", "fee", "recipient", "relayer", "exit_id"]],
  ["exit_queued", ["id", "ext_amount", "fee", "recipient", "relayer"]],
  ["exit_paid", ["id", "payout_paid", "fee_paid", "payout_left", "fee_left"]],
  ["exit_requeued", ["id", "new_id", "payout", "fee"]],
  ["exit_stranded", ["id", "payout", "fee"]],
  ["paused", ["deposits", "transfers"]],
  ["halted", ["until"]],
  ["resumed", ["next_halt_at"]],
  ["limits_queued", ["limits", "ready_at"]],
  ["limits_applied", ["limits", "ready_at"]],
  ["limits_cancelled", ["limits", "ready_at"]],
]);

// The length of a note's ciphertext in a new_commitment event.
const CIPHERTEXT_BYTES = 181;

// The names of a map's symbol keys, or undefined for data that is not such a map.
function fieldNames(value: xdr.ScVal): string[] | undefined {
  if (value.switch().name !== "scvMap") return undefined;
  const names: string[] = [];
  for (const entry of value.map() ?? []) {
    if (entry.key().switch().name !== "scvSymbol") return undefined;
    names.push(entry.key().sym().toString());
  }
  return names;
}

/** What a reader requires of an archive: the vault, its network and its deploy ledger. */
export interface ArchivePin {
  readonly vault: string;
  readonly networkPassphrase: string;
  readonly deployLedger: number;
}

export interface ArchiveWindow {
  readonly start: number;
  readonly end: number;
  readonly events: number;
  // The leaf indices [first, end) its commitments take.
  readonly leaves: readonly [number, number];
  readonly nullifiers: number;
  readonly bytes: number;
  readonly sha256: string | undefined;
}

export interface ArchiveManifest {
  readonly network: string;
  readonly networkPassphrase: string;
  readonly vault: string;
  readonly deployLedger: number;
  readonly coveredTo: number;
  readonly windows: readonly ArchiveWindow[];
  readonly producer: string;
}

// What a window holds that a sync takes: its leaves in index order and its spent nullifiers.
export interface WindowContent {
  readonly leaves: readonly Leaf[];
  readonly nullifiers: readonly SpentNullifier[];
}

function invalid(message: string): never {
  return fail("archive_fault", `the archive ${message}`);
}

function unreachable(message: string): never {
  return fail("history_unavailable", message, { reason: "archive_unreachable" });
}

// Go's encoding/json, which writes the archive, escapes <, >, & and the two line separators inside
// strings; JSON.stringify writes everything else alike.
function goJson(value: unknown, indent?: number): string {
  return JSON.stringify(value, null, indent).replace(
    /[<>&\u2028\u2029]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

const utf8Strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function text(bytes: Uint8Array, what: string): string {
  try {
    return utf8Strict.decode(bytes);
  } catch {
    return invalid(`${what} is not UTF-8`);
  }
}

function record(value: unknown, what: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    invalid(`${what} is not a JSON object`);
  }
  return value as Record<string, unknown>;
}

function str(o: Readonly<Record<string, unknown>>, key: string, what: string): string {
  const v = o[key];
  if (typeof v !== "string") invalid(`${what} has no string ${key}`);
  return v;
}

function int(o: Readonly<Record<string, unknown>>, key: string, what: string, max: number): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || v > max) {
    invalid(`${what} has no ${key} between 0 and ${max}`);
  }
  return v;
}

const windowStart = (ledger: number): number => ledger - (ledger % WINDOW_LEDGERS);

/** The name of a window's file under the archive's base. */
export const windowFile = (w: ArchiveWindow): string =>
  `windows/${String(w.start).padStart(10, "0")}.jsonl.gz`;

/**
 * Reads a manifest. It must be exactly the canonical form the archive tool writes, so a repeated
 * key, a key of its own, other spacing or any other spelling is refused, and it must be of the
 * pinned vault, network and deploy ledger, with windows that follow one another from the deploy
 * ledger's window and leaves that continue from window to window.
 */
export function parseManifest(raw: Uint8Array, pin: ArchivePin): ArchiveManifest {
  let value: unknown;
  const source = text(raw, "manifest");
  try {
    value = JSON.parse(source);
  } catch {
    return invalid("manifest is not JSON");
  }
  const o = record(value, "manifest");
  if (o["format"] !== ARCHIVE_FORMAT) {
    fail("archive_fault", "the archive is of a format this release does not read", {
      format: typeof o["format"] === "string" ? o["format"].slice(0, 80) : "",
    });
  }
  const m = "manifest";
  const listed = o["windows"];
  if (listed !== null && !Array.isArray(listed)) invalid("manifest has no window list");
  const windows: ArchiveWindow[] = (listed ?? []).map((item: unknown, i: number) => {
    const what = `manifest window ${i}`;
    const w = record(item, what);
    const leaves = w["leaves"];
    if (
      !Array.isArray(leaves) ||
      leaves.length !== 2 ||
      !leaves.every((x) => typeof x === "number" && Number.isSafeInteger(x) && x >= 0)
    ) {
      invalid(`${what} has no leaves range of two numbers`);
    }
    const sha = w["sha256"];
    if (sha !== undefined && typeof sha !== "string") invalid(`${what} has no string sha256`);
    return {
      start: int(w, "start", what, UINT32_MAX),
      end: int(w, "end", what, UINT32_MAX),
      events: int(w, "events", what, Number.MAX_SAFE_INTEGER),
      leaves: [leaves[0] as number, leaves[1] as number],
      nullifiers: int(w, "nullifiers", what, Number.MAX_SAFE_INTEGER),
      bytes: int(w, "bytes", what, Number.MAX_SAFE_INTEGER),
      sha256: sha === "" ? undefined : sha,
    };
  });
  const manifest: ArchiveManifest = {
    network: str(o, "network", m),
    networkPassphrase: str(o, "networkPassphrase", m),
    vault: str(o, "vault", m),
    deployLedger: int(o, "deployLedger", m, UINT32_MAX),
    coveredTo: int(o, "coveredTo", m, UINT32_MAX),
    windows,
    producer: str(o, "producer", m),
  };
  const canonical =
    goJson(
      {
        format: ARCHIVE_FORMAT,
        network: manifest.network,
        networkPassphrase: manifest.networkPassphrase,
        vault: manifest.vault,
        deployLedger: manifest.deployLedger,
        windowLedgers: int(o, "windowLedgers", m, UINT32_MAX),
        coveredTo: manifest.coveredTo,
        windows:
          listed === null
            ? null
            : windows.map((w) => ({
                start: w.start,
                end: w.end,
                events: w.events,
                leaves: w.leaves,
                nullifiers: w.nullifiers,
                bytes: w.bytes,
                ...(w.sha256 === undefined ? {} : { sha256: w.sha256 }),
              })),
        producer: manifest.producer,
      },
      2,
    ) + "\n";
  if (canonical !== source) invalid("manifest is not in canonical form");
  if (o["windowLedgers"] !== WINDOW_LEDGERS) invalid(`manifest has windows of other than 17280`);
  validate(manifest, pin);
  return manifest;
}

function validate(m: ArchiveManifest, pin: ArchivePin): void {
  if (!StrKey.isValidContract(m.vault)) invalid("manifest names no contract as its vault");
  if (m.networkPassphrase === "" || m.network === "" || /[ \t\n]/.test(m.network)) {
    invalid("manifest names no network");
  }
  if (m.deployLedger === 0) invalid("manifest has no deploy ledger");
  if (m.producer.length > MAX_PRODUCER_BYTES || !/^[ -~]*$/.test(m.producer)) {
    invalid("manifest's producer is not short printable ASCII");
  }
  if (m.vault !== pin.vault) invalid("is of another vault");
  if (m.networkPassphrase !== pin.networkPassphrase) invalid("is of another network");
  if (m.deployLedger !== pin.deployLedger) invalid("names another deploy ledger");
  let next = windowStart(m.deployLedger);
  let leaves = 0;
  m.windows.forEach((w, i) => {
    const [first, end] = w.leaves;
    if (w.start !== next || w.end !== w.start + WINDOW_LEDGERS - 1) {
      invalid(`manifest's window ${i} does not follow the one before it`);
    }
    if (first !== leaves || end < first || (end - first) % 2 !== 0 || end > TREE_CAPACITY) {
      invalid(`manifest's window ${i} holds leaves that do not continue the ones before them`);
    }
    if (w.bytes > MAX_WINDOW_BYTES || w.events < w.nullifiers + end - first) {
      invalid(`manifest's window ${i} has counts that do not fit`);
    }
    if (w.events === 0) {
      if (w.bytes !== 0 || w.sha256 !== undefined || first !== end || w.nullifiers !== 0) {
        invalid(`manifest's window ${i} has no events but has content`);
      }
    } else if (w.bytes === 0 || w.sha256 === undefined || !/^[0-9a-f]{64}$/.test(w.sha256)) {
      invalid(`manifest's window ${i} has no size or hash`);
    }
    next = w.end + 1;
    leaves = end;
  });
  const last = m.windows[m.windows.length - 1];
  if (m.coveredTo !== (last?.end ?? 0))
    invalid("manifest's coveredTo is not where its windows end");
}

// CRC-32 of gzip, for its trailer and its optional header checksum.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array): number {
  let c = 0xffffffff;
  for (const b of bytes) c = (CRC_TABLE[(c ^ b) & 0xff] as number) ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

async function inflateRaw(body: Uint8Array, limit: number): Promise<Uint8Array> {
  const input = new ReadableStream<BufferSource>({
    start(controller) {
      controller.enqueue(new Uint8Array(body));
      controller.close();
    },
  });
  const reader = input.pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) {
        await reader.cancel();
        return invalid(`window expands past the ${limit} bytes its manifest states`);
      }
      chunks.push(value);
    }
  } catch (err) {
    if (err instanceof CyphrasError) throw err;
    return invalid("window is not one complete gzip member");
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// A window file must be one gzip member and nothing else. The deflate data is inflated on its own,
// from the end of the header to the trailer, so a second member or any byte after the first one
// is refused on every platform, whatever its decompressor does with several members.
async function gunzip(file: Uint8Array, limit: number): Promise<Uint8Array> {
  const bad = (): never => invalid("window is not one complete gzip member");
  if (file.length < 10 || file[0] !== 0x1f || file[1] !== 0x8b || file[2] !== 8) bad();
  const flags = file[3] as number;
  let at = 10;
  if (flags & 4) {
    if (at + 2 > file.length) bad();
    at += 2 + ((file[at] as number) | ((file[at + 1] as number) << 8));
  }
  // A name and a comment end with a zero byte within 512 bytes of their start.
  for (const flag of [8, 16]) {
    if (flags & flag) {
      const zero = file.indexOf(0, at);
      if (zero < 0 || zero - at >= 512) bad();
      at = zero + 1;
    }
  }
  if (flags & 2) {
    if (at + 2 > file.length) bad();
    const stated = (file[at] as number) | ((file[at + 1] as number) << 8);
    if (stated !== (crc32(file.subarray(0, at)) & 0xffff)) bad();
    at += 2;
  }
  if (at > file.length - 8) bad();
  const data = await inflateRaw(file.subarray(at, file.length - 8), limit);
  const trailer = new DataView(file.buffer, file.byteOffset + file.length - 8, 8);
  if (trailer.getUint32(0, true) !== crc32(data) || trailer.getUint32(4, true) !== data.length) {
    bad();
  }
  return data;
}

// The longest file a window of the stated size may be: gzip adds little to what it cannot shrink,
// and a header may carry free text.
const maxCompressed = (w: ArchiveWindow): number => w.bytes + Math.floor(w.bytes / 64) + 4096;

// Whether a topic or value is exactly what encoding its own decoding gives, so the same event
// cannot be written in more than one way.
function canonicalXdr(s: string): xdr.ScVal | undefined {
  try {
    const v = xdr.ScVal.fromXDR(s, "base64");
    return v.toXDR("base64") === s ? v : undefined;
  } catch {
    return undefined;
  }
}

const NEWLINE = 10;

/**
 * Checks a window's file against its manifest entry and every rule of the format, and returns
 * what it holds: its size before and after gzip, its SHA-256, the canonical form of every line,
 * the vault's own events only, in strictly increasing chain order, inside the window and not
 * before the deploy ledger, leaves that continue from the entry's first one in pairs of one
 * transaction, no nullifier twice, a closing line that counts the events, and the counts the
 * manifest states.
 */
export async function checkWindow(
  w: ArchiveWindow,
  compressed: Uint8Array,
  pin: ArchivePin,
): Promise<WindowContent> {
  if (compressed.length > maxCompressed(w)) {
    invalid(`window ${w.start} is a larger file than its ${w.bytes} bytes of content allow`);
  }
  const data = await gunzip(compressed, w.bytes);
  if (data.length !== w.bytes) invalid(`window ${w.start} is not the size its manifest states`);
  if (bytesToHex(sha256(data)) !== w.sha256) {
    invalid(`window ${w.start} has another SHA-256 than its manifest states`);
  }
  const at = (n: number, message: string): never =>
    invalid(`window ${w.start}, line ${n}: ${message}`);
  const leaves: Leaf[] = [];
  const nullifiers: SpentNullifier[] = [];
  const spent = new Set<bigint>();
  let events = 0;
  let nextLeaf = w.leaves[0];
  let left: { readonly leaf: Leaf; readonly tx: number } | undefined;
  let last: readonly [number, number, number, number] | undefined;
  let offset = 0;
  let closing: string | undefined;
  for (let n = 1; offset < data.length; n++) {
    const end = data.indexOf(NEWLINE, offset);
    if (end < 0) at(n, "not ended by a newline");
    if (end - offset >= MAX_LINE_BYTES) at(n, "too long");
    const line = text(data.subarray(offset, end), `window ${w.start}`);
    offset = end + 1;
    if (offset === data.length) {
      closing = line;
      break;
    }
    let parsed: Readonly<Record<string, unknown>>;
    try {
      parsed = record(JSON.parse(line), `window ${w.start} line ${n}`);
    } catch (err) {
      if (err instanceof CyphrasError) throw err;
      return at(n, "not JSON");
    }
    const what = `window ${w.start} line ${n}`;
    const topics = parsed["topics"];
    if (!Array.isArray(topics) || !topics.every((t) => typeof t === "string")) {
      at(n, "no topic list");
    }
    const e = {
      ledger: int(parsed, "ledger", what, UINT32_MAX),
      closed_at: int(parsed, "closed_at", what, Number.MAX_SAFE_INTEGER),
      tx_hash: str(parsed, "tx_hash", what),
      tx: int(parsed, "tx", what, UINT32_MAX),
      op: int(parsed, "op", what, UINT32_MAX),
      index: int(parsed, "index", what, UINT32_MAX),
      contract: str(parsed, "contract", what),
      topics: topics as string[],
      value: str(parsed, "value", what),
    };
    if (goJson(e) !== line) at(n, "not in canonical form");
    if (e.contract !== pin.vault) at(n, "an event of another contract");
    if (e.ledger === 0 || e.closed_at === 0) at(n, "an event without a ledger or close time");
    if (!/^[0-9a-f]{64}$/.test(e.tx_hash)) at(n, "no transaction hash");
    if (e.topics.length === 0 || e.topics.length > 4) at(n, "an event with no or too many topics");
    if (e.topics.reduce((s, t) => s + t.length, e.value.length) > MAX_EVENT_BYTES) {
      at(n, "an event larger than the network allows");
    }
    const topic = e.topics.map(canonicalXdr);
    const value = canonicalXdr(e.value);
    if (value === undefined || topic.some((t) => t === undefined)) {
      at(n, "not in canonical form: a topic or value is not the base64 of its own XDR");
    }
    if (e.ledger < w.start || e.ledger > w.end) at(n, "a ledger outside the window");
    if (e.ledger < pin.deployLedger) at(n, "a ledger before the deploy ledger");
    const pos = [e.ledger, e.tx, e.op, e.index] as const;
    if (last !== undefined && !follows(pos, last)) at(n, "out of chain order");
    last = pos;
    let decoded;
    try {
      decoded = decodeVaultEvent({ topic: topic as xdr.ScVal[], value: value as xdr.ScVal });
    } catch (err) {
      if (!(err instanceof CyphrasError)) throw err;
      return at(n, "not a vault event");
    }
    const name = decoded.kind === "other" ? decoded.topic : decoded.kind;
    const fields = VAULT_TOPICS.get(name);
    if (fields === undefined) return at(n, "an unknown topic");
    const names = fieldNames(value as xdr.ScVal);
    if (
      names === undefined ||
      names.length !== fields.length ||
      !fields.every((f) => names.includes(f))
    ) {
      at(n, `${name} data without exactly its fields`);
    }
    if (
      (decoded.kind === "new_commitment" &&
        (decoded.commitment === 0n ||
          decoded.commitment >= P ||
          decoded.ciphertext.length !== CIPHERTEXT_BYTES)) ||
      (decoded.kind === "new_nullifier" && decoded.nullifier >= P) ||
      (decoded.kind === "deposit_pending" && decoded.commitments.some((c) => c >= P))
    ) {
      at(n, `${name} data the vault never emits`);
    }
    if (decoded.kind === "deposit_pending" && depositAmount(value as xdr.ScVal) <= 0n) {
      at(n, "a deposit of nothing");
    }
    events++;
    if (decoded.kind === "new_nullifier") {
      if (spent.has(decoded.nullifier)) at(n, "a nullifier spent twice");
      spent.add(decoded.nullifier);
      nullifiers.push({ nullifier: decoded.nullifier, ledger: e.ledger, txHash: e.tx_hash });
    } else if (decoded.kind === "new_commitment") {
      if (decoded.index !== nextLeaf) at(n, `leaf ${decoded.index} where ${nextLeaf} belongs`);
      const leaf: Leaf = {
        index: decoded.index,
        commitment: decoded.commitment,
        ciphertext: decoded.ciphertext,
        ledger: e.ledger,
        txHash: e.tx_hash,
      };
      if (nextLeaf % 2 === 0) {
        left = { leaf, tx: e.tx };
      } else {
        if (left === undefined || left.leaf.ledger !== e.ledger || left.tx !== e.tx) {
          return at(n, "a leaf that is not the second of a pair in one transaction");
        }
        leaves.push(left.leaf, leaf);
        left = undefined;
      }
      nextLeaf++;
    }
  }
  if (left !== undefined) invalid(`window ${w.start} ends inside a pair of leaves`);
  if (closing !== `{"covered":[${w.start},${w.end}],"count":${events}}`) {
    invalid(`window ${w.start} has no closing line that counts its events`);
  }
  if (events !== w.events || nextLeaf !== w.leaves[1] || nullifiers.length !== w.nullifiers) {
    invalid(`window ${w.start} holds other counts than its manifest states`);
  }
  return { leaves, nullifiers };
}

function depositAmount(value: xdr.ScVal): bigint {
  const entry = value.map()?.find((e) => e.key().sym().toString() === "amount");
  const v = entry?.val();
  return v?.switch().name === "scvI128" ? scValToBigInt(v) : 0n;
}

function follows(
  a: readonly [number, number, number, number],
  b: readonly [number, number, number, number],
): boolean {
  for (let i = 0; i < 4; i++) {
    if (a[i] !== b[i]) return (a[i] as number) > (b[i] as number);
  }
  return false;
}

// One file of an archive, or undefined when the server says it has none. No header goes out, so a
// browser sends no preflight; no cookies or referrer either. Any other failure to read it within
// its time is the archive being unreachable for now; a file past its limit is refused.
async function getFile(
  fetchFn: FetchLike,
  base: string,
  name: string,
  limit: number,
  timeoutMs: number,
): Promise<Uint8Array | undefined> {
  let response: Response;
  try {
    response = await fetchFn(`${base.replace(/\/+$/, "")}/${name}`, {
      method: "GET",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return unreachable("the archive could not be reached");
  }
  if (response.status === 404) {
    await response.body?.cancel().catch(() => undefined);
    return undefined;
  }
  if (response.status !== 200 || response.body === null) {
    await response.body?.cancel().catch(() => undefined);
    return unreachable(`the archive answered ${response.status}`);
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit) {
        await reader.cancel().catch(() => undefined);
        return invalid(`file ${name} is larger than ${limit} bytes`);
      }
      chunks.push(value);
    }
  } catch (err) {
    if (err instanceof CyphrasError) throw err;
    return unreachable("the archive stopped sending a file");
  }
  const out = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Reads the manifest at an archive's base URL. */
export async function fetchManifest(
  fetchFn: FetchLike,
  base: string,
  pin: ArchivePin,
  timeoutMs = MANIFEST_TIMEOUT_MS,
): Promise<ArchiveManifest> {
  const raw = await getFile(
    fetchFn,
    base,
    "manifest.json",
    MAX_MANIFEST_BYTES,
    Math.min(timeoutMs, MANIFEST_TIMEOUT_MS),
  );
  if (raw === undefined) unreachable("the archive has no manifest");
  return parseManifest(raw, pin);
}

/** Reads and checks one window the manifest lists with events. */
export async function fetchWindow(
  fetchFn: FetchLike,
  base: string,
  w: ArchiveWindow,
  pin: ArchivePin,
  timeoutMs = WINDOW_TIMEOUT_MS,
): Promise<WindowContent> {
  const compressed = await getFile(
    fetchFn,
    base,
    windowFile(w),
    maxCompressed(w),
    Math.min(timeoutMs, WINDOW_TIMEOUT_MS),
  );
  if (compressed === undefined) invalid(`lists window ${w.start} but has no file for it`);
  return checkWindow(w, compressed, pin);
}
