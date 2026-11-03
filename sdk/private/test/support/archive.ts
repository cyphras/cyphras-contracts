import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { xdr } from "@stellar/stellar-base";
import type { FetchLike } from "../../src/net/http.ts";
import type { World } from "./network.ts";
import { map } from "./vault.ts";

// The ledgers of one window, as the format fixes them.
export const WINDOW_LEDGERS = 17_280;

export const ARCHIVE = "http://archive.test";
export const MIRROR = "http://mirror.test";

/** One event line of the format, its fields in their fixed order. */
export interface RawLine {
  ledger: number;
  closed_at: number;
  tx_hash: string;
  tx: number;
  op: number;
  index: number;
  contract: string;
  topics: string[];
  value: string;
}

export interface WindowEntry {
  start: number;
  end: number;
  events: number;
  leaves: [number, number];
  nullifiers: number;
  bytes: number;
  sha256?: string;
}

export interface Manifest {
  format: string;
  network: string;
  networkPassphrase: string;
  vault: string;
  deployLedger: number;
  windowLedgers: number;
  coveredTo: number;
  windows: WindowEntry[] | null;
  producer: string;
}

/** An archive as files by path under its base, with the event lines of each window. */
export interface Archive {
  manifest: Manifest;
  lines: Map<number, RawLine[]>;
  files: Map<string, Uint8Array>;
}

export const fileOf = (start: number): string =>
  `windows/${String(start).padStart(10, "0")}.jsonl.gz`;

export const manifestBytes = (m: unknown): Uint8Array =>
  new TextEncoder().encode(JSON.stringify(m, null, 2) + "\n");

// The vault's events as the archive tool writes them: transactions numbered in the order they
// first appear in their ledger, from 1, and events within one from 0.
export function rawEvents(world: World): RawLine[] {
  const txs = new Map<string, { tx: number; next: number }>();
  const perLedger = new Map<number, number>();
  return world.vault.events.map((e) => {
    const key = `${e.ledger}/${e.txHash}`;
    let t = txs.get(key);
    if (t === undefined) {
      const tx = (perLedger.get(e.ledger) ?? 0) + 1;
      perLedger.set(e.ledger, tx);
      t = { tx, next: 0 };
      txs.set(key, t);
    }
    return {
      ledger: e.ledger,
      closed_at: world.rpc.closeTime(e.ledger),
      tx_hash: e.txHash,
      tx: t.tx,
      op: 0,
      index: t.next++,
      contract: world.vault.address,
      topics: [xdr.ScVal.scvSymbol(e.topic).toXDR("base64")],
      value: map(e.fields).toXDR("base64"),
    };
  });
}

const topicOf = (line: RawLine): string =>
  xdr.ScVal.fromXDR(line.topics[0] as string, "base64")
    .sym()
    .toString();

/** The bytes of a window: its lines and the closing line. */
export function windowBytes(start: number, lines: readonly RawLine[]): Uint8Array {
  const body = lines.map((l) => JSON.stringify(l) + "\n").join("");
  const end = start + WINDOW_LEDGERS - 1;
  return new TextEncoder().encode(`${body}{"covered":[${start},${end}],"count":${lines.length}}\n`);
}

/** Builds the archive of every closed window of the world's vault up to `coveredTo`. */
export function buildArchive(world: World, coveredTo: number, producer = "test"): Archive {
  const deploy = world.deployment.deployLedger;
  const all = rawEvents(world);
  const windows: WindowEntry[] = [];
  const lines = new Map<number, RawLine[]>();
  const files = new Map<string, Uint8Array>();
  let leaves = 0;
  for (let start = deploy - (deploy % WINDOW_LEDGERS); start < coveredTo; start += WINDOW_LEDGERS) {
    const end = start + WINDOW_LEDGERS - 1;
    const inside = all.filter((l) => l.ledger >= start && l.ledger <= end);
    const added = inside.filter((l) => topicOf(l) === "new_commitment").length;
    const entry: WindowEntry = {
      start,
      end,
      events: inside.length,
      leaves: [leaves, leaves + added],
      nullifiers: inside.filter((l) => topicOf(l) === "new_nullifier").length,
      bytes: 0,
    };
    leaves += added;
    if (inside.length > 0) {
      const data = windowBytes(start, inside);
      entry.bytes = data.length;
      entry.sha256 = createHash("sha256").update(data).digest("hex");
      files.set(fileOf(start), gzipSync(data));
      lines.set(start, inside);
    }
    windows.push(entry);
  }
  const manifest: Manifest = {
    format: "cyphras-vault-archive/1",
    network: world.deployment.network,
    networkPassphrase: world.deployment.networkPassphrase,
    vault: world.deployment.vault,
    deployLedger: deploy,
    windowLedgers: WINDOW_LEDGERS,
    coveredTo: windows[windows.length - 1]?.end ?? 0,
    windows,
    producer,
  };
  files.set("manifest.json", manifestBytes(manifest));
  return { manifest, lines, files };
}

/** Writes a window's lines again, with its manifest entry and the manifest made to match. */
export function rewriteWindow(
  archive: Archive,
  start: number,
  change: (lines: RawLine[]) => RawLine[],
  counts?: Partial<WindowEntry>,
): void {
  const lines = change([...(archive.lines.get(start) ?? [])]);
  const data = windowBytes(start, lines);
  const entry = archive.manifest.windows?.find((w) => w.start === start) as WindowEntry;
  entry.events = lines.length;
  entry.bytes = data.length;
  entry.sha256 = createHash("sha256").update(data).digest("hex");
  Object.assign(entry, counts);
  archive.lines.set(start, lines);
  archive.files.set(fileOf(start), gzipSync(data));
  archive.files.set("manifest.json", manifestBytes(archive.manifest));
}

/** What a server of archive files does with each request. */
export interface ArchiveServer {
  readonly fetch: FetchLike;
  readonly requests: string[];
  // Serves this instead of the stored file, or a status, or fails the request, by path.
  answer: ((path: string) => Response | "fail" | undefined) | undefined;
}

/** Routes requests to `base` to the archive's files, and everything else to `next`. */
export function serveArchive(
  next: FetchLike,
  archives: Readonly<Record<string, Archive>>,
): ArchiveServer {
  const server: ArchiveServer = {
    requests: [],
    answer: undefined,
    fetch: async (input, init) => {
      const url = new URL(input);
      const archive = archives[url.origin];
      if (archive === undefined) return next(input, init);
      const path = url.pathname.replace(/^\//, "");
      server.requests.push(`${url.origin}/${path}`);
      const special = server.answer?.(path);
      if (special === "fail") throw new TypeError("Failed to fetch");
      if (special !== undefined) return special;
      const file = archive.files.get(path);
      return file === undefined
        ? new Response("not found", { status: 404 })
        : new Response(new Uint8Array(file), { status: 200 });
    },
  };
  return server;
}

/** A fetch that reads archive files from a directory for requests to `base`. */
export function directoryFetch(next: FetchLike, base: string, dir: string): FetchLike {
  return async (input, init) => {
    if (!input.startsWith(base + "/")) return next(input, init);
    try {
      return new Response(new Uint8Array(readFileSync(join(dir, input.slice(base.length + 1)))));
    } catch {
      return new Response("not found", { status: 404 });
    }
  };
}
