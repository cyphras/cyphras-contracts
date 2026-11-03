import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import { xdr } from "@stellar/stellar-base";
import { PINNED_DEPLOYMENTS } from "../../src/deployments.ts";
import { CyphrasError } from "../../src/errors.ts";
import {
  type ArchivePin,
  type ArchiveWindow,
  MAX_MANIFEST_BYTES,
  checkWindow,
  fetchManifest,
  parseManifest,
} from "../../src/net/archive.ts";
import { type RawLine, windowBytes } from "../support/archive.ts";

const FIXTURES = new URL("../fixtures/archive/", import.meta.url);
const read = (path: string): Uint8Array => new Uint8Array(readFileSync(new URL(path, FIXTURES)));

// The pin of the archives the archive tool's own tests build: its test vault on testnet.
const GO_PIN: ArchivePin = {
  vault: "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5",
  networkPassphrase: "Test SDF Network ; September 2015",
  deployLedger: 10,
};

const testnet = PINNED_DEPLOYMENTS["testnet/xlm"];
const TESTNET_PIN: ArchivePin = {
  vault: testnet?.vault ?? "",
  networkPassphrase: testnet?.networkPassphrase ?? "",
  deployLedger: testnet?.deployLedger ?? 0,
};

const refused = (pattern?: RegExp) => (err: unknown) =>
  err instanceof CyphrasError &&
  err.code === "archive_fault" &&
  (pattern === undefined || pattern.test(err.message));

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);
const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);

function goSample() {
  const manifest = parseManifest(read("go-sample/manifest.json"), GO_PIN);
  const w = manifest.windows[0] as ArchiveWindow;
  const file = read("go-sample/windows/0000000000.jsonl.gz");
  const lines = text(gunzipSync(file))
    .trimEnd()
    .split("\n")
    .slice(0, -1)
    .map((l) => JSON.parse(l) as RawLine);
  return { manifest, w, file, lines };
}

// A window of other lines, with an entry whose size and hash fit them and with `counts` over it.
function variant(
  w: ArchiveWindow,
  lines: readonly RawLine[],
  counts: Partial<ArchiveWindow> = {},
  raw?: string,
): { entry: ArchiveWindow; file: Uint8Array } {
  const data = raw === undefined ? windowBytes(w.start, lines) : bytes(raw);
  return {
    entry: {
      ...w,
      events: lines.length,
      bytes: data.length,
      sha256: createHash("sha256").update(data).digest("hex"),
      ...counts,
    },
    file: new Uint8Array(gzipSync(data)),
  };
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// The same bytes in base64 with the lowest spare bit of the last digit set: a decoder that ignores
// spare bits reads it as the same value.
function spareBit(value: string): string {
  const at = value.replace(/=+$/, "").length - 1;
  return value.slice(0, at) + B64[B64.indexOf(value[at] as string) ^ 1] + value.slice(at + 1);
}

const topicOf = (l: RawLine): string =>
  xdr.ScVal.fromXDR(l.topics[0] as string, "base64")
    .sym()
    .toString();

describe("archive format: files the archive tool wrote", () => {
  it("reads the tool's manifest, with its escapes, and every window of it", async () => {
    const m = parseManifest(read("go-sample/manifest.json"), GO_PIN);
    assert.equal(m.producer, 'go <vectors> & "more"');
    assert.deepEqual(
      m.windows.map((w) => [w.start, w.leaves, w.sha256 === undefined]),
      [
        [0, [0, 4], false],
        [17280, [4, 8], false],
        [34560, [8, 8], true],
      ],
    );
    const contents = await Promise.all(
      m.windows
        .filter((w) => w.events > 0)
        .map((w) =>
          checkWindow(
            w,
            read(`go-sample/windows/${String(w.start).padStart(10, "0")}.jsonl.gz`),
            GO_PIN,
          ),
        ),
    );
    assert.deepEqual(
      contents.map((c) => [c.leaves.map((l) => l.index), c.nullifiers.length]),
      [
        [[0, 1, 2, 3], 4],
        [[4, 5, 6, 7], 4],
      ],
    );
  });

  it("reads a manifest with no closed window yet", () => {
    const m = parseManifest(read("go-empty/manifest.json"), GO_PIN);
    assert.deepEqual([m.windows, m.coveredTo], [[], 0]);
  });

  it("reads the published testnet archive, byte for byte as served", async () => {
    const m = parseManifest(read("testnet/manifest.json"), TESTNET_PIN);
    assert.equal(m.coveredTo, 5_529_599);
    let leaves = 0;
    let nullifiers = 0;
    for (const name of readdirSync(new URL("testnet/windows/", FIXTURES)).sort()) {
      const w = m.windows.find((x) => `${String(x.start).padStart(10, "0")}.jsonl.gz` === name);
      assert.ok(w !== undefined);
      const c = await checkWindow(w, read(`testnet/windows/${name}`), TESTNET_PIN);
      leaves += c.leaves.length;
      nullifiers += c.nullifiers.length;
    }
    assert.deepEqual([leaves, nullifiers], [274, 276]);
    assert.equal(m.windows.filter((w) => w.events > 0).length, 9);
  });

  it("refuses the tool's manifest written without Go's escapes", () => {
    const raw = JSON.stringify(JSON.parse(text(read("go-sample/manifest.json"))), null, 2) + "\n";
    assert.throws(() => parseManifest(bytes(raw), GO_PIN), refused(/canonical/));
  });
});

describe("archive format: manifests that break a rule", () => {
  const source = text(read("go-sample/manifest.json"));
  const cases: [string, (s: string) => string, RegExp][] = [
    [
      "a field of its own",
      (s) => s.replace('"producer"', '"extra": 1,\n  "producer"'),
      /canonical/,
    ],
    ["a key twice", (s) => s.replace('"producer"', '"vault": "x",\n  "producer"'), /canonical/],
    ["a key in other case", (s) => s.replace('"vault"', '"Vault"'), /vault/],
    ["compact text", (s) => JSON.stringify(JSON.parse(s)) + "\n", /canonical/],
    ["no final newline", (s) => s.trimEnd(), /canonical/],
    [
      "a number written otherwise",
      (s) => s.replace('"deployLedger": 10', '"deployLedger": 1e1'),
      /canonical/,
    ],
    ["another vault", (s) => s.replaceAll(GO_PIN.vault, TESTNET_PIN.vault), /another vault/],
    ["another network", (s) => s.replace("Test SDF", "Public Global Stellar"), /another network/],
    [
      "another deploy ledger",
      (s) => s.replace('"deployLedger": 10', '"deployLedger": 11'),
      /deploy ledger/,
    ],
    ["a window left out", (s) => s.replace('"start": 17280', '"start": 17281'), /follow/],
    [
      "leaves that do not continue",
      (s) =>
        s.replace(
          '4,\n        8\n      ],\n      "nullifiers": 4',
          '6,\n        8\n      ],\n      "nullifiers": 4',
        ),
      /continue/,
    ],
    ["an odd leaf count", (s) => s.replace("0,\n        4\n", "0,\n        3\n"), /continue/],
    [
      "coveredTo past its windows",
      (s) => s.replace('"coveredTo": 51839', '"coveredTo": 51840'),
      /coveredTo/,
    ],
    [
      "an empty window with a hash",
      (s) => s.replace('"bytes": 0\n', '"bytes": 0,\n      "sha256": "' + "ab".repeat(32) + '"\n'),
      /no events/,
    ],
    ["a window without a hash", (s) => s.replace(/,\n {6}"sha256": "d8[0-9a-f]+"/, ""), /hash/],
    [
      "more nullifiers than events",
      (s) =>
        s.replace(
          '"nullifiers": 4,\n      "bytes": 6582',
          '"nullifiers": 40,\n      "bytes": 6582',
        ),
      /counts/,
    ],
    [
      "a window past the size limit",
      (s) => s.replace('"bytes": 6582', `"bytes": ${(64 << 20) + 1}`),
      /counts/,
    ],
    [
      "a producer with a control character",
      (s) => s.replace('"producer": "go', '"producer": "\\u0001go'),
      /producer/,
    ],
  ];
  for (const [name, change, pattern] of cases) {
    it(`refuses ${name}`, () => {
      const changed = change(source);
      assert.notEqual(changed, source);
      assert.throws(() => parseManifest(bytes(changed), GO_PIN), refused(pattern));
    });
  }

  it("refuses bytes that are not UTF-8", () => {
    const raw = read("go-sample/manifest.json");
    const broken = new Uint8Array([...raw.subarray(0, 20), 0xff, ...raw.subarray(20)]);
    assert.throws(() => parseManifest(broken, GO_PIN), refused(/UTF-8/));
  });

  it("refuses another format with its name in the details", () => {
    const raw = source.replace("cyphras-vault-archive/1", "cyphras-vault-archive/2");
    assert.throws(
      () => parseManifest(bytes(raw), GO_PIN),
      (err: unknown) =>
        refused(/format/)(err) &&
        (err as CyphrasError).details["format"] === "cyphras-vault-archive/2",
    );
  });

  it("stops reading a manifest past its size limit", async () => {
    let sent = 0;
    const huge = new ReadableStream<Uint8Array>({
      pull(controller) {
        sent += 1 << 20;
        controller.enqueue(new Uint8Array(1 << 20).fill(32));
      },
    });
    await assert.rejects(
      fetchManifest(async () => new Response(huge), "http://archive.test", GO_PIN),
      refused(/larger/),
    );
    assert.ok(sent <= MAX_MANIFEST_BYTES + (2 << 20));
  });
});

describe("archive format: windows that break a rule", () => {
  it("takes the tool's window as it is and as written again from its lines", async () => {
    const { w, file, lines } = goSample();
    await checkWindow(w, file, GO_PIN);
    const again = variant(w, lines);
    assert.equal(again.entry.sha256, w.sha256);
    await checkWindow(again.entry, again.file, GO_PIN);
  });

  const lineCases: [string, (lines: RawLine[]) => RawLine[], RegExp, Partial<ArchiveWindow>?][] = [
    ["events out of order", (l) => [l[1] as RawLine, l[0] as RawLine, ...l.slice(2)], /order/],
    ["an event twice", (l) => [l[0] as RawLine, ...l], /order/],
    [
      "an event of another contract",
      (l) => [{ ...(l[0] as RawLine), contract: TESTNET_PIN.vault }, ...l.slice(1)],
      /another contract/,
    ],
    [
      "a ledger outside the window",
      (l) => [...l.slice(0, -1), { ...(l[l.length - 1] as RawLine), ledger: 17_280 }],
      /outside/,
    ],
    [
      "a ledger before the deploy ledger",
      (l) => [{ ...(l[0] as RawLine), ledger: 9 }, ...l.slice(1)],
      /before the deploy/,
    ],
    ["no close time", (l) => [{ ...(l[0] as RawLine), closed_at: 0 }, ...l.slice(1)], /close time/],
    [
      "a short transaction hash",
      (l) => [{ ...(l[0] as RawLine), tx_hash: "ab" }, ...l.slice(1)],
      /hash/,
    ],
    [
      "an unknown topic",
      (l) => [
        { ...(l[0] as RawLine), topics: [xdr.ScVal.scvSymbol("drained").toXDR("base64")] },
        ...l.slice(1),
      ],
      /unknown topic/,
    ],
    [
      "a topic that is not a symbol",
      (l) => [
        { ...(l[0] as RawLine), topics: [xdr.ScVal.scvU32(1).toXDR("base64")] },
        ...l.slice(1),
      ],
      /vault event/,
    ],
    [
      "base64 with other spare bits",
      (l) =>
        l.map((x) =>
          x === l.find((y) => y.value.endsWith("=")) ? { ...x, value: spareBit(x.value) } : x,
        ),
      /canonical/,
    ],
  ];
  for (const [name, change, pattern, counts] of lineCases) {
    it(`refuses ${name}`, async () => {
      const { w, lines } = goSample();
      const changed = change(lines);
      const v = variant(w, changed, counts);
      await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused(pattern));
    });
  }

  it("refuses a pair of leaves split across transactions", async () => {
    const { w, lines } = goSample();
    const second = lines.findIndex((l) => topicOf(l) === "new_commitment") + 1;
    const changed = lines.map((l, i) => (i === second ? { ...l, tx: l.tx + 1, index: 0 } : l));
    const v = variant(w, changed);
    await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused(/pair|order/));
  });

  it("refuses a leaf left out", async () => {
    const { w, lines } = goSample();
    const first = lines.findIndex((l) => topicOf(l) === "new_commitment");
    const v = variant(
      w,
      lines.filter((_, i) => i !== first),
      { leaves: [0, 3] },
    );
    await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused(/belongs/));
  });

  it("refuses a nullifier spent twice", async () => {
    const { w, lines } = goSample();
    const nf = lines.find((l) => topicOf(l) === "new_nullifier") as RawLine;
    const changed = [...lines, { ...nf, ledger: 17_000, tx: 1, index: 0 }];
    const v = variant(w, changed, { nullifiers: 5 });
    await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused(/twice/));
  });

  it("refuses a line that is not in canonical form", async () => {
    const { w, lines } = goSample();
    const body = lines
      .map((l) => JSON.stringify(l))
      .join("\n")
      .replace('"ledger":', '"ledger": ');
    const v = variant(w, lines, {}, `${body}\n{"covered":[0,17279],"count":${lines.length}}\n`);
    await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused(/canonical/));
  });

  it("refuses a line with a field of its own", async () => {
    const { w, lines } = goSample();
    const body = lines.map((l, i) => JSON.stringify(i === 0 ? { ...l, extra: 1 } : l)).join("\n");
    const v = variant(w, lines, {}, `${body}\n{"covered":[0,17279],"count":${lines.length}}\n`);
    await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused(/canonical/));
  });

  const closings: [string, string][] = [
    ["no closing line", ""],
    ["a closing line of another count", '{"covered":[0,17279],"count":1}\n'],
    ["a closing line of other bounds", '{"covered":[0,17280],"count":13}\n'],
    ["a closing line without its newline", '{"covered":[0,17279],"count":13}'],
  ];
  for (const [name, closing] of closings) {
    it(`refuses ${name}`, async () => {
      const { w, lines } = goSample();
      const body = lines.map((l) => JSON.stringify(l) + "\n").join("");
      const v = variant(w, lines, {}, body + closing);
      await assert.rejects(checkWindow(v.entry, v.file, GO_PIN), refused());
    });
  }

  it("refuses counts other than the manifest states", async () => {
    const { w, file } = goSample();
    for (const counts of [{ nullifiers: 3 }, { leaves: [0, 6] as const }, { events: 14 }]) {
      await assert.rejects(checkWindow({ ...w, ...counts }, file, GO_PIN), refused());
    }
  });

  it("refuses another SHA-256 or size than the manifest states", async () => {
    const { w, file } = goSample();
    const sha256 = (w.sha256 as string).replace(/^./, (c) => (c === "0" ? "1" : "0"));
    await assert.rejects(checkWindow({ ...w, sha256 }, file, GO_PIN), refused(/SHA-256/));
    await assert.rejects(checkWindow({ ...w, bytes: w.bytes + 1 }, file, GO_PIN), refused(/size/));
    await assert.rejects(checkWindow({ ...w, bytes: w.bytes - 1 }, file, GO_PIN), refused());
  });

  it("refuses a truncated gzip file at every cut", async () => {
    const { w, file } = goSample();
    for (const cut of [1, 4, 8, 9, 20, file.length - 100]) {
      await assert.rejects(checkWindow(w, file.subarray(0, file.length - cut), GO_PIN), refused());
    }
  });

  it("refuses a second gzip member, bytes after the first one and a file past its bound", async () => {
    const { w, file } = goSample();
    const empty = new Uint8Array(gzipSync(new Uint8Array(0)));
    const padded = new Uint8Array([...file, ...empty]);
    await assert.rejects(checkWindow(w, padded, GO_PIN), refused(/gzip/));
    await assert.rejects(checkWindow(w, new Uint8Array([...file, 0]), GO_PIN), refused(/gzip/));
    const leading = new Uint8Array([...empty, ...file]);
    await assert.rejects(checkWindow(w, leading, GO_PIN), refused(/gzip/));
    const long = new Uint8Array(w.bytes + Math.floor(w.bytes / 64) + 4097);
    await assert.rejects(checkWindow(w, long, GO_PIN), refused(/larger file/));
    await assert.rejects(checkWindow(w, gunzipSync(file), GO_PIN), refused(/gzip/));
  });

  it("reads gzip headers with a name and a header checksum as Go does", async () => {
    const { w, file } = goSample();
    const body = file.subarray(10);
    const header = (flags: number, extra: number[]): Uint8Array =>
      new Uint8Array([0x1f, 0x8b, 8, flags, 0, 0, 0, 0, 0, 255, ...extra]);
    const named = new Uint8Array([...header(8, [...bytes("w.jsonl"), 0]), ...body]);
    await checkWindow(w, named, GO_PIN);
    const long = new Uint8Array([...header(8, [...new Uint8Array(512).fill(65), 0]), ...body]);
    await assert.rejects(checkWindow(w, long, GO_PIN), refused(/gzip/));
    const crc = (data: Uint8Array): number => {
      let c = 0xffffffff;
      for (const b of data) {
        c ^= b;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      }
      return (c ^ 0xffffffff) >>> 0;
    };
    const plain = header(2, []);
    const sum = crc(plain) & 0xffff;
    const checked = new Uint8Array([...plain, sum & 0xff, sum >> 8, ...body]);
    await checkWindow(w, checked, GO_PIN);
    const wrong = new Uint8Array([...plain, (sum + 1) & 0xff, sum >> 8, ...body]);
    await assert.rejects(checkWindow(w, wrong, GO_PIN), refused(/gzip/));
  });
});
