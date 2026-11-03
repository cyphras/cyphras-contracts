import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import { nativeToScVal, xdr } from "@stellar/stellar-base";
import { PINNED_ARCHIVES, PINNED_DEPLOYMENTS } from "../../src/deployments.ts";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { MemoryStore } from "../../src/storage.ts";
import type { OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import {
  ARCHIVE,
  type Archive,
  MIRROR,
  type RawLine,
  WINDOW_LEDGERS,
  buildArchive,
  directoryFetch,
  fileOf,
  manifestBytes,
  rewriteWindow,
  serveArchive,
} from "../support/archive.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { isError, openWallet } from "../support/wallets.ts";

const SECOND = "http://second-rpc.test";

const topicOf = (l: RawLine): string =>
  xdr.ScVal.fromXDR(l.topics[0] as string, "base64")
    .sym()
    .toString();

// A vault event's data with one field set to another value.
function withField(line: RawLine, name: string, value: xdr.ScVal): RawLine {
  const entries = xdr.ScVal.fromXDR(line.value, "base64").map() ?? [];
  const changed = entries.map((e) =>
    e.key().sym().toString() === name ? new xdr.ScMapEntry({ key: e.key(), val: value }) : e,
  );
  return { ...line, value: xdr.ScVal.scvMap(changed).toXDR("base64") };
}

const reasonIs = (reason: string) => (err: unknown) =>
  err instanceof CyphrasError &&
  err.code === "history_unavailable" &&
  err.details["reason"] === reason;

// Alice pays Bob 10 XLM in the archive's first window and 5 XLM after it; then the indexer goes
// down and RPC keeps only the ledgers from the second window on. Bob restores from his seed.
async function restore(windows = 1) {
  const world = await createWorld();
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  const bob = (await openWallet(world, 1)).generateAddress();
  await alice.send({ to: bob, amount: 10n * XLM, maxFee: 2n * XLM });
  for (let w = 1; w <= windows; w++) {
    world.advance(5 * (w * WINDOW_LEDGERS + 50 - world.vault.ledger));
    await alice.send({ to: bob, amount: 5n * XLM, maxFee: 2n * XLM });
  }
  const archive = buildArchive(world, windows * WINDOW_LEDGERS - 1);
  world.indexer.down = true;
  world.rpc.oldestLedger = windows * WINDOW_LEDGERS;
  const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
  return { world, alice, archive, server };
}

async function bobWith(
  world: World,
  fetchFn: FetchLike,
  options: Partial<OpenOptions> = { archives: [ARCHIVE] },
): Promise<PrivateWallet> {
  return openWallet(world, 1, new MemoryStore(), undefined, { fetch: fetchFn, ...options });
}

// Nothing of a refused sync is kept.
async function keptNothing(wallet: PrivateWallet): Promise<void> {
  assert.equal(wallet.treeStatus().leafCount, 0);
  assert.equal((await wallet.balance()).spendable, 0n);
}

describe("archive sync: restore with no indexer and RPC past its retention", () => {
  it("rebuilds the notes from the archive and RPC's events after it", async () => {
    const { world, server } = await restore();
    const bob = await bobWith(world, server.fetch);
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal(summary.rootVerified, true);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    assert.equal(summary.leafCount, world.vault.tree.leafCount);
    // The archive's four leaves can never be checked; RPC showed the rest.
    assert.equal(summary.lostLeaves, 4);
    assert.equal(summary.uncheckedLeaves, 4);
    assert.ok(server.requests.includes(`${ARCHIVE}/${fileOf(0)}`));
    const again = await bob.sync();
    assert.equal(again.source, "rpc");
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("refuses the restore without an archive, as before", async () => {
    const { world, server } = await restore();
    const bob = await bobWith(world, server.fetch, {});
    await assert.rejects(bob.sync(), reasonIs("archive_unconfigured"));
    assert.deepEqual(server.requests, []);
  });

  it("carries a long restore over several syncs, one window per sync", async () => {
    const { world, server } = await restore(2);
    const bob = await bobWith(world, server.fetch, {
      archives: [ARCHIVE],
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    const first = await bob.sync();
    assert.equal(first.source, "archive");
    assert.ok(!server.requests.includes(`${ARCHIVE}/${fileOf(WINDOW_LEDGERS)}`));
    const second = await bob.sync();
    assert.equal(second.source, "archive");
    assert.equal(second.rootVerified, true);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
  });

  it("reads a copy in a local directory", async () => {
    const { world, archive } = await restore();
    const dir = mkdtempSync(join(tmpdir(), "archive-"));
    for (const [name, file] of archive.files) {
      mkdirSync(dirname(join(dir, name)), { recursive: true });
      writeFileSync(join(dir, name), file);
    }
    const local = "http://127.0.0.1:8765";
    const bob = await bobWith(world, directoryFetch(world.fetch, local, dir), {
      archives: [local],
    });
    assert.equal((await bob.sync()).source, "archive");
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("cross-checks RPC's events after the archive with a second provider", async () => {
    const { world, server } = await restore();
    const routed: FetchLike = (input, init) =>
      server.fetch(input.startsWith(SECOND) ? RPC + input.slice(SECOND.length) : input, init);
    const bob = await bobWith(world, routed, { archives: [ARCHIVE], secondRpcUrl: SECOND });
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal(summary.crossChecked, true);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("runs two syncs at once one after the other", async () => {
    const { world, server } = await restore();
    const bob = await bobWith(world, server.fetch);
    const [a, b] = await Promise.all([bob.sync(), bob.sync()]);
    assert.equal(a.source, "archive");
    assert.equal(b.leafCount, a.leafCount);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});

describe("archive sync: the order of sources", () => {
  it("never asks the archive while the indexer answers", async () => {
    const { world, server } = await restore();
    world.indexer.down = false;
    world.rpc.oldestLedger = 1;
    const bob = await bobWith(world, server.fetch);
    assert.equal((await bob.sync()).source, "indexer");
    assert.deepEqual(server.requests, []);
  });

  it("never asks the archive while RPC holds where the sync starts", async () => {
    const { world, server } = await restore();
    world.rpc.oldestLedger = 1;
    const bob = await bobWith(world, server.fetch);
    assert.equal((await bob.sync()).source, "rpc");
    assert.deepEqual(server.requests, []);
  });

  it("syncs as before through the indexer while the archive is down", async () => {
    const { world, server } = await restore();
    world.indexer.down = false;
    server.answer = () => "fail";
    const bob = await bobWith(world, server.fetch);
    assert.equal((await bob.sync()).source, "indexer");
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("passes over a copy that breaks a rule for the next one", async () => {
    const { world, archive } = await restore();
    const bad = structuredClone(archive);
    bad.files.set(fileOf(0), new Uint8Array(gzipSync("{}\n")));
    const server = serveArchive(world.fetch, { [MIRROR]: bad, [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, { archives: [MIRROR, ARCHIVE] });
    assert.equal((await bob.sync()).source, "archive");
    assert.equal(server.requests[0], `${MIRROR}/manifest.json`);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});

describe("archive sync: hostile archives", () => {
  const faults: [string, (a: Archive, world: World) => void, RegExp][] = [
    [
      "a window with another hash",
      (a) => {
        const file = a.files.get(fileOf(0)) as Uint8Array;
        const data = gunzipSync(file);
        data[10] = (data[10] as number) ^ 1;
        a.files.set(fileOf(0), new Uint8Array(gzipSync(data)));
      },
      /SHA-256/,
    ],
    [
      "a truncated window",
      (a) => {
        const file = a.files.get(fileOf(0)) as Uint8Array;
        a.files.set(fileOf(0), file.subarray(0, file.length - 12));
      },
      /gzip/,
    ],
    [
      "a window it lists but does not hold",
      (a) => {
        a.files.delete(fileOf(0));
      },
      /no file/,
    ],
    [
      "events in another order",
      (a) => rewriteWindow(a, 0, (l) => [l[1] as RawLine, l[0] as RawLine, ...l.slice(2)]),
      /order/,
    ],
    [
      "a nullifier the vault never spent",
      (a) => {
        const nf = a.lines.get(0)?.find((l) => topicOf(l) === "new_nullifier") as RawLine;
        const made = withField(nf, "nullifier", nativeToScVal(123_456_789n, { type: "u256" }));
        const w = a.manifest.windows?.[0];
        rewriteWindow(a, 0, (l) => [...l, { ...made, ledger: WINDOW_LEDGERS - 1, tx: 1 }], {
          nullifiers: (w?.nullifiers ?? 0) + 1,
        });
      },
      /never spent/,
    ],
    [
      "a manifest larger than its limit",
      (a) => {
        a.files.set("manifest.json", new Uint8Array((4 << 20) + 1).fill(32));
      },
      /larger/,
    ],
    [
      "a manifest of another vault",
      (a) => {
        const testnet = PINNED_DEPLOYMENTS["testnet/xlm"];
        a.manifest.vault = testnet?.vault ?? "";
        a.files.set("manifest.json", manifestBytes(a.manifest));
      },
      /another vault/,
    ],
  ];
  for (const [name, change, pattern] of faults) {
    it(`refuses ${name} and keeps nothing`, async () => {
      const { world, archive, server } = await restore();
      change(archive, world);
      const bob = await bobWith(world, server.fetch);
      await assert.rejects(
        bob.sync(),
        (err: unknown) => isError("archive_fault")(err) && pattern.test((err as Error).message),
      );
      assert.equal(bob.treeStatus().fault, true);
      await keptNothing(bob);
    });
  }

  const early: [string, (a: Archive, world: World) => void, RegExp][] = [
    [
      "more leaves than the vault holds",
      (a) => {
        const w = a.manifest.windows?.[0];
        if (w !== undefined) {
          w.leaves = [0, w.leaves[1] + 100];
          w.events += 100;
        }
        a.files.set("manifest.json", manifestBytes(a.manifest));
      },
      /more leaves/,
    ],
    [
      "ledgers the chain has not closed",
      (a, world) => {
        for (let start = WINDOW_LEDGERS; start <= world.vault.ledger; start += WINDOW_LEDGERS) {
          const leaves = a.manifest.windows?.[0]?.leaves[1] ?? 0;
          a.manifest.windows?.push({
            start,
            end: start + WINDOW_LEDGERS - 1,
            events: 0,
            leaves: [leaves, leaves],
            nullifiers: 0,
            bytes: 0,
          });
          a.manifest.coveredTo = start + WINDOW_LEDGERS - 1;
        }
        a.files.set("manifest.json", manifestBytes(a.manifest));
      },
      /not closed/,
    ],
  ];
  for (const [name, change, pattern] of early) {
    it(`refuses a manifest that claims ${name} before reading any window`, async () => {
      const { world, archive, server } = await restore();
      change(archive, world);
      const bob = await bobWith(world, server.fetch);
      await assert.rejects(
        bob.sync(),
        (err: unknown) => isError("archive_fault")(err) && pattern.test((err as Error).message),
      );
      assert.deepEqual(server.requests, [`${ARCHIVE}/manifest.json`]);
      await keptNothing(bob);
    });
  }

  it("refuses a replaced commitment by the vault's root and keeps nothing", async () => {
    const { world, archive, server } = await restore();
    rewriteWindow(archive, 0, (lines) => {
      const at = lines.findIndex((l) => topicOf(l) === "new_commitment");
      return lines.map((l, i) =>
        i === at ? withField(l, "commitment", nativeToScVal(42n, { type: "u256" })) : l,
      );
    });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("tree_unverified"));
    await keptNothing(bob);
  });

  it("refuses an archive whose leaves end before RPC's events go on", async () => {
    const { world, archive, server } = await restore();
    const w = archive.manifest.windows?.[0];
    rewriteWindow(
      archive,
      0,
      (lines) => {
        const last = lines.map(topicOf).lastIndexOf("new_commitment");
        return lines.filter((_, i) => i !== last && i !== last - 1);
      },
      { leaves: [0, (w?.leaves[1] ?? 2) - 2] },
    );
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(
      bob.sync(),
      (err: unknown) => isError("archive_fault")(err) && /join/.test((err as Error).message),
    );
    await keptNothing(bob);
  });
});

describe("archive sync: failures of the archive and of RPC", () => {
  const answers: [string, (path: string) => Response | "fail" | undefined][] = [
    ["a manifest it does not have", () => new Response("", { status: 404 })],
    ["a server error", () => new Response("", { status: 500 })],
    ["a refused cross-origin request", () => "fail"],
    ["too many requests", () => new Response("", { status: 429 })],
    [
      "a body that stops half way",
      () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.enqueue(new TextEncoder().encode("{"));
              controller.error(new TypeError("network error"));
            },
          }),
        ),
    ],
  ];
  for (const [name, answer] of answers) {
    it(`reports ${name} as an unreachable archive`, async () => {
      const { world, server } = await restore();
      server.answer = answer;
      const bob = await bobWith(world, server.fetch);
      await assert.rejects(bob.sync(), reasonIs("archive_unreachable"));
      assert.equal(bob.treeStatus().fault, false);
      await keptNothing(bob);
    });
  }

  it("reports a window that cannot be fetched as an unreachable archive", async () => {
    const { world, server } = await restore();
    server.answer = (path) => (path === fileOf(0) ? "fail" : undefined);
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), reasonIs("archive_unreachable"));
  });

  it("reports an archive that ends before RPC's history begins as a gap", async () => {
    const { world, server } = await restore();
    world.rpc.oldestLedger = WINDOW_LEDGERS + 1;
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), reasonIs("archive_gap"));
    await keptNothing(bob);
  });

  it("reports a gap when RPC's history moves past the archive during the sync", async () => {
    const { world, server } = await restore();
    server.answer = (path) => {
      if (path === "manifest.json") world.rpc.oldestLedger = WINDOW_LEDGERS + 1;
      return undefined;
    };
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), reasonIs("archive_gap"));
    await keptNothing(bob);
  });

  it("keeps to the manifest it read while the archive moves on", async () => {
    const { world, archive, server } = await restore();
    const newer = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    server.answer = (path) => {
      if (path === "manifest.json") {
        const first = archive.files.get("manifest.json") as Uint8Array;
        archive.files = newer.files;
        return new Response(new Uint8Array(first));
      }
      return undefined;
    };
    world.advance(5 * WINDOW_LEDGERS);
    const bob = await bobWith(world, server.fetch);
    assert.equal((await bob.sync()).source, "archive");
    assert.equal(server.requests.filter((r) => r.endsWith("manifest.json")).length, 1);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});

describe("archive sync: where the URLs come from", () => {
  it("pins https copies for each pinned deployment and none for others", () => {
    for (const urls of Object.values(PINNED_ARCHIVES)) {
      assert.ok(urls.length > 0 && urls.every((u) => u.startsWith("https://")));
    }
    assert.ok(Object.isFrozen(PINNED_ARCHIVES["mainnet/xlm"]));
  });

  for (const url of [
    "http://archive.example",
    "https://user:secret@archive.example",
    "ftp://127.0.0.1/a",
    "not a url",
  ]) {
    it(`refuses the archive URL ${url}`, async () => {
      const world = await createWorld();
      await assert.rejects(
        openWallet(world, 1, new MemoryStore(), undefined, {
          deployment: "testnet/xlm",
          archives: [url],
        }),
        isError("invalid_argument"),
      );
    });
  }

  it("takes https and http on this machine", async () => {
    const world = await createWorld();
    await openWallet(world, 1, new MemoryStore(), undefined, {
      deployment: "testnet/xlm",
      archives: ["https://mirror.example/a", "http://localhost:8080", "http://127.0.0.1:1/x"],
    });
  });
});
