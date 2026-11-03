import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { nativeToScVal, xdr } from "@stellar/stellar-base";
import { PINNED_ARCHIVES, PINNED_DEPLOYMENTS, archiveUrls } from "../../src/deployments.ts";
import { CyphrasError } from "../../src/errors.ts";
import { CommitmentTree } from "../../src/merkle.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { SorobanRpc as Rpc } from "../../src/net/rpc.ts";
import { MemoryStore } from "../../src/storage.ts";
import { VaultReader } from "../../src/vault/state.ts";
import { ArchiveSource } from "../../src/wallet/archive.ts";
import { checkRoot } from "../../src/wallet/sync.ts";
import type { OpenOptions, PrivateWallet, SyncSummary } from "../../src/wallet/wallet.ts";
import {
  ARCHIVE,
  type Archive,
  type RawLine,
  WINDOW_LEDGERS,
  buildArchive,
  fileOf,
  rewriteWindow,
  serveArchive,
} from "../support/archive.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const SECOND = "http://second-rpc.test";

const topicOf = (l: RawLine): string =>
  xdr.ScVal.fromXDR(l.topics[0] as string, "base64")
    .sym()
    .toString();

function withField(line: RawLine, name: string, value: xdr.ScVal): RawLine {
  const entries = xdr.ScVal.fromXDR(line.value, "base64").map() ?? [];
  const changed = entries.map((e) =>
    e.key().sym().toString() === name ? new xdr.ScMapEntry({ key: e.key(), val: value }) : e,
  );
  return { ...line, value: xdr.ScVal.scvMap(changed).toXDR("base64") };
}

// Alice pays Bob 10 XLM in window 0 and 5 XLM in each later window up to `windows`, with `filler`
// pairs inserted by others in window 1; then the indexer goes down and RPC keeps the ledgers from
// window `windows` on only.
async function history(windows: number, filler = 0) {
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
    if (w === 1 && filler > 0) world.fill(filler);
    await alice.sync();
    await alice.send({ to: bob, amount: 5n * XLM, maxFee: 2n * XLM });
  }
  world.indexer.down = true;
  world.rpc.oldestLedger = windows * WINDOW_LEDGERS;
  return { world, alice, bob };
}

async function bobWith(
  world: World,
  fetchFn: FetchLike,
  options: Partial<OpenOptions> = {},
): Promise<PrivateWallet> {
  return openWallet(world, 1, new MemoryStore(), undefined, {
    fetch: fetchFn,
    archives: [ARCHIVE],
    ...options,
  });
}

// Syncs until the wallet holds the vault's whole tree under a verified root, at most `max` times,
// and fails when a sync neither moves the tree nor finishes.
async function restore(world: World, bob: PrivateWallet, max: number): Promise<SyncSummary[]> {
  const summaries: SyncSummary[] = [];
  let last = -1;
  for (let n = 0; n < max; n++) {
    const s = await bob.sync();
    summaries.push(s);
    if (s.rootVerified && s.staged === 0 && s.leafCount === world.vault.tree.leafCount) {
      return summaries;
    }
    assert.ok(s.leafCount + s.staged > last, `sync ${n} did not move: ${JSON.stringify(s)}`);
    last = s.leafCount + s.staged;
  }
  assert.fail(`no complete restore in ${max} syncs: ${JSON.stringify(summaries)}`);
}

const windowReads = (requests: readonly string[], start: number): number =>
  requests.filter((r) => r === `${ARCHIVE}/${fileOf(start)}`).length;

describe("archive sync: a payment the wallet sent before it went offline", () => {
  it("keeps the payment's own transaction when the archive names another for its leaves", async () => {
    const limits = { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM };
    const world = await createWorld({ limits });
    let route: FetchLike = world.fetch;
    const alice = await openWallet(world, 0, new MemoryStore(), undefined, {
      fetch: (input, init) => route(input, init),
      archives: [ARCHIVE],
    });
    const carol = await openWallet(world, 2);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    await carol.shield({ amount: 100n * XLM, signer: world.signer("carol depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    await carol.sync();
    const fullWindow = (): void => {
      world.vault.outflowDay = world.vault.timestamp / 86_400n;
      world.vault.outflow = 50n * XLM;
    };
    fullWindow();
    const sent = await alice.unshield({
      to: world.signer("alice dest").publicKey,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok(sent.txHash !== undefined);
    world.advance(5 * (WINDOW_LEDGERS + 50 - world.vault.ledger));
    await carol.sync();
    fullWindow();
    await carol.unshield({
      to: world.signer("carol dest").publicKey,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    const foreign = world.vault.events.find(
      (e) => e.topic === "exit_queued" && e.ledger >= WINDOW_LEDGERS,
    );
    assert.ok(foreign !== undefined);
    world.indexer.down = true;
    world.rpc.oldestLedger = WINDOW_LEDGERS;
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    // Every line of Alice's transaction now names Carol's, the one that queued another exit.
    rewriteWindow(archive, 0, (lines) =>
      lines.map((l) => (l.tx_hash === sent.txHash ? { ...l, tx_hash: foreign.txHash } : l)),
    );
    route = serveArchive(world.fetch, { [ARCHIVE]: archive }).fetch;
    assert.equal((await alice.sync()).source, "archive");
    const plan = (await alice.plans()).find((p) => p.planId === sent.planId);
    assert.ok(plan !== undefined);
    assert.equal(plan.txHash, sent.txHash);
    assert.equal(plan.exitId, undefined);
  });
});

// Routes the second provider to the world's RPC, as it is now or as it was at `lag` when set.
function secondAt(next: FetchLike, at: { lag: number | undefined }): FetchLike {
  return async (input, init) => {
    if (!input.startsWith(SECOND)) return next(input, init);
    const res = await next(RPC + input.slice(SECOND.length), init);
    const lag = at.lag;
    if (lag === undefined) return res;
    const body = (await res.json()) as { result?: Record<string, unknown> };
    const r = body.result;
    if (r !== undefined) {
      if (typeof r["latestLedger"] === "number") r["latestLedger"] = lag;
      if (typeof r["sequence"] === "number") r["sequence"] = lag;
      for (const e of (r["entries"] ?? []) as Record<string, unknown>[]) {
        e["lastModifiedLedgerSeq"] = Math.min(Number(e["lastModifiedLedgerSeq"]), lag);
      }
    }
    return new Response(JSON.stringify(body), { status: 200 });
  };
}

describe("archive sync: a second provider behind the archive", () => {
  it("waits for it without a fault and keeps the staged restore", async () => {
    const { world } = await history(3, 300);
    const archive = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const at: { lag: number | undefined } = { lag: undefined };
    const bob = await bobWith(world, secondAt(server.fetch, at), {
      secondRpcUrl: SECOND,
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    const first = await bob.sync();
    assert.ok(first.staged > 0);
    at.lag = 2 * WINDOW_LEDGERS;
    await assert.rejects(
      bob.sync(),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "history_unavailable" &&
        err.details["reason"] === "rpc_behind",
    );
    assert.equal(bob.treeStatus().fault, false);
    at.lag = undefined;
    await restore(world, bob, 6);
    assert.equal(windowReads(server.requests, 0), 1);
    assert.equal((await bob.balance()).spendable, 25n * XLM);
  });

  it("reports a provider whose ledger or leaves are behind the archive as behind", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const rpc = new Rpc(RPC, server.fetch);
    const { vault, networkPassphrase, deployLedger } = world.deployment;
    const real = new VaultReader(rpc, vault);
    const options = (behind: { ledger?: number; nextLeaf?: number }) => {
      const lagging = {
        view: async () => {
          const v = await real.view();
          return {
            ...v,
            ledger: behind.ledger ?? v.ledger,
            roots: { ...v.roots, nextLeaf: behind.nextLeaf ?? v.roots.nextLeaf },
          };
        },
      } as unknown as VaultReader;
      return {
        urls: [ARCHIVE],
        fetch: server.fetch,
        pin: { vault, networkPassphrase, deployLedger },
        rpcs: [rpc, rpc],
        since: deployLedger,
        leafCount: 0,
        lastLeafLedger: 0,
        windows: 64,
        eventPages: 100,
        vaults: [real, lagging],
      };
    };
    const reasonOf = async (source: ArchiveSource): Promise<string> =>
      source.nullifiers(deployLedger).then(
        () => "ok",
        (err: unknown) =>
          err instanceof CyphrasError ? `${err.code}/${err.details["reason"] ?? ""}` : "other",
      );
    assert.equal(
      await reasonOf(new ArchiveSource(options({ ledger: 100 }))),
      "history_unavailable/rpc_behind",
    );
    assert.equal(
      await reasonOf(new ArchiveSource(options({ nextLeaf: 2 }))),
      "history_unavailable/rpc_behind",
    );
    assert.equal(await reasonOf(new ArchiveSource(options({}))), "ok");
  });
});

describe("archive sync: restores at the edges of the root ring and of the archive", () => {
  // After the first window the tree is 2 pairs in, and the vault `filler` + 4 pairs.
  for (const [filler, behind] of [
    [253, 255],
    [254, 256],
  ] as const) {
    it(`completes a restore whose first cut leaves the tree ${behind} pairs behind`, async () => {
      const { world } = await history(2, filler);
      const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
      const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
      const bob = await bobWith(world, server.fetch, {
        syncLimits: { leafPages: 1, nullifierPages: 1 },
      });
      const [first] = await restore(world, bob, 4);
      assert.equal(first?.leafCount, behind === 255 ? 4 : 0);
      assert.equal(first?.staged, behind === 255 ? 0 : 4);
      assert.equal((await bob.balance()).spendable, 20n * XLM);
      assert.equal(windowReads(server.requests, 0), 1);
    });
  }

  it("restores across an archive whose last window is empty", async () => {
    const { world, alice, bob: to } = await history(1);
    world.indexer.down = false;
    world.advance(5 * (3 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    await alice.sync();
    await alice.send({ to, amount: 5n * XLM, maxFee: 2n * XLM });
    world.indexer.down = true;
    world.rpc.oldestLedger = 3 * WINDOW_LEDGERS;
    const archive = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
    assert.equal(archive.manifest.windows?.[2]?.events, 0);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, {
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    await restore(world, bob, 3);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
  });

  it("restores while other users insert pairs during the sync", async () => {
    const { world } = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    let moves = 0;
    server.answer = (path) => {
      if (path.startsWith("windows/")) {
        world.advance(5);
        world.fill(3);
        moves++;
      }
      return undefined;
    };
    const bob = await bobWith(world, server.fetch, {
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    await restore(world, bob, 4);
    assert.ok(moves >= 2);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
  });

  it("goes on when the archive publishes a new window between the syncs of a restore", async () => {
    const { world, alice, bob: to } = await history(2);
    const archives: Record<string, Archive> = {
      [ARCHIVE]: buildArchive(world, 2 * WINDOW_LEDGERS - 1),
    };
    const server = serveArchive(world.fetch, archives);
    const bob = await bobWith(world, server.fetch, {
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    const first = await bob.sync();
    assert.equal(first.source, "archive");
    world.indexer.down = false;
    world.advance(5 * (3 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    await alice.sync();
    await alice.send({ to, amount: 5n * XLM, maxFee: 2n * XLM });
    world.indexer.down = true;
    world.rpc.oldestLedger = 3 * WINDOW_LEDGERS;
    archives[ARCHIVE] = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
    await restore(world, bob, 4);
    assert.equal((await bob.balance()).spendable, 25n * XLM);
  });
});

// Drops the last `count` new_commitment lines of a window, with its leaf count to match.
function dropLastLeaves(archive: Archive, start: number, count: number): void {
  const w = archive.manifest.windows?.find((x) => x.start === start);
  assert.ok(w !== undefined);
  rewriteWindow(
    archive,
    start,
    (lines) => {
      const out = [...lines];
      for (let n = 0; n < count; n++) {
        out.splice(out.map(topicOf).lastIndexOf("new_commitment"), 1);
      }
      return out;
    },
    { leaves: [w.leaves[0], w.leaves[1] - count] },
  );
}

describe("archive sync: trees shorter or longer than the vault's", () => {
  it("does not settle on a tree that leaves out the archive's last pair", async () => {
    const { world } = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    dropLastLeaves(archive, WINDOW_LEDGERS, 2);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    const outcomes: string[] = [];
    for (let n = 0; n < 3; n++) {
      outcomes.push(
        await bob.sync().then(
          (s) => `${s.rootVerified ? "verified" : "unverified"} ${s.leafCount}`,
          (err: unknown) => (err instanceof CyphrasError ? err.code : "other"),
        ),
      );
    }
    const settledShort = outcomes.includes(`verified ${world.vault.tree.leafCount - 2}`);
    assert.ok(
      !settledShort || (await bob.balance()).spendable === 15n * XLM,
      `the wallet settled on a tree 2 leaves short: ${outcomes.join(", ")}, spendable ${
        (await bob.balance()).spendable
      }`,
    );
  });

  it("refuses an archive that leaves out its last pair before RPC's leaves", async () => {
    const { world } = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    dropLastLeaves(archive, WINDOW_LEDGERS, 2);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.equal(bob.treeStatus().leafCount, 0);
  });

  for (const count of [1, 3]) {
    it(`refuses a window with ${count} leaf too few for its pairs`, async () => {
      const { world } = await history(2);
      const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
      dropLastLeaves(archive, WINDOW_LEDGERS, count);
      const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
      const bob = await bobWith(world, server.fetch);
      await assert.rejects(bob.sync(), isError("archive_fault"));
      assert.equal(bob.treeStatus().leafCount, 0);
    });
  }

  it("refuses a manifest whose leaf count is one or two off its window", async () => {
    for (const off of [-2, -1, 1, 2]) {
      const { world } = await history(1);
      const archive = buildArchive(world, WINDOW_LEDGERS - 1);
      const w = archive.manifest.windows?.[0];
      assert.ok(w !== undefined);
      rewriteWindow(archive, 0, (lines) => lines, { leaves: [0, w.leaves[1] + off] });
      const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
      const bob = await bobWith(world, server.fetch);
      await assert.rejects(bob.sync(), isError("archive_fault"), `off by ${off}`);
    }
  });

  it("refuses an archive with a made-up pair after the vault's last leaf", async () => {
    const { world } = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const w = archive.manifest.windows?.[1];
    assert.ok(w !== undefined);
    rewriteWindow(
      archive,
      WINDOW_LEDGERS,
      (lines) => {
        const pair = lines.filter((l) => topicOf(l) === "new_commitment").slice(-2);
        const last = lines[lines.length - 1] as RawLine;
        const made = pair.map((l, i) => ({
          ...withField(
            withField(l, "index", nativeToScVal(w.leaves[1] + i, { type: "u32" })),
            "commitment",
            nativeToScVal(BigInt(777 + i), { type: "u256" }),
          ),
          ledger: last.ledger,
          tx: last.tx,
          index: last.index + 1 + i,
        }));
        return [...lines, ...made];
      },
      { leaves: [w.leaves[0], w.leaves[1] + 2] },
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.equal(bob.treeStatus().leafCount, 0);
  });
});

describe("archive sync: the root slot across the ring's wrap", () => {
  it("verifies only the root at the tree's own leaf count, up to 255 pairs behind", () => {
    const pairs = 300;
    const tree = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
    const roots = Array.from({ length: 256 }, () => 0n);
    roots[0] = tree.root();
    const byPairs: bigint[] = [tree.root()];
    for (let p = 1; p <= pairs; p++) {
      tree.append([BigInt(2 * p), BigInt(2 * p + 1)]);
      roots[p % 256] = tree.root();
      byPairs.push(tree.root());
    }
    const history = { roots, newest: pairs % 256, nextLeaf: 2 * pairs, ledger: 1 };
    const at = (p: number): CommitmentTree => {
      const t = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
      for (let i = 1; i <= p; i++) t.append([BigInt(2 * i), BigInt(2 * i + 1)]);
      return t;
    };
    assert.equal(checkRoot(at(pairs), history).state, "verified");
    assert.equal(checkRoot(at(pairs - 1), history).state, "verified");
    assert.equal(checkRoot(at(pairs - 255), history).state, "verified");
    assert.equal(checkRoot(at(pairs - 256), history).state, "behind");
    // Pair 300 wrote slot 44 again, so the tree of 44 pairs is behind, not refused.
    assert.equal(checkRoot(at(45), history).state, "verified");
    assert.equal(checkRoot(at(44), history).state, "behind");
    const blanked = at(pairs - 10);
    blanked.append([0n, 0n]);
    assert.equal(blanked.root(), byPairs[pairs - 10]);
    assert.equal(checkRoot(blanked, history).state, "mismatch");
  });
});

describe("archive sync: archive URLs", () => {
  const testnet = PINNED_DEPLOYMENTS["testnet/xlm"];
  const mainnet = PINNED_DEPLOYMENTS["mainnet/xlm"];

  it("takes every pinned copy as it is", () => {
    assert.ok(testnet !== null && mainnet !== null);
    assert.deepEqual(archiveUrls(testnet, PINNED_ARCHIVES["testnet/xlm"]), [
      ...PINNED_ARCHIVES["testnet/xlm"],
    ]);
    assert.deepEqual(archiveUrls(mainnet, PINNED_ARCHIVES["mainnet/xlm"]), [
      ...PINNED_ARCHIVES["mainnet/xlm"],
    ]);
    assert.deepEqual(archiveUrls(mainnet, undefined), PINNED_ARCHIVES["mainnet/xlm"]);
  });

  for (const url of [
    "https://archive.example/xlm?v=1",
    "https://archive.example/xlm#top",
    "https://archive.example/xlm?",
    "https://archive.example/#",
    "http://localhost.archive.example/xlm",
    "http://127.0.0.2/xlm",
    "http://10.0.0.1/xlm",
    "file:///tmp/archive",
    "data:text/plain,x",
  ]) {
    it(`refuses ${url} for a pinned deployment`, () => {
      assert.ok(mainnet !== null);
      assert.throws(() => archiveUrls(mainnet, [url]), isError("invalid_argument"));
    });
  }

  for (const url of [
    "http://LOCALHOST:8080/xlm",
    "http://127.1:8080/xlm",
    "https://archive.example:8443/a/b/",
    "HTTPS://archive.example/xlm",
  ]) {
    it(`takes ${url} for a pinned deployment`, () => {
      assert.ok(mainnet !== null);
      assert.deepEqual(archiveUrls(mainnet, [url]), [url]);
    });
  }

  it("takes http anywhere for a deployment it does not pin, but no query", async () => {
    const world = await createWorld();
    assert.deepEqual(archiveUrls(world.deployment, ["http://archive.example/x"]), [
      "http://archive.example/x",
    ]);
    assert.throws(
      () => archiveUrls(world.deployment, ["http://archive.example/x?y"]),
      isError("invalid_argument"),
    );
  });

  it("does not follow a redirect", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    server.answer = (path) =>
      path === "manifest.json"
        ? new Response(null, {
            status: 302,
            headers: { location: "http://elsewhere.test/manifest.json" },
          })
        : undefined;
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(
      bob.sync(),
      (err: unknown) =>
        err instanceof CyphrasError && err.details["reason"] === "archive_unreachable",
    );
    assert.ok(!server.requests.some((r) => r.includes("elsewhere")));
  });
});

describe("archive sync: sync limits", () => {
  it("raises a wallet error, not a crash, for a leaf page limit of 0", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const opened = bobWith(world, server.fetch, {
      syncLimits: { leafPages: 0, nullifierPages: 1 },
    });
    await assert.rejects(
      opened.then((bob) => bob.sync()),
      (err: unknown) => err instanceof CyphrasError,
    );
  });
});

describe("archive sync: a restore across reopenings", () => {
  it("goes on from the stored staging after the wallet is opened again", async () => {
    const { world } = await history(3, 300);
    const archive = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const store = new MemoryStore();
    const options = {
      fetch: server.fetch,
      archives: [ARCHIVE],
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    };
    const first = await openWallet(world, 1, store, undefined, options);
    assert.ok((await first.sync()).staged > 0);
    const again = await openWallet(world, 1, store, undefined, options);
    await restore(world, again, 6);
    assert.equal(windowReads(server.requests, 0), 1);
    assert.equal((await again.balance()).spendable, 25n * XLM);
  });
});

describe("archive sync: a copy that fails in the middle of a restore", () => {
  for (const kind of ["429", "dropped"] as const) {
    it(`keeps the staged restore when a window read is ${kind}`, async () => {
      const { world } = await history(3, 300);
      const archive = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
      const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
      const bob = await bobWith(world, server.fetch, {
        syncLimits: { leafPages: 1, nullifierPages: 1 },
      });
      assert.ok((await bob.sync()).staged > 0);
      server.answer = (path) =>
        !path.startsWith("windows/")
          ? undefined
          : kind === "429"
            ? new Response("slow down", { status: 429 })
            : "fail";
      await assert.rejects(
        bob.sync(),
        (err: unknown) =>
          err instanceof CyphrasError && err.details["reason"] === "archive_unreachable",
      );
      assert.equal(bob.treeStatus().fault, false);
      server.answer = undefined;
      await restore(world, bob, 6);
      assert.equal(windowReads(server.requests, 0), 1);
      assert.equal((await bob.balance()).spendable, 25n * XLM);
    });
  }
});
