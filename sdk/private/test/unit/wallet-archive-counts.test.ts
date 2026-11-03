import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { xdr } from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { SorobanRpc as Rpc } from "../../src/net/rpc.ts";
import { MemoryStore } from "../../src/storage.ts";
import { type ChainView, VaultReader } from "../../src/vault/state.ts";
import { ArchiveSource, type ArchiveSourceOptions } from "../../src/wallet/archive.ts";
import type { OpenOptions, PrivateWallet, SyncSummary } from "../../src/wallet/wallet.ts";
import {
  ARCHIVE,
  type Archive,
  MIRROR,
  type RawLine,
  WINDOW_LEDGERS,
  buildArchive,
  fileOf,
  rawEvents,
  rewriteWindow,
  serveArchive,
} from "../support/archive.ts";
import { RELAYER, RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const SECOND = "http://second-rpc.test";

const topicOf = (l: RawLine): string =>
  xdr.ScVal.fromXDR(l.topics[0] as string, "base64")
    .sym()
    .toString();

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

// Syncs until the wallet holds the vault's whole tree under a verified root, at most `max` times.
async function restore(world: World, bob: PrivateWallet, max: number): Promise<SyncSummary[]> {
  const summaries: SyncSummary[] = [];
  for (let n = 0; n < max; n++) {
    const s = await bob.sync();
    summaries.push(s);
    if (s.rootVerified && s.staged === 0 && s.leafCount === world.vault.tree.leafCount) {
      return summaries;
    }
  }
  assert.fail(`no complete restore in ${max} syncs: ${JSON.stringify(summaries)}`);
}

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

// A second provider routed to the world's RPC, failing while `down` is set.
function withSecond(next: FetchLike, at: { down: boolean }): FetchLike {
  return (input, init) => {
    if (!input.startsWith(SECOND)) return next(input, init);
    if (at.down) return Promise.reject(new TypeError("Failed to fetch"));
    return next(RPC + input.slice(SECOND.length), init);
  };
}

function sourceWith(
  world: World,
  fetchFn: FetchLike,
  second: (real: VaultReader) => VaultReader,
): ArchiveSource {
  const rpc = new Rpc(RPC, fetchFn);
  const { vault, networkPassphrase, deployLedger } = world.deployment;
  const real = new VaultReader(rpc, vault);
  const options: ArchiveSourceOptions = {
    urls: [ARCHIVE],
    fetch: fetchFn,
    pin: { vault, networkPassphrase, deployLedger },
    rpcs: [rpc, rpc],
    vaults: [real, second(real)],
    since: deployLedger,
    leafCount: 0,
    lastLeafLedger: 0,
    windows: 64,
    eventPages: 100,
  };
  return new ArchiveSource(options);
}

const outcomeOf = (source: ArchiveSource, since: number): Promise<string> =>
  source.nullifiers(since).then(
    () => "ok",
    (err: unknown) =>
      err instanceof CyphrasError ? `${err.code}/${err.details["reason"] ?? ""}` : `${err}`,
  );

const fixed = (view: ChainView): VaultReader => ({ view: async () => view }) as VaultReader;

describe("archive sync: leaf counts against providers at different ledgers", () => {
  it("takes an honest archive when the second provider read the vault before RPC's later leaves", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = (await openWallet(world, 1)).generateAddress();
    await alice.send({ to: bob, amount: 10n * XLM, maxFee: 2n * XLM });
    world.advance(5 * (WINDOW_LEDGERS + 50 - world.vault.ledger));
    await alice.sync();
    const early = await new VaultReader(new Rpc(RPC, world.fetch), world.deployment.vault).view();
    world.advance(5);
    await alice.send({ to: bob, amount: 5n * XLM, maxFee: 2n * XLM });
    world.advance(50);
    world.indexer.down = true;
    world.rpc.oldestLedger = WINDOW_LEDGERS;
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    assert.ok(early.roots.nextLeaf < world.vault.tree.leafCount);
    const source = sourceWith(world, server.fetch, () => fixed(early));
    assert.equal(await outcomeOf(source, world.deployment.deployLedger), "ok");
    const { leaves } = await source.nextLeaves(undefined as never);
    assert.equal(leaves.length, world.vault.tree.leafCount);
  });

  it("refuses a copy short of its last pair against a second provider that lags", async () => {
    const { world } = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 10 - world.vault.ledger));
    const early = await new VaultReader(new Rpc(RPC, world.fetch), world.deployment.vault).view();
    world.advance(5 * 50);
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    dropLastLeaves(archive, WINDOW_LEDGERS, 2);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const source = sourceWith(world, server.fetch, () => fixed(early));
    assert.equal(await outcomeOf(source, world.deployment.deployLedger), "archive_fault/");
  });

  it("checks the first provider's count when the second reads the vault past RPC's events", async () => {
    for (const short of [false, true]) {
      const { world } = await history(1);
      world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
      world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
      const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
      if (short) dropLastLeaves(archive, WINDOW_LEDGERS, 2);
      const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
      const ahead = (real: VaultReader): VaultReader =>
        ({
          view: async () => {
            const v = await real.view();
            return {
              ...v,
              ledger: v.ledger + 1_000,
              roots: { ...v.roots, nextLeaf: v.roots.nextLeaf + 2, ledger: v.ledger + 1_000 },
            };
          },
        }) as VaultReader;
      const source = sourceWith(world, server.fetch, ahead);
      assert.equal(
        await outcomeOf(source, world.deployment.deployLedger),
        short ? "archive_fault/" : "ok",
        short ? "short copy" : "honest copy",
      );
    }
  });
});

describe("archive sync: RPC's events after the archive over more than one sync", () => {
  it("completes a restore whose ledgers after the archive take more pages than one sync reads", async () => {
    const { world } = await history(1);
    // RPC scans at most 10 000 ledgers per request, so two pages reach 20 000 past the archive.
    world.advance(5 * (WINDOW_LEDGERS + 30_000 - world.vault.ledger));
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, { syncLimits: { eventPages: 2 } });
    await restore(world, bob, 6);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});

describe("archive sync: copies when the first leaves out its last pair", () => {
  it("takes the next copy in the same sync", async () => {
    const { world } = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = WINDOW_LEDGERS;
    const short = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    dropLastLeaves(short, WINDOW_LEDGERS, 2);
    const older = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: short, [MIRROR]: older });
    const bob = await bobWith(world, server.fetch, { archives: [ARCHIVE, MIRROR] });
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal(summary.rootVerified, true);
    assert.equal(summary.leafCount, world.vault.tree.leafCount);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("names both copies when they list the window and only one leaves out its last pair", async () => {
    const { world } = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    const short = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    dropLastLeaves(short, WINDOW_LEDGERS, 2);
    const honest = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: short, [MIRROR]: honest });
    const bob = await bobWith(world, server.fetch, { archives: [ARCHIVE, MIRROR] });
    await assert.rejects(
      bob.sync(),
      (err: unknown) =>
        isError("archive_fault")(err) && (err as CyphrasError).details["copies"] === "0,1",
    );
    assert.equal(bob.treeStatus().leafCount, 0);
  });
});

describe("archive sync: a hanging copy", () => {
  for (const hang of ["manifest", "window"] as const) {
    it(`leaves the next copy its own time when the first copy's ${hang} never answers`, async () => {
      const { world } = await history(2);
      const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
      const server = serveArchive(world.fetch, { [ARCHIVE]: archive, [MIRROR]: archive });
      const stuck: FetchLike = (input, init) => {
        const path = hang === "manifest" ? `${ARCHIVE}/manifest.json` : `${ARCHIVE}/windows/`;
        if (!input.startsWith(path)) return server.fetch(input, init);
        return new Promise((_, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new TypeError("aborted")));
        });
      };
      const rpc = new Rpc(RPC, stuck);
      const { vault, networkPassphrase, deployLedger } = world.deployment;
      const source = new ArchiveSource({
        urls: [ARCHIVE, MIRROR],
        fetch: stuck,
        pin: { vault, networkPassphrase, deployLedger },
        rpcs: [rpc],
        vaults: [new VaultReader(rpc, vault)],
        since: deployLedger,
        leafCount: 0,
        lastLeafLedger: 0,
        windows: 64,
        eventPages: 100,
        deadlineMs: 300,
      });
      assert.equal(await outcomeOf(source, deployLedger), "ok");
      assert.equal(await source.copy(), 1);
      assert.ok(server.requests.includes(`${MIRROR}/${fileOf(WINDOW_LEDGERS)}`));
    });
  }
});

describe("archive sync: spends a staged restore took already", () => {
  it("refuses a later window that lists a spend an earlier sync of the restore took", async () => {
    const { world } = await history(3, 300);
    const archive = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
    const early = rawEvents(world).find(
      (l) => l.ledger < WINDOW_LEDGERS && topicOf(l) === "new_nullifier",
    ) as RawLine;
    const w = archive.manifest.windows?.find((x) => x.start === WINDOW_LEDGERS);
    rewriteWindow(
      archive,
      WINDOW_LEDGERS,
      (lines) => [...lines, { ...early, ledger: 2 * WINDOW_LEDGERS - 1, tx: 1, op: 0, index: 0 }],
      { nullifiers: (w?.nullifiers ?? 0) + 1 },
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, {
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    const first = await bob.sync();
    assert.ok(first.staged > 0);
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.equal(bob.treeStatus().leafCount, 0);
  });

  it("takes a newer window that holds the ledgers whose spends a staged sync read from RPC", async () => {
    const { world } = await history(1);
    const archives: Record<string, Archive> = {
      [ARCHIVE]: buildArchive(world, WINDOW_LEDGERS - 1),
    };
    const server = serveArchive(world.fetch, archives);
    const at = { down: true };
    const bob = await bobWith(world, withSecond(server.fetch, at), { secondRpcUrl: SECOND });
    const first = await bob.sync();
    assert.equal(first.source, "archive");
    assert.equal(first.staged, world.vault.tree.leafCount);
    // Days later the archive holds the window those ledgers are in, and RPC no longer holds them.
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    archives[ARCHIVE] = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    at.down = false;
    const second = await bob.sync().catch((err: unknown) => err);
    assert.ok(
      !(second instanceof Error),
      `the restore failed: ${second instanceof CyphrasError ? `${second.code} ${second.message}` : second}`,
    );
    assert.equal(bob.treeStatus().fault, false);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});

describe("archive sync: a restore staged from the archive, then from the indexer", () => {
  it("does not take the indexer's ledgers for the archive's", async () => {
    const { world, alice, bob: to } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const at = { down: true };
    const bob = await bobWith(world, withSecond(server.fetch, at), { secondRpcUrl: SECOND });
    const first = await bob.sync();
    assert.equal(first.source, "archive");
    assert.ok(first.staged > 0);
    const archiveLedger = world.vault.ledger;
    world.indexer.down = false;
    world.advance(5 * 500);
    await alice.sync();
    await alice.send({ to, amount: 5n * XLM, maxFee: 2n * XLM });
    world.advance(5 * 500);
    const second = await bob.sync();
    assert.equal(second.source, "indexer");
    assert.ok(second.staged > 0);
    at.down = false;
    const third = await bob.sync();
    assert.equal(third.source, "indexer");
    assert.equal(third.staged, 0);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
    const deploy = world.deployment.deployLedger;
    assert.ok(
      third.uncheckedLedgers <= archiveLedger - deploy + 1,
      `unchecked ${third.uncheckedLedgers} ledgers, the archive's sync reached ${
        archiveLedger - deploy + 1
      }`,
    );
  });
});

describe("archive sync: a held payment that lands in ledgers only the archive holds", () => {
  it("names no transaction for it and follows no exit", async () => {
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
    const notBefore = Number(world.vault.timestamp) + 3_600;
    const held = await alice.unshield({
      to: world.signer("alice dest").publicKey,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
      notBefore,
    });
    assert.ok("planId" in held);
    assert.equal(held.txHash, undefined);
    world.advance(3_700);
    const before = world.vault.events.length;
    world.relayer.releaseHeld();
    const landed = world.vault.events.slice(before)[0]?.txHash;
    assert.ok(landed !== undefined);
    world.advance(5 * (WINDOW_LEDGERS + 50 - world.vault.ledger));
    await carol.sync();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
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
    rewriteWindow(archive, 0, (lines) =>
      lines.map((l) => (l.tx_hash === landed ? { ...l, tx_hash: foreign.txHash } : l)),
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    // The relayer that held it is gone, so only the chain can show where the payment went.
    route = (input, init) =>
      input.startsWith(RELAYER)
        ? Promise.reject(new TypeError("Failed to fetch"))
        : server.fetch(input, init);
    assert.equal((await alice.sync()).source, "archive");
    const plan = (await alice.plans()).find((p) => p.planId === held.planId);
    assert.ok(plan !== undefined);
    assert.notEqual(plan.txHash, foreign.txHash);
    assert.equal(plan.exitId, undefined);
    assert.equal((await alice.balance()).locked, 0n);
  });
});
