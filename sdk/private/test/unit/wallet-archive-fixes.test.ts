import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { nativeToScVal, xdr } from "@stellar/stellar-base";
import { PINNED_DEPLOYMENTS } from "../../src/deployments.ts";
import { CyphrasError } from "../../src/errors.ts";
import { CommitmentTree } from "../../src/merkle.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { type SorobanRpc, keyId } from "../../src/net/rpc.ts";
import { MemoryStore } from "../../src/storage.ts";
import { type ChainView, VaultReader } from "../../src/vault/state.ts";
import { SorobanRpc as Rpc } from "../../src/net/rpc.ts";
import { ArchiveSource, type ArchiveSourceOptions } from "../../src/wallet/archive.ts";
import { fetchManifest, fetchWindow } from "../../src/net/archive.ts";
import { checkRoot } from "../../src/wallet/sync.ts";
import type { OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import {
  ARCHIVE,
  MIRROR,
  type RawLine,
  WINDOW_LEDGERS,
  buildArchive,
  fileOf,
  rawEvents,
  rewriteWindow,
  serveArchive,
} from "../support/archive.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { ledgerEnd } from "../support/rpc.ts";
import { isError, openWallet } from "../support/wallets.ts";

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
  return world;
}

async function bobWith(
  world: World,
  fetchFn: FetchLike,
  options: Partial<OpenOptions> = { archives: [ARCHIVE] },
): Promise<PrivateWallet> {
  return openWallet(world, 1, new MemoryStore(), undefined, { fetch: fetchFn, ...options });
}

describe("archive sync: restores that span more windows than one sync reads", () => {
  it("moves on every sync and completes a restore staged behind the root ring", async () => {
    const world = await history(3, 300);
    const archive = buildArchive(world, 3 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, {
      archives: [ARCHIVE],
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    let last = -1;
    let summary;
    for (let n = 0; n < 6; n++) {
      summary = await bob.sync();
      const progress = summary.leafCount + summary.staged;
      if (summary.rootVerified && summary.staged === 0 && progress === world.vault.tree.leafCount) {
        break;
      }
      assert.ok(progress > last, `sync ${n} did not move: ${JSON.stringify(summary)}`);
      last = progress;
    }
    assert.equal(summary?.leafCount, world.vault.tree.leafCount);
    assert.equal(summary?.rootVerified, true);
    assert.equal((await bob.balance()).spendable, 25n * XLM);
  });
});

describe("archive sync: the root at the tree's own leaf count", () => {
  it("refuses a tree whose last pair is empty though its root is in the ring", () => {
    const [a, b, c, d] = [11n, 12n, 13n, 14n];
    const at = (leaves: bigint[]): bigint => {
      const t = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
      t.append(leaves);
      return t.root();
    };
    const roots = Array.from({ length: 256 }, () => 0n);
    roots[1] = at([a, b]);
    roots[2] = at([a, b, c, d]);
    roots[3] = at([a, b, c, d, 15n, 16n]);
    const history = { roots, newest: 3, nextLeaf: 6, ledger: 100 };
    const blanked = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
    blanked.append([a, b, 0n, 0n]);
    assert.equal(blanked.root(), roots[1]);
    assert.equal(checkRoot(blanked, history).state, "mismatch");
    const honest = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
    honest.append([a, b, c, d]);
    assert.equal(checkRoot(honest, history).state, "verified");
  });

  it("refuses an archive that blanks its last pairs and keeps nothing", async () => {
    const world = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    rewriteWindow(archive, 0, (lines) => {
      const last = lines.map(topicOf).lastIndexOf("new_commitment");
      return lines.map((l, i) =>
        i === last || i === last - 1
          ? withField(l, "commitment", nativeToScVal(0n, { type: "u256" }))
          : l,
      );
    });
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, {
      archives: [ARCHIVE],
      syncLimits: { leafPages: 1, nullifierPages: 1 },
    });
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.equal(bob.treeStatus().leafCount, 0);
    assert.equal((await bob.balance()).spendable, 0n);
  });
});

describe("archive sync: copies of the archive", () => {
  it("refuses copies that differ in a ciphertext RPC no longer shows, naming them", async () => {
    const world = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const other = structuredClone(archive);
    rewriteWindow(other, 0, (lines) => {
      const at = lines.findIndex((l) => topicOf(l) === "new_commitment");
      return lines.map((l, i) =>
        i === at ? withField(l, "encrypted_output", xdr.ScVal.scvBytes(Buffer.alloc(181, 7))) : l,
      );
    });
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive, [MIRROR]: other });
    const bob = await bobWith(world, server.fetch, { archives: [ARCHIVE, MIRROR] });
    await assert.rejects(
      bob.sync(),
      (err: unknown) =>
        isError("archive_conflict")(err) &&
        (err as CyphrasError).details["windows"] === "0" &&
        (err as CyphrasError).details["copies"] === `${ARCHIVE} ${MIRROR}`,
    );
    assert.equal(bob.treeStatus().leafCount, 0);
    assert.equal(bob.treeStatus().fault, false);
  });

  it("lets RPC's events decide between copies while RPC holds the window", async () => {
    const world = await history(2);
    world.rpc.oldestLedger = WINDOW_LEDGERS;
    const honest = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const altered = structuredClone(honest);
    rewriteWindow(altered, WINDOW_LEDGERS, (lines) => {
      const at = lines.findIndex((l) => topicOf(l) === "new_commitment");
      return lines.map((l, i) =>
        i === at ? withField(l, "encrypted_output", xdr.ScVal.scvBytes(Buffer.alloc(181, 7))) : l,
      );
    });
    for (const urls of [
      [ARCHIVE, MIRROR],
      [MIRROR, ARCHIVE],
    ]) {
      const server = serveArchive(world.fetch, { [ARCHIVE]: altered, [MIRROR]: honest });
      const bob = await bobWith(world, server.fetch, { archives: urls });
      const summary = await bob.sync();
      assert.equal(summary.source, "archive");
      assert.equal((await bob.balance()).spendable, 20n * XLM);
      assert.ok(!server.requests.some((r) => r === `${ARCHIVE}/${fileOf(0)}`));
    }
  });

  it("uses the one copy that can be read as a single copy", async () => {
    const world = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, { archives: [MIRROR, ARCHIVE] });
    assert.equal((await bob.sync()).source, "archive");
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("passes over a copy it could not read for the next syncs", async () => {
    const world = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const asked: string[] = [];
    const fetchFn: FetchLike = async (input, init) => {
      if (input.startsWith(MIRROR)) {
        asked.push(input);
        return new Response("", { status: 503 });
      }
      return server.fetch(input, init);
    };
    const bob = await bobWith(world, fetchFn, { archives: [MIRROR, ARCHIVE] });
    await bob.sync();
    assert.equal(asked.length, 1);
    assert.equal((await bob.rescan()).source, "archive");
    assert.equal(asked.length, 1);
  });

  it("takes the tree from the next copy when the vault refuses the first one's", async () => {
    const world = await history(2);
    world.rpc.oldestLedger = WINDOW_LEDGERS;
    const older = buildArchive(world, WINDOW_LEDGERS - 1);
    const newer = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    rewriteWindow(newer, WINDOW_LEDGERS, (lines) => {
      const at = lines.findIndex((l) => topicOf(l) === "new_commitment");
      return lines.map((l, i) =>
        i === at ? withField(l, "commitment", nativeToScVal(42n, { type: "u256" })) : l,
      );
    });
    const server = serveArchive(world.fetch, { [ARCHIVE]: newer, [MIRROR]: older });
    const bob = await bobWith(world, server.fetch, { archives: [ARCHIVE, MIRROR] });
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal(summary.rootVerified, true);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
  });
});

// The options of an archive source over the world's vault, with one RPC provider.
function sourceOver(world: World, fetchFn: FetchLike): ArchiveSourceOptions {
  const rpc = new Rpc(RPC, fetchFn);
  const { vault, networkPassphrase, deployLedger } = world.deployment;
  return {
    urls: [ARCHIVE],
    fetch: fetchFn,
    pin: { vault, networkPassphrase, deployLedger },
    rpcs: [rpc],
    vaults: [new VaultReader(rpc, vault)],
    since: deployLedger,
    leafCount: 0,
    lastLeafLedger: 0,
    windows: 64,
    eventPages: 100,
  };
}

describe("archive sync: what one sync may cost", () => {
  it("refuses a window of made-up nullifiers before it reads the next one", async () => {
    const world = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const nf = archive.lines.get(0)?.find((l) => topicOf(l) === "new_nullifier") as RawLine;
    const made = Array.from({ length: 300 }, (_, i) => ({
      ...withField(nf, "nullifier", nativeToScVal(BigInt(1_000 + i), { type: "u256" })),
      ledger: WINDOW_LEDGERS - 1,
      tx: 1,
      index: i,
    }));
    const w = archive.manifest.windows?.[0];
    rewriteWindow(archive, 0, (lines) => [...lines, ...made], {
      nullifiers: (w?.nullifiers ?? 0) + made.length,
    });
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.ok(!server.requests.includes(`${ARCHIVE}/${fileOf(WINDOW_LEDGERS)}`));
  });

  it("cuts at the byte budget and reads RPC's events only when nothing was cut", async () => {
    const world = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const first = archive.manifest.windows?.[0];
    const source = new ArchiveSource({
      ...sourceOver(world, server.fetch),
      byteBudget: first?.bytes ?? 0,
    });
    const { completeToLedger } = await source.nullifiers(world.deployment.deployLedger);
    assert.equal(completeToLedger, WINDOW_LEDGERS - 1);
    assert.equal((await source.part()).tailFrom, undefined);
    assert.ok(!server.requests.includes(`${ARCHIVE}/${fileOf(WINDOW_LEDGERS)}`));
  });

  it("gives up on an archive that takes longer than the sync allows", async () => {
    const world = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    let clock = 0;
    server.answer = (path) => {
      if (path.startsWith("windows/")) clock += 700_000;
      return undefined;
    };
    const source = new ArchiveSource({ ...sourceOver(world, server.fetch), now: () => clock });
    await assert.rejects(
      source.nullifiers(world.deployment.deployLedger),
      (err: unknown) =>
        err instanceof CyphrasError && err.details["reason"] === "archive_unreachable",
    );
  });
});

describe("archive sync: what the archive and RPC's events after it hold together", () => {
  it("refuses a copy that leaves out its last pair while RPC shows no later leaf", async () => {
    const world = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const w = archive.manifest.windows?.[1];
    rewriteWindow(
      archive,
      WINDOW_LEDGERS,
      (lines) => {
        const last = lines.map(topicOf).lastIndexOf("new_commitment");
        return lines.filter((_, i) => i !== last && i !== last - 1);
      },
      { leaves: [w?.leaves[0] ?? 0, (w?.leaves[1] ?? 2) - 2] },
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.equal(bob.treeStatus().leafCount, 0);
    assert.equal((await bob.balance()).spendable, 0n);
  });

  it("refuses an archive nullifier that RPC's events after it spend", async () => {
    const world = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const later = rawEvents(world).find(
      (l) => l.ledger >= WINDOW_LEDGERS && topicOf(l) === "new_nullifier",
    ) as RawLine;
    const w = archive.manifest.windows?.[0];
    rewriteWindow(
      archive,
      0,
      (lines) => [...lines, { ...later, ledger: WINDOW_LEDGERS - 1, tx: 1, index: 0 }],
      { nullifiers: (w?.nullifiers ?? 0) + 1 },
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("archive_fault"));
    assert.equal(bob.treeStatus().leafCount, 0);
  });
});

describe("archive sync: the provider whose events carry the tree", () => {
  it("takes nothing when its own view is past its events and the tail has no leaf", async () => {
    const world = await history(1);
    world.advance(5 * (2 * WINDOW_LEDGERS + 50 - world.vault.ledger));
    world.rpc.oldestLedger = 2 * WINDOW_LEDGERS;
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const w = archive.manifest.windows?.[1];
    rewriteWindow(
      archive,
      WINDOW_LEDGERS,
      (lines) => {
        const last = lines.map(topicOf).lastIndexOf("new_commitment");
        return lines.filter((_, i) => i !== last && i !== last - 1);
      },
      { leaves: [w?.leaves[0] ?? 0, (w?.leaves[1] ?? 2) - 2] },
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const options = sourceOver(world, server.fetch);
    const real = options.vaults[0] as VaultReader;
    const ahead = {
      view: async () => ({ ...(await real.view()), ledger: world.vault.ledger + 500 }),
    };
    const lying = {
      view: async () => {
        const v = await real.view();
        return { ...v, roots: { ...v.roots, nextLeaf: v.roots.nextLeaf - 2 } };
      },
    };
    const source = new ArchiveSource({
      ...options,
      rpcs: [options.rpcs[0] as SorobanRpc, options.rpcs[0] as SorobanRpc],
      vaults: [ahead, lying] as unknown as VaultReader[],
    });
    await assert.rejects(
      source.nullifiers(world.deployment.deployLedger),
      (err: unknown) => err instanceof CyphrasError && err.details["reason"] === "rpc_tail_short",
    );
  });
});

describe("archive sync: a slow copy", () => {
  it("leaves the next copy its own time", async () => {
    const world = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive, [MIRROR]: archive });
    let clock = 0;
    const slow: FetchLike = (input, init) => {
      if (input.startsWith(`${ARCHIVE}/windows/`)) clock += 610_000;
      return server.fetch(input, init);
    };
    const source = new ArchiveSource({
      ...sourceOver(world, slow),
      urls: [ARCHIVE, MIRROR],
      now: () => clock,
    });
    await source.nullifiers(world.deployment.deployLedger);
    assert.equal(await source.copy(), 1);
    assert.ok(server.requests.includes(`${MIRROR}/${fileOf(WINDOW_LEDGERS)}`));
  });
});

// A provider that shows the vault as the published archive leaves it, with nothing after it.
function chainOf(leaves: readonly bigint[], latest: number) {
  const tree = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
  tree.append([...leaves]);
  const newest = (leaves.length / 2) % 256;
  const roots = Array.from({ length: 256 }, () => 0n);
  roots[newest] = tree.root();
  const view: ChainView = {
    ledger: latest,
    instance: {} as ChainView["instance"],
    roots: { roots, newest, nextLeaf: leaves.length, ledger: latest },
  };
  const rpc = {
    async getLedgerEntries(keys: readonly xdr.LedgerKey[]) {
      const entries = new Map();
      for (const key of keys) {
        const cd = key.contractData();
        entries.set(keyId(key), {
          key,
          data: xdr.LedgerEntryData.contractData(
            new xdr.ContractDataEntry({
              ext: new xdr.ExtensionPoint(0),
              contract: cd.contract(),
              key: cd.key(),
              durability: cd.durability(),
              val: xdr.ScVal.scvVoid(),
            }),
          ),
          lastModifiedLedger: latest,
          liveUntilLedger: undefined,
        });
      }
      return { latestLedger: latest, entries };
    },
    async getEvents() {
      return {
        events: [],
        cursor: ledgerEnd(latest),
        latestLedger: latest,
        oldestLedger: latest - 100,
        latestCloseTime: undefined,
        oldestCloseTime: undefined,
      };
    },
  };
  return { view, rpc: rpc as unknown as SorobanRpc, vault: { view: async () => view } };
}

describe("archive sync: the published archives, a few windows per sync", () => {
  for (const name of ["testnet/xlm", "mainnet/xlm"] as const) {
    it(`rebuilds the ${name} tree in a bounded number of reads`, async () => {
      const d = PINNED_DEPLOYMENTS[name];
      assert.ok(d !== null);
      const dir = new URL(`../fixtures/archive/${name.split("/")[0]}/`, import.meta.url);
      const fetchFn: FetchLike = async (input) => {
        try {
          return new Response(
            new Uint8Array(readFileSync(new URL(input.slice(ARCHIVE.length + 1), dir))),
          );
        } catch {
          return new Response("", { status: 404 });
        }
      };
      const manifest = JSON.parse(readFileSync(new URL("manifest.json", dir), "utf8")) as {
        coveredTo: number;
        windows: { events: number }[];
      };
      // The chain holds the leaves the archive's windows hold.
      const pin = {
        vault: d.vault,
        networkPassphrase: d.networkPassphrase,
        deployLedger: d.deployLedger,
      };
      const parsed = await fetchManifest(fetchFn, ARCHIVE, pin);
      const chainLeaves: bigint[] = [];
      for (const w of parsed.windows.filter((x) => x.events > 0)) {
        const content = await fetchWindow(fetchFn, ARCHIVE, w, pin);
        chainLeaves.push(...content.leaves.map((l) => l.commitment));
      }
      const files = manifest.windows.filter((w) => w.events > 0).length;
      const chain = chainOf(chainLeaves, manifest.coveredTo + 10);
      let leafCount = 0;
      let since = d.deployLedger;
      let lastLeafLedger = 0;
      const tree = CommitmentTree.fromSnapshot({ leafCount: 0, upper: [], partial: [] });
      let reads = 0;
      for (;;) {
        reads++;
        assert.ok(reads <= Math.ceil(files / 2) + 1, "too many reads");
        const source = new ArchiveSource({
          urls: [ARCHIVE],
          fetch: fetchFn,
          pin: {
            vault: d.vault,
            networkPassphrase: d.networkPassphrase,
            deployLedger: d.deployLedger,
          },
          rpcs: [chain.rpc],
          vaults: [chain.vault as unknown as VaultReader],
          since,
          leafCount,
          lastLeafLedger,
          windows: 2,
          eventPages: 10,
        });
        const { completeToLedger } = await source.nullifiers(since);
        const { leaves } = await source.nextLeaves(tree);
        tree.append(leaves.map((l) => l.commitment));
        assert.ok(completeToLedger >= since, "the cursor did not move");
        leafCount = tree.leafCount;
        lastLeafLedger = leaves[leaves.length - 1]?.ledger ?? lastLeafLedger;
        since = completeToLedger + 1;
        if ((await source.part()).tailFrom !== undefined) break;
      }
      assert.equal(checkRoot(tree, chain.view.roots).state, "verified");
      assert.equal(tree.leafCount, chainLeaves.length);
    });
  }
});
