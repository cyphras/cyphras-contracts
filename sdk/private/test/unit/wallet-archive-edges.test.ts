import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { nativeToScVal, xdr } from "@stellar/stellar-base";
import { P } from "../../src/field.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { MemoryStore } from "../../src/storage.ts";
import type { OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import {
  ARCHIVE,
  MIRROR,
  type RawLine,
  WINDOW_LEDGERS,
  buildArchive,
  rewriteWindow,
  serveArchive,
} from "../support/archive.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";

const SECOND = "http://second-rpc.test";
import { isError, openWallet } from "../support/wallets.ts";

const topicOf = (l: RawLine): string =>
  xdr.ScVal.fromXDR(l.topics[0] as string, "base64")
    .sym()
    .toString();

function fieldOf(line: RawLine, name: string): xdr.ScVal {
  const entry = (xdr.ScVal.fromXDR(line.value, "base64").map() ?? []).find(
    (e) => e.key().sym().toString() === name,
  );
  return entry?.val() as xdr.ScVal;
}

function withField(line: RawLine, name: string, value: xdr.ScVal): RawLine {
  const entries = xdr.ScVal.fromXDR(line.value, "base64").map() ?? [];
  const changed = entries.map((e) =>
    e.key().sym().toString() === name ? new xdr.ScMapEntry({ key: e.key(), val: value }) : e,
  );
  return { ...line, value: xdr.ScVal.scvMap(changed).toXDR("base64") };
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

// Alice pays Bob 10 XLM in window 0 and 5 XLM in each later window; then the indexer goes down
// and RPC keeps only the ledgers after the archive's last window.
async function history(windows: number) {
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
  world.indexer.down = true;
  world.rpc.oldestLedger = windows * WINDOW_LEDGERS;
  return { world, alice, bob };
}

describe("archive sync: window caps", () => {
  it("restores when fewer windows of spends than windows of leaves fit in one sync", async () => {
    const { world } = await history(2);
    const archive = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch, {
      syncLimits: { leafPages: 64, nullifierPages: 1 },
    });
    let last;
    for (let i = 0; i < 3; i++) last = await bob.sync();
    assert.equal(last?.rootVerified, true);
    assert.equal(bob.treeStatus().leafCount, world.vault.tree.leafCount);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
  });
});

describe("archive sync: copies that disagree", () => {
  it("takes a later copy when the first one ends before RPC's history begins", async () => {
    const { world } = await history(2);
    const stale = buildArchive(world, WINDOW_LEDGERS - 1);
    const fresh = buildArchive(world, 2 * WINDOW_LEDGERS - 1);
    // A third copy confirms the fresh one's newer window, which two copies must list alike.
    const third = "http://third.test";
    const server = serveArchive(world.fetch, { [MIRROR]: stale, [ARCHIVE]: fresh, [third]: fresh });
    const bob = await bobWith(world, server.fetch, { archives: [MIRROR, ARCHIVE, third] });
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal(summary.rootVerified, true);
    assert.equal((await bob.balance()).spendable, 20n * XLM);
  });

  it("asks for files with no header, cookie, referrer or redirect", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const inits: (RequestInit | undefined)[] = [];
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const watched: FetchLike = (input, init) => {
      if (input.startsWith(ARCHIVE)) inits.push(init);
      return server.fetch(input, init);
    };
    const bob = await bobWith(world, watched);
    await bob.sync();
    assert.ok(inits.length >= 2);
    for (const init of inits) {
      assert.equal(init?.redirect, "error");
      assert.equal(init?.credentials, "omit");
      assert.equal(init?.headers, undefined);
      assert.ok(init?.signal instanceof AbortSignal);
    }
  });
});

describe("archive sync: commitments the chain cannot tell apart", () => {
  it("refuses a commitment written as itself plus the field's modulus", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    // The root of the tree is the same with either spelling of the leaf.
    rewriteWindow(archive, 0, (lines) => {
      const at = lines.findIndex((l) => topicOf(l) === "new_commitment");
      const parts = fieldOf(lines[at] as RawLine, "commitment").u256();
      const n =
        (parts.hiHi().toBigInt() << 192n) |
        (parts.hiLo().toBigInt() << 128n) |
        (parts.loHi().toBigInt() << 64n) |
        parts.loLo().toBigInt();
      return lines.map((l, i) =>
        i === at ? withField(l, "commitment", nativeToScVal(n + P, { type: "u256" })) : l,
      );
    });
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("archive_fault"));
  });
});

describe("archive sync: a spend the archive leaves out", () => {
  // Bob receives 10 XLM and spends it in window 0, keeping the change, and receives 5 XLM in
  // window 1. Bob restores from his seed.
  async function bobSpent() {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const first = await openWallet(world, 1);
    await alice.send({ to: first.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    await first.sync();
    await first.send({ to: alice.generateAddress(), amount: 3n * XLM, maxFee: 2n * XLM });
    world.advance(5 * (WINDOW_LEDGERS + 50 - world.vault.ledger));
    await alice.send({ to: first.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM });
    await first.sync();
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    world.indexer.down = true;
    world.rpc.oldestLedger = WINDOW_LEDGERS;
    return { world, alice, archive, honest: (await first.balance()).spendable };
  }

  it("marks the restored notes spent by the archive's nullifiers", async () => {
    const { world, archive, honest } = await bobSpent();
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    assert.equal((await bob.sync()).source, "archive");
    assert.equal((await bob.balance()).spendable, honest);
  });

  it("fails spends of a note whose nullifier it left out and loses no note", async () => {
    const { world, alice, archive, honest } = await bobSpent();
    const lines = archive.lines.get(0) as RawLine[];
    const nfs = lines.filter((l) => topicOf(l) === "new_nullifier");
    const last = (nfs[nfs.length - 1] as RawLine).tx_hash;
    const dropped = nfs.filter((l) => l.tx_hash === last).length;
    const w = archive.manifest.windows?.[0];
    rewriteWindow(
      archive,
      0,
      (l) => l.filter((x) => !(topicOf(x) === "new_nullifier" && x.tx_hash === last)),
      { nullifiers: (w?.nullifiers ?? 0) - dropped },
    );
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await bob.sync();
    const shown = (await bob.balance()).spendable;
    assert.equal(shown, honest + 10n * XLM, "the spent note shows as spendable");
    const events = world.vault.events.length;
    // Both need the spent note and one other.
    const amount = honest + 4n * XLM;
    await assert.rejects(
      bob.send({ to: alice.generateAddress(), amount, maxFee: 2n * XLM }),
      isError("service_rejected"),
    );
    world.advance(5 * 400);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, shown);
    const account = world.signer("bob account");
    await assert.rejects(
      bob.unshield({
        to: account.publicKey,
        amount,
        maxFee: 2n * XLM,
        selfRelay: account,
        confirm: () => true,
      }),
      (err: unknown) => isError("transaction_failed")(err) && /NullifierSpent/.test(String(err)),
    );
    world.advance(5 * 400);
    for (let i = 0; i < 2; i++) await bob.sync();
    assert.equal(world.vault.events.length, events, "nothing reached the vault");
    const plans = await bob.plans();
    assert.deepEqual(
      plans.map((p) => p.state),
      ["dead", "dead"],
    );
    assert.equal((await bob.balance()).spendable, shown);
    assert.equal((await bob.balance()).locked, 0n);
  });
});

describe("archive sync: a second provider that cannot answer", () => {
  it("stages the restore while it is down and applies it once it answers", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    let down = true;
    const routed: FetchLike = (input, init) => {
      if (!input.startsWith(SECOND)) return server.fetch(input, init);
      if (down) return Promise.reject(new TypeError("Failed to fetch"));
      return server.fetch(RPC + input.slice(SECOND.length), init);
    };
    const bob = await bobWith(world, routed, { secondRpcUrl: SECOND });
    const first = await bob.sync();
    assert.equal(first.source, "archive");
    assert.equal(first.leafCount, 0);
    assert.equal(first.staged, world.vault.tree.leafCount);
    down = false;
    const second = await bob.sync();
    assert.equal(second.leafCount, world.vault.tree.leafCount);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("keeps RPC's leaves after the archive open for a recheck when they were staged", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    let down = true;
    const routed: FetchLike = (input, init) => {
      if (!input.startsWith(SECOND)) return server.fetch(input, init);
      if (down) return Promise.reject(new TypeError("Failed to fetch"));
      return server.fetch(RPC + input.slice(SECOND.length), init);
    };
    const bob = await bobWith(world, routed, { secondRpcUrl: SECOND });
    await bob.sync();
    down = false;
    assert.equal((await bob.sync()).lostLeaves, 4);
  });
});

describe("archive sync: the vault far ahead of the archive", () => {
  it("carries the tree past the vault's root ring with RPC's events", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    world.advance(50);
    world.fill(300);
    world.advance(50);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal(summary.rootVerified, true);
    assert.equal(summary.leafCount, world.vault.tree.leafCount);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("refuses an archive whose leaves past the ring RPC's events do not carry on", async () => {
    const { world } = await history(1);
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    world.advance(50);
    world.fill(300);
    world.advance(50);
    rewriteWindow(archive, 0, (lines) => {
      const at = lines.findIndex((l) => topicOf(l) === "new_commitment");
      return lines.map((l, i) =>
        i === at ? withField(l, "commitment", nativeToScVal(42n, { type: "u256" })) : l,
      );
    });
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const bob = await bobWith(world, server.fetch);
    await assert.rejects(bob.sync(), isError("tree_unverified"));
    assert.equal(bob.treeStatus().leafCount, 0);
  });
});

describe("archive sync: many spends in the archive", () => {
  it("asks RPC for their entries 200 keys at a time and keeps every one", async () => {
    const { world } = await history(1);
    const at = world.vault.events.findIndex((e) => e.ledger >= WINDOW_LEDGERS);
    const made = Array.from({ length: 401 }, (_, i) => BigInt(i + 1) * 7_919n);
    const txHash = "ab".repeat(32);
    world.vault.events.splice(
      at,
      0,
      ...made.map((nf) => ({
        ledger: WINDOW_LEDGERS - 10,
        txHash,
        topic: "new_nullifier",
        fields: [["nullifier", nativeToScVal(nf, { type: "u256" })] as [string, xdr.ScVal]],
      })),
    );
    for (const nf of made) world.vault.nullifiers.set(nf, { ledger: WINDOW_LEDGERS - 10, txHash });
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    const server = serveArchive(world.fetch, { [ARCHIVE]: archive });
    const sizes: number[] = [];
    const limited: FetchLike = async (input, init) => {
      if (input.startsWith(RPC) && typeof init?.body === "string") {
        const body = JSON.parse(init.body) as {
          id: number;
          method: string;
          params: { keys?: string[] };
        };
        if (body.method === "getLedgerEntries") {
          const n = body.params.keys?.length ?? 0;
          sizes.push(n);
          if (n > 200) {
            return new Response(
              JSON.stringify({
                jsonrpc: "2.0",
                id: body.id,
                error: { code: -32602, message: "too many keys" },
              }),
            );
          }
        }
      }
      return server.fetch(input, init);
    };
    const bob = await bobWith(world, limited);
    const summary = await bob.sync();
    assert.equal(summary.source, "archive");
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    assert.ok(sizes.filter((n) => n === 200).length >= 2);
    assert.ok(sizes.every((n) => n <= 200));
  });
});
