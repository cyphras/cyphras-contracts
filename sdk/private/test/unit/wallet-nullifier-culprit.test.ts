import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { xdr } from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import { type WalletState, loadState } from "../../src/wallet/state.ts";
import type { PrivateWallet } from "../../src/wallet/wallet.ts";
import {
  ARCHIVE,
  type RawLine,
  WINDOW_LEDGERS,
  buildArchive,
  rewriteWindow,
  serveArchive,
} from "../support/archive.ts";
import { XLM, type World, createWorld } from "../support/network.ts";
import { isError, openWallet, sealedState } from "../support/wallets.ts";

const details = (err: unknown): Record<string, unknown> =>
  err instanceof CyphrasError ? (err.details as Record<string, unknown>) : {};

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined).catch((e) => e);

const owedTo = (world: World, destination: string): bigint =>
  world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === destination)
    .reduce((s, e) => s + e.payout, 0n);

const counted = (err: unknown): boolean =>
  details(err)["vaultError"] === "NullifierSpent" && details(err)["everyProvider"] === true;

// Alice pays Bob 10, 5 and 3 XLM, so Bob holds three notes.
async function threeNotes(store: KeyValueStore = new MemoryStore(), maxDailyOutflow?: bigint) {
  const world = await createWorld(
    maxDailyOutflow === undefined ? {} : { limits: { maxDailyOutflow } },
  );
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  const to = (await openWallet(world, 1)).generateAddress();
  await alice.send({ to, amount: 10n * XLM, maxFee: 2n * XLM });
  await alice.send({ to, amount: 5n * XLM, maxFee: 2n * XLM });
  await alice.send({ to, amount: 3n * XLM, maxFee: 2n * XLM });
  const bob: PrivateWallet = await openWallet(world, 1, store);
  await bob.sync();
  assert.equal((await bob.balance()).spendable, 18n * XLM);
  return { world, alice, bob, store };
}

async function stateOf(store: KeyValueStore, world: World): Promise<WalletState> {
  const state = await loadState(sealedState(store, world, 1));
  assert.ok(state !== undefined);
  return state;
}

// The note of `value` is spent by a transaction no source of the wallet shows, at a ledger the
// wallet's syncs are past.
async function spentElsewhere(world: World, store: KeyValueStore, value: bigint): Promise<number> {
  const note = (await stateOf(store, world)).notes.find((n) => n.value === value);
  assert.ok(note?.nf !== undefined);
  world.vault.nullifiers.set(note.nf, { ledger: world.vault.ledger - 1, txHash: "e".repeat(64) });
  return note.pos;
}

async function suspects(store: KeyValueStore, world: World): Promise<Map<number, number>> {
  return new Map((await stateOf(store, world)).suspects.map((s) => [s.pos, s.plans.length]));
}

const selfUnshield = (world: World, bob: PrivateWallet, amount: bigint): Promise<unknown> =>
  caught(
    bob.unshield({
      to: world.signer("carol").publicKey,
      amount,
      selfRelay: world.signer("bob account"),
      confirm: () => true,
    }),
  );

async function pastDeadlines(world: World, bob: PrivateWallet): Promise<void> {
  world.advance(5 * 200);
  await bob.sync();
}

describe("refusals explained by more than one spent note", () => {
  it("gives the shared note back once each of its partners is refused on its own", async () => {
    const { world, bob, store } = await threeNotes();
    const five = await spentElsewhere(world, store, 5n * XLM);
    const three = await spentElsewhere(world, store, 3n * XLM);
    // The 10 and 3 XLM notes are refused, then the 10 and 5 XLM notes.
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    // The 5 XLM note, then the 3 XLM note, is refused alone: each of the two refusals above holds
    // a note spent elsewhere, so they say nothing about the 10 XLM note.
    assert.ok(counted(await selfUnshield(world, bob, 4n * XLM)));
    await pastDeadlines(world, bob);
    assert.ok(counted(await selfUnshield(world, bob, 2n * XLM)));
    await pastDeadlines(world, bob);
    const inputs = (await bob.plans()).map((p) => p.inputValue);
    assert.deepEqual(inputs, [13n * XLM, 15n * XLM, 5n * XLM, 3n * XLM]);
    const left = [...(await suspects(store, world)).keys()].sort((a, b) => a - b);
    assert.deepEqual(
      left,
      [five, three].sort((a, b) => a - b),
      "only the refused-alone notes",
    );
    const balance = await bob.balance();
    assert.deepEqual([balance.spendable, balance.unconfirmed], [10n * XLM, 8n * XLM]);
    assert.equal(await selfUnshield(world, bob, 8n * XLM), undefined);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 8n * XLM);
  });
});

describe("a payment of this wallet that lands with a refused note's partners", () => {
  it("singles out the other note of a refused pair once one of them lands", async () => {
    const store = new MemoryStore();
    const { world, bob } = await threeNotes(store);
    await spentElsewhere(world, store, 5n * XLM);
    // 14 XLM: the 10 and 5 XLM notes are refused together.
    assert.ok(counted(await selfUnshield(world, bob, 14n * XLM)));
    await pastDeadlines(world, bob);
    // The 10 XLM note pays alone and lands, so it was not spent when the pair was refused.
    assert.equal(await selfUnshield(world, bob, 9n * XLM), undefined);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 9n * XLM);
    const balance = await bob.balance();
    assert.equal(balance.unconfirmed, 5n * XLM, "the 5 XLM note is the one the refusal named");
    assert.ok(balance.spendable < 5n * XLM, `spendable ${balance.spendable}`);
  });

  it("keeps the note the refusals share out of spendable", async () => {
    const store = new MemoryStore();
    const { world, bob } = await threeNotes(store);
    const ten = await spentElsewhere(world, store, 10n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    assert.equal((await bob.balance()).unconfirmed, 10n * XLM);
    // The 5 and 3 XLM notes land, so they were unspent: the 10 XLM note is the spent one.
    assert.equal(await selfUnshield(world, bob, 7n * XLM), undefined);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 7n * XLM);
    assert.deepEqual([...(await suspects(store, world)).keys()], [ten]);
    const balance = await bob.balance();
    assert.equal(balance.unconfirmed, 10n * XLM, "the spent note is spendable again");
    assert.ok(balance.spendable < 10n * XLM, `spendable ${balance.spendable}`);
    // So a payment the 10 XLM note alone would cover is not refused once more.
    const err = await selfUnshield(world, bob, 9n * XLM);
    assert.ok(!counted(err), "the spent note went again");
  });
});

describe("a split part refused again with notes refused before", () => {
  it("does not prove the part again", async () => {
    const store = new MemoryStore();
    const world = await createWorld({ limits: { maxDailyOutflow: 12n * XLM } });
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const to = (await openWallet(world, 1)).generateAddress();
    await alice.send({ to, amount: 10n * XLM, maxFee: 2n * XLM });
    await alice.send({ to, amount: 5n * XLM, maxFee: 2n * XLM });
    const bob = await openWallet(world, 1, store);
    await bob.sync();
    const five = await spentElsewhere(world, store, 5n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    const signer = world.signer("bob account");
    // Only the pair covers the first part, so it goes with the pair refused above.
    const err = await caught(
      bob.unshield({
        to: world.signer("carol").publicKey,
        amount: 14n * XLM,
        selfRelay: signer,
        split: true,
        confirm: () => true,
      }),
    );
    assert.ok(counted(err), String(err));
    assert.equal(details(err)["refusedBefore"], true);
    const operationId = String(details(err)["operationId"]);
    await caught(bob.continueOperations(signer));
    await pastDeadlines(world, bob);
    await caught(bob.continueOperations(signer));
    const parts = (await stateOf(store, world)).plans.filter(
      (p) => p.operationId === operationId && p.inputs.some((i) => i.pos === five),
    );
    assert.equal(parts.length, 1, "the refused part went again with the same notes");
    assert.equal(owedTo(world, world.signer("carol").publicKey), 0n);
  });
});

describe("refusals: what holds", () => {
  it("blocks a split operation on its refused part, and resumes with other notes", async () => {
    const store = new MemoryStore();
    const { world, bob } = await threeNotes(store, 8n * XLM);
    const ten = await spentElsewhere(world, store, 10n * XLM);
    const signer = world.signer("bob account");
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({
        to: carol,
        amount: 12n * XLM,
        selfRelay: signer,
        split: true,
        confirm: () => true,
      }),
    );
    assert.ok(counted(err), String(err));
    const operationId = String(details(err)["operationId"]);
    const planId = String(details(err)["planId"]);
    assert.ok(isError("operation_open")(await selfUnshield(world, bob, 1n * XLM)));
    await pastDeadlines(world, bob);
    const [op] = await bob.continueOperations(signer);
    assert.equal(op?.operationId, operationId);
    assert.equal(op?.state, "blocked");
    assert.equal(op?.blockedBy, planId);
    const part = (await bob.plans()).find((p) => p.planId === planId);
    assert.equal(part?.state, "dead");
    assert.equal(part?.lastError?.code, "transaction_failed");
    const resumed = await bob.resumeOperation(operationId, signer);
    assert.equal(resumed.state, "active");
    await bob.sync();
    const plans = (await stateOf(store, world)).plans.filter((p) => p.operationId === operationId);
    assert.equal(plans.filter((p) => p.inputs.some((i) => i.pos === ten)).length, 1);
    assert.equal(owedTo(world, carol), 8n * XLM);
    assert.equal((await bob.balance()).unconfirmed, 10n * XLM);
  });

  it("keeps a shared note out and its partners' marks dropped across a restart", async () => {
    const store = new MemoryStore();
    const { world, bob } = await threeNotes(store);
    const ten = await spentElsewhere(world, store, 10n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    const reopened = await openWallet(world, 1, store);
    await pastDeadlines(world, reopened);
    assert.deepEqual([...(await suspects(store, world))], [[ten, 2]]);
    const balance = await reopened.balance();
    // The shared note counts once in unconfirmed, though two refused plans held it.
    assert.deepEqual(
      [balance.spendable, balance.locked, balance.unconfirmed],
      [8n * XLM, 0n, 10n * XLM],
    );
    // The partners go first again and pay.
    assert.equal(await selfUnshield(world, reopened, 7n * XLM), undefined);
    await reopened.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 7n * XLM);
  });

  it("counts a retry of a refused single-note plan once, and keeps its destination guarded", async () => {
    const store = new MemoryStore();
    const { world, bob } = await threeNotes(store);
    const five = await spentElsewhere(world, store, 5n * XLM);
    const first = await selfUnshield(world, bob, 4n * XLM);
    assert.ok(counted(first));
    for (let i = 0; i < 2; i++) {
      const again = await caught(
        bob.retry(String(details(first)["planId"]), {
          selfRelay: world.signer("bob account"),
          confirm: () => true,
        }),
      );
      assert.ok(counted(again), String(again));
      assert.equal(details(again)["refusedBefore"], true);
    }
    assert.deepEqual([...(await suspects(store, world))], [[five, 1]]);
    assert.ok(isError("operation_open")(await selfUnshield(world, bob, 1n * XLM)));
    const balance = await bob.balance();
    assert.deepEqual(
      [balance.spendable, balance.locked, balance.unconfirmed],
      [13n * XLM, 5n * XLM, 0n],
    );
    await pastDeadlines(world, bob);
    assert.deepEqual(
      [(await bob.balance()).spendable, (await bob.balance()).unconfirmed],
      [13n * XLM, 5n * XLM],
    );
    assert.equal(owedTo(world, world.signer("carol").publicKey), 0n);
  });
});

const topicOf = (l: RawLine): string =>
  xdr.ScVal.fromXDR(l.topics[0] as string, "base64")
    .sym()
    .toString();

describe("a restore from an archive that leaves a spend out", () => {
  it("leaves out the note whose spend it omits after one self-relayed refusal, and pays once", async () => {
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
    const honest = (await first.balance()).spendable;
    const archive = buildArchive(world, WINDOW_LEDGERS - 1);
    world.indexer.down = true;
    world.rpc.oldestLedger = WINDOW_LEDGERS;
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
    const bob = await openWallet(world, 1, new MemoryStore(), undefined, {
      fetch: server.fetch,
      archives: [ARCHIVE],
    });
    await bob.sync();
    assert.equal((await bob.balance()).spendable, honest + 10n * XLM);
    // Only the 10 XLM note, whose spend the archive left out, covers 8 XLM alone.
    const amount = 8n * XLM;
    assert.ok(honest >= amount && honest - 5n * XLM < amount);
    const account = world.signer("bob account");
    const unshield = () =>
      caught(
        bob.unshield({
          to: account.publicKey,
          amount,
          selfRelay: account,
          confirm: () => true,
        }),
      );
    const events = world.vault.events.length;
    assert.ok(counted(await unshield()));
    assert.ok(isError("operation_open")(await unshield()));
    world.advance(5 * 400);
    await bob.sync();
    assert.equal(world.vault.events.length, events, "nothing reached the vault");
    const balance = await bob.balance();
    assert.deepEqual(
      [balance.spendable, balance.locked, balance.unconfirmed],
      [honest, 0n, 10n * XLM],
    );
    assert.equal(await unshield(), undefined);
    await bob.sync();
    assert.equal(owedTo(world, account.publicKey), amount);
    assert.equal((await bob.balance()).unconfirmed, 10n * XLM);
  });
});
