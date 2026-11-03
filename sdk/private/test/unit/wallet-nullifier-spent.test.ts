import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import { nullifierKey } from "../../src/vault/state.ts";
import { type WalletState, loadState } from "../../src/wallet/state.ts";
import type { OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { isError, openWallet, sealedState } from "../support/wallets.ts";

const SECOND = "http://second-rpc.test";

const details = (err: unknown): Record<string, unknown> =>
  err instanceof CyphrasError ? (err.details as Record<string, unknown>) : {};

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined).catch((e) => e);

const owedTo = (world: World, destination: string): bigint =>
  world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === destination)
    .reduce((s, e) => s + e.payout, 0n);

// Alice pays Bob 10 XLM, then 5 XLM, so Bob holds two notes.
async function twoNotes(
  options: (world: World) => Partial<OpenOptions> = () => ({}),
  store: KeyValueStore = new MemoryStore(),
) {
  const world = await createWorld();
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  const to = (await openWallet(world, 1)).generateAddress();
  await alice.send({ to, amount: 10n * XLM, maxFee: 2n * XLM });
  await alice.send({ to, amount: 5n * XLM, maxFee: 2n * XLM });
  const bob: PrivateWallet = await openWallet(world, 1, store, undefined, options(world));
  await bob.sync();
  assert.equal((await bob.balance()).spendable, 15n * XLM);
  return { world, alice, bob, store };
}

async function stateOf(store: KeyValueStore, world: World): Promise<WalletState> {
  const state = await loadState(sealedState(store, world, 1));
  assert.ok(state !== undefined);
  return state;
}

// The note of `value` is spent by a transaction no source of the wallet shows, as an archive that
// left its spend out, at a ledger the wallet's syncs are past.
async function spentElsewhere(world: World, store: KeyValueStore, value: bigint): Promise<number> {
  const note = (await stateOf(store, world)).notes.find((n) => n.value === value);
  assert.ok(note?.nf !== undefined);
  world.vault.nullifiers.set(note.nf, { ledger: world.vault.ledger - 1, txHash: "e".repeat(64) });
  return note.pos;
}

async function suspects(store: KeyValueStore, world: World): Promise<Map<number, number>> {
  return new Map((await stateOf(store, world)).suspects.map((s) => [s.pos, s.plans.length]));
}

// Serves the second provider from the world's RPC, records every request body, and lets a test
// change the second provider's simulations.
function network(world: World, secondSimulation?: (body: { id: unknown }) => Response) {
  const bodies: { origin: string; method: string; text: string }[] = [];
  const fetchFn: FetchLike = async (input, init) => {
    const origin = new URL(input).origin;
    const text = init?.body === undefined ? "" : String(init.body);
    const body = text === "" ? undefined : JSON.parse(text);
    bodies.push({ origin, method: String(body?.method ?? ""), text });
    if (origin === SECOND && body?.method === "simulateTransaction" && secondSimulation) {
      return secondSimulation(body);
    }
    return world.fetch(origin === SECOND ? RPC + input.slice(SECOND.length) : input, init);
  };
  return { bodies, fetchFn };
}

const contractError = (code: number) => (body: { id: unknown }) =>
  new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: body.id,
      result: { error: `HostError: Error(Contract, #${code})`, latestLedger: 1 },
    }),
    { status: 200 },
  );

async function selfUnshield(world: World, bob: PrivateWallet, amount: bigint): Promise<unknown> {
  return caught(
    bob.unshield({
      to: world.signer("carol").publicKey,
      amount,
      selfRelay: world.signer("bob account"),
      confirm: () => true,
    }),
  );
}

// Past the deadline of every plan made so far, and synced.
async function pastDeadlines(world: World, bob: PrivateWallet): Promise<void> {
  world.advance(5 * 200);
  await bob.sync();
}

describe("a spend the vault refuses as spending a note already spent", () => {
  it("marks the plan's notes suspect when every provider's simulation shows it", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob, store } = await twoNotes((world) => {
      net = network(world);
      return { secondRpcUrl: SECOND, fetch: net.fetchFn };
    });
    const five = await spentElsewhere(world, store, 5n * XLM);
    const err = await selfUnshield(world, bob, 4n * XLM);
    assert.ok(isError("transaction_failed")(err), String(err));
    assert.equal(details(err)["vaultError"], "NullifierSpent");
    assert.equal(details(err)["everyProvider"], true);
    assert.deepEqual([...(await suspects(store, world))], [[five, 1]]);
    // The plan fails without a resend and keeps its note and destination until its deadline.
    const [plan] = await bob.plans();
    assert.equal(plan?.state, "prepared");
    await assert.rejects(
      bob.unshield({
        to: world.signer("carol").publicKey,
        amount: 1n * XLM,
        maxFee: 2n * XLM,
        confirm: () => true,
      }),
      isError("operation_open"),
    );
    assert.equal(
      net?.bodies.filter((b) => b.origin === SECOND && b.method === "simulateTransaction").length,
      1,
    );
  });

  it("does not count a refusal the second provider's simulation does not show", async () => {
    const { world, bob, store } = await twoNotes((world) => ({
      secondRpcUrl: SECOND,
      fetch: network(world, contractError(120)).fetchFn,
    }));
    await spentElsewhere(world, store, 5n * XLM);
    const err = await selfUnshield(world, bob, 4n * XLM);
    assert.equal(details(err)["vaultError"], "NullifierSpent");
    assert.equal(details(err)["everyProvider"], false);
    assert.equal((await suspects(store, world)).size, 0);
  });

  it("does not count a relayer's refusal", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    const err = await caught(
      bob.unshield({
        to: world.signer("carol").publicKey,
        amount: 4n * XLM,
        maxFee: 2n * XLM,
        confirm: () => true,
      }),
    );
    assert.ok(isError("service_rejected")(err), String(err));
    assert.equal((await suspects(store, world)).size, 0);
    await pastDeadlines(world, bob);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    assert.equal((await bob.balance()).unconfirmed, 0n);
  });

  it("pays with another note next time, once", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    await selfUnshield(world, bob, 4n * XLM);
    await pastDeadlines(world, bob);
    // The smallest note that covers the payment is the suspect one; the other goes instead.
    const err = await selfUnshield(world, bob, 4n * XLM);
    assert.equal(err, undefined);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 4n * XLM);
    const plans = await bob.plans();
    assert.deepEqual(
      plans.map((p) => p.state),
      ["dead", "settled"],
    );
    assert.equal(plans[1]?.inputValue, 10n * XLM);
  });

  it("pays with the less refused notes, and never repeats a refused set", async () => {
    const { world, alice, bob, store } = await twoNotes();
    await alice.send({ to: bob.generateAddress(), amount: 3n * XLM, maxFee: 2n * XLM });
    await bob.sync();
    const ten = await spentElsewhere(world, store, 10n * XLM);
    // The 10 and 3 XLM notes are refused, then the 10 and 5 XLM notes, not the same set again.
    assert.equal(details(await selfUnshield(world, bob, 12n * XLM))["everyProvider"], true);
    await pastDeadlines(world, bob);
    assert.equal(details(await selfUnshield(world, bob, 12n * XLM))["everyProvider"], true);
    await pastDeadlines(world, bob);
    assert.deepEqual(
      (await bob.plans()).map((p) => p.inputValue),
      [13n * XLM, 15n * XLM],
    );
    assert.equal((await suspects(store, world)).get(ten), 2);
    // Nothing leaves spendable; the refused notes are counted in unconfirmed for information.
    const balance = await bob.balance();
    assert.deepEqual(
      [balance.spendable, balance.locked, balance.unconfirmed],
      [18n * XLM, 0n, 18n * XLM],
    );
    assert.equal((await bob.history()).filter((h) => h.kind === "unshield").length, 0);
    // The 10 XLM note, refused twice, goes after the 5 and 3 XLM notes, refused once each.
    assert.equal(await selfUnshield(world, bob, 8n * XLM), undefined);
    await bob.sync();
    assert.equal((await bob.plans()).at(-1)?.inputValue, 8n * XLM);
    assert.equal(owedTo(world, world.signer("carol").publicKey), 8n * XLM);
  });

  it("keeps the only note of a refused plan spendable, marked", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    await selfUnshield(world, bob, 4n * XLM);
    await pastDeadlines(world, bob);
    const balance = await bob.balance();
    assert.deepEqual([balance.spendable, balance.unconfirmed], [15n * XLM, 5n * XLM]);
  });

  it("fails with notes_refused when only refused sets cover the payment, sending nothing", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob, store } = await twoNotes((world) => {
      net = network(world);
      return { fetch: net.fetchFn };
    });
    await spentElsewhere(world, store, 5n * XLM);
    await selfUnshield(world, bob, 12n * XLM);
    await pastDeadlines(world, bob);
    const before = net?.bodies.length ?? 0;
    const again = await selfUnshield(world, bob, 12n * XLM);
    assert.ok(isError("notes_refused")(again), String(again));
    const sent = (net?.bodies ?? []).slice(before).map((b) => b.method);
    assert.ok(!sent.includes("simulateTransaction") && !sent.includes("sendTransaction"));
    assert.equal((await bob.plans()).length, 1);
    const balance = await bob.balance();
    assert.deepEqual([balance.spendable, balance.unconfirmed], [15n * XLM, 15n * XLM]);
    // A payment the 10 XLM note alone covers goes.
    assert.equal(await selfUnshield(world, bob, 8n * XLM), undefined);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 8n * XLM);
  });

  it("drops the mark once a sync shows the note spent", async () => {
    const { world, bob, store } = await twoNotes();
    // Another instance of Bob's wallet spends the 5 XLM note; Bob's indexer lags behind it.
    const other = await openWallet(world, 1);
    await other.sync();
    world.advance(5);
    world.indexer.completeTo = world.vault.ledger - 1;
    const elsewhere = await other.unshield({
      to: world.signer("dave").publicKey,
      amount: 4n * XLM,
      maxFee: 2n * XLM,
      confirm: () => true,
    });
    await selfUnshield(world, bob, 4n * XLM);
    assert.equal((await suspects(store, world)).size, 1);
    world.indexer.completeTo = undefined;
    world.advance(5);
    await bob.sync();
    assert.equal((await suspects(store, world)).size, 0);
    const spent = (await stateOf(store, world)).notes.find((n) => n.value === 5n * XLM)?.spent;
    assert.equal(spent?.txHash, elsewhere.txHash);
    await pastDeadlines(world, bob);
    const balance = await bob.balance();
    assert.equal(balance.spendable, 10n * XLM + (1n * XLM - elsewhere.fee));
    assert.equal(balance.unconfirmed, 0n);
  });

  it("lets no lying single provider reduce spendable", async () => {
    let faking = 0;
    const { world, bob, store } = await twoNotes((world) => ({
      fetch: (input, init) => {
        const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
        if (faking > 0 && body?.method === "simulateTransaction") {
          faking--;
          return Promise.resolve(contractError(123)(body));
        }
        return world.fetch(input, init);
      },
    }));
    // The only provider makes up a refusal of the 5 XLM note, then of both notes.
    faking = 2;
    await selfUnshield(world, bob, 4n * XLM);
    await pastDeadlines(world, bob);
    await selfUnshield(world, bob, 12n * XLM);
    await pastDeadlines(world, bob);
    assert.equal((await suspects(store, world)).size, 2);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    // A payment of the 10 XLM note alone was never refused, so it goes and lands.
    assert.equal(await selfUnshield(world, bob, 9n * XLM), undefined);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 9n * XLM);
    assert.equal((await bob.balance()).spendable, 5n * XLM + 1n * XLM);
  });

  it("starts the marks anew on a rescan", async () => {
    const { world, bob, store } = await twoNotes();
    const pos = await spentElsewhere(world, store, 5n * XLM);
    await selfUnshield(world, bob, 4n * XLM);
    await pastDeadlines(world, bob);
    await selfUnshield(world, bob, 12n * XLM);
    await pastDeadlines(world, bob);
    assert.equal((await bob.balance()).unconfirmed, 15n * XLM);
    // The made-up spend has no event, which a rescan's cross-check would refuse; it is taken back.
    const note = (await stateOf(store, world)).notes.find((n) => n.pos === pos);
    world.vault.nullifiers.delete(note?.nf ?? 0n);
    await bob.rescan();
    assert.equal((await suspects(store, world)).size, 0);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    assert.equal((await bob.balance()).unconfirmed, 0n);
  });

  it("sends no provider a request that names the plan's nullifiers", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob, store } = await twoNotes((world) => {
      net = network(world);
      return { secondRpcUrl: SECOND, fetch: net.fetchFn };
    });
    await spentElsewhere(world, store, 5n * XLM);
    const before = net?.bodies.length ?? 0;
    await selfUnshield(world, bob, 4n * XLM);
    await pastDeadlines(world, bob);
    await selfUnshield(world, bob, 12n * XLM);
    await pastDeadlines(world, bob);
    const keys = (await stateOf(store, world)).plans
      .flatMap((p) => p.nullifiers)
      .map((nf) => nullifierKey(world.deployment.vault, nf).toXDR("base64"));
    const after = (net?.bodies ?? []).slice(before);
    assert.ok(after.length > 0);
    for (const b of after.filter((b) => b.method === "getLedgerEntries")) {
      for (const key of keys) assert.ok(!b.text.includes(key), "a read names a plan's key");
    }
  });
});
