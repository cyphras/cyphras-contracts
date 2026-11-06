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
  maxDailyOutflow?: bigint,
) {
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

const contractError = (code: number) => (body: { id: unknown }) =>
  new Response(
    JSON.stringify({
      jsonrpc: "2.0",
      id: body.id,
      result: { error: `HostError: Error(Contract, #${code})`, latestLedger: 1 },
    }),
    { status: 200 },
  );

// Serves the second provider from the world's RPC and records every request to either provider;
// `second` answers the second provider's simulations its own way.
function network(world: World, second?: (body: { id: unknown }) => Response | Promise<Response>) {
  const bodies: { origin: string; method: string; params: unknown; text: string }[] = [];
  const fetchFn: FetchLike = async (input, init) => {
    const origin = new URL(input).origin;
    const text = init?.body === undefined ? "" : String(init.body);
    const body = text === "" ? undefined : JSON.parse(text);
    bodies.push({ origin, method: String(body?.method ?? ""), params: body?.params, text });
    if (origin === SECOND && body?.method === "simulateTransaction" && second !== undefined) {
      return second(body);
    }
    return world.fetch(origin === SECOND ? RPC + input.slice(SECOND.length) : input, init);
  };
  return { bodies, fetchFn };
}

// The only RPC provider fails the next `count` simulations with a made-up NullifierSpent.
function lyingRpc(world: World) {
  let count = 0;
  const fetchFn: FetchLike = (input, init) => {
    const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
    if (count > 0 && body?.method === "simulateTransaction") {
      count--;
      return Promise.resolve(contractError(123)(body));
    }
    return world.fetch(input, init);
  };
  return {
    fetchFn,
    lie(n: number) {
      count = n;
    },
  };
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

const relayedUnshield = (world: World, bob: PrivateWallet, amount: bigint): Promise<unknown> =>
  caught(
    bob.unshield({
      to: world.signer("carol").publicKey,
      amount,
      maxFee: 2n * XLM,
      confirm: () => true,
    }),
  );

async function pastDeadlines(world: World, bob: PrivateWallet): Promise<void> {
  world.advance(5 * 200);
  await bob.sync();
}

const counted = (err: unknown): boolean =>
  details(err)["vaultError"] === "NullifierSpent" && details(err)["everyProvider"] === true;

describe("refusals that name no single note", () => {
  it("keeps the honest note of a pair spendable when the same payment is asked for again", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    // Only the refused pair covers the payment again, so nothing is proved.
    assert.ok(isError("notes_refused")(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    // The refusal held two notes, so it does not tell which one is spent.
    const paid = await selfUnshield(world, bob, 8n * XLM);
    assert.equal(paid, undefined, `the 10 XLM note no longer pays: ${String(paid)}`);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 8n * XLM);
  });

  it("keeps the honest note of a pair spendable after a retry is refused too", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    const first = await selfUnshield(world, bob, 12n * XLM);
    assert.ok(counted(first));
    const again = await caught(
      bob.retry(String(details(first)["planId"]), {
        selfRelay: world.signer("bob account"),
        confirm: () => true,
      }),
    );
    assert.ok(counted(again), String(again));
    await pastDeadlines(world, bob);
    const balance = await bob.balance();
    assert.equal(balance.spendable, 15n * XLM);
    assert.ok(balance.spendable >= 10n * XLM, `spendable ${balance.spendable}`);
  });

  it("lets honest notes pay again once a lying provider stops lying", async () => {
    const rpc: { lie(n: number): void }[] = [];
    const { world, bob } = await twoNotes((world) => {
      const lying = lyingRpc(world);
      rpc.push(lying);
      return { fetch: lying.fetchFn };
    });
    rpc[0]?.lie(1);
    assert.ok(counted(await selfUnshield(world, bob, 12n * XLM)));
    await pastDeadlines(world, bob);
    // The refused pair is not proposed again; the spendable balance stays whole.
    assert.ok(isError("notes_refused")(await selfUnshield(world, bob, 12n * XLM)));
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    // Nothing is spent: once a rescan drops the marks, an ordinary payment lands.
    await bob.rescan();
    const paid = await selfUnshield(world, bob, 12n * XLM);
    assert.equal(paid, undefined, `honest notes stay out: ${String(paid)}`);
    await bob.sync();
    assert.equal(owedTo(world, world.signer("carol").publicKey), 12n * XLM);
    assert.equal((await bob.balance()).maybeSpent, 0n);
  });

  it("does not prove a refused split part again with the same notes", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(undefined, store, 8n * XLM);
    const ten = await spentElsewhere(world, store, 10n * XLM);
    const signer = world.signer("bob account");
    const request = {
      to: world.signer("carol").publicKey,
      amount: 12n * XLM,
      selfRelay: signer,
      split: true,
      confirm: () => true,
    } as const;
    const err = await caught(bob.unshield(request));
    assert.ok(counted(err), String(err));
    assert.equal(typeof details(err)["operationId"], "string");
    await caught(bob.continueOperations(signer));
    await pastDeadlines(world, bob);
    await caught(bob.continueOperations(signer));
    const tries = (await stateOf(store, world)).plans.filter((p) =>
      p.inputs.some((i) => i.pos === ten),
    );
    assert.equal(tries.length, 1, "the refused note went again");
    assert.equal(owedTo(world, request.to), 0n);
  });
});

describe("refusals across a restart", () => {
  it("keeps one refusal's mark, and pays with the other note", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(undefined, store);
    const five = await spentElsewhere(world, store, 5n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 4n * XLM)));
    const reopened = await openWallet(world, 1, store);
    await pastDeadlines(world, reopened);
    assert.deepEqual([...(await suspects(store, world))], [[five, 1]]);
    assert.equal(await selfUnshield(world, reopened, 4n * XLM), undefined);
    await reopened.sync();
    const plans = await reopened.plans();
    assert.equal(plans[1]?.inputValue, 10n * XLM);
    assert.equal(owedTo(world, world.signer("carol").publicKey), 4n * XLM);
  });

  it("keeps the only note of a refused payment marked across restarts", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(undefined, store);
    await spentElsewhere(world, store, 5n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 4n * XLM)));
    // While the refused plan is prepared, its note counts as locked, not as maybeSpent.
    let balance = await bob.balance();
    assert.deepEqual(
      [balance.spendable, balance.locked, balance.maybeSpent],
      [10n * XLM, 5n * XLM, 0n],
    );
    const reopened = await openWallet(world, 1, store);
    await pastDeadlines(world, reopened);
    balance = await reopened.balance();
    assert.deepEqual(
      [balance.spendable, balance.locked, balance.maybeSpent],
      [15n * XLM, 0n, 5n * XLM],
    );
    const again = await openWallet(world, 1, store);
    assert.equal((await again.balance()).maybeSpent, 5n * XLM);
  });
});

describe("the second provider's simulation of a refusal", () => {
  const modes: Record<string, (body: { id: unknown }) => Response | Promise<Response>> = {
    "rate limited": () => new Response(JSON.stringify({ error: "slow down" }), { status: 429 }),
    dropped: () => Promise.reject(new TypeError("fetch failed")),
    malformed: (body) =>
      new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { error: 7 } }), {
        status: 200,
      }),
    "another network": (body) =>
      new Response(
        JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32600, message: "bad" } }),
        { status: 200 },
      ),
  };
  for (const [mode, reply] of Object.entries(modes)) {
    it(`counts nothing and keeps the plan when it is not answered (${mode})`, async () => {
      const { world, bob, store } = await twoNotes((world) => ({
        secondRpcUrl: SECOND,
        fetch: network(world, reply).fetchFn,
      }));
      await spentElsewhere(world, store, 5n * XLM);
      const err = await selfUnshield(world, bob, 12n * XLM);
      assert.ok(isError("transaction_failed")(err), String(err));
      assert.equal(details(err)["vaultError"], "NullifierSpent");
      assert.equal(details(err)["everyProvider"], false);
      assert.equal((await suspects(store, world)).size, 0);
      const [plan] = await bob.plans();
      assert.equal(plan?.state, "prepared");
      assert.equal(plan?.lastError?.code, "transaction_failed");
      assert.equal((await bob.balance()).locked, 15n * XLM);
      assert.ok(isError("operation_open")(await selfUnshield(world, bob, 1n * XLM)));
      await pastDeadlines(world, bob);
      assert.equal((await bob.balance()).spendable, 15n * XLM);
      assert.equal(owedTo(world, world.signer("carol").publicKey), 0n);
    });
  }

  it("gets the first provider's envelope and nothing more about the plan", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob, store } = await twoNotes((world) => {
      net = network(world);
      return { secondRpcUrl: SECOND, fetch: net.fetchFn };
    });
    await spentElsewhere(world, store, 5n * XLM);
    const before = net?.bodies.length ?? 0;
    assert.ok(counted(await selfUnshield(world, bob, 4n * XLM)));
    await pastDeadlines(world, bob);
    await spentElsewhere(world, store, 10n * XLM);
    assert.ok(counted(await selfUnshield(world, bob, 8n * XLM)));
    // A relayed refusal asks the second provider nothing.
    await pastDeadlines(world, bob);
    await relayedUnshield(world, bob, 3n * XLM);
    await pastDeadlines(world, bob);
    const after = (net?.bodies ?? []).slice(before);
    const sims = after.filter((b) => b.method === "simulateTransaction");
    const second = sims.filter((b) => b.origin === SECOND);
    assert.equal(second.length, 2);
    const first = sims.filter((b) => b.origin === RPC).map((b) => JSON.stringify(b.params));
    for (const s of second) assert.ok(first.includes(JSON.stringify(s.params)));
    const keys = (await stateOf(store, world)).plans
      .flatMap((p) => p.nullifiers)
      .map((nf) => nullifierKey(world.deployment.vault, nf).toXDR("base64"));
    const reads = after.filter(
      (b) => b.method !== "simulateTransaction" && b.method !== "sendTransaction",
    );
    for (const b of reads) {
      for (const key of keys) assert.ok(!b.text.includes(key), `${b.method} names a plan's key`);
    }
  });
});

describe("a relayed-only wallet with a note spent elsewhere", () => {
  it("is refused on every payment that picks the note, and leaves nothing out", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    for (let i = 0; i < 3; i++) {
      const err = await relayedUnshield(world, bob, 3n * XLM);
      assert.ok(isError("service_rejected")(err), String(err));
      const plan = (await bob.plans()).at(-1);
      assert.equal(plan?.inputValue, 5n * XLM, "the same note goes each time");
      assert.equal(plan?.lastError?.code, "service_rejected");
      assert.equal(plan?.lastError?.message, "the relayer refused the submission");
      assert.ok(isError("operation_open")(await relayedUnshield(world, bob, 1n * XLM)));
      await pastDeadlines(world, bob);
    }
    assert.equal((await suspects(store, world)).size, 0);
    const balance = await bob.balance();
    assert.deepEqual([balance.spendable, balance.maybeSpent], [15n * XLM, 0n]);
    assert.equal(owedTo(world, world.signer("carol").publicKey), 0n);
  });

  it("marks nothing from a relayer that fails a taken request", async () => {
    const { world, bob, store } = await twoNotes();
    world.relayer.failNext = 1;
    const sub = await caught(relayedUnshield(world, bob, 12n * XLM));
    assert.equal(sub, undefined);
    for (let i = 0; i < 3; i++) {
      world.advance(5);
      await bob.sync();
    }
    assert.equal((await suspects(store, world)).size, 0);
    await pastDeadlines(world, bob);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("keeps the first proof's notes and destination after a fee retry is refused", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 10n * XLM);
    world.relayer.failures.push({ error: "fee_too_low" }, { error: "rejected" });
    const err = await relayedUnshield(world, bob, 12n * XLM);
    assert.ok(isError("service_rejected")(err), String(err));
    assert.deepEqual(
      (await bob.plans()).map((p) => p.state),
      ["prepared", "prepared"],
    );
    assert.ok(isError("operation_open")(await relayedUnshield(world, bob, 3n * XLM)));
    assert.equal((await bob.balance()).spendable, 0n);
    await pastDeadlines(world, bob);
    assert.deepEqual(
      (await bob.plans()).map((p) => p.state),
      ["dead", "dead"],
    );
    assert.equal((await suspects(store, world)).size, 0);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
    assert.equal(owedTo(world, world.signer("carol").publicKey), 0n);
  });

  it("marks nothing and pays nothing when a restarted relayer fails a held request", async () => {
    const { world, bob, store } = await twoNotes();
    const carol = world.signer("carol").publicKey;
    await bob.unshield({
      to: carol,
      amount: 12n * XLM,
      maxFee: 2n * XLM,
      notBefore: Number(world.vault.timestamp) + 60,
      confirm: () => true,
    });
    world.relayer.restart();
    await spentElsewhere(world, store, 10n * XLM);
    world.relayer.failures.push({ error: "rejected" });
    world.advance(5);
    await bob.sync();
    assert.equal((await suspects(store, world)).size, 0);
    world.relayer.releaseHeld();
    // The held request's deadline lies past its not_before and the relayer's window.
    world.advance(5 * 400);
    await bob.sync();
    assert.equal((await bob.plans())[0]?.state, "dead");
    assert.equal(owedTo(world, carol), 0n);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});
