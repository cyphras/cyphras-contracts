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

// A getLedgerEntries request at least this long would be a read of many nullifiers at once.
const BATCH = 100;

const details = (err: unknown): Record<string, unknown> =>
  err instanceof CyphrasError ? (err.details as Record<string, unknown>) : {};

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined).catch((e) => e);

interface Read {
  readonly origin: string;
  readonly keys: string[];
}

// Serves the second provider from the world's RPC and records every getLedgerEntries request.
function network(world: World) {
  const asked: Read[] = [];
  const fetchFn: FetchLike = async (input, init) => {
    const origin = new URL(input).origin;
    const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
    if (body?.method === "getLedgerEntries") {
      asked.push({ origin, keys: body.params.keys as string[] });
    }
    const target = origin === SECOND ? RPC + input.slice(SECOND.length) : input;
    return world.fetch(target, init);
  };
  return { asked, fetchFn };
}

async function stateOf(store: KeyValueStore, world: World): Promise<WalletState> {
  const state = await loadState(sealedState(store, world, 1));
  assert.ok(state !== undefined);
  return state;
}

const keyOf = (world: World, nf: bigint): string =>
  nullifierKey(world.deployment.vault, nf).toXDR("base64");

// Alice pays Bob 10 XLM, then 5 XLM, and other users spend `spends` times.
async function twoNotes(
  options: (world: World) => Partial<OpenOptions> = () => ({}),
  store: KeyValueStore = new MemoryStore(),
  spends = 40,
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
  world.spends(spends);
  const bob: PrivateWallet = await openWallet(world, 1, store, undefined, options(world));
  await bob.sync();
  assert.equal((await bob.balance()).spendable, 15n * XLM);
  return { world, alice, bob, store };
}

describe("no request names a refused plan's nullifier keys", () => {
  it("keeps the keys of a request the relayer failed hidden across syncs", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob, store } = await twoNotes((world) => {
      net = network(world);
      return { secondRpcUrl: SECOND, fetch: net.fetchFn };
    });
    const carol = world.signer("carol").publicKey;
    world.relayer.failNext = 1;
    await bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true });
    for (let i = 0; i < 3; i++) {
      world.advance(5);
      await bob.sync();
    }
    const plan = (await stateOf(store, world)).plans[0];
    assert.equal(plan?.state, "submitted");
    const real = (plan?.nullifiers ?? []).map((nf) => keyOf(world, nf));
    const reads = (net?.asked ?? []).filter(
      (a) => a.origin === RPC && a.keys.some((k) => real.includes(k)),
    );
    assert.equal(reads.length, 0, "no request holds the plan's keys");
  });

  it("keeps the keys of a payment refused again on retry hidden", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob, store } = await twoNotes((world) => {
      net = network(world);
      return { fetch: net.fetchFn };
    });
    const carol = world.signer("carol").publicKey;
    world.relayer.failures.push({ error: "rejected" }, { error: "rejected" });
    const first = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.ok(isError("service_rejected")(first), String(first));
    const again = await caught(
      bob.retry(String(details(first)["planId"]), { confirm: () => true }),
    );
    assert.ok(isError("service_rejected")(again), String(again));
    const real = ((await stateOf(store, world)).plans[1]?.nullifiers ?? []).map((nf) =>
      keyOf(world, nf),
    );
    const reads = (net?.asked ?? []).filter((a) => a.keys.some((k) => real.includes(k)));
    assert.equal(reads.length, 0, "no request holds the plan's keys");
  });
});

describe("a shield that fails", () => {
  it("reads no nullifier and changes no note", async () => {
    let net: ReturnType<typeof network> | undefined;
    const { world, bob } = await twoNotes((world) => {
      net = network(world);
      return { fetch: net.fetchFn };
    });
    const before = net?.asked.length ?? 0;
    world.rpc.failNext = 1;
    await assert.rejects(bob.shield({ amount: 20n * XLM, signer: world.signer("bob depositor") }));
    const reads = (net?.asked ?? []).slice(before).filter((a) => a.keys.length >= BATCH);
    assert.equal(reads.length, 0);
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });
});
