import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import { nullifierKey } from "../../src/vault/state.ts";
import { type OwnedNote, type WalletState, loadState } from "../../src/wallet/state.ts";
import type { OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { isError, openWallet, sealedState } from "../support/wallets.ts";

const SECOND = "http://second-rpc.test";

// A getLedgerEntries request this long is a read of a plan's nullifiers among decoys.
const BATCH = 100;

const details = (err: unknown): Record<string, unknown> =>
  err instanceof CyphrasError ? (err.details as Record<string, unknown>) : {};

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined).catch((e) => e);

const owedTo = (world: World, destination: string): bigint =>
  world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === destination)
    .reduce((s, e) => s + e.payout, 0n);

interface Read {
  readonly origin: string;
  readonly keys: string[];
}

// Serves the second provider from the world's RPC, records every getLedgerEntries request, and
// lets a test answer a batch read of the second provider its own way.
function network(world: World) {
  const asked: Read[] = [];
  let breakSecond: ((body: { id: unknown }) => Response | Promise<Response>) | undefined;
  const fetchFn: FetchLike = async (input, init) => {
    const origin = new URL(input).origin;
    const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
    if (body?.method === "getLedgerEntries") {
      const keys = body.params.keys as string[];
      asked.push({ origin, keys });
      if (origin === SECOND && keys.length >= BATCH && breakSecond !== undefined) {
        return breakSecond(body);
      }
    }
    const target = origin === SECOND ? RPC + input.slice(SECOND.length) : input;
    return world.fetch(target, init);
  };
  return {
    asked,
    fetchFn,
    breakWith(f: typeof breakSecond) {
      breakSecond = f;
    },
  };
}

async function stateOf(store: KeyValueStore, world: World): Promise<WalletState> {
  const state = await loadState(sealedState(store, world, 1));
  assert.ok(state !== undefined);
  return state;
}

const notesOf = async (store: KeyValueStore, world: World): Promise<OwnedNote[]> =>
  (await stateOf(store, world)).notes;

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

async function spentElsewhere(world: World, store: KeyValueStore, value: bigint): Promise<bigint> {
  const note = (await notesOf(store, world)).find((n) => n.value === value);
  assert.ok(note?.nf !== undefined);
  world.vault.nullifiers.set(note.nf, { ledger: world.vault.ledger - 1, txHash: "e".repeat(64) });
  return note.nf;
}

describe("repeated reads of a plan's nullifiers", () => {
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

describe("a read of a plan's nullifiers that a provider does not answer", () => {
  const modes: Record<string, (body: { id: unknown }) => Response | Promise<Response>> = {
    "rate limited": () => new Response(JSON.stringify({ error: "slow down" }), { status: 429 }),
    dropped: () => Promise.reject(new TypeError("fetch failed")),
    "made-up key": (body) =>
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: body.id,
          result: {
            latestLedger: 10_000,
            entries: [{ key: "AAAA", xdr: "AAAA", lastModifiedLedgerSeq: 1 }],
          },
        }),
        { status: 200 },
      ),
  };
  for (const [mode, reply] of Object.entries(modes)) {
    it(`changes nothing and pays nothing (${mode})`, async () => {
      let net: ReturnType<typeof network> | undefined;
      const { world, bob, store } = await twoNotes((world) => {
        net = network(world);
        return { secondRpcUrl: SECOND, fetch: net.fetchFn };
      });
      await spentElsewhere(world, store, 10n * XLM);
      net?.breakWith(reply);
      const carol = world.signer("carol").publicKey;
      const err = await caught(
        bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
      );
      assert.ok(isError("service_rejected")(err), String(err));
      assert.equal((await bob.plans())[0]?.state, "prepared");
      assert.equal((await notesOf(store, world)).filter((n) => n.spent !== undefined).length, 0);
      assert.equal((await bob.balance()).locked, 15n * XLM);
      await assert.rejects(
        bob.unshield({ to: carol, amount: 3n * XLM, maxFee: 2n * XLM, confirm: () => true }),
        isError("operation_open"),
      );
      assert.equal(owedTo(world, carol), 0n);
    });
  }
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
