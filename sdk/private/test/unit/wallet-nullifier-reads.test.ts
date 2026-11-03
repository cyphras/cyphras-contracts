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

// The keys every one of `reads` holds.
function common(reads: readonly Read[]): Set<string> {
  const [first, ...rest] = reads;
  const out = new Set(first?.keys ?? []);
  for (const r of rest) for (const k of [...out]) if (!r.keys.includes(k)) out.delete(k);
  return out;
}

describe("repeated reads of a plan's nullifiers", () => {
  // Whatever one provider was asked about a plan over several reads, the plan's keys still hide
  // among as many public and random keys as in one read.
  function assertHidden(world: World, reads: readonly Read[], real: readonly string[]): void {
    assert.ok(reads.length >= 1, "the plan's keys were read");
    const vault = new Set([...world.vault.nullifiers.keys()].map((nf) => keyOf(world, nf)));
    const kept = common(reads);
    for (const key of real) assert.ok(kept.has(key));
    const decoys = [...kept].filter((k) => !real.includes(k));
    const misses = decoys.filter((k) => !vault.has(k)).length;
    const spends = decoys.filter((k) => vault.has(k)).length;
    assert.ok(misses >= 31 * real.length, `${reads.length} reads leave ${misses} random keys`);
    assert.ok(spends >= 31 * real.length, `${reads.length} reads leave ${spends} public spends`);
  }

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
    assertHidden(world, reads, real);
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
    assertHidden(world, reads, real);
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
      assert.equal(details(err)["spentCheck"], "unconfirmed");
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

describe("a refused plan with one note and a dummy input", () => {
  it("marks the note, frees the destination and pays once", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 5n * XLM);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 4n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    const [plan] = (await stateOf(store, world)).plans;
    assert.equal(plan?.inputs.length, 1);
    assert.equal(plan?.state, "superseded");
    assert.equal((await bob.balance()).spendable, 10n * XLM);
    await bob.unshield({ to: carol, amount: 4n * XLM, maxFee: 2n * XLM, confirm: () => true });
    await bob.sync();
    assert.equal(owedTo(world, carol), 4n * XLM);
  });
});

describe("the read across a restart", () => {
  it("reads among public spends kept in the stored state, and keeps the mark", async () => {
    const store = new MemoryStore();
    const { world } = await twoNotes(undefined, store);
    const kept = (await stateOf(store, world)).publicNullifiers;
    assert.ok(kept.length >= 62);
    assert.ok(kept.every((nf) => typeof nf === "bigint"));
    const reopened = await openWallet(world, 1, store);
    await spentElsewhere(world, store, 10n * XLM);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      reopened.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    const again = await openWallet(world, 1, store);
    assert.equal((await again.plans())[0]?.state, "superseded");
    const spent = (await notesOf(store, world)).find((n) => n.value === 10n * XLM)?.spent;
    assert.equal(spent?.external, true);
    assert.equal((await again.balance()).spendable, 5n * XLM);
  });
});

describe("the public spends a wallet keeps", () => {
  it("keeps at most the newest 1024, none of the wallet's own", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(undefined, store, 600);
    const carol = world.signer("carol").publicKey;
    await bob.unshield({ to: carol, amount: 4n * XLM, maxFee: 2n * XLM, confirm: () => true });
    world.advance(5);
    await bob.sync();
    const state = await stateOf(store, world);
    assert.ok(state.publicNullifiers.length <= 1024, `${state.publicNullifiers.length} kept`);
    const all = [...world.vault.nullifiers.keys()];
    assert.ok(state.publicNullifiers.includes(all[all.length - 3] as bigint), "the newest is kept");
    assert.ok(!state.publicNullifiers.includes(all[0] as bigint), "the oldest is dropped");
    const own = state.notes.flatMap((n) => (n.nf === undefined ? [] : [n.nf]));
    assert.ok(own.every((nf) => !state.publicNullifiers.includes(nf)));
  });

  it("never puts the wallet's own earlier spends among a read's decoys", async () => {
    let net: ReturnType<typeof network> | undefined;
    const store = new MemoryStore();
    const { world, bob } = await twoNotes((world) => {
      net = network(world);
      return { fetch: net.fetchFn };
    }, store);
    const carol = world.signer("carol").publicKey;
    await bob.unshield({ to: carol, amount: 4n * XLM, maxFee: 2n * XLM, confirm: () => true });
    world.advance(5);
    await bob.sync();
    const before = await stateOf(store, world);
    assert.equal(before.plans[0]?.state, "settled");
    const landed = (before.plans[0]?.nullifiers ?? []).map((nf) => keyOf(world, nf));
    await spentElsewhere(world, store, 10n * XLM);
    const err = await caught(
      bob.unshield({ to: carol, amount: 8n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    const reads = (net?.asked ?? []).filter((a) => a.keys.length >= BATCH);
    assert.equal(reads.length, 1);
    for (const key of landed) assert.ok(!reads[0]?.keys.includes(key));
  });
});

describe("a refusal after a fee retry", () => {
  it("keeps the first proof's notes and destination until its fate is known", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 10n * XLM);
    const carol = world.signer("carol").publicKey;
    world.relayer.failures.push({ error: "fee_too_low" }, { error: "rejected" });
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    assert.deepEqual(
      (await bob.plans()).map((p) => p.state),
      ["prepared", "superseded"],
    );
    // The relayer holds the first proof, which spends the same notes.
    await assert.rejects(
      bob.unshield({ to: carol, amount: 3n * XLM, maxFee: 2n * XLM, confirm: () => true }),
      isError("operation_open"),
    );
    assert.equal((await bob.balance()).spendable, 0n);
    world.advance(5 * 200);
    await bob.sync();
    assert.equal((await bob.plans())[0]?.state, "dead");
    assert.equal((await bob.balance()).spendable, 5n * XLM);
    assert.equal(owedTo(world, carol), 0n);
  });
});

describe("a self-relayed simulation that names a spent nullifier", () => {
  // Bob's self-relayed unshield, whose simulation the only RPC provider fails with the vault's
  // NullifierSpent while no note of it is spent.
  async function refused() {
    let faking = false;
    const { world, bob, store } = await twoNotes((world) => ({
      fetch: async (input, init) => {
        const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
        if (faking && body?.method === "simulateTransaction") {
          faking = false;
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: body.id,
              result: {
                error: "HostError: Error(Contract, #123)",
                latestLedger: world.vault.ledger,
              },
            }),
            { status: 200 },
          );
        }
        return world.fetch(input, init);
      },
    }));
    faking = true;
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({
        to: carol,
        amount: 12n * XLM,
        selfRelay: world.signer("bob account"),
        confirm: () => true,
      }),
    );
    return { world, bob, store, err };
  }

  it("changes nothing when no provider shows one spent", async () => {
    const { world, bob, store, err } = await refused();
    assert.ok(isError("nullifier_disputed")(err), String(err));
    assert.equal(typeof details(err)["planId"], "string");
    assert.equal((await bob.plans())[0]?.state, "prepared");
    assert.equal((await bob.plans())[0]?.lastError?.code, "nullifier_disputed");
    assert.equal((await notesOf(store, world)).filter((n) => n.spent !== undefined).length, 0);
    assert.equal((await bob.balance()).locked, 15n * XLM);
  });

  it("carries the vault's refusal as the cause of nullifier_disputed", async () => {
    const { err } = await refused();
    assert.ok(isError("nullifier_disputed")(err), String(err));
    const cause = (err as Error).cause;
    assert.ok(isError("transaction_failed")(cause), `cause ${String(cause)}`);
  });
});

describe("a held request the relayer fails after a restart", () => {
  it("marks the note spent elsewhere and pays nothing", async () => {
    const { world, bob, store } = await twoNotes();
    const carol = world.signer("carol").publicKey;
    await bob.unshield({
      to: carol,
      amount: 12n * XLM,
      maxFee: 2n * XLM,
      notBefore: Number(world.vault.timestamp) + 60,
      confirm: () => true,
    });
    assert.equal((await bob.plans())[0]?.relayerStatus, undefined);
    world.relayer.restart();
    await spentElsewhere(world, store, 10n * XLM);
    world.relayer.failures.push({ error: "rejected" });
    world.advance(5);
    await bob.sync();
    assert.equal((await bob.plans())[0]?.state, "superseded");
    assert.equal((await bob.balance()).spendable, 5n * XLM);
    world.relayer.releaseHeld();
    world.advance(5 * 200);
    await bob.sync();
    assert.equal(owedTo(world, carol), 0n);
  });
});

describe("a spend the vault's entry showed, named later by a recheck", () => {
  it("takes the transaction the vault's events name, counted once", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(() => ({ syncLimits: { eventPages: 1 } }), store);
    const other = await openWallet(world, 1);
    await other.sync();
    // Other users fill more events than one page of RPC's holds, then another instance of Bob's
    // wallet spends the 10 XLM note, a spend the indexer leaves out.
    world.advance(5);
    world.fill(600);
    world.advance(5);
    const dave = world.signer("dave").publicKey;
    const elsewhere = await other.unshield({
      to: dave,
      amount: 8n * XLM,
      maxFee: 2n * XLM,
      confirm: () => true,
    });
    world.indexer.hideNullifiers = true;
    world.advance(5);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent", String(err));
    const state = await stateOf(store, world);
    assert.ok(state.unchecked.some((r) => r.status === "open"));
    assert.equal(state.notes.find((n) => n.value === 10n * XLM)?.spent?.external, true);
    world.indexer.hideNullifiers = false;
    const reopened = await openWallet(world, 1, store);
    world.advance(5);
    await reopened.sync();
    const spent = (await notesOf(store, world)).find((n) => n.value === 10n * XLM)?.spent;
    assert.equal(spent?.external, undefined);
    assert.equal(spent?.txHash, elsewhere.txHash);
    const change = 2n * XLM - elsewhere.fee;
    assert.equal((await reopened.balance()).spendable, 5n * XLM + change);
    const entries = (await reopened.history()).filter((h) => h.txHash === elsewhere.txHash);
    assert.equal(entries.length, 1);
    assert.equal(entries[0]?.kind, "unshield");
    assert.equal(owedTo(world, carol), 0n);
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
