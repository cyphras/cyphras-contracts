import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Address, scValToBigInt, xdr } from "@stellar/stellar-base";
import { P } from "../../src/field.ts";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import { nullifierKey } from "../../src/vault/state.ts";
import { type OwnedNote, loadState } from "../../src/wallet/state.ts";
import type { OpenOptions, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { isError, openWallet, sealedState } from "../support/wallets.ts";

const SECOND = "http://second-rpc.test";

const details = (err: unknown): Record<string, unknown> =>
  err instanceof CyphrasError ? (err.details as Record<string, unknown>) : {};

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined).catch((e) => e);

// What the vault paid a destination or owes it in its exit queue.
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
  spends = 40,
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
  // Other users' spends, which a read of Bob's nullifiers hides among.
  world.spends(spends);
  const bob: PrivateWallet = await openWallet(world, 1, store, undefined, options(world));
  await bob.sync();
  assert.equal((await bob.balance()).spendable, 15n * XLM);
  return { world, alice, bob, store };
}

async function notesOf(store: KeyValueStore, world: World): Promise<OwnedNote[]> {
  const state = await loadState(sealedState(store, world, 1));
  return state?.notes ?? [];
}

// The note of `value` is spent by a transaction no source of the wallet shows, as an archive that
// left its spend out, at a ledger the wallet's syncs are past.
async function spentElsewhere(world: World, store: KeyValueStore, value: bigint): Promise<bigint> {
  const note = (await notesOf(store, world)).find((n) => n.value === value);
  assert.ok(note?.nf !== undefined);
  world.vault.nullifiers.set(note.nf, { ledger: world.vault.ledger - 1, txHash: "e".repeat(64) });
  return note.nf;
}

// An RPC provider, served from the world's, whose getLedgerEntries replies leave out the entries of
// `hidden` nullifiers and add made-up ones for `faked`.
function provider(
  world: World,
  routes: Readonly<Record<string, { readonly hidden?: Set<bigint>; readonly faked?: Set<bigint> }>>,
): FetchLike {
  const id = (nf: bigint): string => nullifierKey(world.deployment.vault, nf).toXDR("base64");
  return async (input, init) => {
    const origin = new URL(input).origin;
    const route = routes[origin];
    const target = origin === SECOND ? RPC + input.slice(SECOND.length) : input;
    const res = await world.fetch(target, init);
    const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
    if (route === undefined || body?.method !== "getLedgerEntries") return res;
    const reply = (await res.json()) as {
      result: { entries?: { key: string }[]; latestLedger: number };
    };
    const hidden = new Set([...(route.hidden ?? [])].map(id));
    const entries = (reply.result.entries ?? []).filter((e) => !hidden.has(e.key));
    const asked = new Set(body.params.keys as string[]);
    for (const nf of route.faked ?? new Set<bigint>()) {
      const key = nullifierKey(world.deployment.vault, nf);
      if (!asked.has(id(nf)) || entries.some((e) => e.key === id(nf))) continue;
      const k = key.contractData();
      const data = xdr.LedgerEntryData.contractData(
        new xdr.ContractDataEntry({
          ext: new xdr.ExtensionPoint(0),
          contract: k.contract(),
          key: k.key(),
          durability: k.durability(),
          val: xdr.ScVal.scvVoid(),
        }),
      );
      const ledger = reply.result.latestLedger;
      entries.push({
        key: id(nf),
        xdr: data.toXDR("base64"),
        lastModifiedLedgerSeq: ledger - 1,
        liveUntilLedgerSeq: ledger + 1000,
      } as { key: string });
    }
    return new Response(JSON.stringify({ ...reply, result: { ...reply.result, entries } }), {
      status: 200,
    });
  };
}

describe("a spend the vault refuses because a note was spent elsewhere", () => {
  for (const route of ["relayed", "self-relayed"] as const) {
    it(`marks that note spent and frees the other one (${route})`, async () => {
      const { world, bob, store } = await twoNotes();
      await spentElsewhere(world, store, 10n * XLM);
      const carol = world.signer("carol").publicKey;
      const account = world.signer("bob account");
      const request = (amount: bigint) => ({
        to: carol,
        amount,
        confirm: () => true,
        ...(route === "relayed" ? { maxFee: 2n * XLM } : { selfRelay: account }),
      });
      const events = world.vault.events.length;
      const err = await caught(bob.unshield(request(12n * XLM)));
      if (route === "relayed") {
        assert.ok(isError("service_rejected")(err), String(err));
      } else {
        assert.ok(isError("transaction_failed")(err), String(err));
        assert.equal(details(err)["vaultError"], "NullifierSpent");
      }
      assert.equal(details(err)["spentCheck"], "spent");
      assert.equal(world.vault.events.length, events, "nothing reached the vault");
      const [plan] = await bob.plans();
      assert.equal(plan?.state, "superseded");
      assert.equal(plan?.mustRetry, false);
      const balance = await bob.balance();
      assert.equal(balance.spendable, 5n * XLM, "only the note spent elsewhere is gone");
      assert.equal(balance.locked, 0n);
      const spent = (await notesOf(store, world)).find((n) => n.value === 10n * XLM)?.spent;
      assert.equal(spent?.external, true);
      assert.equal(spent?.txHash, undefined);
      assert.ok((spent?.ledger ?? 0) >= world.vault.ledger - 1);
      // The refused plan can never land, so the destination takes the next unshield, paid once.
      await bob.unshield(request(3n * XLM));
      await bob.sync();
      assert.equal(owedTo(world, carol), 3n * XLM);
      const fee = (await bob.plans())[1]?.fee ?? 0n;
      assert.equal((await bob.balance()).spendable, 2n * XLM - fee);
      assert.deepEqual(
        (await bob.plans()).map((p) => p.state),
        ["superseded", "settled"],
      );
    });
  }

  it("keeps a plan both of whose notes were spent until its fate is known, and pays nothing", async () => {
    const { world, bob, store } = await twoNotes();
    await spentElsewhere(world, store, 10n * XLM);
    await spentElsewhere(world, store, 5n * XLM);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    // Its own proof may have written both entries, so it may have landed and still holds the
    // destination.
    const [plan] = await bob.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal((await bob.balance()).spendable, 0n);
    await assert.rejects(
      bob.unshield({ to: carol, amount: 1n * XLM, maxFee: 2n * XLM, confirm: () => true }),
      isError("operation_open"),
    );
    await assert.rejects(bob.retry(plan?.planId ?? ""), isError("invalid_argument"));
    world.advance(5 * 200);
    await bob.sync();
    assert.equal((await bob.plans())[0]?.state, "dead");
    const balance = await bob.balance();
    assert.equal(balance.spendable, 0n);
    assert.equal(balance.locked, 0n);
    assert.equal(owedTo(world, carol), 0n);
  });

  it("changes nothing when the two RPC providers disagree", async () => {
    const hidden = new Set<bigint>();
    const { world, bob, store } = await twoNotes((world) => ({
      secondRpcUrl: SECOND,
      fetch: provider(world, { [SECOND]: { hidden } }),
    }));
    hidden.add(await spentElsewhere(world, store, 10n * XLM));
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.ok(isError("nullifier_disputed")(err), String(err));
    assert.equal(details(err)["spentCheck"], "disputed");
    assert.equal(typeof details(err)["planId"], "string");
    const [plan] = await bob.plans();
    assert.equal(plan?.state, "prepared");
    assert.match(plan?.lastError?.message ?? "", /do not agree/);
    assert.equal((await notesOf(store, world)).filter((n) => n.spent !== undefined).length, 0);
    const balance = await bob.balance();
    assert.equal(balance.spendable, 0n);
    assert.equal(balance.locked, 15n * XLM);
  });

  it("hides no note when one of two RPC providers fakes a nullifier entry", async () => {
    const faked = new Set<bigint>();
    const { world, bob, store } = await twoNotes((world) => ({
      secondRpcUrl: SECOND,
      fetch: provider(world, { [RPC]: { faked } }),
    }));
    for (const n of await notesOf(store, world)) if (n.nf !== undefined) faked.add(n.nf);
    world.relayer.failures.push({ error: "rejected" });
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.ok(isError("nullifier_disputed")(err), String(err));
    assert.equal((await notesOf(store, world)).filter((n) => n.spent !== undefined).length, 0);
    assert.equal((await bob.plans())[0]?.state, "prepared");
    // Past its deadline the plan is dead and every note spendable again.
    world.advance(5 * 200);
    await bob.sync();
    assert.equal((await bob.plans())[0]?.state, "dead");
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("takes the word of the only RPC provider, as the sync does", async () => {
    const faked = new Set<bigint>();
    const { world, bob, store } = await twoNotes((world) => ({
      fetch: provider(world, { [RPC]: { faked } }),
    }));
    const five = (await notesOf(store, world)).find((n) => n.value === 5n * XLM);
    faked.add(five?.nf ?? 0n);
    world.relayer.failures.push({ error: "rejected" });
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    assert.equal((await bob.plans())[0]?.state, "superseded");
    assert.equal((await bob.balance()).spendable, 10n * XLM);
  });

  it("marks the note once the relayer fails a request it took", async () => {
    const { world, bob, store } = await twoNotes();
    const carol = world.signer("carol").publicKey;
    world.relayer.failNext = 1;
    await bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true });
    assert.equal((await bob.plans())[0]?.state, "submitted");
    await spentElsewhere(world, store, 10n * XLM);
    await bob.sync();
    assert.equal((await bob.plans())[0]?.state, "superseded");
    assert.equal((await bob.balance()).spendable, 5n * XLM);
    assert.equal(owedTo(world, carol), 0n);
  });

  it("takes the transaction a later sync names for the spend, counted once", async () => {
    const { world, bob, store } = await twoNotes();
    // Another instance of Bob's wallet spends the 10 XLM note; Bob's indexer lags behind it.
    const other = await openWallet(world, 1);
    await other.sync();
    world.advance(5);
    world.indexer.completeTo = world.vault.ledger - 1;
    const dave = world.signer("dave").publicKey;
    const elsewhere = await other.unshield({
      to: dave,
      amount: 8n * XLM,
      maxFee: 2n * XLM,
      confirm: () => true,
    });
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    const marked = (await notesOf(store, world)).find((n) => n.value === 10n * XLM)?.spent;
    assert.equal(marked?.external, true);
    const change = 2n * XLM - elsewhere.fee;
    assert.equal((await bob.balance()).spendable, 5n * XLM + change);
    world.indexer.completeTo = undefined;
    world.advance(5);
    await bob.sync();
    const spent = (await notesOf(store, world)).find((n) => n.value === 10n * XLM)?.spent;
    assert.equal(spent?.external, undefined);
    assert.equal(spent?.txHash, elsewhere.txHash);
    assert.equal((await bob.balance()).spendable, 5n * XLM + change);
    const entries = (await bob.history()).filter((h) => h.txHash === elsewhere.txHash);
    assert.equal(entries.length, 1);
    assert.equal(entries[0]?.kind, "unshield");
    assert.equal(owedTo(world, carol), 0n);
  });

  it("blocks a split unshield whose part spent a note spent elsewhere, and pays nothing more", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(undefined, store, 8n * XLM);
    await spentElsewhere(world, store, 10n * XLM);
    const carol = world.signer("carol").publicKey;
    const request = {
      to: carol,
      amount: 12n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: () => true,
    };
    const err = await caught(bob.unshield(request));
    assert.equal(details(err)["spentCheck"], "spent");
    const operationId = details(err)["operationId"];
    assert.equal(typeof operationId, "string");
    assert.equal((await bob.plans())[0]?.state, "superseded");
    const [op] = await bob.continueOperations();
    assert.equal(op?.state, "blocked");
    assert.equal(op?.operationId, operationId);
    await assert.rejects(
      bob.unshield({ ...request, amount: 3n * XLM, split: false }),
      isError("operation_open"),
    );
    world.advance(5 * 200);
    await bob.continueOperations();
    assert.equal((await bob.plans()).length, 1, "no part went with other notes");
    assert.equal(owedTo(world, carol), 0n);
    assert.equal((await bob.balance()).spendable, 5n * XLM);
  });
});

describe("the read of a refused plan's nullifiers", () => {
  // Every getLedgerEntries request a provider was sent, by provider, as its list of keys.
  function recorded(inner: FetchLike) {
    const asked: { origin: string; keys: string[] }[] = [];
    const fetchFn: FetchLike = async (input, init) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      if (body?.method === "getLedgerEntries") {
        asked.push({ origin: new URL(input).origin, keys: body.params.keys as string[] });
      }
      return inner(input, init);
    };
    return { asked, fetchFn };
  }

  const keyOf = (world: World, nf: bigint): string =>
    nullifierKey(world.deployment.vault, nf).toXDR("base64");

  async function planNullifiers(store: KeyValueStore, world: World): Promise<bigint[]> {
    const state = await loadState(sealedState(store, world, 1));
    return [...(state?.plans[0]?.nullifiers ?? [])];
  }

  it("asks every provider for the same batch, the plan's keys among public and random ones", async () => {
    let asked: { origin: string; keys: string[] }[] = [];
    const { world, bob, store } = await twoNotes((world) => {
      const r = recorded(provider(world, {}));
      asked = r.asked;
      return { secondRpcUrl: SECOND, fetch: r.fetchFn };
    });
    await spentElsewhere(world, store, 10n * XLM);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    const real = (await planNullifiers(store, world)).map((nf) => keyOf(world, nf));
    assert.equal(real.length, 2);
    const reads = asked.filter((a) => a.keys.some((k) => real.includes(k)));
    assert.deepEqual(reads.map((a) => a.origin).sort(), [RPC, SECOND].sort());
    for (const read of reads) {
      assert.ok(read.keys.length >= real.length * (1 + 2 * 31), `${read.keys.length} keys`);
      assert.equal(new Set(read.keys).size, read.keys.length);
      for (const key of real) assert.ok(read.keys.includes(key));
    }
    assert.deepEqual(reads[0]?.keys, reads[1]?.keys);
    const vault = new Set([...world.vault.nullifiers.keys()].map((nf) => keyOf(world, nf)));
    const decoys = (reads[0]?.keys ?? []).filter((k) => !real.includes(k));
    const spentDecoys = decoys.filter((k) => vault.has(k));
    const randomDecoys = decoys.filter((k) => !vault.has(k));
    assert.ok(spentDecoys.length >= 31 * real.length, `${spentDecoys.length} public spends`);
    assert.ok(randomDecoys.length >= 31 * real.length, `${randomDecoys.length} random keys`);
    // Every key is a persistent Nullifier entry of the vault with a field element, as the plan's are.
    for (const key of reads[0]?.keys ?? []) {
      const data = xdr.LedgerKey.fromXDR(key, "base64").contractData();
      assert.equal(Address.fromScAddress(data.contract()).toString(), world.deployment.vault);
      assert.equal(data.durability().name, "persistent");
      const [name, value] = data.key().vec() ?? [];
      assert.equal(name?.sym().toString(), "Nullifier");
      assert.equal(value?.switch().name, "scvU256");
      const nf = scValToBigInt(value as xdr.ScVal);
      assert.ok(nf >= 0n && nf < P);
      assert.equal(keyOf(world, nf), key);
    }
    // The plan's unspent key misses along with every random key, so it is not the only miss.
    const misses = (reads[0]?.keys ?? []).filter((k) => !vault.has(k));
    assert.ok(misses.length >= 31 * real.length + 1, `${misses.length} misses`);
    assert.ok(real.some((k) => misses.includes(k)));
  });

  it("takes nothing from what a provider shows of the random keys", async () => {
    const store = new MemoryStore();
    const { world, bob } = await twoNotes(
      (world) => ({
        secondRpcUrl: SECOND,
        // The first provider shows an entry for every key no spend wrote but the plan's own.
        fetch: async (input, init) => {
          const res = await provider(world, {})(input, init);
          const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
          if (new URL(input).origin !== RPC || body?.method !== "getLedgerEntries") return res;
          const state = await loadState(sealedState(store, world, 1));
          const own = new Set(
            state?.plans.flatMap((p) => p.nullifiers.map((nf) => keyOf(world, nf))),
          );
          const reply = (await res.json()) as {
            result: { entries?: { key: string }[]; latestLedger: number };
          };
          const entries = [...(reply.result.entries ?? [])];
          for (const key of body.params.keys as string[]) {
            if (own.has(key) || entries.some((e) => e.key === key)) continue;
            const k = xdr.LedgerKey.fromXDR(key, "base64").contractData();
            if (k.key().vec()?.[0]?.sym().toString() !== "Nullifier") continue;
            const data = xdr.LedgerEntryData.contractData(
              new xdr.ContractDataEntry({
                ext: new xdr.ExtensionPoint(0),
                contract: k.contract(),
                key: k.key(),
                durability: k.durability(),
                val: xdr.ScVal.scvVoid(),
              }),
            );
            const ledger = reply.result.latestLedger;
            entries.push({
              key,
              xdr: data.toXDR("base64"),
              lastModifiedLedgerSeq: ledger - 1,
              liveUntilLedgerSeq: ledger + 1000,
            } as { key: string });
          }
          return new Response(JSON.stringify({ ...reply, result: { ...reply.result, entries } }), {
            status: 200,
          });
        },
      }),
      store,
    );
    const x = await spentElsewhere(world, store, 10n * XLM);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(err)["spentCheck"], "spent");
    assert.equal((await bob.plans())[0]?.state, "superseded");
    assert.deepEqual(
      (await notesOf(store, world)).filter((n) => n.spent !== undefined).map((n) => n.nf),
      [x],
    );
    assert.equal((await bob.balance()).spendable, 5n * XLM);
  });

  it("reads nothing and changes nothing while too few public spends are known", async () => {
    let asked: { origin: string; keys: string[] }[] = [];
    const { world, bob, store } = await twoNotes(
      (world) => {
        const r = recorded(world.fetch);
        asked = r.asked;
        return { fetch: r.fetchFn };
      },
      new MemoryStore(),
      undefined,
      0,
    );
    await spentElsewhere(world, store, 10n * XLM);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.ok(isError("service_rejected")(err), String(err));
    assert.equal(details(err)["spentCheck"], undefined);
    const real = (await planNullifiers(store, world)).map((nf) => keyOf(world, nf));
    assert.equal(asked.filter((a) => a.keys.some((k) => real.includes(k))).length, 0);
    assert.equal((await bob.plans())[0]?.state, "prepared");
    assert.equal((await notesOf(store, world)).filter((n) => n.spent !== undefined).length, 0);
    assert.equal((await bob.balance()).locked, 15n * XLM);
  });

  it("takes nothing from what the providers show of the other keys", async () => {
    const hidden = new Set<bigint>();
    const faked = new Set<bigint>();
    const { world, bob, store } = await twoNotes((world) => ({
      secondRpcUrl: SECOND,
      fetch: provider(world, { [RPC]: { faked }, [SECOND]: { hidden } }),
    }));
    const x = await spentElsewhere(world, store, 10n * XLM);
    // The second provider shows no other user's spend at all, and the first one makes up entries
    // for keys no spend wrote, among them Bob's other notes.
    for (const nf of world.vault.nullifiers.keys()) if (nf !== x) hidden.add(nf);
    for (const n of await notesOf(store, world))
      if (n.nf !== undefined && n.nf !== x) faked.add(n.nf);
    const carol = world.signer("carol").publicKey;
    const err = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    // Only the plan's own keys count, and the first provider's made-up entry for its other note
    // makes it disputed, nothing else.
    assert.ok(isError("nullifier_disputed")(err), String(err));
    assert.equal((await notesOf(store, world)).filter((n) => n.spent !== undefined).length, 0);
    faked.clear();
    world.advance(5 * 200);
    await bob.sync();
    world.relayer.failures.push({ error: "rejected" });
    const again = await caught(
      bob.unshield({ to: carol, amount: 12n * XLM, maxFee: 2n * XLM, confirm: () => true }),
    );
    assert.equal(details(again)["spentCheck"], "spent");
    const marked = (await notesOf(store, world)).filter((n) => n.spent !== undefined);
    assert.deepEqual(
      marked.map((n) => n.nf),
      [x],
    );
    assert.equal((await bob.balance()).spendable, 5n * XLM);
  });
});
