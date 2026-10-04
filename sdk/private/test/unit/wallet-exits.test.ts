import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Account, Address, Asset, Keypair, MuxedAccount, StrKey, xdr } from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import type { ExitEntry, ExitQueue } from "../../src/net/indexer.ts";
import { SorobanRpc } from "../../src/net/rpc.ts";
import { payKeys, queuedExit } from "../../src/vault/state.ts";
import { type Core, transactRoom } from "../../src/wallet/core.ts";
import {
  DEFAULT_NETWORK_FEE_CAPS,
  type Extra,
  type TransactionSigner,
  invokeVault,
} from "../../src/vault/invoke.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { applyExits, shownParts } from "../../src/wallet/exits.ts";
import type { ExitEvent } from "../../src/wallet/sources.ts";
import {
  type Plan,
  type PlanExit,
  type WalletState,
  emptyState,
  loadState,
  saveState,
} from "../../src/wallet/state.ts";
import type { OpenOptions, OperationView, PrivateWallet } from "../../src/wallet/wallet.ts";
import { INDEXER, RPC, XLM, createWorld, rewritingFetch } from "../support/network.ts";
import { diagnostic, keypairFor } from "../support/rpc.ts";
import { confirmAll, isError, openWallet, storeKeyOf } from "../support/wallets.ts";

const SMALL = { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM };

async function funded(limits = SMALL) {
  const world = await createWorld({ limits });
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  return { world, alice };
}

describe("exits above the single-exit cap", () => {
  it("refuses an unshield above the cap unless it may be split", async () => {
    const { world, alice } = await funded();
    await assert.rejects(
      alice.unshield({
        to: world.signer("dest").publicKey,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
      }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "limit_exceeded" &&
        err.details["maxPerTransaction"] === (50n * XLM).toString(),
    );
    await assert.rejects(
      alice.unshield({
        to: world.signer("dest").publicKey,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
      }),
      isError("not_confirmed"),
    );
  });

  it("splits it into parts within the cap, each after the last landed and a random gap", async () => {
    const { world, alice } = await funded();
    const destination = world.signer("dest").publicKey;
    const op = (await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    })) as OperationView;
    assert.equal(op.parts, 2);
    assert.equal(op.plans.length, 1);
    assert.equal(world.relayer.submissions[0]?.ext.ext_amount, (-48n * XLM).toString());

    let [view] = await alice.continueOperations();
    assert.equal(view?.sent, 48n * XLM);
    assert.equal(view?.plans.length, 1);
    assert.ok((view?.nextAt as number) >= world.clock() + 3_600_000);
    world.advance(6 * 3_600 + 1);
    [view] = await alice.continueOperations();
    assert.equal(view?.plans.length, 2);
    [view] = await alice.continueOperations();
    assert.equal(view?.state, "done");
    assert.equal(view?.sent, 90n * XLM);
    const paid = world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount);
    assert.deepEqual(paid, [48n * XLM, 42n * XLM]);
  });
});

describe("split unshields whose parts do not plainly land", () => {
  const SPLIT = { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 350n * XLM };

  // A wallet with notes of these values, by default two, of 60 and 70 XLM, so a part sent again
  // could use the other one.
  async function withNotes(
    world: Awaited<ReturnType<typeof createWorld>>,
    fetch?: FetchLike,
    values = [60n * XLM, 70n * XLM],
  ) {
    const store = new MemoryStore();
    const alice = await openWallet(fetch === undefined ? world : { ...world, fetch }, 0, store);
    for (const amount of values) {
      await alice.shield({ amount, signer: world.signer("alice depositor") });
    }
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    return { alice, store };
  }

  // What the vault paid or still owes the destination.
  const owedTo = (world: Awaited<ReturnType<typeof createWorld>>, to: string): bigint =>
    world.vault.transfers.filter((t) => t.to === to).reduce((s, t) => s + t.amount, 0n) +
    [...world.vault.exits.values()]
      .filter((e) => e.recipient === to)
      .reduce((s, e) => s + e.payout, 0n);

  async function finish(world: Awaited<ReturnType<typeof createWorld>>, wallet: PrivateWallet) {
    let view: OperationView | undefined;
    for (let round = 0; round < 4 && view?.state !== "done"; round++) {
      world.advance(7 * 3600);
      world.fill(1);
      [view] = await wallet.continueOperations();
    }
    return view;
  }

  it("pays a split unshield once when a part's leaves arrive in a batch held aside", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice, store } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    });
    world.fill(800);
    const later = await openWallet(world, 0, store, undefined, { syncLimits: { leafPages: 1 } });
    await later.sync();
    await later.sync();
    assert.deepEqual(
      (await later.plans()).map((p) => p.state),
      ["settled"],
    );
    const view = await finish(world, later);
    assert.equal(view?.state, "done");
    assert.equal(view?.sent, 90n * XLM);
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("pays a split unshield once though one of its syncs could not be cross-checked", async () => {
    const world = await createWorld({ limits: SPLIT });
    let down = false;
    const flaky: FetchLike = async (input, init) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      if (down && body?.method === "getEvents") {
        const error = { code: -32603, message: "busy" };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }));
      }
      return world.fetch(input, init);
    };
    const { alice } = await withNotes(world, flaky);
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    });
    down = true;
    assert.equal((await alice.sync()).crossChecked, false);
    down = false;
    const view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
    assert.equal(world.relayer.submissions.length, 2);
  });

  it("sends a dead part again with its own notes", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice, store } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      isError("service_rejected"),
    );
    world.advance(121 * 5);
    world.fill(1);
    let [view] = await alice.continueOperations();
    const [dead, again] = await alice.plans();
    assert.equal(dead?.state, "dead");
    assert.equal(view?.plans.length, 2);
    assert.equal(again?.amount, dead?.amount);
    const kept = (await loadState(new SealedStore(store, storeKeyOf(0)))) as WalletState;
    const [first, second] = kept.plans as [Plan, Plan];
    assert.equal(second.retryOf, first.id);
    assert.deepEqual(
      second.inputs.map((i) => i.pos),
      first.inputs.map((i) => i.pos),
    );
    view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("follows a part whose submission reply was lost, and waits its gap before the next", async () => {
    const world = await createWorld({ limits: SPLIT });
    let cut = false;
    const cutting: FetchLike = async (input, init) => {
      const url = new URL(input);
      if (cut && url.origin === "http://relayer.test" && url.pathname === "/v1/submit") {
        cut = false;
        // The relayer takes the part, but its reply never arrives.
        await world.fetch(input, init);
        throw new TypeError("the connection was lost");
      }
      return world.fetch(input, init);
    };
    const { alice } = await withNotes(world, cutting);
    const destination = world.signer("exchange").publicKey;
    cut = true;
    let named: unknown;
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      (err: unknown) => {
        named = err instanceof CyphrasError ? err.details["planId"] : undefined;
        return isError("service_unavailable")(err);
      },
    );
    const [part] = await alice.plans();
    assert.equal(named, part?.planId);
    let [view] = await alice.continueOperations();
    assert.equal(view?.plans.length, 1);
    assert.equal(view?.sent, 48n * XLM);
    assert.ok((view?.nextAt as number) >= world.clock() + 3_600_000);
    [view] = await alice.continueOperations();
    assert.equal(view?.plans.length, 1);
    view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
    assert.equal(world.relayer.submissions.length, 2);
  });

  it("moves a self-relayed split along without its signer, and sends parts only with it", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    const account = world.signer("my account");
    await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      selfRelay: account,
      split: true,
      confirm: confirmAll,
    });
    world.advance(60);
    // The first part landed: its gap starts without the signer, and nothing more is sent.
    let [view] = await alice.continueOperations();
    assert.equal(view?.sent, 50n * XLM);
    assert.ok((view?.nextAt as number) >= world.clock() + 3_600_000);
    world.advance(7 * 3600);
    [view] = await alice.continueOperations();
    assert.equal(view?.plans.length, 1);
    [view] = await alice.continueOperations(account);
    assert.equal(view?.plans.length, 2);
    world.advance(60);
    [view] = await alice.continueOperations();
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("goes on with a split whose part the user retried by hand once the retry lands", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    const [part] = await alice.plans();
    await alice.retry(part?.planId as string, { maxFee: 2n * XLM, confirm: confirmAll });
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "superseded");
    const view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("blocks a split whose part did not land when its notes were spent elsewhere, until abandoned", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    const [part] = await alice.plans();
    // The same account on another device, which knows nothing of the part, spends its notes.
    const other = await openWallet(world, 0, new MemoryStore());
    await other.sync();
    const bob = await openWallet(world, 1);
    await other.send({ to: bob.generateAddress(), amount: 100n * XLM, maxFee: 2n * XLM });
    world.advance(7 * 3600);
    let [view] = await alice.continueOperations();
    assert.equal((await alice.plans())[0]?.state, "superseded");
    assert.equal(view?.state, "blocked");
    assert.equal(view?.blockedBy, part?.planId);
    assert.equal(owedTo(world, destination), 0n);
    // A blocked operation stays as it is until the caller decides.
    world.advance(7 * 3600);
    assert.equal((await alice.continueOperations())[0]?.state, "blocked");
    assert.equal((await alice.plans()).length, 1);
    const id = view?.operationId as string;
    await assert.rejects(alice.abandonOperation("00".repeat(16)), isError("not_found"));
    view = await alice.abandonOperation(id);
    assert.equal(view.state, "abandoned");
    world.advance(7 * 3600);
    assert.equal((await alice.continueOperations())[0]?.state, "abandoned");
    await assert.rejects(alice.resumeOperation(id), isError("invalid_argument"));
    assert.equal((await alice.plans()).length, 1);
    assert.equal(world.relayer.submissions.length, 1);
  });

  it("resumes a blocked split on the caller's word that its part never paid, with other notes", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice } = await withNotes(world, undefined, [50n * XLM, 60n * XLM, 70n * XLM]);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    const [part] = await alice.plans();
    const other = await openWallet(world, 0, new MemoryStore());
    await other.sync();
    const bob = await openWallet(world, 1);
    await other.send({ to: bob.generateAddress(), amount: 30n * XLM, maxFee: 2n * XLM });
    let [view] = await alice.continueOperations();
    assert.equal(view?.state, "blocked");
    assert.equal(view?.blockedBy, part?.planId);
    const id = view?.operationId as string;
    view = await alice.resumeOperation(id);
    assert.equal(view.state, "active");
    assert.equal(view.blockedBy, undefined);
    assert.equal(view.plans.length, 2);
    await assert.rejects(alice.resumeOperation(id), isError("invalid_argument"));
    view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("goes on with a split once a payment of the wallet spent a dead part's note", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice } = await withNotes(world, undefined, [50n * XLM, 60n * XLM, 70n * XLM]);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      isError("service_rejected"),
    );
    world.advance(3600);
    world.fill(1);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
    // Meanwhile the user pays someone else, and the wallet picks the dead part's free note.
    const bob = await openWallet(world, 1);
    await alice.send({
      to: bob.generateAddress(),
      amount: 30n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    // The payment's leaves are in, though the indexer does not list its spend yet.
    world.indexer.completeTo = world.vault.ledger - 1;
    let [view] = await alice.continueOperations();
    assert.equal((await alice.plans())[0]?.state, "superseded");
    assert.equal(view?.state, "active");
    assert.equal(view?.plans.length, 2);
    world.indexer.completeTo = undefined;
    view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 30n * XLM);
  });

  it("goes on with a split past a payment of the wallet that every RPC provider saw land", async () => {
    const world = await createWorld({ limits: SPLIT });
    const second = "http://rpc2.test";
    const fetch: FetchLike = (input, init) =>
      new URL(input).origin === second ? world.fetch(RPC, init) : world.fetch(input, init);
    const store = new MemoryStore();
    const alice = await openWallet({ ...world, fetch }, 0, store, undefined, {
      secondRpcUrl: second,
    });
    for (const amount of [50n * XLM, 60n * XLM, 70n * XLM]) {
      await alice.shield({ amount, signer: world.signer("alice depositor") });
    }
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    world.advance(3600);
    world.fill(1);
    await alice.sync();
    const bob = await openWallet(world, 1);
    await alice.send({
      to: bob.generateAddress(),
      amount: 30n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    let [view] = await alice.continueOperations();
    assert.equal(view?.state, "active");
    assert.equal(view?.plans.length, 2);
    view = await finish(world, alice);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("blocks a split whose part's note a payment spent that not every RPC provider saw land", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice, store } = await withNotes(world, undefined, [50n * XLM, 60n * XLM, 70n * XLM]);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    world.advance(3600);
    world.fill(1);
    await alice.sync();
    const bob = await openWallet(world, 1);
    await alice.send({
      to: bob.generateAddress(),
      amount: 30n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    // The payment's landing is taken while the wallet reads the vault from one RPC provider.
    await alice.sync();
    const second = "http://rpc2.test";
    const both = await openWallet(
      {
        ...world,
        fetch: (input, init) =>
          new URL(input).origin === second ? world.fetch(RPC, init) : world.fetch(input, init),
      },
      0,
      store,
      undefined,
      { secondRpcUrl: second },
    );
    let [view] = await both.continueOperations();
    assert.equal(view?.state, "blocked");
    assert.equal(view?.plans.length, 1);
    // The caller, who knows the part never paid, goes on.
    view = await both.resumeOperation(view?.operationId as string);
    assert.equal(view.plans.length, 2);
    view = await finish(world, both);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });

  it("blocks a split whose dead part's note was spent elsewhere rather than send it again", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    world.advance(3600);
    world.fill(1);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
    // The same account on another device spends the dead part's note, which the wallet then
    // learns from RPC alone, the indexer being down: no checked event shows whose spend it was.
    const other = await openWallet(world, 0, new MemoryStore());
    await other.sync();
    const bob = await openWallet(world, 1);
    await other.send({ to: bob.generateAddress(), amount: 50n * XLM, maxFee: 2n * XLM });
    world.indexer.down = true;
    const sent = world.relayer.submissions.length;
    const [view] = await alice.continueOperations();
    assert.equal((await alice.plans())[0]?.state, "dead");
    assert.equal(view?.state, "blocked");
    assert.equal(world.relayer.submissions.length, sent);
    assert.equal(owedTo(world, destination), 0n);
  });

  it("blocks a split whose part a payment of the wallet shares notes with that did not land", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice, store } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    });
    await alice.sync();
    // An earlier reading took the part, which landed, for dead; and the wallet holds another
    // payment, which never landed, of the same notes.
    const sealed = new SealedStore(store, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const part = state.plans[0] as Plan;
    Object.assign(part, { state: "dead", evidence: [] });
    state.plans.push({ ...part, id: "ee".repeat(16), operationId: undefined, state: "prepared" });
    await saveState(sealed, state);
    const reopened = await openWallet(world, 0, store);
    world.advance(7 * 3600);
    const [view] = await reopened.continueOperations();
    assert.equal(view?.state, "blocked");
    assert.equal(view?.plans.length, 1);
    assert.equal(owedTo(world, destination), 48n * XLM);
  });

  it("goes on with a blocked split once its part turns out to have landed", async () => {
    const world = await createWorld({ limits: SPLIT });
    const { alice, store } = await withNotes(world);
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    });
    await alice.sync();
    // An earlier reading took the part, which landed, for superseded, and so blocked the split.
    const sealed = new SealedStore(store, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const part = state.plans[0] as Plan;
    Object.assign(part, { state: "superseded", evidence: [] });
    Object.assign(state.operations[0] as object, { state: "blocked", blockedBy: part.id });
    await saveState(sealed, state);
    const reopened = await openWallet(world, 0, store);
    let [view] = await reopened.continueOperations();
    assert.equal(view?.state, "blocked");
    await reopened.rescan();
    [view] = await reopened.continueOperations();
    assert.equal(view?.state, "active");
    assert.equal(view?.sent, 48n * XLM);
    assert.equal(view?.plans.length, 1);
    assert.ok((view?.nextAt as number) >= world.clock() + 3_600_000);
    view = await finish(world, reopened);
    assert.equal(view?.state, "done");
    assert.equal(owedTo(world, destination), 90n * XLM);
  });
});

describe("the exit queue", () => {
  it("queues a payout when the day's window is full and releases it in parts", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 45n * XLM;
    const destination = world.signer("dest").publicKey;
    const warnings: string[] = [];
    const sub = await alice.unshield({
      to: destination,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: (review) => {
        warnings.push(...review.warnings.map((w) => w.code));
        return true;
      },
    });
    assert.ok(warnings.includes("exit_will_queue"));
    assert.ok("planId" in sub);
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    // exit IDs start at 1
    assert.equal(plan?.exitId, 1);
    assert.equal((await alice.balance()).awaitingPayout, 20n * XLM);
    const position = await alice.exitPosition(sub.planId);
    assert.equal(position?.ahead, 0);
    assert.equal(position?.payoutLeft, 20n * XLM);
    assert.equal(position?.feeLeft, 1n * XLM);
    // paid in full by the end of tomorrow at the latest
    assert.equal(position?.paidBy, Number((world.vault.timestamp / 86_400n + 2n) * 86_400n) - 1);

    // What is left of today's window pays part of the payout now.
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.payoutLeft, 15n * XLM);
    assert.equal((await alice.balance()).awaitingPayout, 15n * XLM);

    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.payoutLeft, 0n);
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount),
      [5n * XLM, 15n * XLM],
    );
  });

  it("follows a stranded payout through its claim, requeued at the tail, until release pays it", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const destination = world.signer("closed account").publicKey;
    const sub = await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in sub);
    world.vault.unpayable.add(destination);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "stranded");
    // the relayer's fee was paid at release; only the payout waits
    assert.equal(world.vault.queuedTotal, 10n * XLM);
    assert.equal(plan?.payoutLeft, 10n * XLM);
    assert.deepEqual(plan?.exitParts, [
      { id: 1, payoutLeft: 10n * XLM, feeLeft: 0n, stranded: true },
    ]);
    // A stranded payout has no place in the queue.
    assert.equal(await alice.exitPosition(sub.planId), undefined);
    // A claim that can move no part fails.
    await assert.rejects(
      alice.claimExit(1, world.signer("anyone")),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "transaction_failed" &&
        err.details["vaultError"] === "NothingClaimable",
    );
    world.vault.unpayable.delete(destination);
    // A claim pays nothing: it queues the payout again, at the tail, still owed.
    const claim = await alice.claimExit(1, world.signer("anyone"));
    assert.equal(claim.requeuedAs, 2);
    assert.equal(world.vault.queuedTotal, 10n * XLM);
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination),
      [],
    );
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitId, 1);
    assert.equal(plan?.payoutLeft, 10n * XLM);
    assert.deepEqual(plan?.exitParts, [
      { id: 2, payoutLeft: 10n * XLM, feeLeft: 0n, stranded: false },
    ]);
    assert.equal((await alice.exitPosition(sub.planId))?.exitId, 2);
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.deepEqual(plan?.exitParts, []);
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount),
      [10n * XLM],
    );
  });

  it("requeues only the parts whose party can receive, and leaves the rest stranded", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const destination = world.signer("closed account").publicKey;
    const sub = await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in sub);
    world.vault.unpayable.add(destination);
    world.vault.unpayable.add(world.relayer.feeAddress);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    world.vault.unpayable.delete(destination);
    assert.equal((await alice.claimExit(1, world.signer("anyone"))).requeuedAs, 2);
    await alice.sync();
    const [plan] = await alice.plans();
    // The fee stays stranded and concerns only the relayer: the payout waits in the queue.
    assert.equal(plan?.state, "queued");
    assert.deepEqual(plan?.exitParts, [
      { id: 1, payoutLeft: 0n, feeLeft: 1n * XLM, stranded: true },
      { id: 2, payoutLeft: 10n * XLM, feeLeft: 0n, stranded: false },
    ]);
    assert.equal((await alice.exitPosition(sub.planId))?.exitId, 2);
  });

  it("waits for a window that can pay the first part of a payout that creates its account", async () => {
    const { world, alice } = await funded();
    const day = (): bigint => world.vault.timestamp / 86_400n;
    world.vault.outflowDay = day();
    world.vault.outflow = 50n * XLM;
    const fresh = keypairFor("fresh account").publicKey();
    const sub = await alice.unshield({
      to: fresh,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in sub);
    await alice.sync();
    let position = await alice.exitPosition(sub.planId);
    assert.equal(position?.createsAccount, true);
    assert.equal(position?.paidBy, Number((day() + 2n) * 86_400n) - 1);

    // Less than the new account's minimum balance is left of tomorrow's window: nothing is paid.
    world.advance(86_400);
    world.vault.outflowDay = day();
    world.vault.outflow = 50n * XLM - XLM / 2n;
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.payoutLeft, 20n * XLM);
    assert.equal(world.rpc.accounts.has(fresh), false);

    // A first part that funds the minimum balance creates the account.
    world.vault.outflow = 45n * XLM;
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.payoutLeft, 15n * XLM);
    assert.ok(world.rpc.accounts.has(fresh));
    position = await alice.exitPosition(sub.planId);
    assert.equal(position?.createsAccount, false);
    assert.equal(position?.paidBy, Number((day() + 2n) * 86_400n) - 1);
  });

  it("puts queued payouts in FIFO order behind the ones ahead", async () => {
    const { world, alice } = await funded({ maxDailyOutflow: 30n * XLM, tvlCap: 210n * XLM });
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 30n * XLM;
    const first = await alice.unshield({
      to: world.signer("a").publicKey,
      amount: 25n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    const second = await alice.unshield({
      to: world.signer("b").publicKey,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    assert.ok("planId" in first && "planId" in second);
    const p1 = await alice.exitPosition(first.planId);
    const p2 = await alice.exitPosition(second.planId);
    assert.equal(p1?.ahead, 0);
    assert.equal(p2?.ahead, 1);
    assert.equal(p2?.aheadAmount, 26n * XLM);
    // 26 fits tomorrow's window of 30; the 47 owed up to the second needs a further day
    assert.equal(p2?.paidBy, (p1?.paidBy as number) + 86_400);
  });
});

describe("the exit queue: what the vault refuses", () => {
  const vaultError = (name: string) => (err: unknown) =>
    err instanceof CyphrasError &&
    err.code === "transaction_failed" &&
    err.details["vaultError"] === name;

  it("reports an exit refused because its recipient cannot receive now", async () => {
    const { world, alice } = await funded();
    const destination = world.signer("frozen account").publicKey;
    world.vault.unpayable.add(destination);
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 10n * XLM,
        selfRelay: world.signer("my account"),
        confirm: confirmAll,
      }),
      vaultError("CannotReceive"),
    );
    // Nothing was spent: the plan never landed and may be retried with the same notes.
    const [plan] = await alice.plans();
    assert.equal(plan?.mustRetry, true);
    assert.equal(world.vault.exitTail, 1);
  });

  it("reports a release the vault cannot pay, with the queue left as it is", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    await alice.unshield({
      to: world.signer("dest").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    world.advance(86_400);
    world.vault.vaultCannotPay = true;
    await assert.rejects(alice.releaseExits(world.signer("anyone")), vaultError("VaultCannotPay"));
    assert.equal(world.vault.exitHead, 1);
    world.vault.vaultCannotPay = false;
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });
});

describe("the exit queue: sources", () => {
  // Today's window is full, so the next exit queues.
  function fillWindow(world: Awaited<ReturnType<typeof createWorld>>): void {
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
  }

  it("follows a payout through the vault's RPC events when the indexer is down", async () => {
    const { world, alice } = await funded();
    fillWindow(world);
    const destination = world.signer("closed account").publicKey;
    const sub = await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in sub);
    world.indexer.down = true;
    assert.equal((await alice.sync()).source, "rpc");
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitId, 1);
    // the position comes from the indexer alone
    await assert.rejects(alice.exitPosition(sub.planId), isError("service_unavailable"));
    world.vault.unpayable.add(destination);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "stranded");
    world.vault.unpayable.delete(destination);
    await alice.claimExit(1, world.signer("anyone"));
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.deepEqual(
      plan?.exitParts.map((p) => p.id),
      [2],
    );
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });

  it("follows a payout stranded while RPC no longer covered it, by its exit ID", async () => {
    const { world, alice } = await funded();
    fillWindow(world);
    const destination = world.signer("closed account").publicKey;
    const sub = await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in sub);
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    world.vault.unpayable.add(destination);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    // RPC no longer covers the release, so no event of it reaches the wallet.
    world.rpc.oldestLedger = world.vault.ledger + 1;
    assert.equal((await alice.sync()).crossChecked, false);
    [plan] = await alice.plans();
    assert.equal(plan?.state, "stranded");
    assert.equal(plan?.exitId, 1);
    world.vault.unpayable.delete(destination);
    await alice.claimExit(1, world.signer("anyone"));
    world.rpc.oldestLedger = world.vault.ledger + 1;
    assert.equal((await alice.sync()).crossChecked, false);
    // The indexer links the requeued exit to the stranded one it came from.
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.deepEqual(
      plan?.exitParts.map((p) => p.id),
      [2],
    );
    await alice.releaseExits(world.signer("anyone"));
    world.rpc.oldestLedger = world.vault.ledger + 1;
    assert.equal((await alice.sync()).crossChecked, false);
    assert.equal((await alice.plans())[0]?.state, "settled");
  });

  it("follows a self-relayed unshield's exit through the vault's events", async () => {
    const { world, alice } = await funded();
    fillWindow(world);
    const destination = world.signer("merchant").publicKey;
    const result = await alice.unshield({
      to: destination,
      amount: 25n * XLM,
      selfRelay: world.signer("my account"),
      confirm: confirmAll,
    });
    assert.ok("planId" in result && result.state === "submitted");
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "queued");
    assert.equal((await alice.plans())[0]?.exitId, 1);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount),
      [25n * XLM],
    );
  });

  // A wallet of 100 XLM that reads the vault from a second RPC provider too, whose getEvents
  // fails while `busy` is set, and whose first provider passes its getEvents replies through
  // `rewrite`.
  async function withTwoProviders(rewrite: (events: { topic: string[] }[]) => unknown[]) {
    const world = await createWorld({ limits: SMALL });
    const second = "http://rpc2.test";
    const control = { busy: false, rewriting: false };
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (url.origin === second) {
        if (control.busy && body?.method === "getEvents") {
          const error = { code: -32603, message: "busy" };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }));
        }
        return world.fetch(RPC, init);
      }
      const res = await world.fetch(input, init);
      if (!control.rewriting || url.origin !== RPC || body?.method !== "getEvents") return res;
      const reply = await res.json();
      reply.result.events = rewrite(reply.result.events);
      return new Response(JSON.stringify(reply), { status: 200 });
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    return { world, alice, control };
  }

  it("follows a payout only on the events every RPC provider shows", async () => {
    const { world, alice, control } = await withTwoProviders((events) => events);
    fillWindow(world);
    const sub = await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in sub);
    // The indexer's account of the queue would show the payout too.
    world.indexer.down = true;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "queued");
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    control.busy = true;
    assert.equal((await alice.sync()).crossChecked, false);
    assert.equal((await alice.plans())[0]?.state, "queued");
    control.busy = false;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });

  it("shows an exit the indexer alone gave as unconfirmed, until the events every provider shows confirm it", async () => {
    const { world, alice, control } = await withTwoProviders((events) => events);
    fillWindow(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    control.busy = true;
    assert.equal((await alice.sync()).crossChecked, false);
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitConfirmed, false);
    control.busy = false;
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitConfirmed, true);
  });

  it("refuses a payout's events that the RPC providers show differently", async () => {
    const settled = xdr.ScVal.scvSymbol("settled").toXDR("base64");
    const { world, alice, control } = await withTwoProviders((events) =>
      events.filter((e) => e.topic[0] !== settled),
    );
    fillWindow(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    control.rewriting = true;
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    assert.equal((await alice.plans())[0]?.state, "queued");
  });

  it("follows a payout only on the events of ledgers the sync checked", async () => {
    const world = await createWorld({ limits: SMALL });
    // The indexer keeps no account of the queue, which would show the payout too.
    const noQueue: FetchLike = async (input, init) => {
      const url = new URL(input);
      if (url.origin === INDEXER && url.pathname === "/v1/exits") {
        return new Response("{}", { status: 503 });
      }
      return world.fetch(input, init);
    };
    const alice = await openWallet({ ...world, fetch: noQueue }, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    fillWindow(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "queued");
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    // The indexer is complete only up to the ledger before the release.
    world.indexer.completeTo = world.vault.ledger - 1;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "queued");
    world.indexer.completeTo = undefined;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });

  it("shows an exit the indexer's account alone moved as unconfirmed, until checked events take over", async () => {
    const world = await createWorld({ limits: SMALL });
    let settled = false;
    // While forging, the indexer's account has every queued exit paid in full.
    const forging = rewritingFetch(world, {
      "/v1/exits": (body) => {
        if (!settled) return body;
        const exits = body["exits"] as Record<string, unknown>[];
        return {
          ...body,
          head: body["tail"],
          exits: exits.map(({ position: _p, paid_by: _b, ...e }) => ({
            ...e,
            state: "settled",
            payout_left: "0",
            fee_left: "0",
          })),
        };
      },
    });
    const alice = await openWallet({ ...world, fetch: forging }, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    fillWindow(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitConfirmed, true);
    // The indexer's account reaches a ledger past those the sync checked.
    settled = true;
    world.indexer.completeTo = world.vault.ledger - 1;
    world.fill(1);
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.payoutLeft, 0n);
    assert.equal(plan?.exitConfirmed, false);
    // Once checked events reach that ledger, they decide: the exit still waits in the queue.
    world.indexer.completeTo = undefined;
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.payoutLeft, 10n * XLM);
    assert.equal(plan?.exitConfirmed, true);
  });

  it("counts a split part that waits in the queue as sent", async () => {
    const { world, alice } = await funded();
    await alice.unshield({
      to: world.signer("dest").publicKey,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    });
    let [view] = await alice.continueOperations();
    assert.equal(view?.plans.length, 1);
    world.advance(6 * 3_600 + 1);
    fillWindow(world);
    [view] = await alice.continueOperations();
    assert.equal(view?.plans.length, 2);
    await alice.sync();
    const second = (await alice.plans()).find((p) => p.amount === 42n * XLM);
    assert.equal(second?.state, "queued");
    [view] = await alice.continueOperations();
    assert.equal(view?.state, "done");
    assert.equal(view?.sent, 90n * XLM);
  });
});

describe("an exit the indexer's account alone settled", () => {
  type World = Awaited<ReturnType<typeof createWorld>>;
  const SECOND = "http://rpc2.test";

  // A fetch whose first RPC provider answers getEvents from a start ledger `refusing` picks with
  // the error it gives, and whose indexer has every exit settled while `lying` is set.
  function liar(world: World, refusing: (start: number) => number | undefined) {
    const control = { lying: false };
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      const start = body?.params?.startLedger as number | undefined;
      const code = start === undefined ? undefined : refusing(start);
      if (url.origin === RPC && body?.method === "getEvents" && code !== undefined) {
        const error = { code, message: "refused" };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }));
      }
      const res = await world.fetch(url.origin === SECOND ? RPC : input, init);
      if (!control.lying || url.origin !== INDEXER || url.pathname !== "/v1/exits") return res;
      const queue = (await res.json()) as Record<string, unknown>;
      const exits = (queue["exits"] as Record<string, unknown>[]).map(
        ({ position: _p, paid_by: _b, ...e }) => ({
          ...e,
          state: "settled",
          payout_left: "0",
          fee_left: "0",
        }),
      );
      return new Response(JSON.stringify({ ...queue, head: queue["tail"], exits }));
    };
    return { fetch, control };
  }

  // A wallet with 100 XLM shielded that unshields 10 XLM to an account the vault cannot pay, into
  // a queue the day's outflow keeps it in.
  async function unshielding(world: World, fetch: FetchLike) {
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: SECOND,
    });
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const destination = world.signer("closed account").publicKey;
    await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    world.vault.unpayable.add(destination);
    return alice;
  }

  // One indexer reply that settles every exit, newer than the ledgers its sync checks.
  async function lie(world: World, alice: PrivateWallet, control: { lying: boolean }) {
    control.lying = true;
    world.indexer.completeTo = world.vault.ledger;
    world.fill(1);
    await alice.sync();
    control.lying = false;
    world.indexer.completeTo = undefined;
  }

  it("is moved back by the vault's events of a later strand, when the indexer alone gave the exit", async () => {
    const world = await createWorld({ limits: SMALL });
    let disowned = 0;
    const { fetch, control } = liar(world, (start) => (start <= disowned ? -32600 : undefined));
    const alice = await unshielding(world, fetch);
    // The first provider claims to hold no history up to the landing.
    disowned = world.vault.ledger;
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitConfirmed, false);
    await lie(world, alice, control);
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    for (let i = 0; i < 3; i++) {
      world.advance(3_600);
      world.fill(1);
      await alice.sync();
    }
    [plan] = await alice.plans();
    assert.equal(world.vault.stranded.get(1)?.payout, 10n * XLM);
    assert.equal(plan?.state, "stranded");
    assert.equal(plan?.payoutLeft, 10n * XLM);
  });

  it("is moved back by the vault's events of a later strand, when a gap left a confirmed exit on the indexer's word", async () => {
    const world = await createWorld({ limits: SMALL });
    let busy = { from: Number.POSITIVE_INFINITY, to: 0 };
    const { fetch, control } = liar(world, (start) =>
      start >= busy.from && start <= busy.to ? -32603 : undefined,
    );
    const alice = await unshielding(world, fetch);
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.exitConfirmed, true);
    await lie(world, alice, control);
    // The first provider leaves one sync unchecked, and keeps its recheck busy while the indexer
    // lies; the next sync's events leave a gap in what the exit followed.
    control.lying = true;
    busy = { from: world.vault.ledger, to: world.vault.ledger + 1 };
    world.fill(1);
    await alice.sync();
    control.lying = false;
    world.fill(1);
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.exitConfirmed, false);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    world.fill(1);
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(world.vault.stranded.get(1)?.payout, 10n * XLM);
    assert.equal(plan?.state, "stranded");
    assert.equal(plan?.payoutLeft, 10n * XLM);
  });
});

describe("an indexer that renames the transaction a payment landed in", () => {
  type Entry = { tx_hash: string; ledger: number };
  const renamed = (x: Entry): Entry => ({ ...x, tx_hash: "ab".repeat(32) });

  // A fetch whose indexer relabels the entries of the newest transaction in the replies of `paths`
  // while `renaming` is set, by default naming another transaction for it, and whose RPC answers
  // getEvents with an error while `eventsDown` is set.
  function renamingFetch(
    world: Awaited<ReturnType<typeof createWorld>>,
    paths = ["/v1/leaves", "/v1/nullifiers"],
    relabel = renamed,
  ) {
    const control = {
      renaming: false,
      eventsDown: false,
      fetch: (async (input, init) => {
        const url = new URL(input);
        const body =
          init?.body === undefined || init.body === null
            ? undefined
            : JSON.parse(String(init.body));
        if (control.eventsDown && body?.method === "getEvents") {
          const error = { code: -32603, message: "busy" };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }));
        }
        const res = await world.fetch(input, init);
        if (
          !control.renaming ||
          url.origin !== "http://indexer.test" ||
          !paths.includes(url.pathname)
        ) {
          return res;
        }
        const reply = await res.json();
        const landing = world.vault.leaves.at(-1)?.txHash;
        const rename = (x: Entry) => (x.tx_hash === landing ? relabel(x) : x);
        if (reply.leaves !== undefined) reply.leaves = reply.leaves.map(rename);
        if (reply.nullifiers !== undefined) reply.nullifiers = reply.nullifiers.map(rename);
        return new Response(JSON.stringify(reply), { status: 200 });
      }) as FetchLike,
    };
    return control;
  }

  async function fundedThrough(world: Awaited<ReturnType<typeof createWorld>>, fetch: FetchLike) {
    const alice = await openWallet({ ...world, fetch }, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    return alice;
  }

  it("follows a queued payout's exit once a rescan takes its landing transaction again", async () => {
    const world = await createWorld({ limits: SMALL });
    const control = renamingFetch(world);
    const alice = await fundedThrough(world, control.fetch);
    // Today's window is nearly used up, so the payout waits in the exit queue.
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 45n * XLM;
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 20n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    const exit = [...world.vault.exits.values()][0];
    // The sync that takes the landing cannot be cross-checked.
    control.renaming = true;
    control.eventsDown = true;
    await alice.sync();
    control.renaming = false;
    control.eventsDown = false;
    world.fill(1);
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    await alice.rescan();
    const [plan] = await alice.plans();
    assert.equal(plan?.txHash, exit?.txHash);
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitId, exit?.id);
    assert.equal(plan?.payoutLeft, 20n * XLM);
  });

  it("catches the renamed landing of a payment that left no change", async () => {
    const world = await createWorld();
    // Only the leaves are renamed: no note of the wallet, nor a spend of one, shows the lie.
    const control = renamingFetch(world, ["/v1/leaves"]);
    const alice = await fundedThrough(world, control.fetch);
    // The payout and the fee take the whole note, so no note of the wallet is at its leaves.
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 99n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    const landing = world.vault.leaves.at(-1)?.txHash;
    control.renaming = true;
    control.eventsDown = true;
    await alice.sync();
    control.renaming = false;
    control.eventsDown = false;
    assert.equal((await alice.plans())[0]?.state, "confirmed");
    world.fill(1);
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    await alice.rescan();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.txHash, landing);
  });

  it("catches a forged ledger on the landing of a payment that left no change", async () => {
    const world = await createWorld();
    // The leaves of the landing keep their transaction and are given a later ledger.
    const control = renamingFetch(world, ["/v1/leaves"], (x) => ({ ...x, ledger: x.ledger + 50 }));
    const alice = await fundedThrough(world, control.fetch);
    const destination = world.signer("exchange").publicKey;
    await alice.unshield({
      to: destination,
      amount: 99n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    control.renaming = true;
    control.eventsDown = true;
    await alice.sync();
    control.renaming = false;
    control.eventsDown = false;
    world.fill(1);
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    await alice.rescan();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });
});

describe("following an exit from the vault's events and the indexer's account", () => {
  const TX = "a".repeat(64);
  let order = 0;

  function withUnshield(): { state: WalletState; plan: Plan } {
    const state = emptyState(1);
    const plan: Plan = {
      id: "plan",
      kind: "unshield",
      state: "confirmed",
      createdAt: 0,
      route: { kind: "relayer", url: "http://relayer.test" },
      amount: 10n,
      fee: 1n,
      to: "recipient",
      createsAccount: false,
      inputs: [],
      nullifiers: [1n, 2n],
      commitments: [3n, 4n],
      outputs: [],
      root: 0n,
      builtAt: 1,
      deadline: 100,
      ext: {} as Plan["ext"],
      proof: {} as Plan["proof"],
      notBefore: undefined,
      operationId: undefined,
      retryOf: undefined,
      txHash: TX,
      heldId: undefined,
      ledger: 10,
      evidence: [],
      relayerStatus: undefined,
      exit: undefined,
      error: undefined,
    };
    state.plans.push(plan);
    return { state, plan };
  }

  const at = (ledger: number) => ({
    ledger,
    eventId: `${String(ledger).padStart(12, "0")}-${String(order++).padStart(8, "0")}`,
    txHash: TX,
  });
  const queued = (ledger: number): ExitEvent => ({
    kind: "exit_queued",
    id: 1,
    payout: 10n,
    fee: 1n,
    ...at(ledger),
  });
  const stranded = (ledger: number, feeLeft = 0n): ExitEvent => ({
    kind: "exit_stranded",
    id: 1,
    payoutLeft: 10n,
    feeLeft,
    ...at(ledger),
  });
  const requeued = (ledger: number): ExitEvent => ({
    kind: "exit_requeued",
    id: 1,
    newId: 2,
    payout: 10n,
    fee: 0n,
    ...at(ledger),
  });
  const paidPart = (id: number, ledger: number, payoutLeft: bigint, feeLeft = 0n): ExitEvent => ({
    kind: "exit_paid",
    id,
    payoutLeft,
    feeLeft,
    ...at(ledger),
  });
  const events = (from: number, to: number, list: ExitEvent[]) => ({ from, to, events: list });
  const entry = (
    id: number,
    state: ExitEntry["state"],
    payoutLeft: bigint,
    extra: Partial<ExitEntry> = {},
  ): ExitEntry => ({
    id,
    state,
    position: undefined,
    paidBy: undefined,
    payoutLeft,
    feeLeft: 0n,
    txHash: "b".repeat(64),
    requeuedFrom: undefined,
    requeuedTo: [],
    ...extra,
  });
  const account = (completeTo: number, exits: ExitEntry[]): ExitQueue => ({
    head: 3,
    tail: 3,
    exits,
    completeTo,
  });

  // The plan's payout stranded in exit 1, as the events of ledgers 5 to 30 show.
  function strandedPlan(): { state: WalletState; plan: Plan } {
    const fixture = withUnshield();
    applyExits(fixture.state, [events(5, 30, [queued(10), stranded(20)])], undefined, 30);
    assert.equal(fixture.plan.state, "stranded");
    return fixture;
  }

  it("applies a requeue once, however often its event is seen", () => {
    const { state, plan } = withUnshield();
    // The relayer still cannot receive, so its fee stays stranded and the claim moves the payout.
    const once = [queued(10), stranded(20, 1n), requeued(25)];
    applyExits(state, [events(5, 30, once)], undefined, 30);
    applyExits(state, [events(5, 40, once)], undefined, 40);
    assert.equal(plan.state, "queued");
    assert.deepEqual(plan.exit?.parts, [
      { id: 1, payoutLeft: 0n, feeLeft: 1n, stranded: true },
      { id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false },
    ]);
    applyExits(state, [events(41, 50, [{ kind: "settled", exitId: 2, ...at(45) }])], undefined, 50);
    assert.equal(plan.state, "settled");
  });

  it("takes the indexer's account only when it is newer than the events and no newer than the vault read", () => {
    const { state, plan } = withUnshield();
    applyExits(state, [events(5, 30, [queued(10)])], undefined, 30);
    const paid = (completeTo: number) => account(completeTo, [entry(1, "settled", 0n)]);
    applyExits(state, [], paid(30), 40);
    assert.equal(plan.state, "queued");
    applyExits(state, [], paid(50), 40);
    assert.equal(plan.state, "queued");
    applyExits(state, [], paid(50), 50);
    assert.equal(plan.state, "settled");
  });

  it("follows a requeue in the indexer's account by either of its links", () => {
    for (const exits of [
      [entry(1, "requeued", 0n, { requeuedTo: [2] }), entry(2, "queued", 10n, { position: 0 })],
      [entry(2, "queued", 10n, { position: 0, requeuedFrom: 1 })],
    ]) {
      const { state, plan } = strandedPlan();
      applyExits(state, [], account(40, exits), 40);
      assert.equal(plan.state, "queued");
      assert.deepEqual(shownParts(plan.exit as PlanExit), [
        { id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false },
      ]);
    }
  });

  it("shows the indexer's newer account as unconfirmed, until the vault's events reach its ledger and decide", () => {
    const { state, plan } = withUnshield();
    applyExits(state, [events(5, 30, [queued(10)])], undefined, 30);
    applyExits(state, [], account(50, [entry(1, "settled", 0n)]), 50);
    assert.equal(plan.state, "settled");
    assert.equal(plan.exit?.confirmed, true);
    assert.deepEqual(plan.exit?.account, {
      parts: [{ id: 1, payoutLeft: 0n, feeLeft: 0n, stranded: false }],
      ledger: 50,
    });
    // An account older than the one shown is not taken.
    applyExits(state, [], account(40, [entry(1, "paid_in_part", 6n, { position: 0 })]), 50);
    assert.equal(plan.state, "settled");
    // The events up to the account's ledger have the exit paid in part only.
    applyExits(state, [events(31, 50, [paidPart(1, 45, 6n, 1n)])], undefined, 50);
    assert.equal(plan.state, "queued");
    assert.equal(plan.exit?.account, undefined);
    assert.deepEqual(plan.exit?.parts, [{ id: 1, payoutLeft: 6n, feeLeft: 1n, stranded: false }]);
  });

  it("rests an exit on the indexer's account once the vault's events leave a gap in what it follows", () => {
    const { state, plan } = strandedPlan();
    // Events of no ledger leave no gap.
    applyExits(state, [events(40, 35, [])], undefined, 40);
    assert.equal(plan.exit?.confirmed, true);
    const requeued = [
      entry(1, "requeued", 0n, { requeuedTo: [2] }),
      entry(2, "queued", 10n, { position: 0 }),
    ];
    applyExits(state, [], account(40, requeued), 40);
    // The events from ledger 51 on leave those up to 50 unseen.
    applyExits(state, [events(51, 60, [paidPart(2, 55, 4n)])], undefined, 60);
    assert.equal(plan.state, "queued");
    assert.equal(plan.exit?.confirmed, false);
    assert.deepEqual(shownParts(plan.exit as PlanExit), [
      { id: 2, payoutLeft: 4n, feeLeft: 0n, stranded: false },
    ]);
  });

  // The indexer's account of the plan's own exit 1 alone.
  const mine = (completeTo: number, entryState: ExitEntry["state"], payoutLeft: bigint) =>
    account(completeTo, [
      entry(1, entryState, payoutLeft, {
        txHash: TX,
        position: entryState === "settled" ? undefined : 0,
      }),
    ]);

  it("gives way to the vault's events where the indexer's account alone gave the plan its exit", () => {
    let { state, plan } = withUnshield();
    applyExits(state, [], mine(40, "queued", 10n), 40);
    assert.equal(plan.state, "queued");
    assert.equal(plan.exit?.confirmed, false);
    applyExits(state, [], mine(45, "settled", 0n), 45);
    assert.equal(plan.state, "settled");
    // Events of older ledgers show the exit queued: the exit follows them, and the account, newer
    // than they are, stands until they reach it.
    applyExits(state, [events(5, 30, [queued(10)])], undefined, 45);
    assert.equal(plan.exit?.confirmed, true);
    assert.equal(plan.state, "settled");
    applyExits(state, [events(31, 50, [])], undefined, 50);
    assert.equal(plan.state, "queued");
    assert.equal(plan.exit?.account, undefined);
    // The events show the transaction paid at once: the exit the account gave it never was.
    ({ state, plan } = withUnshield());
    applyExits(state, [], mine(30, "queued", 10n), 30);
    const once: ExitEvent = { kind: "settled", exitId: undefined, ...at(10) };
    applyExits(state, [events(5, 30, [once])], mine(30, "queued", 10n), 30);
    assert.equal(plan.state, "settled");
    assert.equal(plan.exit, undefined);
  });

  it("keeps an exit the indexer's account settles among the plan's, for the vault's events to rebuild", () => {
    const { state, plan } = withUnshield();
    applyExits(state, [], mine(40, "queued", 10n), 40);
    // An exit the account settles owes nothing, whatever it says is left.
    applyExits(state, [], mine(45, "settled", 5n), 45);
    assert.equal(plan.state, "settled");
    assert.deepEqual(plan.exit?.parts, [{ id: 1, payoutLeft: 0n, feeLeft: 0n, stranded: false }]);
    // The events show it claimed as exit 2, though not the strand before: it owes nothing more.
    const claimed: ExitEvent = {
      kind: "exit_requeued",
      id: 1,
      newId: 2,
      payout: 10n,
      fee: 1n,
      ...at(50),
    };
    applyExits(state, [events(46, 55, [claimed])], undefined, 55);
    assert.equal(plan.state, "queued");
    assert.deepEqual(plan.exit?.parts, [
      { id: 1, payoutLeft: 0n, feeLeft: 0n, stranded: false },
      { id: 2, payoutLeft: 10n, feeLeft: 1n, stranded: false },
    ]);
    // An account that pays exit 2 in part, and so does not contradict what the wallet knows.
    const paidInPart = [
      entry(1, "requeued", 0n, { requeuedTo: [2] }),
      entry(2, "paid_in_part", 4n, { position: 0, requeuedFrom: 1 }),
    ];
    applyExits(state, [], account(60, paidInPart), 60);
    assert.deepEqual(shownParts(plan.exit as PlanExit), [
      { id: 2, payoutLeft: 4n, feeLeft: 0n, stranded: false },
    ]);
  });

  it("rebuilds an exit the indexer's account no longer lists, or already listed, from the vault's events", () => {
    let { state, plan } = withUnshield();
    applyExits(state, [], mine(40, "queued", 10n), 40);
    // Exit 1 no longer listed, and a claim queued from it: it owes nothing, until an event says.
    applyExits(
      state,
      [],
      account(45, [entry(2, "queued", 10n, { position: 0, requeuedFrom: 1 })]),
      45,
    );
    applyExits(state, [events(46, 55, [stranded(50, 1n)])], undefined, 55);
    assert.deepEqual(shownParts(plan.exit as PlanExit), [
      { id: 1, payoutLeft: 10n, feeLeft: 1n, stranded: true },
      { id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false },
    ]);
    // Exit 2 listed before the event that queues it: the event gives the plan one exit 2.
    ({ state, plan } = withUnshield());
    applyExits(state, [], mine(40, "queued", 10n), 40);
    const claimed = [
      entry(1, "requeued", 0n, { txHash: TX, requeuedTo: [2] }),
      entry(2, "queued", 10n, { position: 0, requeuedFrom: 1 }),
    ];
    applyExits(state, [], account(45, claimed), 45);
    applyExits(state, [events(46, 55, [requeued(50)])], undefined, 55);
    assert.deepEqual(shownParts(plan.exit as PlanExit), [
      { id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false },
    ]);
  });

  it("keeps an exit the vault's events gave the plan when it falls back on an account that leaves it out", () => {
    const { state, plan } = strandedPlan();
    // The account has exit 1 claimed, though it names no exit the claim queued.
    applyExits(state, [], account(50, [entry(1, "requeued", 0n)]), 50);
    assert.equal(plan.state, "settled");
    // The events up to ledger 40 queue the claimed payout as exit 2; then a gap.
    applyExits(state, [events(31, 40, [requeued(35)])], undefined, 50);
    applyExits(state, [events(61, 70, [paidPart(2, 65, 4n)])], undefined, 70);
    assert.equal(plan.exit?.confirmed, false);
    assert.equal(plan.state, "queued");
    assert.deepEqual(shownParts(plan.exit as PlanExit), [
      { id: 2, payoutLeft: 4n, feeLeft: 0n, stranded: false },
    ]);
  });

  it("takes no account that contradicts what the wallet knows of the exit", () => {
    for (const exits of [
      // a stranded exit owing more than it did
      [entry(1, "stranded", 12n)],
      // a stranded exit back in the queue, or paid from it
      [entry(1, "queued", 10n, { position: 0 })],
      [entry(1, "settled", 0n)],
      // a requeue that queues more than the stranded exit owed
      [entry(1, "requeued", 0n), entry(2, "queued", 15n, { position: 0, requeuedFrom: 1 })],
    ]) {
      const { state, plan } = strandedPlan();
      applyExits(state, [], account(40, exits), 40);
      assert.equal(plan.state, "stranded");
      assert.deepEqual(shownParts(plan.exit as PlanExit), [
        { id: 1, payoutLeft: 10n, feeLeft: 0n, stranded: true },
      ]);
    }
  });
});

describe("exits that other exits race in the same ledger", () => {
  type World = Awaited<ReturnType<typeof createWorld>>;

  // Other wallets' exits, each its own transaction, applied before this wallet's next one is.
  function othersFirst(world: World, count: number): () => void {
    return () => {
      for (let i = 0; i < count; i++) {
        world.rpc.run(String(i).padStart(64, "e"), () =>
          world.vault.queueOther(world.signer(`other ${i}`).publicKey, 1n * XLM),
        );
      }
    };
  }

  // The vault calls this wallet sent, by function.
  const sentCalls = (world: World, fn: string): number =>
    world.rpc.sent.filter(
      (tx) =>
        tx.operations[0]?.type === "invokeHostFunction" &&
        tx.operations[0].func.invokeContract().functionName().toString() === fn,
    ).length;

  async function selfRelayed(world: World, alice: PrivateWallet, amount = 10n * XLM) {
    return alice.unshield({
      to: world.signer("merchant").publicKey,
      amount,
      selfRelay: world.signer("my account"),
      confirm: confirmAll,
    });
  }

  it("lands an exit queued behind exits other transactions queued at the tail first", async () => {
    const { world, alice } = await funded();
    world.rpc.enforceFootprint = true;
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    world.rpc.beforeApply = othersFirst(world, 4);
    await selfRelayed(world, alice);
    assert.equal(sentCalls(world, "transact"), 1);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitId, 5);
  });

  it("lands an exit that queues though its simulation paid it at once, and the other way round", async () => {
    const { world, alice } = await funded();
    world.rpc.enforceFootprint = true;
    world.rpc.beforeApply = othersFirst(world, 1);
    await selfRelayed(world, alice);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "queued");
    // A release pays the queue before the next exit applies, which its simulation saw queue.
    world.advance(86_400);
    world.rpc.beforeApply = () => world.rpc.run("ab".repeat(32), () => world.vault.release(10));
    await selfRelayed(world, alice, 5n * XLM);
    assert.equal(sentCalls(world, "transact"), 2);
    await alice.sync();
    const states = (await alice.plans()).map((p) => [p.amount, p.state]);
    assert.deepEqual(states, [
      [10n * XLM, "settled"],
      [5n * XLM, "settled"],
    ]);
  });

  it("sends the same proof again after a fresh simulation when the tail moved past its footprint", async () => {
    const { world, alice } = await funded();
    world.rpc.enforceFootprint = true;
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    world.rpc.beforeApply = othersFirst(world, 5);
    await selfRelayed(world, alice);
    assert.equal(sentCalls(world, "transact"), 2);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitId, 6);
  });

  it("gives up after five attempts that fail on the host's storage, and leaves the payment to the chain", async () => {
    const { world, alice } = await funded();
    world.rpc.enforceFootprint = true;
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const always = (): void => {
      othersFirst(world, 5)();
      world.rpc.beforeApply = always;
    };
    world.rpc.beforeApply = always;
    await assert.rejects(selfRelayed(world, alice), isError("transaction_failed"));
    world.rpc.beforeApply = undefined;
    assert.equal(sentCalls(world, "transact"), 5);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.mustRetry, true);
  });

  // A getTransaction reply of the second provider, as JSON.
  type Reply = { id: number; result: Record<string, unknown> };
  const notFound = (reply: Reply): Reply => ({
    ...reply,
    result: { status: "NOT_FOUND", latestLedger: reply.result["latestLedger"] },
  });

  // A wallet whose self-relayed exit fails on the host's storage on the first provider, while
  // `answer` gives the second provider's reply to the failed transaction's nth getTransaction, from
  // the reply as it is.
  async function conflictedBehind(
    answer: (reply: Reply, nth: number) => unknown,
    options: Partial<OpenOptions> = {},
  ) {
    const second = "http://rpc2.test";
    const world = await createWorld({ limits: SMALL });
    let asked = 0;
    const fetch: FetchLike = async (input, init) => {
      if (new URL(input).origin !== second) return world.fetch(input, init);
      const res = await world.fetch(RPC, init);
      const body = JSON.parse(String(init?.body));
      if (body.method !== "getTransaction") return res;
      const reply = await res.json();
      if (reply.result?.status !== "FAILED") return new Response(JSON.stringify(reply));
      return new Response(JSON.stringify(answer(reply, ++asked)));
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
      ...options,
    });
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    world.rpc.conflictNext = 1;
    return { world, landing: () => selfRelayed(world, alice), asked: () => asked };
  }

  it("sends a call on the exit queue again only once a second RPC provider reports its failure on the host's storage too", async () => {
    const busy = (reply: Reply) => ({
      jsonrpc: "2.0",
      id: reply.id,
      error: { code: -32603, message: "busy" },
    });
    const withDiagnostics = (reply: Reply, events: string[] | undefined): Reply => ({
      ...reply,
      result: { ...reply.result, diagnosticEventsXdr: events },
    });
    const contractError = diagnostic(xdr.ScError.sceContract(121));
    // The failure as it is, at once or after the second provider first answers that it does not
    // hold it yet or is busy; or the failure without diagnostic events, with another error, or
    // never the transaction, each with the reason the call goes no further.
    const cases: [string, (reply: Reply, nth: number) => unknown, string | undefined][] = [
      ["the failure", (r) => r, undefined],
      ["the failure, late", (r, n) => (n <= 3 ? notFound(r) : r), undefined],
      ["the failure, once not busy", (r, n) => (n <= 2 ? busy(r) : r), undefined],
      ["no diagnostic events", (r) => withDiagnostics(r, undefined), "no_diagnostics"],
      ["another error", (r) => withDiagnostics(r, [contractError]), "other_outcome"],
      ["no transaction", notFound, "no_answer"],
    ];
    for (const [shows, answer, why] of cases) {
      const { world, landing } = await conflictedBehind(answer);
      if (why === undefined) {
        await landing();
        assert.equal(sentCalls(world, "transact"), 2, shows);
      } else {
        await assert.rejects(
          landing(),
          (err: unknown) =>
            err instanceof CyphrasError &&
            err.code === "transaction_failed" &&
            err.details["secondProvider"] === why,
        );
        assert.equal(sentCalls(world, "transact"), 1, shows);
      }
    }
  });

  it("asks a second RPC provider that does not hold the failed transaction again at an interval, and for half a minute at most", async () => {
    // Each wait passes a second of the clock.
    const slept: number[] = [];
    let world: World | undefined;
    const steady = await conflictedBehind(notFound, {
      sleep: async (ms) => {
        slept.push(ms);
        world?.advance(1);
      },
    });
    world = steady.world;
    slept.length = 0;
    await assert.rejects(steady.landing(), isError("transaction_failed"));
    assert.equal(steady.asked(), 20);
    assert.deepEqual(
      slept,
      Array.from({ length: 19 }, () => 1_500),
    );
    // A provider that takes ten seconds over each answer is asked for no longer than the window.
    const slow = await conflictedBehind((reply) => {
      world?.advance(10);
      return notFound(reply);
    });
    world = slow.world;
    await assert.rejects(slow.landing(), isError("transaction_failed"));
    assert.equal(slow.asked(), 3);
  });

  it("releases again after a failure on the host's storage, and goes no further after any other", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    await selfRelayed(world, alice);
    world.advance(86_400);
    world.rpc.failNext = 1;
    await assert.rejects(alice.releaseExits(world.signer("anyone")), isError("transaction_failed"));
    assert.equal(sentCalls(world, "release"), 1);
    // whether the RPC returns the failure's diagnostic events apart or in its meta
    world.rpc.diagnosticsInMeta = true;
    world.rpc.conflictNext = 1;
    await alice.releaseExits(world.signer("anyone"));
    assert.equal(sentCalls(world, "release"), 3);
    world.rpc.diagnosticsInMeta = false;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    // A deposit that fails on chain goes no further either.
    world.rpc.conflictNext = 1;
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: world.signer("alice depositor") }),
      isError("transaction_failed"),
    );
    assert.equal(sentCalls(world, "shield"), 2);
  });

  // A key of the vault's storage, or of the asset contract's, and of an account.
  const dataKey = (contract: string, ...key: xdr.ScVal[]): xdr.LedgerKey =>
    xdr.LedgerKey.contractData(
      new xdr.LedgerKeyContractData({
        contract: new Address(contract).toScAddress(),
        key: xdr.ScVal.scvVec(key),
        durability: xdr.ContractDataDurability.persistent(),
      }),
    );
  const exitAt = (world: World, id: bigint, name = "Exit"): xdr.LedgerKey =>
    dataKey(world.vault.address, xdr.ScVal.scvSymbol(name), xdr.ScVal.scvU64(new xdr.Uint64(id)));
  const accountOf = (address: string): xdr.LedgerKey =>
    xdr.LedgerKey.account(
      new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(address).xdrAccountId() }),
    );
  const ids = (keys: readonly xdr.LedgerKey[] | undefined): string[] =>
    (keys ?? []).map((k) => k.toXDR("base64"));
  const lastData = (world: World) =>
    world.rpc.sent[world.rpc.sent.length - 1]?.toEnvelope().v1().tx().ext().sorobanData();

  it("gives a self-relayed exit the room the relayer gives its own, in the same order", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const merchant = world.signer("merchant").publicKey;
    const balance = dataKey(
      world.deployment.asset.contract,
      xdr.ScVal.scvSymbol("Balance"),
      new Address(world.vault.address).toScVal(),
    );
    // The simulation queued the exit and only read the merchant's account.
    world.rpc.simulated = {
      readOnly: [accountOf(merchant)],
      readWrite: [exitAt(world, 1n)],
      instructions: 4_000_000,
      readBytes: 300,
      writeBytes: 300,
      fee: 1_000,
    };
    await selfRelayed(world, alice);
    const resources = lastData(world)?.resources();
    // The vault's balance and the exits after the tail are added, and the merchant's account,
    // which only paying at once writes, moves from the read entries after them.
    assert.deepEqual(
      ids(resources?.footprint().readWrite()),
      ids([
        exitAt(world, 1n),
        balance,
        exitAt(world, 2n),
        exitAt(world, 3n),
        exitAt(world, 4n),
        exitAt(world, 5n),
        accountOf(merchant),
      ]),
    );
    assert.deepEqual(ids(resources?.footprint().readOnly()), []);
    assert.equal(resources?.instructions(), 5_000_000);
    // an exit entry and the vault's balance entry, and room for the merchant's account to grow
    assert.equal(resources?.diskReadBytes(), 300 + 2048);
    assert.equal(resources?.writeBytes(), 300 + 400 + 256 + 2048);
  });

  it("pads a call as the relayer's engine does, to the stroop, within the network's limits and the fee cap", async () => {
    const world = await createWorld({ limits: SMALL });
    const payee = world.signer("payee").publicKey;
    const issuer = world.signer("issuer").publicKey;
    const vault = world.vault.address;
    const exit = exitAt(world, 7n);
    const next = exitAt(world, 8n);
    const account = accountOf(payee);
    const fresh = accountOf(world.signer("newcomer").publicKey);
    const trustline = xdr.LedgerKey.trustline(
      new xdr.LedgerKeyTrustLine({
        accountId: Keypair.fromPublicKey(payee).xdrAccountId(),
        asset: new Asset("USDC", issuer).toTrustLineXDRObject(),
      }),
    );
    const instance = xdr.LedgerKey.contractData(
      new xdr.LedgerKeyContractData({
        contract: new Address(vault).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent(),
      }),
    );
    const balance = dataKey(vault, xdr.ScVal.scvSymbol("Balance"), new Address(vault).toScVal());
    world.rpc.simulated = {
      readOnly: [account, trustline, instance],
      readWrite: [exit],
      instructions: 1_000_000,
      readBytes: 500,
      writeBytes: 300,
      fee: 100_000,
    };
    const extra: Extra = {
      readWrite: [exit, next, account, balance, fresh],
      instructions: 1_000_000,
      writeBytes: 656,
      newBytes: 656,
      rentLedgers: 519_120,
      eventBytes: 512,
    };
    const fees: bigint[] = [];
    const anyone = world.signer("anyone");
    const signer: TransactionSigner = {
      publicKey: anyone.publicKey,
      signTransaction: (x, p) => anyone.signTransaction(x, p),
      confirmFee: (fee) => {
        fees.push(fee.resource);
        return true;
      },
    };
    const context = {
      rpc: new SorobanRpc(RPC, world.fetch),
      second: undefined,
      networkPassphrase: world.deployment.networkPassphrase,
      vault,
      feeCaps: DEFAULT_NETWORK_FEE_CAPS,
      now: () => Date.now(),
      sleep: async () => {},
    };
    const call = {
      fn: "release",
      args: [xdr.ScVal.scvU32(1)],
      transfers: [],
      extend: async () => extra,
    };
    await invokeVault(context, signer, call);
    const resources = lastData(world)?.resources();
    assert.deepEqual(
      ids(resources?.footprint().readWrite()),
      ids([exit, next, balance, fresh, account]),
    );
    assert.deepEqual(ids(resources?.footprint().readOnly()), ids([trustline, instance]));
    assert.equal(resources?.instructions(), 2_000_000);
    assert.equal(resources?.writeBytes(), 300 + 656 + 2 * 2048);
    assert.equal(resources?.diskReadBytes(), 500 + 3 * 2048);
    // The Go engine's figures on the public network's settings: the simulated 100,000; 2,682 and
    // 3,500 for the bytes of the three accounts and trustlines; and the other path's 1,112,211:
    // four entries written more, one more read from disk, a million instructions, 656 bytes
    // written, 232 bytes of keys sent, the rent of 656 new bytes for the network's least TTL of a
    // new persistent entry with its TTL entry, and 512 bytes of events.
    const other = 4 * 2_500 + 1_563 + 700 + (817 - 257) + 92 + 920 + 1_093_334 + 2_500 + 42 + 2_500;
    assert.equal(fees[0], BigInt(100_000 + 2_682 + 3_500 + other));
    // The network's limits on written entries, on entries and on entries read from disk stop the
    // additions in their order.
    for (const [limit, value, written] of [
      ["maxWriteEntries", 3, [exit, next, account]],
      ["maxFootprintEntries", 5, [exit, next, account]],
      ["maxDiskReadEntries", 2, [exit, next, balance, account]],
    ] as const) {
      world.rpc[limit] = value;
      await invokeVault(context, signer, call);
      world.rpc[limit] = 200;
      assert.deepEqual(ids(lastData(world)?.resources().footprint().readWrite()), ids(written));
    }
    // The cap bounds the fee with its padding.
    const capped = { ...context, feeCaps: { inclusion: 100_000n, resource: 1_000_000n } };
    await assert.rejects(invokeVault(capped, signer, call), isError("fee_above_cap"));
  });

  it("leaves out a key a network limit has no room for and goes on, as the relayer's engine does, to the stroop", async () => {
    const world = await createWorld({ limits: SMALL });
    const vault = world.vault.address;
    const [first, second, recipient] = [1, 2, 3].map((i) =>
      accountOf(world.signer(`holder ${i}`).publicKey),
    ) as [xdr.LedgerKey, xdr.LedgerKey, xdr.LedgerKey];
    const instance = xdr.LedgerKey.contractData(
      new xdr.LedgerKeyContractData({
        contract: new Address(vault).toScAddress(),
        key: xdr.ScVal.scvLedgerKeyContractInstance(),
        durability: xdr.ContractDataDurability.persistent(),
      }),
    );
    const balance = dataKey(vault, xdr.ScVal.scvSymbol("Balance"), new Address(vault).toScVal());
    const room = (...readWrite: xdr.LedgerKey[]): Extra => ({
      readWrite,
      instructions: 1_000_000,
      writeBytes: 656,
      newBytes: 656,
      rentLedgers: 519_120,
      eventBytes: 512,
    });
    const simulated = (readOnly: xdr.LedgerKey[], readWrite: xdr.LedgerKey[]) => ({
      readOnly,
      readWrite,
      instructions: 1_000_000,
      readBytes: 500,
      writeBytes: 300,
      fee: 100_000,
    });
    const fees: bigint[] = [];
    const anyone = world.signer("anyone");
    const signer: TransactionSigner = {
      publicKey: anyone.publicKey,
      signTransaction: (x, p) => anyone.signTransaction(x, p),
      confirmFee: (fee) => {
        fees.push(fee.resource);
        return true;
      },
    };
    const context = {
      rpc: new SorobanRpc(RPC, world.fetch),
      second: undefined,
      networkPassphrase: world.deployment.networkPassphrase,
      vault,
      feeCaps: DEFAULT_NETWORK_FEE_CAPS,
      now: () => Date.now(),
      sleep: async () => {},
    };
    const send = (extra: Extra) =>
      invokeVault(context, signer, {
        fn: "release",
        args: [xdr.ScVal.scvU32(1)],
        transfers: [],
        extend: async () => extra,
      });
    // The footprint already reads as many entries from disk as the network allows: the recipient's
    // account is left out, and both exits go in.
    world.rpc.maxDiskReadEntries = 2;
    world.rpc.simulated = simulated([first, second], []);
    await send(room(recipient, exitAt(world, 5n), exitAt(world, 6n)));
    let resources = lastData(world)?.resources();
    assert.deepEqual(
      ids(resources?.footprint().readWrite()),
      ids([exitAt(world, 5n), exitAt(world, 6n)]),
    );
    assert.deepEqual(ids(resources?.footprint().readOnly()), ids([first, second]));
    assert.equal(resources?.instructions(), 2_000_000);
    assert.equal(resources?.diskReadBytes(), 4_596);
    assert.equal(resources?.writeBytes(), 956);
    // The Go engine's resource fee for this footprint: 100,000 simulated, 1,105,335 for the room it
    // adds and 1,788 for the accounts' room to grow.
    assert.equal(fees[0], 1_207_123n);
    // A full footprint takes no new entry, but still moves a later one it only read to the written
    // ones.
    world.rpc.maxDiskReadEntries = 200;
    world.rpc.maxFootprintEntries = 3;
    world.rpc.simulated = simulated([instance, first], [exitAt(world, 5n)]);
    await send(room(balance, first));
    resources = lastData(world)?.resources();
    assert.deepEqual(ids(resources?.footprint().readWrite()), ids([exitAt(world, 5n), first]));
    assert.deepEqual(ids(resources?.footprint().readOnly()), ids([instance]));
    assert.equal(resources?.diskReadBytes(), 2_548);
    assert.equal(resources?.writeBytes(), 3_004);
    // 100,000 simulated, 1,102,136 for the room and 2,644 for the account's room to grow
    assert.equal(fees[1], 1_204_780n);
  });

  it("sends a relayed payment again when its relayer reports a failure on the host's storage", async () => {
    const { world, alice } = await funded();
    world.relayer.conflictNext = 1;
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    assert.equal(world.relayer.submissions.length, 2);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(world.relayer.submissions.length, 2);
    // A payment the wallet cannot yet tell the fate of past its deadline is not sent again.
    world.relayer.conflictNext = 1;
    const built = world.vault.ledger;
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 5n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    world.advance(121 * 5);
    world.indexer.leafLimit = world.vault.leaves.length;
    world.indexer.completeTo = built + 100;
    world.fill(2);
    await alice.sync();
    assert.equal((await alice.plans())[1]?.needsUserDecision, true);
    assert.equal(world.relayer.submissions.length, 3);
  });

  it("sends a relayed payment no further when its relayer reports any other failure", async () => {
    const { world, alice } = await funded();
    world.relayer.failNext = 1;
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    await alice.sync();
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(world.relayer.submissions.length, 1);
  });

  it("gives a transact that pays only a fee its room, and one that pays nothing none, from the tail it queued at", async () => {
    const vault = StrKey.encodeContract(Buffer.alloc(32, 9));
    const token = StrKey.encodeContract(Buffer.alloc(32, 7));
    const relayer = keypairFor("relayer").publicKey();
    // The vault's tail now is 3.
    const core = {
      deployment: { vault, asset: { contract: token, name: "native" } },
      services: { vault: { instance: async () => ({ status: { exitTail: 3n } }) } },
    } as unknown as Core;
    const exit = (id: bigint) =>
      dataKey(vault, xdr.ScVal.scvSymbol("Exit"), xdr.ScVal.scvU64(new xdr.Uint64(id)));
    const balance = dataKey(token, xdr.ScVal.scvSymbol("Balance"), new Address(vault).toScVal());
    const footprint = (readWrite: xdr.LedgerKey[]) =>
      new xdr.LedgerFootprint({ readOnly: [], readWrite });
    const fee = { extAmount: 0n, fee: 5n, recipient: relayer, relayer };
    const room = await transactRoom(core, fee)(footprint([]));
    assert.deepEqual(
      ids(room.readWrite),
      ids([balance, accountOf(relayer), exit(3n), exit(4n), exit(5n), exit(6n), exit(7n)]),
    );
    assert.equal(room.writeBytes, 400 + 256);
    // A simulation that queued its exit at 5 names the tail, whatever the vault's is now.
    const queued = await transactRoom(core, fee)(footprint([exit(5n)]));
    assert.deepEqual(ids(queued.readWrite.slice(2)), ids([5n, 6n, 7n, 8n, 9n].map(exit)));
    const nothing = await transactRoom(core, { ...fee, fee: 0n })(footprint([]));
    assert.deepEqual(nothing.readWrite, []);
  });

  it("names each payee's pay entry and the tail a simulation queued at, as the relayer does", () => {
    const token = StrKey.encodeContract(Buffer.alloc(32, 7));
    const vault = StrKey.encodeContract(Buffer.alloc(32, 9));
    const holder = keypairFor("payee").publicKey();
    const issuer = keypairFor("issuer").publicKey();
    const muxed = new MuxedAccount(new Account(holder, "0"), "7").accountId();
    const contract = StrKey.encodeContract(Buffer.alloc(32, 5));
    const usdc = `USDC:${issuer}`;
    const trustline = xdr.LedgerKey.trustline(
      new xdr.LedgerKeyTrustLine({
        accountId: Keypair.fromPublicKey(holder).xdrAccountId(),
        asset: new Asset("USDC", issuer).toTrustLineXDRObject(),
      }),
    );
    const balance = dataKey(token, xdr.ScVal.scvSymbol("Balance"), new Address(contract).toScVal());
    assert.deepEqual(ids(payKeys(token, "native", holder)), ids([accountOf(holder)]));
    assert.deepEqual(ids(payKeys(token, "native", muxed)), ids([accountOf(holder)]));
    assert.deepEqual(ids(payKeys(token, usdc, muxed)), ids([trustline]));
    assert.deepEqual(payKeys(token, usdc, issuer), []);
    assert.deepEqual(ids(payKeys(token, usdc, contract)), ids([balance]));
    const exit = (id: bigint, of = vault) =>
      dataKey(of, xdr.ScVal.scvSymbol("Exit"), xdr.ScVal.scvU64(new xdr.Uint64(id)));
    const footprint = (readWrite: xdr.LedgerKey[]) =>
      new xdr.LedgerFootprint({ readOnly: [exit(9n)], readWrite });
    assert.equal(queuedExit(vault, footprint([exit(3n), exit(8n, token), exit(5n), balance])), 5n);
    assert.equal(queuedExit(vault, footprint([balance])), undefined);
  });

  it("lands a claim whose exit other transactions moved the tail of", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const destination = world.signer("closed account").publicKey;
    await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    world.vault.unpayable.add(destination);
    world.advance(86_400);
    await alice.releaseExits(world.signer("anyone"));
    world.vault.unpayable.delete(destination);
    world.rpc.enforceFootprint = true;
    world.rpc.beforeApply = othersFirst(world, 2);
    const claim = await alice.claimExit(1, world.signer("anyone"));
    assert.equal(claim.requeuedAs, 4);
    assert.equal(sentCalls(world, "claim"), 1);
  });

  it("gives a release the stranded entries of its exits and the entries of the exits after them", async () => {
    const { world, alice } = await funded();
    const parties = [0, 1, 2].map((i) => world.signer(`other ${i}`).publicKey);
    for (const party of parties) world.vault.queueOther(party, 1n * XLM);
    await alice.releaseExits(world.signer("anyone"), 1);
    assert.deepEqual(
      ids(lastData(world)?.resources().footprint().readWrite()),
      ids([
        exitAt(world, 1n, "Stranded"),
        exitAt(world, 2n),
        exitAt(world, 2n, "Stranded"),
        accountOf(parties[1] as string),
        exitAt(world, 3n),
        exitAt(world, 3n, "Stranded"),
        accountOf(parties[2] as string),
      ]),
    );
  });
});
