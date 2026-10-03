import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import type { ExitEntry, ExitQueue } from "../../src/net/indexer.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { applyExits } from "../../src/wallet/exits.ts";
import type { ExitEvent } from "../../src/wallet/sources.ts";
import {
  type Plan,
  type WalletState,
  emptyState,
  loadState,
  saveState,
} from "../../src/wallet/state.ts";
import type { OperationView, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, createWorld } from "../support/network.ts";
import { keypairFor } from "../support/rpc.ts";
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
    applyExits(fixture.state, events(5, 30, [queued(10), stranded(20)]), undefined, 30);
    assert.equal(fixture.plan.state, "stranded");
    return fixture;
  }

  it("applies a requeue once, however often its event is seen", () => {
    const { state, plan } = withUnshield();
    // The relayer still cannot receive, so its fee stays stranded and the claim moves the payout.
    const once = [queued(10), stranded(20, 1n), requeued(25)];
    applyExits(state, events(5, 30, once), undefined, 30);
    applyExits(state, events(5, 40, once), undefined, 40);
    assert.equal(plan.state, "queued");
    assert.deepEqual(plan.exit?.parts, [
      { id: 1, payoutLeft: 0n, feeLeft: 1n, stranded: true },
      { id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false },
    ]);
    applyExits(state, events(41, 50, [{ kind: "settled", exitId: 2, ...at(45) }]), undefined, 50);
    assert.equal(plan.state, "settled");
  });

  it("takes the indexer's account only when it is newer than the events and no newer than the vault read", () => {
    const { state, plan } = withUnshield();
    applyExits(state, events(5, 30, [queued(10)]), undefined, 30);
    const paid = (completeTo: number) => account(completeTo, [entry(1, "settled", 0n)]);
    applyExits(state, undefined, paid(30), 40);
    assert.equal(plan.state, "queued");
    applyExits(state, undefined, paid(50), 40);
    assert.equal(plan.state, "queued");
    applyExits(state, undefined, paid(50), 50);
    assert.equal(plan.state, "settled");
  });

  it("follows a requeue in the indexer's account by either of its links", () => {
    for (const exits of [
      [entry(1, "requeued", 0n, { requeuedTo: [2] }), entry(2, "queued", 10n, { position: 0 })],
      [entry(2, "queued", 10n, { position: 0, requeuedFrom: 1 })],
    ]) {
      const { state, plan } = strandedPlan();
      applyExits(state, undefined, account(40, exits), 40);
      assert.equal(plan.state, "queued");
      assert.deepEqual(plan.exit?.parts, [
        { id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false },
      ]);
    }
  });

  it("takes no account that contradicts what the wallet knows of the exit", () => {
    for (const exits of [
      // a stranded exit owing more than it did
      [entry(1, "stranded", 12n)],
      // a stranded exit back in the queue
      [entry(1, "queued", 10n, { position: 0 })],
      // a requeue that queues more than the stranded exit owed
      [entry(1, "requeued", 0n), entry(2, "queued", 15n, { position: 0, requeuedFrom: 1 })],
    ]) {
      const { state, plan } = strandedPlan();
      applyExits(state, undefined, account(40, exits), 40);
      assert.equal(plan.state, "stranded");
      assert.deepEqual(plan.exit?.parts, [{ id: 1, payoutLeft: 10n, feeLeft: 0n, stranded: true }]);
    }
  });
});
