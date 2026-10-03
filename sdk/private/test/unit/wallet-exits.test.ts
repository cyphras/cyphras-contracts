import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import type { ExitEntry, ExitQueue } from "../../src/net/indexer.ts";
import { applyExits } from "../../src/wallet/exits.ts";
import type { ExitEvent } from "../../src/wallet/sources.ts";
import { type Plan, type WalletState, emptyState } from "../../src/wallet/state.ts";
import type { OperationView } from "../../src/wallet/wallet.ts";
import { XLM, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

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
  const stranded = (ledger: number): ExitEvent => ({
    kind: "exit_stranded",
    id: 1,
    payoutLeft: 10n,
    feeLeft: 0n,
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
    const once = [queued(10), stranded(20), requeued(25)];
    applyExits(state, events(5, 30, once), undefined, 30);
    applyExits(state, events(5, 40, once), undefined, 40);
    assert.equal(plan.state, "queued");
    assert.deepEqual(plan.exit?.parts, [{ id: 2, payoutLeft: 10n, feeLeft: 0n, stranded: false }]);
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
