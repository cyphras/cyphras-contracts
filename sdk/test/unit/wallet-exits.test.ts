import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
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

  it("follows a stranded payout until it is claimed", async () => {
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
    assert.equal((await alice.plans())[0]?.state, "stranded");
    // the relayer's fee was paid at release; only the payout waits
    assert.equal(world.vault.queuedTotal, 10n * XLM);
    assert.equal((await alice.plans())[0]?.payoutLeft, 10n * XLM);
    // A claim that can pay no part fails.
    await assert.rejects(
      alice.claimExit(1, world.signer("anyone")),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "transaction_failed" &&
        err.details["vaultError"] === "NothingClaimable",
    );
    world.vault.unpayable.delete(destination);
    await alice.claimExit(1, world.signer("anyone"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "claimed");
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount),
      [10n * XLM],
    );
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
    assert.equal(plan?.state, "claimed");
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
    [plan] = await alice.plans();
    assert.equal(plan?.state, "claimed");
  });

  it("takes the exit ID of a self-relayed unshield from its own transaction", async () => {
    const { world, alice } = await funded();
    fillWindow(world);
    const destination = world.signer("merchant").publicKey;
    const result = await alice.unshield({
      to: destination,
      amount: 25n * XLM,
      selfRelay: world.signer("my account"),
      confirm: confirmAll,
    });
    assert.ok("planId" in result && result.state === "queued");
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
