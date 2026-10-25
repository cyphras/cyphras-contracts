import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MemoryStore } from "../../src/storage.ts";
import type { SpendReview } from "../../src/wallet/spend.ts";
import { type Operation, type WalletState, loadState, saveState } from "../../src/wallet/state.ts";
import { RELAYER, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet, sealedState } from "../support/wallets.ts";

const owedTo = (world: World, destination: string): bigint =>
  world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === destination)
    .reduce((s, e) => s + e.payout, 0n);

// A wallet whose store holds a split unshield as earlier releases left it when its first part
// stopped before a plan: the operation saved, active, with no plan.
async function withStoredOperation(route: "self" | "relayed") {
  const world = await createWorld({
    limits: { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 500n * XLM },
  });
  const store = new MemoryStore();
  const alice = await openWallet(world, 0, store);
  for (const amount of [60n * XLM, 70n * XLM, 100n * XLM]) {
    await alice.shield({ amount, signer: world.signer("alice depositor") });
  }
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  const account = world.signer("my account");
  const to = world.signer("exchange").publicKey;
  const stored: Operation = {
    id: "ab".repeat(16),
    kind: "split_unshield",
    to,
    total: 90n * XLM,
    partSize: route === "self" ? 50n * XLM : 48n * XLM,
    maxFee: route === "self" ? 0n : 2n * XLM,
    route:
      route === "self"
        ? { kind: "self", account: account.publicKey }
        : { kind: "relayers", urls: [RELAYER] },
    awaiting: undefined,
    nextAt: world.clock(),
    state: "active",
    blockedBy: undefined,
  };
  const sealed = sealedState(store, world);
  const state = (await loadState(sealed)) as WalletState;
  state.operations.push(stored);
  await saveState(sealed, state);
  const wallet = await openWallet(world, 0, store);
  world.rpc.sent = [];
  return { world, wallet, account, to, stored };
}

// The user agrees to the payment as a whole and declines the first part's review.
function declining(reviews: SpendReview[]): (review: SpendReview) => boolean {
  return (review) => {
    reviews.push(review);
    return review.parts > 1 && review.amount === 90n * XLM;
  };
}

describe("a split unshield an earlier release stored without a plan", () => {
  it("asks both reviews again on the same request, and sends nothing when declined (self)", async () => {
    const { world, wallet, account, to } = await withStoredOperation("self");
    const reviews: SpendReview[] = [];
    await assert.rejects(
      wallet.unshield({
        to,
        amount: 90n * XLM,
        selfRelay: account,
        split: true,
        confirm: declining(reviews),
      }),
      isError("not_confirmed"),
    );
    assert.equal(reviews.length, 2);
    assert.deepEqual(world.rpc.sent, []);
  });

  it("pays nothing on the same relayed request when the first part is declined", async () => {
    const { world, wallet, to } = await withStoredOperation("relayed");
    const reviews: SpendReview[] = [];
    await assert.rejects(
      wallet.unshield({
        to,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: declining(reviews),
      }),
      isError("not_confirmed"),
    );
    assert.equal(reviews.length, 2);
    await wallet.sync();
    assert.equal(owedTo(world, to), 0n);
    assert.deepEqual(world.relayer.submissions, []);
  });

  it("sends nothing of it on continueOperations, and drops it", async () => {
    const { world, wallet, account } = await withStoredOperation("self");
    assert.deepEqual(await wallet.continueOperations(account), []);
    assert.deepEqual(world.rpc.sent, []);
  });

  it("does not hold back another unshield to its destination", async () => {
    const { world, wallet, account, to } = await withStoredOperation("self");
    await wallet.unshield({ to, amount: 10n * XLM, selfRelay: account, confirm: confirmAll });
    assert.equal(world.rpc.sent.length, 1);
    assert.equal(owedTo(world, to), 10n * XLM);
  });
});
