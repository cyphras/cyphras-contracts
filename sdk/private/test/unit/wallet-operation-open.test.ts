import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import type { TransactionSigner } from "../../src/vault/invoke.ts";
import type { SpendReview } from "../../src/wallet/spend.ts";
import type { PrivateWallet } from "../../src/wallet/wallet.ts";
import { XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const SPLIT = { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 500n * XLM };

async function withNotes(): Promise<{ world: World; alice: PrivateWallet }> {
  const world = await createWorld({ limits: SPLIT });
  const alice = await openWallet(world, 0);
  for (const amount of [60n * XLM, 70n * XLM, 100n * XLM]) {
    await alice.shield({ amount, signer: world.signer("alice depositor") });
  }
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  return { world, alice };
}

// A signer that counts the transactions it is asked to sign.
function counting(world: World): TransactionSigner & { readonly signed: () => number } {
  const account = world.signer("my account");
  let signed = 0;
  return {
    publicKey: account.publicKey,
    signTransaction: (x, p) => {
      signed++;
      return account.signTransaction(x, p);
    },
    signed: () => signed,
  };
}

describe("a split unshield whose first part the user declines", () => {
  it("asks the user again when the same request is repeated, and sends nothing", async () => {
    const { world, alice } = await withNotes();
    const reviews: SpendReview[] = [];
    // The user agrees to the payment as a whole and declines the first part's review.
    const confirm = (review: SpendReview): boolean => {
      reviews.push(review);
      return review.parts > 1 && review.amount === 90n * XLM;
    };
    const signer = counting(world);
    const request = {
      to: world.signer("exchange").publicKey,
      amount: 90n * XLM,
      selfRelay: signer,
      split: true,
      confirm,
    } as const;
    await assert.rejects(alice.unshield(request), isError("not_confirmed"));
    assert.equal(reviews.length, 2);
    await assert.rejects(alice.unshield(request), isError("not_confirmed"));
    assert.equal(reviews.length, 4);
    assert.equal(signer.signed(), 0);
    assert.deepEqual(world.rpc.sent, []);
    assert.deepEqual(await alice.continueOperations(signer), []);
  });
});

describe("another unshield to a destination with an open operation", () => {
  it("is refused while the operation or a part of it is open, and goes once the part settled", async () => {
    const { world, alice } = await withNotes();
    const destination = world.signer("exchange").publicKey;
    const signer = counting(world);
    // The wallet rejects the first part's transaction, which leaves that part open.
    let rejected = false;
    const rejecting: TransactionSigner = {
      publicKey: signer.publicKey,
      signTransaction: async (x, p) => {
        if (rejected) return signer.signTransaction(x, p);
        rejected = true;
        return { signedTxXdr: "", error: "User declined access" };
      },
    };
    const err = await alice
      .unshield({
        to: destination,
        amount: 90n * XLM,
        selfRelay: rejecting,
        split: true,
        confirm: confirmAll,
      })
      .catch((e: unknown) => e);
    assert.ok(isError("signer_rejected")(err));
    const operationId = (err as CyphrasError).details["operationId"];
    const single = {
      to: destination,
      amount: 10n * XLM,
      selfRelay: signer,
      confirm: confirmAll,
    } as const;
    const refused = (e: unknown): boolean =>
      e instanceof CyphrasError &&
      e.code === "operation_open" &&
      e.details["operationId"] === operationId;
    await assert.rejects(alice.unshield(single), refused);
    // Abandoned, its first part may still land until its deadline.
    await alice.abandonOperation(operationId as string);
    assert.equal((await alice.plans())[0]?.state, "prepared");
    await assert.rejects(alice.unshield(single), refused);
    assert.equal(signer.signed(), 0);
    assert.deepEqual(world.rpc.sent, []);
    // Past its deadline the part is dead and the destination free again.
    world.advance(121 * 5);
    world.fill(1);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
    await alice.unshield(single);
    assert.equal(signer.signed(), 1);
  });
});

describe("a new unshield beside a single one that may still land", () => {
  // A wallet with notes of 100 and 50 XLM, and an unshield of 10 XLM whose wallet rejected its
  // transaction, so its plan may still land.
  async function stalled() {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    for (const amount of [100n * XLM, 50n * XLM]) {
      await alice.shield({ amount, signer: world.signer("alice depositor") });
    }
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.rpc.sent = [];
    const destination = world.signer("exchange").publicKey;
    const signer = counting(world);
    const rejecting: TransactionSigner = {
      publicKey: signer.publicKey,
      signTransaction: async () => ({ signedTxXdr: "", error: "User declined access" }),
    };
    const err = await alice
      .unshield({ to: destination, amount: 10n * XLM, selfRelay: rejecting, confirm: confirmAll })
      .catch((e: unknown) => e);
    assert.ok(isError("signer_rejected")(err));
    const planId = (err as CyphrasError).details["planId"] as string;
    return { world, alice, destination, signer, planId };
  }

  it("is refused before anything is proved or sent, and the plan goes on through retry", async () => {
    const { world, alice, destination, signer, planId } = await stalled();
    const refused = (e: unknown): boolean =>
      e instanceof CyphrasError && e.code === "operation_open" && e.details["planId"] === planId;
    await assert.rejects(
      alice.unshield({ to: destination, amount: 5n * XLM, selfRelay: signer, confirm: confirmAll }),
      refused,
    );
    await assert.rejects(
      alice.unshield({ to: destination, amount: 10n * XLM, maxFee: 2n * XLM, confirm: confirmAll }),
      refused,
    );
    assert.equal((await alice.plans()).length, 1);
    assert.equal(signer.signed(), 0);
    assert.deepEqual(world.rpc.sent, []);
    // Another destination is not held back.
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 5n * XLM,
      selfRelay: signer,
      confirm: confirmAll,
    });
    assert.equal(signer.signed(), 1);
    await alice.retry(planId, { selfRelay: signer, confirm: confirmAll });
    assert.equal(signer.signed(), 2);
    assert.equal(world.rpc.sent.length, 2);
    // Once it landed, the destination is free again.
    await alice.unshield({
      to: destination,
      amount: 5n * XLM,
      selfRelay: signer,
      confirm: confirmAll,
    });
    assert.equal(signer.signed(), 3);
    const paid = world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount);
    assert.deepEqual(paid, [10n * XLM, 5n * XLM]);
  });

  it("goes once the single plan is dead past its deadline", async () => {
    const { world, alice, destination, signer } = await stalled();
    world.advance(121 * 5);
    world.fill(1);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
    await alice.unshield({
      to: destination,
      amount: 5n * XLM,
      selfRelay: signer,
      confirm: confirmAll,
    });
    assert.equal(signer.signed(), 1);
  });
});
