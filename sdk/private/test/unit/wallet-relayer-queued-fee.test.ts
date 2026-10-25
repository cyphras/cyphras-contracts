import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import { RelayerClient } from "../../src/net/relayer.ts";
import type { SpendReview } from "../../src/wallet/spend.ts";
import { XLM, createWorld } from "../support/network.ts";
import { openWallet } from "../support/wallets.ts";

async function funded() {
  const world = await createWorld({ limits: { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM } });
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.relayer.queuedFee = 2n * XLM;
  return { world, alice };
}

function useToday(world: Awaited<ReturnType<typeof createWorld>>, outflow: bigint): void {
  world.vault.outflowDay = world.vault.timestamp / 86_400n;
  world.vault.outflow = outflow;
}

const reviewing = (reviews: SpendReview[]) => (review: SpendReview) => {
  reviews.push(review);
  return true;
};

const sentFees = (world: Awaited<ReturnType<typeof createWorld>>): string[] =>
  world.relayer.submissions.map((s) => s.ext.fee);

describe("a payment the vault would queue", () => {
  it("reads the queued fee of a quote", async () => {
    const reply = (body: unknown) => async () =>
      new Response(JSON.stringify(body), { status: 200 });
    const base = {
      fee: "1000000",
      asset: "native",
      tier: "100000",
      margin_bps: 500,
      valid_until: 1,
      fee_address: "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH",
      vault: "C",
      network_id: "00".repeat(32),
    };
    assert.equal((await new RelayerClient("http://r", reply(base)).quote()).queuedFee, undefined);
    const queued = await new RelayerClient(
      "http://r",
      reply({ ...base, queued_fee: "2300000" }),
    ).quote();
    assert.equal(queued.queuedFee, 2_300_000n);
    await assert.rejects(
      new RelayerClient("http://r", reply({ ...base, queued_fee: "x" })).quote(),
      (err: unknown) => err instanceof CyphrasError && err.code === "quote_invalid",
    );
  });

  it("pays the queued fee, which the user confirms, and lands in the queue", async () => {
    const { world, alice } = await funded();
    useToday(world, 45n * XLM);
    const reviews: SpendReview[] = [];
    const to = world.signer("dest").publicKey;
    await alice.unshield({ to, amount: 20n * XLM, maxFee: 3n * XLM, confirm: reviewing(reviews) });
    assert.equal(reviews.length, 1);
    assert.equal(reviews[0]?.fee, 2n * XLM);
    assert.ok(reviews[0]?.warnings.some((w) => w.code === "exit_will_queue"));
    assert.deepEqual(sentFees(world), [(2n * XLM).toString()]);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
  });

  it("pays the ordinary fee when the payment fits today's window", async () => {
    const { world, alice } = await funded();
    const reviews: SpendReview[] = [];
    await alice.unshield({
      to: world.signer("dest").publicKey,
      amount: 20n * XLM,
      maxFee: 3n * XLM,
      confirm: reviewing(reviews),
    });
    assert.equal(reviews[0]?.fee, 1n * XLM);
    assert.deepEqual(sentFees(world), [(1n * XLM).toString()]);
  });

  it("refuses a queued fee above the caller's cap before anything is proved or sent", async () => {
    const { world, alice } = await funded();
    useToday(world, 45n * XLM);
    await assert.rejects(
      alice.unshield({
        to: world.signer("dest").publicKey,
        amount: 20n * XLM,
        maxFee: (3n * XLM) / 2n,
        confirm: () => true,
      }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "fee_above_cap" &&
        err.details["queued"] === true &&
        err.details["fee"] === (2n * XLM).toString(),
    );
    assert.equal(world.relayer.submissions.length, 0);
    assert.equal((await alice.plans()).length, 0);
  });

  it("pays the queued fee for a transfer while today's window is full, and nothing if declined", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    useToday(world, 50n * XLM);
    const quote = await alice.quote({ kind: "send", maxFee: 3n * XLM });
    assert.equal(quote.fee, 2n * XLM);
    assert.equal(quote.queuedFee, 2n * XLM);
    await assert.rejects(
      alice.send({
        to: bob.generateAddress(),
        amount: 10n * XLM,
        maxFee: 3n * XLM,
        confirm: () => false,
      }),
      (err: unknown) => err instanceof CyphrasError && err.code === "not_confirmed",
    );
    assert.equal(world.relayer.submissions.length, 0);
    const reviews: SpendReview[] = [];
    await alice.send({
      to: bob.generateAddress(),
      amount: 10n * XLM,
      maxFee: 3n * XLM,
      confirm: reviewing(reviews),
    });
    assert.equal(reviews[0]?.fee, 2n * XLM);
    assert.deepEqual(sentFees(world), [(2n * XLM).toString()]);
  });
});
