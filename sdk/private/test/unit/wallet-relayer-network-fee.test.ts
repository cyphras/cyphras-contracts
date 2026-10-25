import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { CyphrasError } from "../../src/errors.ts";
import { RelayerClient } from "../../src/net/relayer.ts";
import { XLM, createWorld } from "../support/network.ts";
import { confirmAll, openWallet } from "../support/wallets.ts";

async function funded() {
  const world = await createWorld({ limits: { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM } });
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  return { world, alice };
}

const paidTo = (world: Awaited<ReturnType<typeof createWorld>>, to: string): bigint =>
  world.vault.transfers.filter((t) => t.to === to).reduce((s, t) => s + t.amount, 0n);

const submitWith = (body: unknown) =>
  new RelayerClient(
    "http://r",
    async () => new Response(JSON.stringify(body), { status: 422 }),
  ).submit(
    {} as Parameters<RelayerClient["submit"]>[0],
    {} as Parameters<RelayerClient["submit"]>[1],
  );

describe("a relayer that refuses a network fee above its own", () => {
  it("reads network_fee_high and the network fee it names", async () => {
    assert.deepEqual(await submitWith({ error: "network_fee_high", network_fee: "153276561" }), {
      accepted: false,
      error: "network_fee_high",
      reason: undefined,
      networkFee: 153_276_561n,
    });
    assert.deepEqual(await submitWith({ error: "network_fee_high" }), {
      accepted: false,
      error: "network_fee_high",
      reason: undefined,
      networkFee: undefined,
    });
    // Another refusal carries no network fee, whatever the reply holds.
    assert.deepEqual(await submitWith({ error: "rejected", network_fee: "x" }), {
      accepted: false,
      error: "rejected",
      reason: undefined,
      networkFee: undefined,
    });
    for (const bad of ["-1", "1.5", 7]) {
      await assert.rejects(
        submitWith({ error: "network_fee_high", network_fee: bad }),
        (err: unknown) => err instanceof CyphrasError && err.code === "service_rejected",
      );
    }
  });

  it("names the fee and the ways on without trying again, and the payment goes self-relayed", async () => {
    const { world, alice } = await funded();
    const merchant = world.signer("merchant").publicKey;
    // A second refusal waits for a second relayed attempt, which must not come.
    world.relayer.failures.push(
      { error: "network_fee_high", network_fee: "153276561" },
      { error: "network_fee_high", network_fee: "153276561" },
    );
    const refused = await alice
      .unshield({ to: merchant, amount: 10n * XLM, maxFee: 2n * XLM, confirm: confirmAll })
      .then(
        () => assert.fail("the unshield went"),
        (err: unknown) => err,
      );
    assert.ok(refused instanceof CyphrasError);
    assert.equal(refused.code, "service_rejected");
    assert.equal(refused.details["code"], "network_fee_high");
    assert.equal(refused.details["networkFee"], "153276561");
    assert.match(refused.message, /network fee is high now \(153276561 stroops\)/);
    assert.match(refused.message, /selfRelay/);
    assert.match(refused.message, /networkFeeCaps\.resource/);
    assert.match(refused.message, /later/);
    assert.equal(world.relayer.failures.length, 1);
    const planId = refused.details["planId"];
    assert.equal(typeof planId, "string");
    assert.equal(paidTo(world, merchant), 0n);

    // The way on it names: the same payment again, self-relayed, with the same notes, once.
    world.relayer.failures.length = 0;
    await alice.retry(planId as string, {
      selfRelay: world.signer("my account"),
      networkFeeCaps: { resource: 200_000_000n },
      confirm: confirmAll,
    });
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
  });

  it("tells a transfer, which cannot be self-relayed, to try again later", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "network_fee_high", network_fee: "60000100" });
    await assert.rejects(
      alice.send({
        to: bob.generateAddress(),
        amount: 10n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
      }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "service_rejected" &&
        err.details["code"] === "network_fee_high" &&
        err.details["networkFee"] === "60000100" &&
        /later/.test(err.message) &&
        !/selfRelay/.test(err.message),
    );
    assert.equal(world.relayer.failures.length, 0);
  });
});
