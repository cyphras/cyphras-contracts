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

describe("a relayer that refuses to pay for a restore", () => {
  it("reads restore_needed as its own code", async () => {
    const reply = async () =>
      new Response(JSON.stringify({ error: "restore_needed" }), { status: 422 });
    const result = await new RelayerClient("http://r", reply).submit(
      {} as Parameters<RelayerClient["submit"]>[0],
      {} as Parameters<RelayerClient["submit"]>[1],
    );
    assert.deepEqual(result, { accepted: false, error: "restore_needed", reason: undefined });
  });

  it("tells the caller to self-relay or restore the vault, and the payment goes self-relayed", async () => {
    const { world, alice } = await funded();
    const merchant = world.signer("merchant").publicKey;
    world.relayer.failures.push({ error: "restore_needed" });
    const refused = await alice
      .unshield({ to: merchant, amount: 10n * XLM, maxFee: 2n * XLM, confirm: confirmAll })
      .then(
        () => assert.fail("the unshield went"),
        (err: unknown) => err,
      );
    assert.ok(refused instanceof CyphrasError);
    assert.equal(refused.code, "service_rejected");
    assert.equal(refused.details["code"], "restore_needed");
    assert.match(refused.message, /selfRelay/);
    assert.match(refused.message, /networkFeeCaps\.restore/);
    assert.match(refused.message, /restoreVault/);
    const planId = refused.details["planId"];
    assert.equal(typeof planId, "string");
    assert.equal(paidTo(world, merchant), 0n);

    // The way on it names: the same payment again, self-relayed, with the same notes.
    await alice.retry(planId as string, {
      selfRelay: world.signer("my account"),
      confirm: confirmAll,
    });
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
  });

  it("tells a transfer, which cannot be self-relayed, to restore the vault", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "restore_needed" });
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
        err.details["code"] === "restore_needed" &&
        /restoreVault/.test(err.message) &&
        !/selfRelay/.test(err.message),
    );
  });
});
