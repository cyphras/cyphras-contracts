import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Account, MuxedAccount } from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import { MemoryStore } from "../../src/storage.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { INDEXER, RPC, XLM, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

async function funded(amount = 100n * XLM) {
  const world = await createWorld();
  const alice = await openWallet(world, 0);
  const depositor = world.signer("alice depositor");
  const receipt = await alice.shield({ amount, signer: depositor });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  return { world, alice, depositor, receipt };
}

describe("wallet: opening", () => {
  it("refuses a deployment this release does not pin", async () => {
    const world = await createWorld();
    await assert.rejects(
      PrivateWallet.open({
        deployment: "testnet/xlm",
        keys: (await import("../../src/keysource.ts")).keySource.random(),
        prover: { prove: async () => assert.fail("no proof expected") },
        artifacts: { load: async () => new Uint8Array() },
        storage: new MemoryStore(),
        rpcUrl: RPC,
        fetch: world.fetch,
      }),
      isError("deployment_not_pinned"),
    );
    await assert.rejects(
      PrivateWallet.open({
        deployment: world.deployment,
        keys: (await import("../../src/keysource.ts")).keySource.random(),
        prover: { prove: async () => assert.fail("no proof expected") },
        artifacts: { load: async () => new Uint8Array() },
        storage: new MemoryStore(),
        rpcUrl: RPC,
        fetch: world.fetch,
      }),
      isError("deployment_not_pinned"),
    );
  });

  it("checks the RPC, the vault and every service against the pinned deployment", async () => {
    const world = await createWorld();
    const wallet = await openWallet(world, 0);
    const v = wallet.verification();
    assert.equal(v.state, "verified");
    assert.deepEqual(
      [v.rpc, v.vault, v.indexers[0]?.state, v.relayers[0]?.state],
      ["ok", "ok", "ok", "ok"],
    );
    assert.match(wallet.generateAddress(), /^cyt1/);
    assert.notEqual(wallet.generateAddress(5), wallet.generateAddress());
  });
});

describe("wallet: deposits", () => {
  it("shields, follows the deposit through the queue and spends it once admitted", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    const receipt = await alice.shield({ amount: 100n * XLM, signer: depositor });
    assert.equal(receipt.depositId, 1);
    assert.equal(world.vault.pending.size, 1);
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.attested, false);
    assert.equal((await alice.balance()).pendingDeposits, 100n * XLM);
    assert.equal((await alice.balance()).spendable, 0n);

    world.advance(3_601);
    world.admitAll();
    const summary = await alice.sync();
    assert.equal(summary.source, "indexer");
    assert.equal(summary.rootVerified, true);
    assert.equal(summary.newNotes, 1);
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
    const balance = await alice.balance();
    assert.equal(balance.spendable, 100n * XLM);
    assert.equal(balance.pendingDeposits, 0n);
    const history = await alice.history();
    assert.equal(history[0]?.kind, "shield");
    assert.equal(history[0]?.amount, 100n * XLM);
  });

  it("refuses a deposit below the vault's minimum before proving", async () => {
    const world = await createWorld({ limits: { minDeposit: 10n * XLM } });
    const alice = await openWallet(world, 0);
    await assert.rejects(
      alice.shield({ amount: 5n * XLM, signer: world.signer("d") }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "limit_exceeded" &&
        err.details["minDeposit"] === (10n * XLM).toString(),
    );
    assert.equal(world.vault.pending.size, 0);
  });

  it("cancels a pending deposit and refunds a flagged one only a day after the flag", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    const first = await alice.shield({ amount: 10n * XLM, signer: depositor });
    const second = await alice.shield({ amount: 20n * XLM, signer: depositor });
    const stranger = world.signer("anyone");
    await assert.rejects(
      alice.cancelDeposit(first.depositId, stranger),
      isError("invalid_argument"),
    );
    await alice.cancelDeposit(first.depositId, depositor);
    world.rpc.run("ab".repeat(32), () => world.vault.flag(second.depositId, 1));
    await alice.sync();
    const flagged = (await alice.deposits()).find((d) => d.id === second.depositId);
    assert.equal(flagged?.flag?.reason, 1);
    assert.equal(flagged?.refundableAt, Number(world.vault.timestamp) + 86_400);
    await assert.rejects(
      alice.refundDeposit(second.depositId, stranger),
      isError("vault_unavailable"),
    );
    world.advance(86_400);
    await alice.refundDeposit(second.depositId, stranger);
    await alice.sync();
    const states = (await alice.deposits()).map((d) => d.state);
    assert.deepEqual(states, ["cancelled", "refunded"]);
    const kinds = (await alice.history()).map((h) => h.kind).sort();
    assert.deepEqual(kinds, ["cancel", "refund", "shield", "shield"]);
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.from === world.vault.address).map((t) => t.to),
      [depositor.publicKey, depositor.publicKey],
    );
  });
});

describe("wallet: spends", () => {
  it("pays a shielded address through a relayer, which names no party but itself", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const sent = await alice.send({
      to: bob.generateAddress(),
      amount: 30n * XLM,
      maxFee: 2n * XLM,
    });
    assert.equal(sent.state, "submitted");
    assert.equal(sent.fee, 1n * XLM);
    const [submission] = world.relayer.submissions;
    assert.equal(submission?.ext.ext_amount, "0");
    assert.equal(submission?.ext.recipient, world.relayer.feeAddress);
    assert.equal(submission?.ext.relayer, world.relayer.feeAddress);

    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.txHash, sent.txHash);
    assert.equal((await alice.balance()).spendable, 69n * XLM);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 30n * XLM);
    const received = (await bob.history()).find((h) => h.kind === "receive");
    assert.equal(received?.amount, 30n * XLM);
  });

  it("unshields only after the user confirms the warnings", async () => {
    const { world, alice } = await funded();
    const destination = world.signer("exchange").publicKey;
    await assert.rejects(
      alice.unshield({ to: destination, amount: 40n * XLM, maxFee: 2n * XLM }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "not_confirmed" &&
        String(err.details["warnings"]).includes("recent_shield"),
    );
    const reviews: string[][] = [];
    const result = await alice.unshield({
      to: destination,
      amount: 40n * XLM,
      maxFee: 2n * XLM,
      confirm: (review) => {
        reviews.push(review.warnings.map((w) => w.code));
        return true;
      },
    });
    assert.ok("planId" in result);
    assert.ok(reviews[0]?.includes("small_anonymity_set"));
    assert.ok(reviews[0]?.includes("new_destination_account"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    assert.deepEqual(
      world.vault.transfers
        .filter((t) => t.from === world.vault.address)
        .map((t) => [t.to, t.amount]),
      [
        [destination, 40n * XLM],
        [world.relayer.feeAddress, 1n * XLM],
      ],
    );
    assert.equal((await alice.balance()).spendable, 59n * XLM);
  });

  it("self-relays an unshield, warning that the account becomes public", async () => {
    const { world, alice } = await funded();
    const me = world.signer("my account");
    let warned = false;
    const result = await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 25n * XLM,
      selfRelay: me,
      confirm: (review) => {
        warned = review.warnings.some((w) => w.code === "self_relay_links_account");
        return review.fee === 0n;
      },
    });
    assert.ok(warned);
    assert.ok("planId" in result && result.state === "settled");
    assert.equal(world.relayer.submissions.length, 0);
    // the spent note is gone at once; the change counts once a sync has found its leaf
    assert.equal((await alice.balance()).spendable, 0n);
    await alice.sync();
    assert.equal((await alice.balance()).spendable, 75n * XLM);
  });

  it("pays a muxed exchange address, which the vault credits to its base account", async () => {
    const { world, alice } = await funded();
    const exchange = world.signer("exchange");
    const muxed = new MuxedAccount(
      new Account(exchange.publicKey, "0"),
      "1234567890123",
    ).accountId();
    const result = await alice.unshield({
      to: muxed,
      amount: 12n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in result);
    assert.equal(world.relayer.submissions[0]?.ext.recipient, muxed);
    await alice.sync();
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === exchange.publicKey).map((t) => t.amount),
      [12n * XLM],
    );
  });

  it("asks the relayer to hold a payment, with a deadline that covers the hold", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 3_600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    const [submission] = world.relayer.submissions;
    assert.equal(submission?.notBefore, notBefore);
    // an hour of five-second ledgers, the relayer's 10-minute jitter and the usual 120 ledgers
    assert.ok((submission?.ext.deadline as number) >= world.vault.ledger + 720 + 120);
    await assert.rejects(
      alice.send({
        to: bob.generateAddress(),
        amount: 1n * XLM,
        maxFee: 2n * XLM,
        notBefore: notBefore + 2 * 86_400,
      }),
      isError("invalid_argument"),
    );
  });

  it("refuses a destination that does not exist, the vault itself, and self-relayed transfers", async () => {
    const { world, alice } = await funded();
    const missing = "GCFX7GZHEKRT3B6VQ2DXBUZOFHPDQPWF3RN6ZC4KSPV5R4UE6RYQKQVX";
    await assert.rejects(
      alice.unshield({ to: missing, amount: 1n * XLM, maxFee: 2n * XLM, confirm: confirmAll }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        (err.code === "destination_invalid" || err.code === "invalid_argument"),
    );
    await assert.rejects(
      alice.unshield({
        to: world.vault.address,
        amount: 1n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
      }),
      isError("destination_invalid"),
    );
    await assert.rejects(
      alice.send({ to: "not an address", amount: 1n, maxFee: 2n * XLM }),
      isError("invalid_address"),
    );
  });

  it("refuses a quote above the smallest cap and proves again when the relayer wants more", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.fee = 3n * XLM;
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM }),
      isError("fee_above_cap"),
    );
    world.relayer.fee = 1n * XLM;
    world.relayer.failures.push({ error: "fee_too_low" });
    const fees: bigint[] = [];
    const sent = await alice.send({
      to: bob.generateAddress(),
      amount: 1n * XLM,
      maxFee: 2n * XLM,
      confirm: (r) => {
        fees.push(r.fee);
        return true;
      },
    });
    assert.equal(sent.state, "submitted");
    assert.equal(fees.length, 2);
    await alice.sync();
    const states = (await alice.plans()).map((p) => p.state).sort();
    // the refused proof keeps its notes until it is superseded by the one that landed
    assert.deepEqual(states, ["settled", "superseded"]);
  });
});

describe("wallet: keys and state", () => {
  it("restores the balance and the history from the mnemonic alone", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 30n * XLM, maxFee: 2n * XLM });
    await alice.sync();
    const restored = await openWallet(world, 0);
    await restored.sync();
    assert.equal((await restored.balance()).spendable, (await alice.balance()).spendable);
    const history = await restored.history();
    const kinds = history.map((h) => h.kind).sort();
    assert.deepEqual(kinds, ["send", "shield"]);
    const send = history.find((h) => h.kind === "send");
    assert.equal(send?.recovered, true);
    assert.equal(send?.amount, 30n * XLM);
    assert.equal(send?.fee, 1n * XLM);
    assert.equal(send?.counterparty, bob.generateAddress());
  });

  it("keeps its state encrypted and reloads it", async () => {
    const world = await createWorld();
    const storage = new MemoryStore();
    const alice = await openWallet(world, 0, storage);
    await alice.shield({ amount: 50n * XLM, signer: world.signer("d") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const reopened = await openWallet(world, 0, storage);
    assert.equal((await reopened.balance()).spendable, 50n * XLM);
    const address = alice.generateAddress();
    for (const key of storage.keys()) {
      const value = Buffer.from((await storage.get(key)) as Uint8Array);
      assert.ok(!value.includes(Buffer.from(address)));
      assert.ok(!value.includes(Buffer.from("spendable")));
      assert.ok(!value.includes(Buffer.from("notes")));
    }
    const other = await openWallet(world, 1, storage);
    assert.equal((await other.balance()).spendable, 0n);
  });

  it("reports from viewing keys and cannot spend with them", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 30n * XLM, maxFee: 2n * XLM });
    const view = async (key: string) =>
      PrivateWallet.openViewOnly({
        deployment: world.deployment,
        allowUnpinnedDeployment: true,
        viewingKey: key,
        storage: new MemoryStore(),
        rpcUrl: RPC,
        fetch: world.fetch,
        clock: world.clock,
      });
    const full = await view(alice.exportViewingKey("full").viewingKey);
    await full.sync();
    assert.equal(full.viewOnly, true);
    assert.equal((await full.balance()).spendable, 69n * XLM);
    assert.ok((await full.history()).some((h) => h.kind === "send"));
    const incoming = await view(alice.exportViewingKey("incoming").viewingKey);
    await incoming.sync();
    const balance = await incoming.balance();
    assert.equal(balance.spendsUnknown, true);
    // without nk the spent note still counts, with the change it produced
    assert.equal(balance.spendable, 100n * XLM + 69n * XLM);
    await assert.rejects(
      full.send({ to: bob.generateAddress(), amount: 1n, maxFee: 2n * XLM }),
      isError("view_only"),
    );
    assert.throws(() => incoming.exportViewingKey("full"), isError("view_only"));
    assert.match(alice.exportViewingKey("full").warning, /whole history/);
  });

  it("discloses one payment to a third party, with esk from the sender", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const sent = await alice.send({
      to: bob.generateAddress(),
      amount: 30n * XLM,
      maxFee: 2n * XLM,
    });
    await alice.sync();
    await bob.sync();
    const payment = world.vault.leaves.find(
      (l) => l.txHash === sent.txHash && (bob as PrivateWallet) !== undefined,
    );
    const leaf = (await bob.history()).find((h) => h.kind === "receive")?.leafIndex as number;
    assert.ok(payment !== undefined);
    const options = {
      deployment: world.deployment,
      allowUnpinnedDeployment: true,
      rpcUrl: RPC,
      fetch: world.fetch,
      indexers: [INDEXER],
    };
    const fromSender = await alice.disclosePayment({
      txHash: sent.txHash as string,
      leafIndex: leaf,
    });
    assert.ok(fromSender.esk !== undefined);
    const check = await PrivateWallet.verifyDisclosure(fromSender, options);
    assert.equal(check.value, 30n * XLM);
    assert.equal(check.address, bob.generateAddress());
    assert.equal(check.senderProven, true);
    assert.equal(check.confirmedByRpc, true);
    const fromRecipient = await bob.disclosePayment({
      txHash: sent.txHash as string,
      leafIndex: leaf,
    });
    assert.equal(fromRecipient.esk, undefined);
    assert.equal(
      (await PrivateWallet.verifyDisclosure(fromRecipient, options)).senderProven,
      false,
    );
    await assert.rejects(
      PrivateWallet.verifyDisclosure(
        { ...fromSender, note: { ...fromSender.note, value: "1" } },
        options,
      ),
      isError("invalid_argument"),
    );
  });
});
