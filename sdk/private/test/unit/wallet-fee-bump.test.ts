import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Address,
  FeeBumpTransaction,
  type Transaction,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from "@stellar/stellar-base";
import { bytesToHex, hexToBytes } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import type { NetworkFee, NetworkFeeCaps, TransactionSigner } from "../../src/vault/invoke.ts";
import type { SpendReview } from "../../src/wallet/spend.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");

const dataKey = (contract: string, key: xdr.ScVal): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key,
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const vaultData = (world: World, name: string): xdr.LedgerKey =>
  dataKey(world.vault.address, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name)]));

const instanceOf = (world: World): xdr.LedgerKey =>
  dataKey(world.vault.address, xdr.ScVal.scvLedgerKeyContractInstance());

const balanceOf = (world: World, holder: string): xdr.LedgerKey =>
  dataKey(
    world.deployment.asset.contract,
    xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Balance"), new Address(holder).toScVal()]),
  );

const codeOf = (world: World): xdr.LedgerKey =>
  xdr.LedgerKey.contractCode(
    new xdr.LedgerKeyContractCode({
      hash: hexToBytes(world.vault.wasmHash) as unknown as ReturnType<
        xdr.LedgerKeyContractCode["hash"]
      >,
    }),
  );

const dataEntry = (key: xdr.LedgerKey, val: xdr.ScVal): xdr.LedgerEntryData =>
  xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: new xdr.ExtensionPoint(0),
      contract: key.contractData().contract(),
      key: key.contractData().key(),
      durability: key.contractData().durability(),
      val,
    }),
  );

const details = (err: unknown): CyphrasError["details"] =>
  err instanceof CyphrasError ? err.details : {};

const caught = async (p: Promise<unknown>): Promise<unknown> =>
  p.then(
    () => undefined,
    (err: unknown) => err,
  );

const hashOf = (tx: Transaction | FeeBumpTransaction | undefined): string =>
  tx === undefined ? "" : bytesToHex(Uint8Array.from(tx.hash()));

// The inclusion fee the fake RPC quotes, which a fee bump bids for each of its two operations.
const QUOTED = 150n;
const BUMPED = 2n * QUOTED;
// A restore of about 1,690 XLM, above the 2^32 - 1 stroops one transaction's fee field holds.
const RESTORE = 16_900_000_000;

type Reply = (envelope: string, tx: Transaction | FeeBumpTransaction) => unknown;

// The user's own account: shows every fee to `agree` and keeps it, keeps what it was asked to sign,
// in order, and answers a fee bump with `onBump` in place of its signature.
function payer(
  world: World,
  options: {
    readonly label?: string;
    readonly agree?: (fee: NetworkFee) => boolean;
    readonly onBump?: Reply;
    readonly signsFeeBumps?: boolean;
  } = {},
) {
  const account = world.signer(options.label ?? "my account");
  const shown: NetworkFee[] = [];
  const asked: ("tx" | "bump")[] = [];
  const envelopes: string[] = [];
  const signer: TransactionSigner = {
    publicKey: account.publicKey,
    async signTransaction(envelope, passphrase) {
      const tx = TransactionBuilder.fromXDR(envelope, passphrase);
      const bump = tx instanceof FeeBumpTransaction;
      asked.push(bump ? "bump" : "tx");
      envelopes.push(envelope);
      if (bump && options.onBump !== undefined) return options.onBump(envelope, tx);
      return account.signTransaction(envelope, passphrase);
    },
    confirmFee: (fee) => {
      shown.push(fee);
      return options.agree?.(fee) ?? true;
    },
    ...(options.signsFeeBumps === undefined ? {} : { signsFeeBumps: options.signsFeeBumps }),
  };
  return { signer, shown, asked, envelopes, account };
}

const sends = (world: World): number =>
  world.rpc.calls.filter((m) => m === "sendTransaction").length;

const sentOps = (world: World): string[] =>
  world.rpc.sent.map((tx: Transaction) => {
    const op = tx.operations[0];
    return op?.type === "invokeHostFunction"
      ? op.func.invokeContract().functionName().toString()
      : (op?.type ?? "none");
  });

// A world whose vault's instance and Roots are archived, ready for restoreVault.
async function archivedWorld(): Promise<World> {
  const world = await createWorld();
  world.rpc.archived.add(id(instanceOf(world)));
  world.rpc.archived.add(id(vaultData(world, "Roots")));
  world.rpc.restoreFee = RESTORE;
  return world;
}

const restoreOptions = (world: World, caps?: Partial<NetworkFeeCaps>) => ({
  deployment: world.deployment,
  allowUnpinnedDeployment: true,
  rpcUrl: RPC,
  fetch: world.fetch,
  clock: world.clock,
  sleep: async () => {},
  ...(caps === undefined ? {} : { networkFeeCaps: caps }),
});

async function funded(limits?: Parameters<typeof createWorld>[0]) {
  const world = await createWorld(limits);
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  world.rpc.calls = [];
  return { world, alice };
}

// Simulations that read and write the vault's instance and Roots, for `fee` stroops.
function simulate(world: World, fee: number): void {
  world.rpc.simulated = {
    readOnly: [],
    readWrite: [instanceOf(world), vaultData(world, "Roots")],
    instructions: 1_000_000,
    readBytes: 1_000,
    writeBytes: 1_000,
    fee,
  };
}

const paidTo = (world: World, to: string): bigint =>
  world.vault.transfers.filter((t) => t.to === to).reduce((s, t) => s + t.amount, 0n);

describe("restores above what one transaction carries", () => {
  it("restores the vault in a fee bump the donor signs after the transaction inside it", async () => {
    const world = await archivedWorld();
    const donor = payer(world, { label: "donor" });
    const restore = await PrivateWallet.restoreVault(
      donor.signer,
      restoreOptions(world, { restore: 2_000n * XLM }),
    );
    // One consent for the whole fee, then the transaction, then the fee bump that holds it.
    assert.equal(donor.shown.length, 1);
    const fee = donor.shown[0] as NetworkFee;
    assert.equal(fee.feeBump, true);
    assert.equal(fee.inclusion, BUMPED);
    assert.equal(fee.resource, BigInt(RESTORE));
    assert.equal(fee.total, BUMPED + BigInt(RESTORE));
    assert.deepEqual(donor.asked, ["tx", "bump"]);
    const inner = TransactionBuilder.fromXDR(
      donor.envelopes[0] as string,
      world.deployment.networkPassphrase,
    ) as Transaction;
    assert.equal(inner.fee, "0");
    assert.equal(inner.signatures.length, 0);
    // The fee bump holds the transaction as the donor signed it, and the donor's account pays it.
    const [bump] = world.rpc.bumps;
    assert.ok(bump !== undefined);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(bump.feeSource, donor.signer.publicKey);
    assert.equal(BigInt(bump.fee), fee.total);
    assert.equal(hashOf(bump.innerTransaction), hashOf(inner));
    assert.deepEqual(world.rpc.sentFees, [fee.total]);
    // The SDK follows the bump's hash, which RPC finds it by as well as by the inner one.
    assert.equal(restore.txHash, hashOf(bump));
    assert.notEqual(restore.txHash, hashOf(inner));
    assert.deepEqual(restore.restored, ["instance", "Roots"]);
    assert.equal(world.rpc.archived.size, 0);
    assert.deepEqual(sentOps(world), ["restoreFootprint"]);
  });

  it("still asks for consent and keeps the caps for a fee-bumped restore", async () => {
    // Declined: nothing signed, nothing sent.
    let world = await archivedWorld();
    let donor = payer(world, { label: "donor", agree: () => false });
    let err = await caught(
      PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 2_000n * XLM })),
    );
    assert.ok(isError("not_confirmed")(err), String(err));
    assert.equal(donor.shown[0]?.feeBump, true);
    assert.deepEqual(donor.asked, []);
    assert.equal(sends(world), 0);
    // Above the restore cap: refused before the donor is asked, with the true fee.
    world = await archivedWorld();
    donor = payer(world, { label: "donor" });
    err = await caught(
      PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 1_000n * XLM })),
    );
    assert.ok(isError("fee_above_cap")(err), String(err));
    assert.equal(details(err)["reason"], "restore");
    assert.equal(details(err)["inclusion"], BUMPED.toString());
    assert.equal(details(err)["resource"], String(RESTORE));
    assert.deepEqual(donor.shown, []);
    assert.deepEqual(donor.asked, []);
    assert.equal(sends(world), 0);
    // A fee bump bids for two operations, so it is held to the inclusion cap at twice the quote.
    world = await archivedWorld();
    donor = payer(world, { label: "donor" });
    err = await caught(
      PrivateWallet.restoreVault(
        donor.signer,
        restoreOptions(world, { restore: 2_000n * XLM, inclusion: BUMPED - 1n }),
      ),
    );
    assert.ok(isError("fee_above_cap")(err), String(err));
    assert.deepEqual(donor.asked, []);
    assert.equal(sends(world), 0);
  });

  it("refuses a fee that needs a fee bump from a signer that cannot sign one, before asking", async () => {
    const world = await archivedWorld();
    const donor = payer(world, { label: "donor", signsFeeBumps: false });
    const err = await caught(
      PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 2_000n * XLM })),
    );
    assert.ok(isError("fee_above_limit")(err), String(err));
    assert.equal(details(err)["limit"], "4294967295");
    assert.equal(details(err)["feeBump"], "unsupported");
    assert.deepEqual(donor.shown, []);
    assert.deepEqual(donor.asked, []);
    assert.equal(sends(world), 0);
  });

  it("sends nothing when the signer gives back no signed fee bump", async () => {
    const replies: Record<string, Reply> = {
      // A signer that handles plain transactions only and hands anything else back as it came.
      unchanged: (envelope) => envelope,
      // One that signs the transaction inside instead.
      inner: (_envelope, tx) => (tx as FeeBumpTransaction).innerTransaction.toXDR(),
      declined: () => ({ error: "the user declined" }),
      nothing: () => ({}),
    };
    for (const [name, onBump] of Object.entries(replies)) {
      const world = await archivedWorld();
      const donor = payer(world, { label: "donor", onBump });
      const err = await caught(
        PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 2_000n * XLM })),
      );
      const code = name === "declined" ? "signer_rejected" : "signer_mismatch";
      assert.ok(isError(code)(err), `${name}: ${String(err)}`);
      assert.equal(details(err)["feeBump"], true, name);
      assert.deepEqual(donor.asked, ["tx", "bump"], name);
      assert.equal(sends(world), 0, name);
      assert.equal(world.rpc.archived.size, 2, name);
    }
    // A signer that throws on a fee bump: its error, and nothing sent.
    const world = await archivedWorld();
    const donor = payer(world, {
      label: "donor",
      onBump: () => {
        throw new Error("unsupported envelope type");
      },
    });
    await assert.rejects(
      PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 2_000n * XLM })),
      /unsupported envelope type/,
    );
    assert.equal(sends(world), 0);
  });

  it("names the restored entries by kind and key, beside their names", async () => {
    const world = await createWorld();
    const code = codeOf(world);
    const balance = balanceOf(world, world.vault.address);
    world.rpc.extraEntries.set(
      id(code),
      xdr.LedgerEntryData.contractCode(
        new xdr.ContractCodeEntry({
          ext: new xdr.ContractCodeEntryExt(0),
          hash: code.contractCode().hash(),
          code: Buffer.alloc(64),
        }),
      ),
    );
    world.rpc.extraEntries.set(
      id(balance),
      dataEntry(balance, nativeToScVal(1n, { type: "i128" })),
    );
    const keys = [code, instanceOf(world), vaultData(world, "Roots"), balance];
    for (const key of keys) world.rpc.archived.add(id(key));
    world.rpc.restoreFee = 1_080_000_000;
    const donor = payer(world, { label: "donor" });
    const err = await caught(PrivateWallet.restoreVault(donor.signer, restoreOptions(world)));
    assert.ok(isError("fee_above_cap")(err), String(err));
    assert.equal(details(err)["entries"], "code,instance,Roots,asset Balance");
    assert.equal(details(err)["entryKinds"], "code,instance,tree,balance");
    await PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 110n * XLM }));
    const fee = donor.shown[0] as NetworkFee;
    assert.deepEqual(fee.entries, ["code", "instance", "Roots", "asset Balance"]);
    assert.deepEqual(
      fee.feeEntries.map((e) => [e.kind, e.name, e.key]),
      [
        ["code", "code", id(code)],
        ["instance", "instance", id(instanceOf(world))],
        ["tree", "Roots", id(vaultData(world, "Roots"))],
        ["balance", "asset Balance", id(balance)],
      ],
    );
  });
});

describe("self-submitted calls above what one transaction carries", () => {
  it("self-relays an unshield in a fee bump, and the plan follows the bump's hash", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 5_000_000_000);
    const me = payer(world);
    const merchant = world.signer("merchant").publicKey;
    const sub = await alice.unshield({
      to: merchant,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
      networkFeeCaps: { restore: 1_000n * XLM },
    });
    assert.deepEqual(me.asked, ["tx", "bump"]);
    assert.equal(me.shown.length, 1);
    assert.equal(me.shown[0]?.feeBump, true);
    assert.equal(me.shown[0]?.reason, "restore");
    assert.deepEqual(sentOps(world), ["transact"]);
    const [bump] = world.rpc.bumps;
    assert.equal(sub.txHash, hashOf(bump));
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.txHash, hashOf(bump));
    assert.equal(paidTo(world, merchant), 10n * XLM);
    assert.equal(world.rpc.archived.has(id(instanceOf(world))), false);
  });

  it("makes a deposit in a fee bump, followed by the bump's hash", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 5_000_000_000);
    const depositor = payer(world, { label: "alice depositor" });
    const receipt = await alice.shield({
      amount: 10n * XLM,
      signer: depositor.signer,
      networkFeeCaps: { restore: 1_000n * XLM },
    });
    assert.deepEqual(depositor.asked, ["tx", "bump"]);
    assert.equal(receipt.txHash, hashOf(world.rpc.bumps[0]));
    assert.equal(typeof receipt.depositId, "number");
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.txHash, receipt.txHash);
    assert.equal(deposit?.state, "pending");
  });

  it("goes once more in a new fee bump after a failure on an archived entry", async () => {
    const { world, alice } = await funded();
    simulate(world, 5_000_000_000);
    world.rpc.archiveNext = 1;
    const me = payer(world);
    const sub = await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
      networkFeeCaps: { resource: 1_000n * XLM },
    });
    assert.deepEqual(me.asked, ["tx", "bump", "tx", "bump"]);
    assert.deepEqual(sentOps(world), ["transact", "transact"]);
    const [first, second] = world.rpc.bumps;
    assert.equal(world.rpc.records.get(hashOf(first))?.status, "FAILED");
    assert.equal(sub.txHash, hashOf(second));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.txHash, hashOf(second));
  });

  it("bounds the transaction inside a fee bump at an archival edge, and goes again once dropped", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world);
    const edge = world.vault.ledger + 3;
    world.rpc.ttl.set(id(instance), edge);
    simulate(world, 5_000_000_000);
    world.rpc.beforeApply = () => {
      world.vault.ledger += 10;
    };
    const me = payer(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
      networkFeeCaps: { restore: 1_000n * XLM },
    });
    assert.deepEqual(sentOps(world), ["transact", "transact"]);
    assert.equal(world.rpc.bumps.length, 2);
    assert.equal(world.rpc.sent[0]?.ledgerBounds?.maxLedger, edge + 1);
    assert.deepEqual(
      me.shown.map((f) => [f.reason, f.feeBump]),
      [
        ["rent", true],
        ["restore", true],
      ],
    );
    assert.equal(world.rpc.archived.has(id(instance)), false);
  });

  it("sends a RestoreFootprint the RPC asks for in a fee bump, then the call alone", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world);
    world.rpc.archived.add(id(instance));
    world.rpc.preambleNext = [instance];
    world.rpc.restoreFee = 5_000_000_000;
    simulate(world, 1_000);
    const me = payer(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
      networkFeeCaps: { restore: 1_000n * XLM },
    });
    assert.deepEqual(sentOps(world), ["restoreFootprint", "transact"]);
    assert.deepEqual(me.asked, ["tx", "bump", "tx"]);
    assert.deepEqual(
      me.shown.map((f) => f.feeBump),
      [true, false],
    );
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(world.rpc.bumps[0]?.innerTransaction.operations[0]?.type, "restoreFootprint");
  });

  it("sends a call within what one transaction carries as before, without a fee bump", async () => {
    const { world, alice } = await funded();
    simulate(world, 1_000);
    const me = payer(world);
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
    });
    assert.deepEqual(me.asked, ["tx"]);
    assert.equal(me.shown[0]?.feeBump, false);
    assert.equal(me.shown[0]?.inclusion, QUOTED);
    assert.equal(world.rpc.bumps.length, 0);
    assert.equal(me.shown[0]?.total, QUOTED + (me.shown[0]?.resource ?? 0n));
    assert.deepEqual(world.rpc.sentFees.slice(-1), [me.shown[0]?.total]);
    assert.equal(world.rpc.sent[0]?.fee, me.shown[0]?.total.toString());
  });
});

describe("why a plan stopped", () => {
  it("shows the relayer's code and the error of a relayed refusal", async () => {
    const { world, alice } = await funded();
    world.relayer.failures.push({ error: "restore_needed" });
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
      }),
    );
    assert.ok(isError("service_rejected")(err), String(err));
    const [plan] = await alice.plans();
    assert.equal(plan?.relayerCode, "restore_needed");
    assert.equal(plan?.lastError?.code, "service_rejected");
    assert.equal(plan?.lastError?.message, (err as CyphrasError).message);
  });

  it("shows the relayer's code of a held request it failed", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.held = [];
    for (const [heldId, request] of world.relayer.heldRequests) {
      world.relayer.heldRequests.set(heldId, {
        ...request,
        failure: { code: "restore_needed", reason: 0 },
      });
    }
    world.advance(700);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.relayerStatus, "failed");
    assert.equal(plan?.relayerCode, "restore_needed");
    assert.equal(plan?.lastError?.code, "service_rejected");
    assert.match(plan?.lastError?.message ?? "", /restoreVault/);
  });

  it("shows the error of a self-relayed plan, which has no relayer's code", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 1_110_000_000);
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: payer(world).signer,
        confirm: confirmAll,
      }),
    );
    assert.ok(isError("fee_above_cap")(err), String(err));
    const [plan] = await alice.plans();
    assert.equal(plan?.relayerCode, undefined);
    assert.deepEqual(plan?.lastError, {
      code: "fee_above_cap",
      message: (err as CyphrasError).message,
    });
  });

  it("shows no error for a plan that went", async () => {
    const { world, alice } = await funded();
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    const [plan] = await alice.plans();
    assert.equal(plan?.relayerCode, undefined);
    assert.equal(plan?.lastError, undefined);
  });
});

describe("a review of a payment the vault queues", () => {
  const LIMITS = { limits: { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM } };

  const reviewing = (reviews: SpendReview[]) => (review: SpendReview) => {
    reviews.push(review);
    return true;
  };

  it("says the payment will queue before the user confirms it", async () => {
    const { world, alice } = await funded(LIMITS);
    world.relayer.queuedFee = 2n * XLM;
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 45n * XLM;
    const reviews: SpendReview[] = [];
    await alice.unshield({
      to: world.signer("dest").publicKey,
      amount: 20n * XLM,
      maxFee: 3n * XLM,
      confirm: reviewing(reviews),
    });
    assert.equal(reviews[0]?.queued, true);
    assert.equal(reviews[0]?.fee, 2n * XLM);
  });

  it("says a payment that fits today's window will not queue", async () => {
    const { world, alice } = await funded(LIMITS);
    world.relayer.queuedFee = 2n * XLM;
    const reviews: SpendReview[] = [];
    await alice.unshield({
      to: world.signer("dest").publicKey,
      amount: 20n * XLM,
      maxFee: 3n * XLM,
      confirm: reviewing(reviews),
    });
    assert.equal(reviews[0]?.queued, false);
  });
});
