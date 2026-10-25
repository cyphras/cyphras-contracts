import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Address,
  FeeBumpTransaction,
  Keypair,
  type Transaction,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-base";
import { bytesToHex } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import type { NetworkFee, NetworkFeeCaps, TransactionSigner } from "../../src/vault/invoke.ts";
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

const details = (err: unknown): CyphrasError["details"] =>
  err instanceof CyphrasError ? err.details : {};

const caught = async (p: Promise<unknown>): Promise<unknown> =>
  p.then(
    () => undefined,
    (err: unknown) => err,
  );

const hashOf = (tx: Transaction | FeeBumpTransaction | undefined): string =>
  tx === undefined ? "" : bytesToHex(Uint8Array.from(tx.hash()));

// The fake RPC quotes 150 stroops for inclusion; a fee bump bids it for each of its two operations.
const BUMPED = 300n;
const LIMIT = 2n ** 50n;
const SECOND = "http://rpc2.test";

type Reply = (envelope: string, tx: Transaction | FeeBumpTransaction) => unknown;

// The user's own account: shows every fee to `agree`, keeps what it was asked to sign, in order,
// and answers a fee bump with `onBump` in place of its signature.
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
  const signer: TransactionSigner = {
    publicKey: account.publicKey,
    async signTransaction(envelope, passphrase) {
      const tx = TransactionBuilder.fromXDR(envelope, passphrase);
      const bump = tx instanceof FeeBumpTransaction;
      asked.push(bump ? "bump" : "tx");
      if (bump && options.onBump !== undefined) return options.onBump(envelope, tx);
      return account.signTransaction(envelope, passphrase);
    },
    confirmFee: (fee) => {
      shown.push(fee);
      return options.agree?.(fee) ?? true;
    },
    ...(options.signsFeeBumps === undefined ? {} : { signsFeeBumps: options.signsFeeBumps }),
  };
  return { signer, shown, asked, account };
}

const sends = (world: World): number =>
  world.rpc.calls.filter((m) => m === "sendTransaction").length;

const restoreOptions = (world: World, caps?: Partial<NetworkFeeCaps>) => ({
  deployment: world.deployment,
  allowUnpinnedDeployment: true,
  rpcUrl: RPC,
  fetch: world.fetch,
  clock: world.clock,
  sleep: async () => {},
  ...(caps === undefined ? {} : { networkFeeCaps: caps }),
});

// A world whose vault instance is archived, and whose restore costs `fee` stroops.
async function archivedWorld(fee: number): Promise<World> {
  const world = await createWorld();
  world.rpc.archived.add(id(instanceOf(world)));
  world.rpc.restoreFee = fee;
  return world;
}

async function funded() {
  const world = await createWorld();
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  world.rpc.calls = [];
  world.rpc.sentFees = [];
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

describe("the most a fee bump carries", () => {
  it("pays a fee of exactly 2^50 stroops in a fee bump and refuses one stroop more before asking", async () => {
    let world = await archivedWorld(Number(LIMIT - BUMPED));
    let donor = payer(world, { label: "donor" });
    await PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: LIMIT }));
    assert.equal(donor.shown[0]?.total, LIMIT);
    assert.equal(donor.shown[0]?.feeBump, true);
    assert.deepEqual(world.rpc.sentFees, [LIMIT]);

    world = await archivedWorld(Number(LIMIT - BUMPED + 1n));
    donor = payer(world, { label: "donor" });
    const err = await caught(
      PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: LIMIT })),
    );
    assert.ok(isError("fee_above_limit")(err), String(err));
    assert.equal(details(err)["limit"], LIMIT.toString());
    assert.equal(details(err)["inclusion"], BUMPED.toString());
    assert.deepEqual(donor.shown, []);
    assert.deepEqual(donor.asked, []);
    assert.equal(sends(world), 0);
  });

  it("refuses a self-relayed fee above the limit before the user is asked, and keeps the plan", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, Number(LIMIT));
    const me = payer(world);
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: me.signer,
        confirm: confirmAll,
        networkFeeCaps: { restore: 2n * LIMIT },
      }),
    );
    assert.ok(isError("fee_above_limit")(err), String(err));
    assert.deepEqual(me.shown, []);
    assert.deepEqual(me.asked, []);
    assert.equal(sends(world), 0);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.lastError?.code, "fee_above_limit");
  });
});

describe("signers and fee bumps", () => {
  it("sends a call within the envelope limit alone for a signer that does not sign fee bumps", async () => {
    const { world, alice } = await funded();
    simulate(world, 1_000);
    const me = payer(world, { signsFeeBumps: false });
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
    });
    assert.deepEqual(me.asked, ["tx"]);
    assert.equal(me.shown[0]?.feeBump, false);
    assert.equal(world.rpc.bumps.length, 0);
  });

  it("refuses a fee bump the signer gave back with a higher fee, and sends nothing", async () => {
    const world = await archivedWorld(16_900_000_000);
    const donor = payer(world, {
      label: "donor",
      onBump: (_envelope, tx) => {
        const bump = tx as FeeBumpTransaction;
        const richer = TransactionBuilder.buildFeeBumpTransaction(
          bump.feeSource,
          "100000",
          bump.innerTransaction,
          world.deployment.networkPassphrase,
        );
        richer.sign(donor.account.keypair);
        return richer.toXDR();
      },
    });
    const err = await caught(
      PrivateWallet.restoreVault(donor.signer, restoreOptions(world, { restore: 2_000n * XLM })),
    );
    assert.ok(isError("signer_mismatch")(err), String(err));
    assert.equal(details(err)["feeBump"], true);
    assert.equal(sends(world), 0);
  });

  it("keeps a self-relayed payment's plan and notes when the user declines the fee bump", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 5_000_000_000);
    const merchant = world.signer("merchant").publicKey;
    const declining = payer(world, { onBump: () => ({ error: "the user declined" }) });
    const err = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: declining.signer,
        confirm: confirmAll,
        networkFeeCaps: { restore: 1_000n * XLM },
      }),
    );
    assert.ok(isError("signer_rejected")(err), String(err));
    assert.equal(details(err)["feeBump"], true);
    assert.equal(sends(world), 0);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.txHash, undefined);
    assert.equal(plan?.lastError?.code, "signer_rejected");
    // The same notes go again once the user signs both.
    const me = payer(world);
    await alice.retry(plan?.planId as string, {
      selfRelay: me.signer,
      confirm: confirmAll,
      networkFeeCaps: { restore: 1_000n * XLM },
    });
    assert.deepEqual(me.asked, ["tx", "bump"]);
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
  });

  it("names a signer that throws on a fee bump with a signer error and details.feeBump", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 5_000_000_000);
    const me = payer(world, {
      onBump: () => {
        throw new Error("unsupported envelope type");
      },
    });
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: me.signer,
        confirm: confirmAll,
        networkFeeCaps: { restore: 1_000n * XLM },
      }),
    );
    assert.equal(sends(world), 0);
    assert.ok(
      isError("signer_mismatch")(err) || isError("signer_rejected")(err),
      `a signer's throw on the fee bump surfaces as ${String(err)}`,
    );
    assert.equal(details(err)["feeBump"], true);
  });
});

describe("following a fee bump", () => {
  it("resends the same signed fee bump when the network asks to try again later", async () => {
    const world = await archivedWorld(16_900_000_000);
    world.rpc.sendOnce = "TRY_AGAIN_LATER";
    const donor = payer(world, { label: "donor" });
    const restore = await PrivateWallet.restoreVault(
      donor.signer,
      restoreOptions(world, { restore: 2_000n * XLM }),
    );
    assert.deepEqual(donor.asked, ["tx", "bump"]);
    assert.equal(donor.shown.length, 1);
    assert.equal(sends(world), 2);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(restore.txHash, hashOf(world.rpc.bumps[0]));
  });

  it("never sends the transaction inside a fee bump alone, which core refuses", async () => {
    const world = await archivedWorld(16_900_000_000);
    const donor = payer(world, { label: "donor" });
    await PrivateWallet.restoreVault(
      donor.signer,
      restoreOptions(world, { restore: 2_000n * XLM }),
    );
    const inner = world.rpc.sent[0] as Transaction;
    assert.equal(inner.fee, "0");
    // The fake RPC refuses it alone as core does: its fee is below its resource fee.
    const alone = world.rpc.handle("sendTransaction", { transaction: inner.toXDR() }) as {
      status: string;
    };
    assert.equal(alone.status, "ERROR");
    assert.equal(world.rpc.sent.length, 1);
  });

  it("goes again after a fee bump failed on an archived entry, which a second provider confirms", async () => {
    const world = await createWorld();
    const routed: FetchLike = async (input, init) =>
      new URL(input).origin === SECOND ? world.fetch(RPC, init) : world.fetch(input, init);
    const alice = await openWallet({ ...world, fetch: routed }, 0, undefined, undefined, {
      secondRpcUrl: SECOND,
    });
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.rpc.sent = [];
    simulate(world, 5_000_000_000);
    world.rpc.archiveNext = 1;
    const me = payer(world);
    const merchant = world.signer("merchant").publicKey;
    const sub = await alice.unshield({
      to: merchant,
      amount: 10n * XLM,
      selfRelay: me.signer,
      confirm: confirmAll,
      networkFeeCaps: { resource: 1_000n * XLM },
    });
    assert.deepEqual(me.asked, ["tx", "bump", "tx", "bump"]);
    assert.equal(sub.txHash, hashOf(world.rpc.bumps[1]));
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
  });

  it("finds a fee-bumped deposit that landed inside another account's fee bump", async () => {
    // Anyone holding the signed transaction can wrap it in a fee bump of their own, which lands it
    // under another hash; RPC finds it by the hash of the transaction inside as well.
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    world.rpc.ttl.set(id(instanceOf(world)), world.vault.ledger + 3);
    simulate(world, 5_000_000_000);
    const other = Keypair.random();
    world.rpc.account(other);
    const handle = world.rpc.handle.bind(world.rpc);
    let wrapped = false;
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      if (method !== "sendTransaction" || wrapped) return handle(method, params);
      const passphrase = world.deployment.networkPassphrase;
      const mine = TransactionBuilder.fromXDR(params["transaction"] as string, passphrase);
      if (!(mine instanceof FeeBumpTransaction)) return handle(method, params);
      wrapped = true;
      const theirs = TransactionBuilder.buildFeeBumpTransaction(
        other.publicKey(),
        "200",
        mine.innerTransaction,
        passphrase,
      );
      theirs.sign(other);
      handle(method, { transaction: theirs.toXDR() });
      // Ledgers close past the deposit's ledger bound before the user's own fee bump is taken.
      world.vault.ledger += 10;
      return { status: "PENDING", hash: hashOf(mine), latestLedger: world.vault.ledger };
    };
    const depositor = payer(world, { label: "alice depositor" });
    const err = await caught(
      alice.shield({
        amount: 10n * XLM,
        signer: depositor.signer,
        networkFeeCaps: { restore: 1_000n * XLM },
      }),
    );
    assert.equal(world.vault.pending.size, 1);
    assert.equal(err, undefined, `the landed deposit was reported as ${String(err)}`);
    const [deposit] = await alice.deposits();
    assert.notEqual(deposit?.state, "failed");
  });
});

describe("why a plan stopped, once it went after all", () => {
  it("shows no relayer refusal for a relayed payment whose resend the relayer then took", async () => {
    const { world, alice } = await funded();
    world.relayer.conflictNext = 1;
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    // The resend after the failure on the host's storage is refused once, then taken.
    world.relayer.failures.push({ error: "network_fee_high" });
    await alice.sync();
    assert.equal((await alice.plans())[0]?.relayerCode, "network_fee_high");
    await alice.sync();
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.relayerCode, undefined);
    assert.equal(plan?.lastError, undefined);
  });
});
