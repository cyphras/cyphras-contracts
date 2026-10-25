import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Address,
  FeeBumpTransaction,
  type Transaction,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-base";
import { bytesToHex } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import type { NetworkFeeCaps, TransactionSigner } from "../../src/vault/invoke.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");
const SECOND = "http://rpc2.test";

const dataKey = (contract: string, key: xdr.ScVal): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key,
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const instanceOf = (world: World): xdr.LedgerKey =>
  dataKey(world.vault.address, xdr.ScVal.scvLedgerKeyContractInstance());

const rootsOf = (world: World): xdr.LedgerKey =>
  dataKey(world.vault.address, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Roots")]));

const details = (err: unknown): CyphrasError["details"] =>
  err instanceof CyphrasError ? err.details : {};

const caught = async (p: Promise<unknown>): Promise<unknown> =>
  p.then(
    () => undefined,
    (err: unknown) => err,
  );

const hashOf = (tx: Transaction | FeeBumpTransaction | undefined): string =>
  tx === undefined ? "" : bytesToHex(Uint8Array.from(tx.hash()));

const sends = (world: World): number =>
  world.rpc.calls.filter((m) => m === "sendTransaction").length;

// An observer of the signed fee bump, as the RPC it goes through or any peer it floods to, wraps
// the signed transaction inside in a fee bump of its own and lands that one first.
function rewrapping(world: World, fetch: FetchLike = world.fetch): FetchLike {
  const other = world.signer("someone else");
  return async (input, init) => {
    const body =
      init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
    if (new URL(input).origin === RPC && body?.method === "sendTransaction") {
      const passphrase = world.deployment.networkPassphrase;
      const mine = TransactionBuilder.fromXDR(body.params.transaction, passphrase);
      if (mine instanceof FeeBumpTransaction) {
        const theirs = TransactionBuilder.buildFeeBumpTransaction(
          other.publicKey,
          "1500",
          mine.innerTransaction,
          passphrase,
        );
        theirs.sign(other.keypair);
        world.rpc.handle("sendTransaction", { transaction: theirs.toXDR() });
      }
    }
    return fetch(input, init);
  };
}

// The user's account, which takes fee bumps and counts what it is asked to sign.
function opted(world: World, label: string): TransactionSigner & { readonly asked: string[] } {
  const account = world.signer(label);
  const asked: string[] = [];
  return {
    publicKey: account.publicKey,
    signsFeeBumps: true,
    asked,
    signTransaction(envelope, passphrase) {
      const tx = TransactionBuilder.fromXDR(envelope, passphrase);
      asked.push(tx instanceof FeeBumpTransaction ? "bump" : "tx");
      return account.signTransaction(envelope, passphrase);
    },
  };
}

async function archivedWorld(fee: number): Promise<World> {
  const world = await createWorld();
  world.rpc.archived.add(id(instanceOf(world)));
  world.rpc.archived.add(id(rootsOf(world)));
  world.rpc.restoreFee = fee;
  return world;
}

const restoreOptions = (world: World, fetch: FetchLike, caps: Partial<NetworkFeeCaps>) => ({
  deployment: world.deployment,
  allowUnpinnedDeployment: true,
  rpcUrl: RPC,
  fetch,
  clock: world.clock,
  sleep: async () => {},
  networkFeeCaps: caps,
});

describe("a fee-bumped transaction that lands inside another account's fee bump", () => {
  it("reports a restore that landed so as landed, with the hash of the fee bump that held it", async () => {
    const world = await archivedWorld(16_900_000_000);
    const donor = opted(world, "donor");
    const restore = await PrivateWallet.restoreVault(
      donor,
      restoreOptions(world, rewrapping(world), { restore: 2_000n * XLM }),
    );
    const [theirs] = world.rpc.bumps;
    assert.notEqual(theirs?.feeSource, donor.publicKey);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(restore.txHash, hashOf(theirs));
    assert.deepEqual(restore.restored, ["instance", "Roots"]);
    assert.equal(world.rpc.archived.size, 0);
    assert.deepEqual(donor.asked, ["tx", "bump"]);
  });

  it("settles a self-relayed unshield landed so once, with a second provider, and sends it no more", async () => {
    const world = await createWorld();
    const routed: FetchLike = async (input, init) =>
      new URL(input).origin === SECOND ? world.fetch(RPC, init) : world.fetch(input, init);
    const alice = await openWallet(
      { ...world, fetch: rewrapping(world, routed) },
      0,
      undefined,
      undefined,
      {
        secondRpcUrl: SECOND,
      },
    );
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.rpc.archived.add(id(instanceOf(world)));
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [instanceOf(world), rootsOf(world)],
      instructions: 1_000_000,
      readBytes: 1_000,
      writeBytes: 1_000,
      fee: 5_000_000_000,
    };
    const me = opted(world, "my account");
    const merchant = world.signer("merchant").publicKey;
    const sub = await alice.unshield({
      to: merchant,
      amount: 10n * XLM,
      selfRelay: me,
      confirm: confirmAll,
      networkFeeCaps: { restore: 1_000n * XLM },
    });
    const [theirs] = world.rpc.bumps;
    assert.deepEqual(me.asked, ["tx", "bump"]);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(sub.txHash, hashOf(theirs));
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.txHash, hashOf(theirs));
    const paid = world.vault.transfers.filter((t) => t.to === merchant);
    assert.deepEqual(
      paid.map((t) => t.amount),
      [10n * XLM],
    );
  });
});

describe("a fee bump the network refuses", () => {
  it("is reported refused once the transaction's sequence number went to another one", async () => {
    const world = await archivedWorld(16_900_000_000);
    const donor = opted(world, "donor");
    const handle = world.rpc.handle.bind(world.rpc);
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      const passphrase = world.deployment.networkPassphrase;
      if (method === "sendTransaction") {
        const env = TransactionBuilder.fromXDR(params["transaction"] as string, passphrase);
        if (env instanceof FeeBumpTransaction) {
          // Another transaction of the same account takes the sequence number first.
          const account = world.rpc.accounts.get(donor.publicKey);
          if (account !== undefined) account.sequence++;
          return { status: "ERROR", hash: hashOf(env), latestLedger: world.vault.ledger };
        }
      }
      return handle(method, params);
    };
    const err = await caught(
      PrivateWallet.restoreVault(
        donor,
        restoreOptions(world, world.fetch, { restore: 2_000n * XLM }),
      ),
    );
    assert.ok(isError("restore_failed")(err), String(err));
    assert.equal(details(err)["refused"], true);
    assert.equal(typeof details(err)["feeBumpHash"], "string");
    assert.equal(world.rpc.archived.size, 2);
  });
});

describe("fee bumps are the signer's choice", () => {
  it("keeps the envelope limit for a signer that did not opt in, whatever the caps", async () => {
    // An RPC prices a restore at 100,000 XLM; a headless signer without confirmFee and a cap far
    // above the envelope limit.
    const world = await archivedWorld(1_000_000_000_000);
    const headless = world.signer("donor");
    const err = await caught(
      PrivateWallet.restoreVault(
        headless,
        restoreOptions(world, world.fetch, { restore: 2n ** 60n }),
      ),
    );
    assert.ok(isError("fee_above_limit")(err), String(err));
    assert.equal(details(err)["limit"], "4294967295");
    assert.equal(details(err)["feeBump"], "unsupported");
    assert.equal(sends(world), 0);
    assert.equal(world.rpc.archived.size, 2);
  });

  it("goes in a fee bump for the same signer once it opts in", async () => {
    const world = await archivedWorld(16_900_000_000);
    const signer = { ...world.signer("donor"), signsFeeBumps: true };
    const restore = await PrivateWallet.restoreVault(
      signer,
      restoreOptions(world, world.fetch, { restore: 2_000n * XLM }),
    );
    assert.equal(restore.txHash, hashOf(world.rpc.bumps[0]));
    assert.equal(world.rpc.archived.size, 0);
  });
});
