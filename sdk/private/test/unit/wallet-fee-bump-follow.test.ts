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
import { type OpenOptions, type OperationView, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");
const SECOND = "http://rpc2.test";
const SMALL = { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 350n * XLM };
// A resource fee above what one envelope carries, and caps that let it through.
const HIGH = 5_000_000_000;
const CAPS: Partial<NetworkFeeCaps> = { resource: 1_000n * XLM, restore: 1_000n * XLM };

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

const passphraseOf = (world: World): string => world.deployment.networkPassphrase;

// Simulations that read and write the vault's instance and Roots, for `fee` stroops.
function simulate(world: World, fee: number): void {
  world.rpc.simulated = {
    readOnly: [],
    readWrite: [instanceOf(world), rootsOf(world)],
    instructions: 1_000_000,
    readBytes: 1_000,
    writeBytes: 1_000,
    fee,
  };
}

// An account that takes fee bumps, counts what it is asked to sign and keeps the transactions it
// signed, in order. Its first `together` transactions wait for each other before they are signed.
function opted(
  world: World,
  label: string,
  options: { readonly together?: number; readonly onBump?: () => unknown } = {},
): TransactionSigner & { readonly asked: string[]; readonly inner: Transaction[] } {
  const account = world.signer(label);
  const asked: string[] = [];
  const inner: Transaction[] = [];
  let waiting: (() => void)[] = [];
  return {
    publicKey: account.publicKey,
    signsFeeBumps: true,
    asked,
    inner,
    async signTransaction(envelope, passphrase) {
      const tx = TransactionBuilder.fromXDR(envelope, passphrase);
      const bump = tx instanceof FeeBumpTransaction;
      asked.push(bump ? "bump" : "tx");
      if (bump && options.onBump !== undefined) return options.onBump();
      if (!bump && inner.length < (options.together ?? 0)) {
        inner.push(tx);
        if (inner.length < (options.together ?? 0)) {
          await new Promise<void>((resolve) => waiting.push(resolve));
        } else {
          for (const go of waiting) go();
          waiting = [];
        }
      } else if (!bump) {
        inner.push(tx);
      }
      return account.signTransaction(envelope, passphrase);
    },
  };
}

// An observer of the signed fee bump that, while `control.on`, lands the transaction inside it in
// a fee bump of its own before the user's reaches the network.
function rewrapping(world: World, control: { on: boolean }, fetch = world.fetch): FetchLike {
  const other = world.signer("someone else");
  return async (input, init) => {
    const body =
      init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
    if (control.on && new URL(input).origin === RPC && body?.method === "sendTransaction") {
      const mine = TransactionBuilder.fromXDR(body.params.transaction, passphraseOf(world));
      if (mine instanceof FeeBumpTransaction) {
        const theirs = TransactionBuilder.buildFeeBumpTransaction(
          other.publicKey,
          "1500",
          mine.innerTransaction,
          passphraseOf(world),
        );
        theirs.sign(other.keypair);
        world.rpc.handle("sendTransaction", { transaction: theirs.toXDR() });
      }
    }
    return fetch(input, init);
  };
}

// A pause that lets the vault's clock run, as time passes while the SDK waits.
const ticking = (world: World) => async (ms: number) => {
  world.vault.timestamp += BigInt(Math.ceil(ms / 1000));
};

// A second RPC provider that answers from the same network.
const withSecond =
  (world: World, fetch: FetchLike = world.fetch): FetchLike =>
  async (input, init) =>
    new URL(input).origin === SECOND ? world.fetch(RPC, init) : fetch(input, init);

// While `on`, every fee bump `from` pays is refused by the network, as for a fee source short of
// funds, with the ERROR reply a node gives.
function refuseBumps(world: World, from: string): { on: boolean } {
  const handle = world.rpc.handle.bind(world.rpc);
  const control = { on: true };
  world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
    if (control.on && method === "sendTransaction") {
      const env = TransactionBuilder.fromXDR(params["transaction"] as string, passphraseOf(world));
      if (env instanceof FeeBumpTransaction && env.feeSource === from) {
        return { status: "ERROR", hash: hashOf(env), latestLedger: world.vault.ledger };
      }
    }
    return handle(method, params);
  };
  return control;
}

async function fundedWallet(
  world: World,
  fetch?: FetchLike,
  amounts = [100n * XLM],
  options: Partial<OpenOptions> = {},
) {
  const alice = await openWallet(
    fetch === undefined ? world : { ...world, fetch },
    0,
    undefined,
    undefined,
    { ...(fetch === undefined ? {} : { secondRpcUrl: SECOND }), ...options },
  );
  for (const amount of amounts) {
    await alice.shield({ amount, signer: world.signer("alice depositor") });
  }
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  return alice;
}

const paidTo = (world: World, to: string): bigint =>
  world.vault.transfers.filter((t) => t.to === to).reduce((s, t) => s + t.amount, 0n);

const owedTo = (world: World, to: string): bigint =>
  paidTo(world, to) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === to)
    .reduce((s, e) => s + e.payout, 0n);

const restoreOptions = (
  world: World,
  extra: { readonly sleep?: (ms: number) => Promise<void> } = {},
) => ({
  deployment: world.deployment,
  allowUnpinnedDeployment: true,
  rpcUrl: RPC,
  fetch: world.fetch,
  clock: world.clock,
  sleep: extra.sleep ?? (async () => {}),
  networkFeeCaps: { restore: 2_000n * XLM },
});

async function archivedWorld(): Promise<World> {
  const world = await createWorld();
  world.rpc.archived.add(id(instanceOf(world)));
  world.rpc.archived.add(id(rootsOf(world)));
  world.rpc.restoreFee = 16_900_000_000;
  return world;
}

describe("split unshields through fee bumps", () => {
  it("pays each part in its own fee bump, follows the parts by the hashes events carry, and pays once", async () => {
    const world = await createWorld({ limits: SMALL });
    const control = { on: false };
    const alice = await fundedWallet(world, withSecond(world, rewrapping(world, control)), [
      60n * XLM,
      70n * XLM,
    ]);
    simulate(world, HIGH);
    const me = opted(world, "my account");
    const destination = world.signer("exchange").publicKey;
    const op = (await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      selfRelay: me,
      split: true,
      confirm: confirmAll,
      networkFeeCaps: CAPS,
    })) as OperationView;
    assert.equal(op.parts, 2);
    assert.equal(op.plans[0]?.txHash, hashOf(world.rpc.bumps[0]));
    world.advance(60);
    let [view] = await alice.continueOperations();
    assert.equal(view?.sent, 50n * XLM);
    world.advance(7 * 3600);
    // The second part lands inside another account's fee bump first.
    control.on = true;
    [view] = await alice.continueOperations(me, CAPS);
    control.on = false;
    assert.equal(view?.plans.length, 2);
    const theirs = world.rpc.bumps[1];
    assert.notEqual(theirs?.feeSource, me.publicKey);
    assert.equal(view?.plans[1]?.txHash, hashOf(theirs));
    assert.deepEqual(me.asked, ["tx", "bump", "tx", "bump"]);
    world.advance(60);
    [view] = await alice.continueOperations(me, CAPS);
    assert.equal(view?.state, "done");
    assert.equal(world.rpc.bumps.length, 2);
    assert.equal(owedTo(world, destination), 90n * XLM);
    const plans = await alice.plans();
    assert.deepEqual(
      plans.map((p) => p.txHash),
      world.rpc.bumps.map(hashOf),
    );
  });
});

describe("the exit queue through fee bumps", () => {
  it("releases and claims through fee bumps, one landed by another account, and pays the payout once", async () => {
    const world = await createWorld({ limits: SMALL });
    const control = { on: false };
    const alice = await fundedWallet(world, withSecond(world, rewrapping(world, control)));
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    const destination = world.signer("closed account").publicKey;
    await alice.unshield({
      to: destination,
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    world.vault.unpayable.add(destination);
    world.advance(86_400);
    simulate(world, HIGH);
    const anyone = opted(world, "anyone");
    const release = await alice.releaseExits(anyone, 10, CAPS);
    assert.equal(release.txHash, hashOf(world.rpc.bumps[0]));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "stranded");
    world.vault.unpayable.delete(destination);
    control.on = true;
    const claim = await alice.claimExit(1, anyone, CAPS);
    control.on = false;
    const theirs = world.rpc.bumps[1];
    assert.notEqual(theirs?.feeSource, anyone.publicKey);
    assert.equal(claim.txHash, hashOf(theirs));
    assert.equal(claim.requeuedAs, 2);
    assert.deepEqual(anyone.asked, ["tx", "bump", "tx", "bump"]);
    await alice.releaseExits(anyone, 10, CAPS);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount),
      [10n * XLM],
    );
  });
});

describe("calls of one account side by side", () => {
  it("pays once for two identical fee-bumped restores sent side by side, which are one transaction", async () => {
    const world = await archivedWorld();
    const donor = opted(world, "donor", { together: 2 });
    const options = restoreOptions(world);
    const [a, b] = await Promise.all([
      PrivateWallet.restoreVault(donor, options),
      PrivateWallet.restoreVault(donor, options),
    ]);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(a.txHash, hashOf(world.rpc.bumps[0]));
    assert.equal(b.txHash, a.txHash);
    assert.equal(world.rpc.archived.size, 0);
  });

  it("lands one of two fee-bumped calls of two wallets signed for the same sequence number, and reports the other refused at once", async () => {
    const world = await createWorld();
    let sleeps = 0;
    const counting = { sleep: async () => void sleeps++ };
    const alice = await openWallet(world, 0, undefined, undefined, counting);
    const bob = await openWallet(world, 1, undefined, undefined, counting);
    simulate(world, HIGH);
    const anyone = opted(world, "anyone", { together: 2 });
    const [a, b] = await Promise.allSettled([
      alice.releaseExits(anyone, 10, CAPS),
      bob.releaseExits(anyone, 5, CAPS),
    ]);
    assert.equal(anyone.inner[0]?.sequence, anyone.inner[1]?.sequence);
    const landed = [a, b].filter((r) => r.status === "fulfilled");
    const refused = [a, b].flatMap((r) => (r.status === "rejected" ? [r.reason] : []));
    assert.equal(landed.length, 1);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(
      (landed[0] as PromiseFulfilledResult<{ txHash: string }>).value.txHash,
      hashOf(world.rpc.bumps[0]),
    );
    assert.ok(isError("transaction_failed")(refused[0]), String(refused[0]));
    assert.equal(details(refused[0])["refused"], true);
    assert.deepEqual(anyone.asked, ["tx", "tx", "bump", "bump"]);
    // The sequence number was taken already: no wait for the time bound.
    assert.ok(sleeps <= 2, `slept ${sleeps} times`);
  });

  it("runs a wallet's own fee-bumped calls one after the other, so neither is refused", async () => {
    const world = await createWorld({ limits: SMALL });
    const alice = await fundedWallet(world);
    simulate(world, HIGH);
    world.rpc.calls = [];
    const me = opted(world, "my account");
    const merchant = world.signer("merchant").publicKey;
    const [sub, release] = await Promise.all([
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: me,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
      alice.releaseExits(me, 10, CAPS),
    ]);
    assert.equal(world.rpc.bumps.length, 2);
    assert.equal(world.rpc.calls.filter((m) => m === "sendTransaction").length, 2);
    assert.equal(sub.txHash, hashOf(world.rpc.bumps[0]));
    assert.equal(release.txHash, hashOf(world.rpc.bumps[1]));
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
  });
});

describe("a fee bump the network refuses", () => {
  it("follows it until the transaction's time bound has passed, then reports it refused, sending nothing more", async () => {
    const world = await archivedWorld();
    const donor = opted(world, "donor");
    refuseBumps(world, donor.publicKey);
    const polls = { getTransaction: 0, getLedgerEntries: 0, sendTransaction: 0 };
    const handle = world.rpc.handle.bind(world.rpc);
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      if (method in polls) polls[method as keyof typeof polls]++;
      return handle(method, params);
    };
    const started = world.clock();
    const err = await caught(
      PrivateWallet.restoreVault(
        donor,
        restoreOptions(world, {
          sleep: ticking(world),
        }),
      ),
    );
    assert.ok(isError("restore_failed")(err), String(err));
    assert.equal(details(err)["refused"], true);
    assert.equal(details(err)["hash"], hashOf(donor.inner[0]));
    const waited = world.clock() - started;
    assert.ok(waited > 300_000 && waited <= 335_000, `waited ${waited} ms`);
    assert.ok(polls.getTransaction <= 230, `${polls.getTransaction} polls`);
    assert.deepEqual(donor.asked, ["tx", "bump"]);
    assert.equal(polls.sendTransaction, 1);
    assert.equal(world.rpc.archived.size, 2);
  });

  it("keeps a self-relayed payment's plan and notes through the wait, refuses a new unshield beside it, and pays once on retry", async () => {
    const world = await createWorld();
    const alice = await fundedWallet(world, undefined, undefined, { sleep: ticking(world) });
    simulate(world, HIGH);
    const me = opted(world, "my account");
    const refusing = refuseBumps(world, me.publicKey);
    const merchant = world.signer("merchant").publicKey;
    const err = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: me,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    assert.ok(isError("transaction_failed")(err), String(err));
    assert.equal(details(err)["refused"], true);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.lastError?.code, "transaction_failed");
    const again = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: me,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    assert.ok(isError("operation_open")(again), String(again));
    assert.equal(details(again)["planId"], plan?.planId);
    refusing.on = false;
    const payer = opted(world, "my account");
    await alice.retry(plan?.planId as string, {
      selfRelay: payer,
      confirm: confirmAll,
      networkFeeCaps: CAPS,
    });
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
    assert.equal(world.rpc.bumps.length, 1);
  });

  it("shows a deposit as being submitted, under the hash of the transaction inside, while it waits", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0, undefined, undefined, {
      sleep: async (ms) => {
        seen.push((await alice.deposits())[0]?.state);
        world.vault.timestamp += BigInt(Math.ceil(ms / 1000));
      },
    });
    const seen: (string | undefined)[] = [];
    simulate(world, HIGH);
    const depositor = opted(world, "alice depositor");
    refuseBumps(world, depositor.publicKey);
    const err = await caught(
      alice.shield({ amount: 10n * XLM, signer: depositor, networkFeeCaps: CAPS }),
    );
    assert.ok(isError("transaction_failed")(err), String(err));
    assert.equal(details(err)["refused"], true);
    assert.ok(seen.length > 0 && seen.every((s) => s === "submitting"), String(seen));
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "submitting");
    assert.equal(deposit?.txHash, hashOf(depositor.inner[0]));
    assert.equal(world.vault.pending.size, 0);
  });

  it("goes again after the ledger bound of a refused fee bump, once the second provider confirms the drop by the inner hash", async () => {
    const world = await createWorld();
    const alice = await openWallet(
      { ...world, fetch: withSecond(world) },
      0,
      undefined,
      undefined,
      {
        secondRpcUrl: SECOND,
      },
    );
    world.rpc.ttl.set(id(instanceOf(world)), world.vault.ledger + 3);
    simulate(world, HIGH);
    const depositor = opted(world, "alice depositor");
    const handle = world.rpc.handle.bind(world.rpc);
    let first = true;
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      if (method === "sendTransaction" && first) {
        const env = TransactionBuilder.fromXDR(
          params["transaction"] as string,
          passphraseOf(world),
        );
        if (env instanceof FeeBumpTransaction) {
          first = false;
          // Ledgers close past the bound, and the instance is extended meanwhile.
          world.vault.ledger += 10;
          world.rpc.ttl.delete(id(instanceOf(world)));
          return { status: "ERROR", hash: hashOf(env), latestLedger: world.vault.ledger };
        }
      }
      return handle(method, params);
    };
    const receipt = await alice.shield({
      amount: 10n * XLM,
      signer: depositor,
      networkFeeCaps: CAPS,
    });
    assert.deepEqual(depositor.asked, ["tx", "bump", "tx", "bump"]);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(receipt.txHash, hashOf(world.rpc.bumps[0]));
    assert.equal(world.vault.pending.size, 1);
  });

  it("sends no more when the primary reports a drop that the second provider shows landed inside another account's fee bump", async () => {
    const world = await createWorld();
    const lying = { on: false };
    const primary: FetchLike = async (input, init) => {
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (lying.on && new URL(input).origin === RPC && body?.method === "getTransaction") {
        const result = { status: "NOT_FOUND", latestLedger: world.vault.ledger, oldestLedger: 1 };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(input, init);
    };
    const alice = await openWallet(
      { ...world, fetch: withSecond(world, primary) },
      0,
      undefined,
      undefined,
      { secondRpcUrl: SECOND },
    );
    world.rpc.ttl.set(id(instanceOf(world)), world.vault.ledger + 3);
    simulate(world, HIGH);
    const other = world.signer("someone else");
    const handle = world.rpc.handle.bind(world.rpc);
    let wrapped = false;
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      if (method !== "sendTransaction" || wrapped) return handle(method, params);
      const mine = TransactionBuilder.fromXDR(params["transaction"] as string, passphraseOf(world));
      if (!(mine instanceof FeeBumpTransaction)) return handle(method, params);
      wrapped = true;
      const theirs = TransactionBuilder.buildFeeBumpTransaction(
        other.publicKey,
        "200",
        mine.innerTransaction,
        passphraseOf(world),
      );
      theirs.sign(other.keypair);
      handle(method, { transaction: theirs.toXDR() });
      world.vault.ledger += 10;
      lying.on = true;
      return { status: "PENDING", hash: hashOf(mine), latestLedger: world.vault.ledger };
    };
    const depositor = opted(world, "alice depositor");
    const err = await caught(
      alice.shield({ amount: 10n * XLM, signer: depositor, networkFeeCaps: CAPS }),
    );
    lying.on = false;
    assert.ok(isError("transaction_failed")(err), String(err));
    assert.equal(details(err)["secondProvider"], "other_outcome");
    assert.deepEqual(depositor.asked, ["tx", "bump"]);
    assert.equal(world.vault.pending.size, 1);
    assert.equal((await alice.deposits())[0]?.state, "submitting");
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.txHash, hashOf(world.rpc.bumps[0]));
  });

  it("does not report refused a transaction that landed inside another account's fee bump while the primary's index lags", async () => {
    const world = await createWorld();
    const lag = { left: 0 };
    const primary: FetchLike = async (input, init) => {
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (lag.left > 0 && new URL(input).origin === RPC && body?.method === "getTransaction") {
        lag.left--;
        const result = { status: "NOT_FOUND", latestLedger: world.vault.ledger, oldestLedger: 1 };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(input, init);
    };
    const control = { on: false };
    const alice = await fundedWallet(world, withSecond(world, rewrapping(world, control, primary)));
    simulate(world, HIGH);
    const me = opted(world, "my account");
    const merchant = world.signer("merchant").publicKey;
    control.on = true;
    // The primary's ledger entries show the sequence number taken a moment before its
    // transaction index holds the ledger; a second provider already does.
    const handle = world.rpc.handle.bind(world.rpc);
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      const reply = handle(method, params) as { status?: string };
      if (method === "sendTransaction" && reply.status === "ERROR") lag.left = 2;
      return reply;
    };
    const err = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: me,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    control.on = false;
    assert.equal(world.rpc.bumps.length, 1);
    assert.notEqual(world.rpc.bumps[0]?.feeSource, me.publicKey);
    assert.equal(
      details(err)["refused"],
      undefined,
      `a call that landed is reported as ${String(err)}`,
    );
  });
});

describe("signers that did not opt in to fee bumps", () => {
  for (const signsFeeBumps of [undefined, false] as const) {
    it(`sends 2^32 - 1 stroops alone and refuses one more before asking, signsFeeBumps ${String(signsFeeBumps)}`, async () => {
      const world = await createWorld();
      const alice = await openWallet(world, 0);
      const account = world.signer("alice depositor");
      const asked: string[] = [];
      const shown: bigint[] = [];
      const signer: TransactionSigner = {
        publicKey: account.publicKey,
        ...(signsFeeBumps === undefined ? {} : { signsFeeBumps }),
        signTransaction: (x, p) => {
          asked.push("tx");
          return account.signTransaction(x, p);
        },
        confirmFee: (fee) => {
          shown.push(fee.total);
          return true;
        },
      };
      const caps = { resource: 2n ** 33n };
      simulate(world, 4_294_967_295 - 150);
      await alice.shield({ amount: 10n * XLM, signer, networkFeeCaps: caps });
      assert.deepEqual(shown, [4_294_967_295n]);
      assert.deepEqual(asked, ["tx"]);
      assert.equal(world.rpc.bumps.length, 0);
      simulate(world, 4_294_967_295 - 149);
      const err = await caught(alice.shield({ amount: 10n * XLM, signer, networkFeeCaps: caps }));
      assert.ok(isError("fee_above_limit")(err), String(err));
      assert.equal(details(err)["limit"], "4294967295");
      assert.equal(details(err)["feeBump"], "unsupported");
      assert.deepEqual(shown, [4_294_967_295n]);
      assert.deepEqual(asked, ["tx"]);
      // Nothing left the device, so the deposit is void and holds no new one back.
      const deposits = await alice.deposits();
      assert.equal(deposits[1]?.state, "failed");
      simulate(world, 1_000);
      await alice.shield({ amount: 10n * XLM, signer });
    });
  }

  it("keeps a self-relayed plan whose fee needs a fee bump, and pays it once when retried with a signer that opts in", async () => {
    const world = await createWorld();
    const alice = await fundedWallet(world);
    simulate(world, HIGH);
    const plain = world.signer("my account");
    const merchant = world.signer("merchant").publicKey;
    const err = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: plain,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    assert.ok(isError("fee_above_limit")(err), String(err));
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.txHash, undefined);
    assert.equal(plan?.lastError?.code, "fee_above_limit");
    const me = opted(world, "my account");
    await alice.retry(plan?.planId as string, {
      selfRelay: me,
      confirm: confirmAll,
      networkFeeCaps: CAPS,
    });
    assert.deepEqual(me.asked, ["tx", "bump"]);
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
    const plans = await alice.plans();
    assert.equal(plans.find((p) => p.state === "settled")?.lastError, undefined);
  });
});

describe("a signer that throws on the fee bump", () => {
  it("keeps the self-relayed plan and its notes, refuses a new unshield beside it, and pays once on retry", async () => {
    const world = await createWorld();
    const alice = await fundedWallet(world);
    simulate(world, HIGH);
    world.rpc.calls = [];
    const merchant = world.signer("merchant").publicKey;
    const throwing = opted(world, "my account", {
      onBump: () => {
        throw new Error("unsupported envelope type");
      },
    });
    const err = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: throwing,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    assert.ok(isError("signer_mismatch")(err), String(err));
    assert.equal(details(err)["feeBump"], true);
    assert.equal(world.rpc.calls.filter((m) => m === "sendTransaction").length, 0);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.txHash, undefined);
    assert.equal(plan?.lastError?.code, "signer_mismatch");
    assert.equal(plan?.lastError?.message, "the signer could not sign the fee bump");
    const again = await caught(
      alice.unshield({
        to: merchant,
        amount: 10n * XLM,
        selfRelay: opted(world, "my account"),
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    assert.ok(isError("operation_open")(again), String(again));
    await alice.retry(plan?.planId as string, {
      selfRelay: opted(world, "my account"),
      confirm: confirmAll,
      networkFeeCaps: CAPS,
    });
    await alice.sync();
    assert.equal(paidTo(world, merchant), 10n * XLM);
    assert.equal(world.rpc.bumps.length, 1);
  });

  it("voids a deposit whose fee bump the signer could not sign, so the next one goes", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    simulate(world, HIGH);
    const throwing = opted(world, "alice depositor", {
      onBump: () => {
        throw new Error("unsupported envelope type");
      },
    });
    const err = await caught(
      alice.shield({ amount: 10n * XLM, signer: throwing, networkFeeCaps: CAPS }),
    );
    assert.ok(isError("signer_mismatch")(err), String(err));
    assert.equal((await alice.deposits())[0]?.state, "failed");
    await alice.shield({
      amount: 10n * XLM,
      signer: opted(world, "alice depositor"),
      networkFeeCaps: CAPS,
    });
    assert.equal(world.vault.pending.size, 1);
  });
});

describe("a fee bump followed through a rate-limited RPC", () => {
  it("keeps the plan submitted under the inner hash, sends nothing more, and links its queued exit once a sync finds it", async () => {
    const world = await createWorld({ limits: SMALL });
    const limited = { on: false };
    const primary: FetchLike = async (input, init) => {
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (limited.on && new URL(input).origin === RPC && body?.method === "getTransaction") {
        limited.on = false;
        return new Response(JSON.stringify({}), { status: 429 });
      }
      return world.fetch(input, init);
    };
    const alice = await openWallet({ ...world, fetch: primary }, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    simulate(world, HIGH);
    const me = opted(world, "my account");
    const handle = world.rpc.handle.bind(world.rpc);
    world.rpc.handle = (method: string, params: Record<string, unknown>): unknown => {
      const reply = handle(method, params);
      if (method === "sendTransaction") limited.on = true;
      return reply;
    };
    const merchant = world.signer("merchant").publicKey;
    const err = await caught(
      alice.unshield({
        to: merchant,
        amount: 25n * XLM,
        selfRelay: me,
        confirm: confirmAll,
        networkFeeCaps: CAPS,
      }),
    );
    assert.ok(isError("rpc_error")(err), String(err));
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.txHash, hashOf(me.inner[0]));
    world.rpc.handle = handle;
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "queued");
    assert.equal(plan?.exitId, 1);
    assert.equal(plan?.txHash, hashOf(world.rpc.bumps[0]));
    assert.equal(plan?.lastError, undefined);
    assert.deepEqual(me.asked, ["tx", "bump"]);
  });
});

// An RPC that finds a fee bump by its own hash only, not by the hash of the transaction inside.
function outerOnly(world: World, fetch: FetchLike = world.fetch): FetchLike {
  const inner = new Set<string>();
  return async (input, init) => {
    const body =
      init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
    if (body?.method === "sendTransaction") {
      const env = TransactionBuilder.fromXDR(body.params.transaction, passphraseOf(world));
      if (env instanceof FeeBumpTransaction) inner.add(hashOf(env.innerTransaction));
    }
    if (body?.method === "getTransaction" && inner.has(body.params.hash)) {
      const result = { status: "NOT_FOUND", latestLedger: world.vault.ledger, oldestLedger: 1 };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
    }
    return fetch(input, init);
  };
}

describe("an RPC that finds fee bumps by their own hash only", () => {
  it("finds a restore's own fee bump that landed", async () => {
    const world = await archivedWorld();
    const donor = opted(world, "donor");
    const restore = await caught(
      PrivateWallet.restoreVault(donor, {
        ...restoreOptions(world, { sleep: ticking(world) }),
        fetch: outerOnly(world),
      }),
    );
    assert.equal(world.rpc.archived.size, 0);
    assert.equal(world.rpc.bumps.length, 1);
    assert.equal(restore, undefined, `the restore that landed was reported as ${String(restore)}`);
  });

  it("releases once at a ledger bound, and does not pay for a second release", async () => {
    const world = await createWorld();
    const alice = await openWallet({ ...world, fetch: outerOnly(world) }, 0, undefined, undefined, {
      sleep: async (ms) => world.advance(Math.ceil(ms / 1000)),
    });
    world.rpc.ttl.set(id(instanceOf(world)), world.vault.ledger + 3);
    // The release extends the instance as it lands.
    world.rpc.beforeApply = () => world.rpc.ttl.delete(id(instanceOf(world)));
    simulate(world, HIGH);
    const anyone = opted(world, "anyone");
    const err = await caught(alice.releaseExits(anyone, 10, CAPS));
    assert.equal(
      world.rpc.bumps.length,
      1,
      `paid for ${world.rpc.bumps.length} releases; the call ended in ${String(err)}`,
    );
    assert.equal(err, undefined, String(err));
  });
});
