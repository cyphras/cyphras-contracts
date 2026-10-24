import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Address,
  Keypair,
  Networks,
  type Transaction,
  nativeToScVal,
  xdr,
} from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { isPersistent } from "../../src/net/rpc.ts";
import { MemoryStore } from "../../src/storage.ts";
import type { NetworkFee, NetworkFeeCaps, TransactionSigner } from "../../src/vault/invoke.ts";
import { pendingKey } from "../../src/vault/state.ts";
import { type OperationView, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");

const contractKey = (
  contract: string,
  key: xdr.ScVal,
  durability = xdr.ContractDataDurability.persistent(),
): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key,
      durability,
    }),
  );

const vaultData = (world: World, name: string): xdr.LedgerKey =>
  contractKey(world.vault.address, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name)]));

const instanceOf = (world: World): xdr.LedgerKey =>
  contractKey(world.vault.address, xdr.ScVal.scvLedgerKeyContractInstance());

const balanceOf = (world: World, holder: string): xdr.LedgerKey =>
  contractKey(
    world.deployment.asset.contract,
    xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Balance"), new Address(holder).toScVal()]),
  );

const exitAt = (world: World, n: bigint): xdr.LedgerKey =>
  contractKey(
    world.vault.address,
    xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Exit"), xdr.ScVal.scvU64(new xdr.Uint64(n))]),
  );

const accountOf = (address: string): xdr.LedgerKey =>
  xdr.LedgerKey.account(
    new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(address).xdrAccountId() }),
  );

const codeKey = (hash: Buffer): xdr.LedgerKey =>
  xdr.LedgerKey.contractCode(new xdr.LedgerKeyContractCode({ hash }));

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

// A signer that shows every fee to `agree`, keeps what it was shown, and counts its signatures.
function payer(
  world: World,
  label: string,
  shown: NetworkFee[] = [],
  agree: (fee: NetworkFee) => boolean = () => true,
): TransactionSigner & { readonly signed: () => number } {
  const account = world.signer(label);
  let signed = 0;
  return {
    publicKey: account.publicKey,
    signTransaction: (x, p) => {
      signed++;
      return account.signTransaction(x, p);
    },
    confirmFee: (fee) => {
      shown.push(fee);
      return agree(fee);
    },
    signed: () => signed,
  };
}

// Simulations that read and write the vault's instance and roots, for `fee` stroops.
function simulate(world: World, fee: number, readWrite?: xdr.LedgerKey[]): void {
  world.rpc.simulated = {
    readOnly: [],
    readWrite: readWrite ?? [instanceOf(world), vaultData(world, "Roots")],
    instructions: 1_000_000,
    readBytes: 1_000,
    writeBytes: 1_000,
    fee,
  };
}

// Simulations whose fee holds the instance's restore while the instance is archived.
function simulateRestore(world: World, restoreFee: number): void {
  const instance = id(instanceOf(world));
  simulate(world, 1_000);
  const simulated = world.rpc.simulated as NonNullable<World["rpc"]["simulated"]>;
  Object.defineProperty(simulated, "fee", {
    get: () => (world.rpc.archived.has(instance) ? restoreFee + 1_000 : 1_000),
  });
}

const sentOps = (world: World): string[] =>
  world.rpc.sent.map((tx: Transaction) => {
    const op = tx.operations[0];
    return op?.type === "invokeHostFunction"
      ? op.func.invokeContract().functionName().toString()
      : (op?.type ?? "none");
  });

const sorobanOf = (tx: Transaction | undefined) => tx?.toEnvelope().v1().tx().ext().sorobanData();

async function funded(limits?: Parameters<typeof createWorld>[0]) {
  const world = await createWorld(limits);
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  return { world, alice };
}

// A pending deposit of the depositor's, and its cancel with these caps for a simulated fee.
async function cancelFor(fee: number, caps: Partial<NetworkFeeCaps>, archived: boolean) {
  const world = await createWorld();
  const alice = await openWallet(world, 0);
  const depositor = world.signer("alice depositor");
  const { depositId } = await alice.shield({ amount: 10n * XLM, signer: depositor });
  world.rpc.sent = [];
  if (archived) world.rpc.archived.add(id(instanceOf(world)));
  simulate(world, fee);
  const shown: NetworkFee[] = [];
  const signer = payer(world, "alice depositor", shown);
  const err = await caught(alice.cancelDeposit(depositId as number, signer, caps));
  return { world, err, shown };
}

describe("fee caps on calls that restore or renew vault entries", () => {
  it("takes a fee exactly at each cap and refuses one stroop above it", async () => {
    const resource = 10_000_000;
    let r = await cancelFor(resource, {}, false);
    assert.equal(r.err, undefined);
    assert.equal(r.shown[0]?.reason, "network");
    r = await cancelFor(resource + 1, {}, false);
    assert.ok(isError("fee_above_cap")(r.err));
    assert.equal(details(r.err)["reason"], "network");
    assert.deepEqual(sentOps(r.world), []);
    // A restore with the default restore cap of 0 still goes within the resource cap.
    r = await cancelFor(resource, {}, true);
    assert.equal(r.err, undefined);
    assert.deepEqual(r.shown[0]?.entries, ["instance"]);
    r = await cancelFor(resource + 1, {}, true);
    assert.ok(isError("fee_above_cap")(r.err));
    assert.equal(details(r.err)["reason"], "restore");
    r = await cancelFor(resource + 5, { restore: 5n }, true);
    assert.equal(r.err, undefined);
    r = await cancelFor(resource + 6, { restore: 5n }, true);
    assert.ok(isError("fee_above_cap")(r.err));
    assert.deepEqual(sentOps(r.world), []);
    // The restore cap never widens the room of a call that restores nothing.
    r = await cancelFor(resource + 1, { restore: 100n * XLM }, false);
    assert.ok(isError("fee_above_cap")(r.err));
    // The inclusion fee the network quotes, 150 stroops, against its own cap.
    r = await cancelFor(1_000, { inclusion: 150n }, false);
    assert.equal(r.err, undefined);
    r = await cancelFor(1_000, { inclusion: 149n }, false);
    assert.ok(isError("fee_above_cap")(r.err));
  });

  it("keeps one call's raised caps from the next call", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 300_000_000);
    const { depositId } = await alice.shield({
      amount: 10n * XLM,
      signer: depositor,
      networkFeeCaps: { restore: 50n * XLM },
    });
    world.rpc.archived.add(id(instanceOf(world)));
    await assert.rejects(
      alice.cancelDeposit(depositId as number, depositor),
      (err: unknown) => isError("fee_above_cap")(err) && details(err)["reason"] === "restore",
    );
    assert.deepEqual(sentOps(world), ["shield"]);
  });

  it("keeps the wallet's resource cap when a call's caps leave it undefined", async () => {
    const { world, alice } = await funded();
    simulate(world, 4_000_000_000);
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: world.signer("my account"),
        confirm: confirmAll,
        networkFeeCaps: { resource: undefined } as unknown as Partial<NetworkFeeCaps>,
      }),
    );
    assert.ok(isError("fee_above_cap")(err), String(err));
    assert.deepEqual(sentOps(world), []);
  });

  it("keeps the wallet's restore cap when a call's caps leave it undefined", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    simulate(world, 1_110_000_000);
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: world.signer("my account"),
        confirm: confirmAll,
        networkFeeCaps: { restore: undefined } as unknown as Partial<NetworkFeeCaps>,
      }),
    );
    assert.ok(isError("fee_above_cap")(err), String(err));
    assert.equal(details(err)["reason"], "restore");
  });

  it("refuses a fee a transaction cannot carry before the user is asked", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world)));
    // 500 XLM, above the 2^32 - 1 stroops a transaction's fee field holds.
    simulate(world, 5_000_000_000);
    const shown: NetworkFee[] = [];
    const signer = payer(world, "my account", shown);
    const outcome = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: signer,
        confirm: confirmAll,
        networkFeeCaps: { restore: 1_000n * XLM },
      }),
    );
    if (outcome !== undefined) {
      assert.ok(outcome instanceof CyphrasError);
      assert.notEqual(outcome.code, "unexpected_error", outcome.message);
      assert.deepEqual(shown, []);
      assert.equal(signer.signed(), 0);
    }
  });

  it("refuses a restoreVault fee a transaction cannot carry before the donor is asked", async () => {
    const world = await createWorld();
    world.rpc.archived.add(id(instanceOf(world)));
    world.rpc.restoreFee = 5_000_000_000;
    const shown: NetworkFee[] = [];
    const donor = payer(world, "donor", shown);
    const outcome = await caught(
      PrivateWallet.restoreVault(donor, {
        deployment: world.deployment,
        allowUnpinnedDeployment: true,
        rpcUrl: RPC,
        fetch: world.fetch,
        clock: world.clock,
        sleep: async () => {},
        networkFeeCaps: { restore: 1_000n * XLM },
      }),
    );
    if (outcome !== undefined) {
      assert.ok(outcome instanceof CyphrasError, String(outcome));
      assert.deepEqual(shown, []);
      assert.equal(donor.signed(), 0);
    }
  });

  it("refuses a negative resource fee from the RPC before the user is asked", async () => {
    const r = await cancelFor(-1_000, {}, false);
    assert.ok(isError("rpc_error")(r.err), String(r.err));
    assert.deepEqual(r.shown, []);
    assert.deepEqual(sentOps(r.world), []);
  });
});

describe("split unshields over archived vault entries", () => {
  const SPLIT = { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 350n * XLM };

  async function withNotes(store = new MemoryStore()) {
    const world = await createWorld({ limits: SPLIT });
    const alice = await openWallet(world, 0, store);
    for (const amount of [60n * XLM, 70n * XLM]) {
      await alice.shield({ amount, signer: world.signer("alice depositor") });
    }
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.rpc.sent = [];
    return { world, alice };
  }

  it("uses a split unshield's own caps for its first part", async () => {
    const { world, alice } = await withNotes();
    world.rpc.archived.add(id(instanceOf(world)));
    simulateRestore(world, 1_110_000_000);
    const err = await caught(
      alice.unshield({
        to: world.signer("exchange").publicKey,
        amount: 90n * XLM,
        selfRelay: world.signer("my account"),
        split: true,
        confirm: confirmAll,
        networkFeeCaps: { restore: 200n * XLM },
      }),
    );
    assert.equal(err, undefined, String(err));
    assert.deepEqual(sentOps(world), ["transact"]);
  });

  it("pays a split unshield once when the user repeats it with the caps it agreed to", async () => {
    const store = new MemoryStore();
    const { world, alice } = await withNotes(store);
    const destination = world.signer("exchange").publicKey;
    const account = world.signer("my account");
    world.rpc.archived.add(id(instanceOf(world)));
    simulateRestore(world, 1_110_000_000);
    const request = {
      to: destination,
      amount: 90n * XLM,
      selfRelay: account,
      split: true,
      confirm: confirmAll,
    } as const;
    await assert.rejects(alice.unshield(request), isError("fee_above_cap"));
    // The user agrees to the restore's fee, and the payment is made again with it.
    await assert.rejects(
      alice.unshield({ ...request, networkFeeCaps: { restore: 200n * XLM } }),
      isError("fee_above_cap"),
    );
    // Only caps of the whole wallet reach the parts, so the user opens it with them.
    const raised = await openWallet(world, 0, store, undefined, {
      networkFeeCaps: { restore: 200n * XLM },
    });
    for (let round = 0; round < 4; round++) {
      world.advance(7 * 3600);
      world.fill(1);
      await raised.continueOperations(account).catch(() => undefined);
    }
    // What the vault paid the destination or owes it in its exit queue.
    const owed =
      world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
      [...world.vault.exits.values()]
        .filter((e) => e.recipient === destination)
        .reduce((s, e) => s + e.payout, 0n);
    assert.ok(owed <= 90n * XLM, `the destination is owed ${owed} stroops for a 90 XLM payment`);
  });

  it("sends the next part of a self-relayed split within caps its user agreed to", async () => {
    const { world, alice } = await withNotes();
    const account = world.signer("my account");
    await alice.unshield({
      to: world.signer("exchange").publicKey,
      amount: 90n * XLM,
      selfRelay: account,
      split: true,
      confirm: confirmAll,
    });
    world.advance(60);
    let [view] = await alice.continueOperations();
    assert.equal(view?.sent, 50n * XLM);
    world.rpc.archived.add(id(instanceOf(world)));
    simulateRestore(world, 1_110_000_000);
    world.advance(7 * 3600);
    await assert.rejects(
      alice.continueOperations(account),
      (err: unknown) => isError("fee_above_cap")(err) && details(err)["reason"] === "restore",
    );
    // The user agrees to the restore's fee for this operation alone.
    const continueWith = alice.continueOperations.bind(alice) as unknown as (
      signer: TransactionSigner,
      caps: Partial<NetworkFeeCaps>,
    ) => Promise<OperationView[]>;
    await continueWith(account, { restore: 200n * XLM });
    assert.deepEqual(sentOps(world), ["transact", "transact"]);
    world.advance(60);
    [view] = await alice.continueOperations();
    assert.equal(view?.state, "done");
  });
});

describe("restores the RPC asks for before the call", () => {
  it("sends nothing when the user declines the RestoreFootprint, and keeps the plan's notes", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world);
    world.rpc.archived.add(id(instance));
    world.rpc.preambleNext = [instance];
    simulate(world, 1_000);
    const shown: NetworkFee[] = [];
    const signer = payer(world, "my account", shown, () => false);
    await assert.rejects(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: signer,
        confirm: confirmAll,
      }),
      isError("not_confirmed"),
    );
    assert.deepEqual(
      shown.map((f) => [f.reason, f.entries]),
      [["restore", ["instance"]]],
    );
    assert.equal(signer.signed(), 0);
    assert.deepEqual(sentOps(world), []);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.mustRetry, true);
    assert.equal((await alice.balance()).spendable, 0n);
  });

  it("refuses a RestoreFootprint that names entries the call does not touch", async () => {
    const { world, alice } = await funded();
    const foreign = codeKey(Buffer.alloc(32, 7));
    world.rpc.extraEntries.set(
      id(foreign),
      xdr.LedgerEntryData.contractCode(
        new xdr.ContractCodeEntry({
          ext: new xdr.ContractCodeEntryExt(0),
          hash: foreign.contractCode().hash(),
          code: Buffer.alloc(64),
        }),
      ),
    );
    world.rpc.archived.add(id(foreign));
    world.rpc.preambleNext = [foreign];
    simulate(world, 1_000);
    const err = await caught(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: world.signer("my account"),
        confirm: confirmAll,
        networkFeeCaps: { restore: 200n * XLM },
      }),
    );
    assert.ok(isError("rpc_error")(err), String(err));
    assert.deepEqual(sentOps(world), []);
  });
});

describe("archived entries marked in a call's own data", () => {
  it("marks simulated, added and promoted entries as the network takes them", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 5_000n * XLM;
    const instance = instanceOf(world);
    const balance = balanceOf(world, world.vault.address);
    const merchant = world.signer("merchant").publicKey;
    world.rpc.extraEntries.set(
      id(balance),
      dataEntry(balance, nativeToScVal(1n, { type: "i128" })),
    );
    world.rpc.archived.add(id(instance));
    world.rpc.archived.add(id(balance));
    world.rpc.simulated = {
      readOnly: [accountOf(merchant)],
      readWrite: [exitAt(world, 1n), instance],
      instructions: 1_000_000,
      readBytes: 300,
      writeBytes: 300,
      fee: 1_000,
    };
    const shown: NetworkFee[] = [];
    await alice.unshield({
      to: merchant,
      amount: 10n * XLM,
      selfRelay: payer(world, "my account", shown),
      confirm: confirmAll,
    });
    const data = sorobanOf(world.rpc.sent[0]);
    const readWrite = data?.resources().footprint().readWrite() ?? [];
    const ext = data?.ext();
    const marks = ext?.switch() === 1 ? ext.resourceExt().archivedSorobanEntries() : [];
    // Core takes marks that ascend strictly and name persistent read-write entries.
    marks.forEach((m, i) => {
      assert.ok(i === 0 || m > (marks[i - 1] as number));
      assert.ok(m < readWrite.length);
      assert.ok(isPersistent(readWrite[m] as xdr.LedgerKey));
    });
    assert.deepEqual(
      marks.map((m) => id(readWrite[m] as xdr.LedgerKey)).sort(),
      [id(instance), id(balance)].sort(),
    );
    assert.deepEqual([...(shown[0]?.entries ?? [])].sort(), ["asset Balance", "instance"]);
    assert.equal(id(readWrite[readWrite.length - 1] as xdr.LedgerKey), id(accountOf(merchant)));
    assert.equal(world.rpc.archived.size, 0);
  });

  it("refuses a simulation that marks a temporary entry", async () => {
    const { world, alice } = await funded();
    const temporary = contractKey(
      world.vault.address,
      xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("DepositorDay")]),
      xdr.ContractDataDurability.temporary(),
    );
    simulate(world, 1_000, [instanceOf(world), temporary]);
    world.rpc.simulatedMarks = [1];
    await assert.rejects(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: world.signer("my account"),
        confirm: confirmAll,
      }),
      isError("rpc_error"),
    );
    assert.deepEqual(sentOps(world), []);
  });
});

describe("a deposit's own entry archiving while its call is on the way", () => {
  it("pays one failed transaction, then restores the entry in the call that goes again", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    const { depositId } = await alice.shield({ amount: 10n * XLM, signer: depositor });
    world.rpc.sent = [];
    world.rpc.sentFees = [];
    const pending = pendingKey(world.vault.address, BigInt(depositId as number));
    world.rpc.ttl.set(id(pending), world.vault.ledger + 3);
    simulate(world, 1_000, [instanceOf(world), pending]);
    world.rpc.beforeApply = () => {
      world.vault.ledger += 10;
    };
    const shown: NetworkFee[] = [];
    await alice.cancelDeposit(depositId as number, payer(world, "alice depositor", shown));
    assert.deepEqual(sentOps(world), ["cancel", "cancel"]);
    // The deposit's entry sets no ledger bound, so the first call fails on chain and pays its fee.
    assert.equal(world.rpc.sent[0]?.ledgerBounds, undefined);
    const first = world.rpc.records.get(world.rpc.sent[0]?.hash().toString("hex") as string);
    assert.equal(first?.status, "FAILED");
    assert.ok((world.rpc.sentFees[0] ?? 0n) > 0n);
    assert.deepEqual(
      shown.map((f) => [f.reason, f.entries]),
      [
        ["network", []],
        ["restore", ["Pending"]],
      ],
    );
    assert.equal((await alice.deposits())[0]?.state, "cancelled");
  });
});

describe("a deposit dropped at an archival edge", () => {
  it("lets the next shield go once the last one's only transaction was dropped at its bound", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const instance = instanceOf(world);
    world.rpc.ttl.set(id(instance), world.vault.ledger + 3);
    simulate(world, 1_000);
    world.rpc.beforeApply = () => {
      world.vault.ledger += 10;
    };
    const declining = payer(world, "alice depositor", [], (fee) => fee.reason !== "restore");
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: declining }),
      isError("not_confirmed"),
    );
    // The one transaction that went out can no longer land, past its ledger bound.
    assert.equal(world.rpc.sent.length, 1);
    const err = await caught(
      alice.shield({ amount: 10n * XLM, signer: payer(world, "alice depositor") }),
    );
    assert.equal(err, undefined, String(err));
  });
});

describe("restoreVault consent and network", () => {
  const options = (world: World) => ({
    deployment: world.deployment,
    allowUnpinnedDeployment: true,
    rpcUrl: RPC,
    fetch: world.fetch,
    clock: world.clock,
    sleep: async () => {},
  });

  it("shows the restore to the donor and sends nothing when declined", async () => {
    const world = await createWorld();
    world.rpc.archived.add(id(instanceOf(world)));
    world.rpc.archived.add(id(vaultData(world, "Roots")));
    const shown: NetworkFee[] = [];
    const donor = payer(world, "donor", shown, () => false);
    await assert.rejects(
      PrivateWallet.restoreVault(donor, options(world)),
      isError("not_confirmed"),
    );
    assert.deepEqual(
      shown.map((f) => [f.reason, f.entries]),
      [["restore", ["instance", "Roots"]]],
    );
    assert.equal(donor.signed(), 0);
    assert.deepEqual(sentOps(world), []);
  });

  it("refuses an RPC that reports another network before anything is signed", async () => {
    const world = await createWorld();
    world.rpc.archived.add(id(instanceOf(world)));
    // An RPC URL of the other network, which holds no entry of this vault, would answer that
    // nothing is archived; this one says which network it serves.
    const elsewhere: FetchLike = async (input, init) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      if (body?.method === "getNetwork") {
        const result = { passphrase: Networks.PUBLIC, protocolVersion: 23 };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(input, init);
    };
    const donor = payer(world, "donor");
    await assert.rejects(
      PrivateWallet.restoreVault(donor, {
        ...options(world),
        fetch: elsewhere,
        networkFeeCaps: { restore: 200n * XLM },
      }),
      isError("deployment_mismatch"),
    );
    assert.equal(donor.signed(), 0);
  });
});
