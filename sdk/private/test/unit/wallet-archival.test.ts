import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Address, Keypair, type Transaction, nativeToScVal, xdr } from "@stellar/stellar-base";
import { hexToBytes } from "../../src/bytes.ts";
import { CyphrasError } from "../../src/errors.ts";
import type { NetworkFee, TransactionSigner } from "../../src/vault/invoke.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");

const vaultData = (world: World, name: string): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(world.vault.address).toScAddress(),
      key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name)]),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const instanceOf = (contract: string): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key: xdr.ScVal.scvLedgerKeyContractInstance(),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const codeOf = (world: World): xdr.LedgerKey =>
  xdr.LedgerKey.contractCode(
    new xdr.LedgerKeyContractCode({
      hash: hexToBytes(world.vault.wasmHash) as unknown as ReturnType<
        xdr.LedgerKeyContractCode["hash"]
      >,
    }),
  );

const balanceOf = (world: World, holder: string): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(world.deployment.asset.contract).toScAddress(),
      key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Balance"), new Address(holder).toScVal()]),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const exitAt = (world: World, n: bigint): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(world.vault.address).toScAddress(),
      key: xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Exit"), xdr.ScVal.scvU64(new xdr.Uint64(n))]),
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const accountOf = (address: string): xdr.LedgerKey =>
  xdr.LedgerKey.account(
    new xdr.LedgerKeyAccount({ accountId: Keypair.fromPublicKey(address).xdrAccountId() }),
  );

// An entry of contract data the mock models no other way, with any value.
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

async function funded() {
  const world = await createWorld();
  const alice = await openWallet(world, 0);
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  return { world, alice };
}

// The user's own account, which shows every fee to `agree` and keeps what it was shown.
function payer(
  world: World,
  shown: NetworkFee[],
  agree: (fee: NetworkFee) => boolean = () => true,
): TransactionSigner {
  const account = world.signer("my account");
  return {
    publicKey: account.publicKey,
    signTransaction: (x, p) => account.signTransaction(x, p),
    confirmFee: (fee) => {
      shown.push(fee);
      return agree(fee);
    },
  };
}

// A simulation that reads and writes the vault's instance and roots, for `fee` stroops.
function simulate(world: World, fee: number, readOnly: xdr.LedgerKey[] = []): void {
  world.rpc.simulated = {
    readOnly,
    readWrite: [instanceOf(world.vault.address), vaultData(world, "Roots")],
    instructions: 1_000_000,
    readBytes: 1_000,
    writeBytes: 1_000,
    fee,
  };
}

const unshield = (world: World, alice: PrivateWallet, signer: TransactionSigner) =>
  alice.unshield({
    to: world.signer("merchant").publicKey,
    amount: 10n * XLM,
    selfRelay: signer,
    confirm: confirmAll,
  });

const sentOps = (world: World): string[] =>
  world.rpc.sent.map((tx: Transaction) => {
    const op = tx.operations[0];
    return op?.type === "invokeHostFunction"
      ? op.func.invokeContract().functionName().toString()
      : (op?.type ?? "none");
  });

const sorobanOf = (tx: Transaction | undefined) => tx?.toEnvelope().v1().tx().ext().sorobanData();

const marksOf = (tx: Transaction | undefined): number[] => {
  const ext = sorobanOf(tx)?.ext();
  return ext?.switch() === 1 ? ext.resourceExt().archivedSorobanEntries() : [];
};

const details = (err: unknown): CyphrasError["details"] =>
  err instanceof CyphrasError ? err.details : {};

describe("self-relay with archived vault entries", () => {
  it("names a restore above the cap, and lands it with a raised restore cap", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    world.rpc.archived.add(id(instance));
    simulate(world, 1_110_000_000);
    const shown: NetworkFee[] = [];
    let caught: unknown;
    await unshield(world, alice, payer(world, shown)).catch((err: unknown) => {
      caught = err;
    });
    assert.ok(isError("fee_above_cap")(caught));
    assert.equal(details(caught)["reason"], "restore");
    assert.equal(details(caught)["entries"], "instance");
    assert.ok(BigInt(details(caught)["resource"] as string) > 1_110_000_000n);
    assert.deepEqual(sentOps(world), []);
    const planId = details(caught)["planId"] as string;
    assert.equal((await alice.plans())[0]?.state, "prepared");
    await alice.retry(planId, {
      selfRelay: payer(world, shown),
      networkFeeCaps: { restore: 200n * XLM },
      confirm: confirmAll,
    });
    assert.deepEqual(sentOps(world), ["transact"]);
    assert.equal(shown[0]?.reason, "restore");
    assert.deepEqual(shown[0]?.entries, ["instance"]);
    // The simulation's mark stays on the instance, which the network restored.
    const tx = world.rpc.sent[0];
    assert.deepEqual(marksOf(tx), [0]);
    assert.equal(
      id(sorobanOf(tx)?.resources().footprint().readWrite()[0] as xdr.LedgerKey),
      id(instance),
    );
    assert.equal(world.rpc.archived.has(id(instance)), false);
  });

  it("keeps the simulation's marks through the room and padding of a queued exit", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 5_000n * XLM;
    const instance = instanceOf(world.vault.address);
    const merchant = world.signer("merchant").publicKey;
    world.rpc.archived.add(id(instance));
    world.rpc.simulated = {
      readOnly: [accountOf(merchant)],
      readWrite: [exitAt(world, 1n), instance],
      instructions: 1_000_000,
      readBytes: 300,
      writeBytes: 300,
      fee: 1_000,
    };
    await unshield(world, alice, payer(world, []));
    const data = sorobanOf(world.rpc.sent[0]);
    const readWrite = data?.resources().footprint().readWrite() ?? [];
    // The account moved from the read entries to the end of the written ones; the mark still
    // names the instance.
    assert.equal(id(readWrite[readWrite.length - 1] as xdr.LedgerKey), id(accountOf(merchant)));
    assert.deepEqual(marksOf(world.rpc.sent[0]), [1]);
    assert.equal(id(readWrite[1] as xdr.LedgerKey), id(instance));
  });

  it("marks an archived balance the room adds beyond the simulation, and pays its restore", async () => {
    const { world, alice } = await funded();
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 5_000n * XLM;
    const balance = balanceOf(world, world.vault.address);
    world.rpc.extraEntries.set(
      id(balance),
      dataEntry(balance, nativeToScVal(1n, { type: "i128" })),
    );
    world.rpc.archived.add(id(balance));
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [exitAt(world, 1n)],
      instructions: 1_000_000,
      readBytes: 300,
      writeBytes: 300,
      fee: 1_000,
    };
    const shown: NetworkFee[] = [];
    await unshield(world, alice, payer(world, shown));
    const tx = world.rpc.sent[0];
    const readWrite = sorobanOf(tx)?.resources().footprint().readWrite() ?? [];
    assert.equal(id(readWrite[1] as xdr.LedgerKey), id(balance));
    assert.deepEqual(marksOf(tx), [1]);
    assert.equal(shown[0]?.reason, "restore");
    assert.deepEqual(shown[0]?.entries, ["asset Balance"]);
    // Its read from disk and its write join the room's.
    assert.ok((sorobanOf(tx)?.resources().diskReadBytes() ?? 0) > 300 + 2048);
    assert.equal(world.rpc.archived.has(id(balance)), false);
  });

  it("sends the RestoreFootprint the RPC asks for first, then the call on a fresh simulation", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    world.rpc.archived.add(id(instance));
    world.rpc.preambleNext = [instance];
    simulate(world, 1_000);
    const shown: NetworkFee[] = [];
    await unshield(world, alice, payer(world, shown));
    assert.deepEqual(sentOps(world), ["restoreFootprint", "transact"]);
    assert.deepEqual(
      shown.map((f) => [f.reason, f.entries]),
      [
        ["restore", ["instance"]],
        ["network", []],
      ],
    );
    assert.equal(world.rpc.archived.has(id(instance)), false);
    assert.equal((await alice.plans())[0]?.state, "submitted");
  });

  it("fails with restore_failed when the RestoreFootprint fails, and sends no call", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    world.rpc.archived.add(id(instance));
    world.rpc.preambleNext = [instance];
    world.rpc.restoreFailNext = 1;
    simulate(world, 1_000);
    let caught: unknown;
    await unshield(world, alice, payer(world, [])).catch((err: unknown) => {
      caught = err;
    });
    assert.ok(isError("restore_failed")(caught));
    assert.equal(typeof details(caught)["hash"], "string");
    assert.deepEqual(sentOps(world), ["restoreFootprint"]);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.mustRetry, true);
  });

  it("refuses a restore whose fee is above the restore cap before signing", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    world.rpc.archived.add(id(instance));
    world.rpc.preambleNext = [instance];
    world.rpc.restoreFee = 500_000_000;
    simulate(world, 1_000);
    let caught: unknown;
    await unshield(world, alice, payer(world, [])).catch((err: unknown) => {
      caught = err;
    });
    assert.ok(isError("fee_above_cap")(caught));
    assert.equal(details(caught)["reason"], "restore");
    assert.deepEqual(sentOps(world), []);
  });

  it("refuses a simulation that marks entries outside its read-write footprint", async () => {
    for (const marks of [[5], [1, 0], [0, 0], [2]]) {
      const { world, alice } = await funded();
      simulate(world, 1_000);
      const readWrite = world.rpc.simulated?.readWrite ?? [];
      // A mark on an entry that is not persistent is refused as the network refuses it.
      readWrite.push(accountOf(world.signer("merchant").publicKey));
      world.rpc.simulatedMarks = marks;
      await assert.rejects(unshield(world, alice, payer(world, [])), isError("rpc_error"));
      assert.deepEqual(sentOps(world), [], String(marks));
    }
  });

  it("sends nothing when the user declines a restore's fee, and keeps the error with the plan", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(instanceOf(world.vault.address)));
    simulate(world, 1_000);
    const shown: NetworkFee[] = [];
    await assert.rejects(
      unshield(
        world,
        alice,
        payer(world, shown, (fee) => fee.reason !== "restore"),
      ),
      isError("not_confirmed"),
    );
    assert.equal(shown[0]?.reason, "restore");
    assert.deepEqual(sentOps(world), []);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
  });

  it("drops a call at an archival edge with a ledger bound, and sends it again restoring the entry", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    const edge = world.vault.ledger + 3;
    world.rpc.ttl.set(id(instance), edge);
    simulate(world, 1_000);
    world.rpc.beforeApply = () => {
      world.vault.ledger += 10;
    };
    const shown: NetworkFee[] = [];
    await unshield(world, alice, payer(world, shown));
    assert.deepEqual(sentOps(world), ["transact", "transact"]);
    assert.equal(world.rpc.sent[0]?.ledgerBounds?.maxLedger, edge + 1);
    assert.deepEqual(marksOf(world.rpc.sent[1]), [0]);
    assert.equal(world.rpc.sent[1]?.ledgerBounds, undefined);
    assert.deepEqual(
      shown.map((f) => f.reason),
      ["rent", "restore"],
    );
    assert.equal(world.rpc.archived.has(id(instance)), false);
  });

  it("goes once more after a failure on an archived entry, and no further", async () => {
    const { world, alice } = await funded();
    simulate(world, 1_000);
    world.rpc.archiveNext = 1;
    await unshield(world, alice, payer(world, []));
    assert.deepEqual(sentOps(world), ["transact", "transact"]);
    world.rpc.archiveNext = 2;
    let caught: unknown;
    await unshield(world, alice, payer(world, [])).catch((err: unknown) => {
      caught = err;
    });
    assert.ok(isError("transaction_failed")(caught));
    assert.equal(details(caught)["archived"], true);
    assert.equal(sentOps(world).length, 4);
  });

  it("leaves a payment its notes when the restore lands past the call's deadline", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    world.rpc.archived.add(id(instance));
    world.rpc.preambleNext = [instance];
    simulate(world, 1_000);
    world.rpc.beforeApply = () => {
      world.vault.ledger += 200;
    };
    let caught: unknown;
    await unshield(world, alice, payer(world, [])).catch((err: unknown) => {
      caught = err;
    });
    assert.ok(isError("transaction_failed")(caught));
    assert.equal(details(caught)["vaultError"], "Expired");
    assert.deepEqual(sentOps(world), ["restoreFootprint"]);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    // A new proof with the same notes lands.
    await alice.retry(plan?.planId as string, { selfRelay: payer(world, []), confirm: confirmAll });
    assert.deepEqual(sentOps(world), ["restoreFootprint", "transact"]);
  });

  it("names the rent of vault entries close to archival, and pays it within a raised cap", async () => {
    const { world, alice } = await funded();
    const instance = instanceOf(world.vault.address);
    world.rpc.ttl.set(id(instance), world.vault.ledger + 10 * 17_280);
    simulate(world, 20_000_000);
    let caught: unknown;
    await unshield(world, alice, payer(world, [])).catch((err: unknown) => {
      caught = err;
    });
    assert.ok(isError("fee_above_cap")(caught));
    assert.equal(details(caught)["reason"], "rent");
    assert.equal(details(caught)["entries"], "instance");
    const shown: NetworkFee[] = [];
    await alice.retry(details(caught)["planId"] as string, {
      selfRelay: payer(world, shown),
      networkFeeCaps: { restore: 2n * XLM },
      confirm: confirmAll,
    });
    assert.equal(shown[0]?.reason, "rent");
    assert.deepEqual(sentOps(world), ["transact"]);
  });

  it("restores an archived instance for a shield within the shield's own raised cap", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    world.rpc.archived.add(id(instanceOf(world.vault.address)));
    simulate(world, 300_000_000);
    const depositor = world.signer("alice depositor");
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: depositor }),
      (err: unknown) => isError("fee_above_cap")(err) && details(err)["reason"] === "restore",
    );
    await alice.shield({
      amount: 10n * XLM,
      signer: depositor,
      networkFeeCaps: { restore: 50n * XLM },
    });
    assert.deepEqual(sentOps(world), ["shield"]);
    assert.deepEqual(marksOf(world.rpc.sent[0]), [0]);
  });
});

describe("restoreVault", () => {
  it("restores the vault's archived entries with one RestoreFootprint within the restore cap", async () => {
    const world = await createWorld();
    const code = codeOf(world);
    const frontier = vaultData(world, "Frontier");
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
    world.rpc.extraEntries.set(id(frontier), dataEntry(frontier, xdr.ScVal.scvVec([])));
    world.rpc.extraEntries.set(
      id(balance),
      dataEntry(balance, nativeToScVal(1n, { type: "i128" })),
    );
    for (const key of [code, instanceOf(world.vault.address), vaultData(world, "Roots")]) {
      world.rpc.archived.add(id(key));
    }
    world.rpc.restoreFee = 1_080_000_000;
    const options = {
      deployment: world.deployment,
      allowUnpinnedDeployment: true,
      rpcUrl: RPC,
      fetch: world.fetch,
      clock: world.clock,
      sleep: async () => {},
    };
    const donor = world.signer("donor");
    await assert.rejects(
      PrivateWallet.restoreVault(donor, options),
      (err: unknown) => isError("fee_above_cap")(err) && details(err)["reason"] === "restore",
    );
    assert.deepEqual(sentOps(world), []);
    const restore = await PrivateWallet.restoreVault(donor, {
      ...options,
      networkFeeCaps: { restore: 110n * XLM },
    });
    assert.deepEqual(restore.restored, ["code", "instance", "Roots"]);
    assert.equal(typeof restore.txHash, "string");
    assert.deepEqual(sentOps(world), ["restoreFootprint"]);
    assert.equal(world.rpc.archived.size, 0);
    // Nothing archived, nothing sent.
    assert.deepEqual(await PrivateWallet.restoreVault(donor, options), {
      txHash: undefined,
      restored: [],
    });
    assert.equal(sentOps(world).length, 1);
  });
});
