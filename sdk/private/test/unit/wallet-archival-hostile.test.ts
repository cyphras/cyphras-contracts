import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Account,
  Address,
  Operation,
  type Transaction,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { MemoryStore } from "../../src/storage.ts";
import type { NetworkFee, NetworkFeeCaps, TransactionSigner } from "../../src/vault/invoke.ts";
import { type OperationView, PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");
const FOREIGN = "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA";

const dataKey = (contract: string, key: xdr.ScVal): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key,
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const vaultData = (world: World, name: string): xdr.LedgerKey =>
  dataKey(
    world.vault.address,
    name === "instance"
      ? xdr.ScVal.scvLedgerKeyContractInstance()
      : xdr.ScVal.scvVec([xdr.ScVal.scvSymbol(name)]),
  );

const foreignData = (): xdr.LedgerKey =>
  dataKey(FOREIGN, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Balance")]));

const foreignCode = (): xdr.LedgerKey =>
  xdr.LedgerKey.contractCode(
    new xdr.LedgerKeyContractCode({
      hash: Buffer.alloc(32, 7) as unknown as ReturnType<xdr.LedgerKeyContractCode["hash"]>,
    }),
  );

// Archived entries of a contract that is not the vault's, as an RPC could slip into a call.
function plant(world: World): void {
  const d = foreignData();
  world.rpc.extraEntries.set(
    id(d),
    xdr.LedgerEntryData.contractData(
      new xdr.ContractDataEntry({
        ext: new xdr.ExtensionPoint(0),
        contract: d.contractData().contract(),
        key: d.contractData().key(),
        durability: d.contractData().durability(),
        val: xdr.ScVal.scvBytes(Buffer.alloc(600)),
      }),
    ),
  );
  const c = foreignCode();
  world.rpc.extraEntries.set(
    id(c),
    xdr.LedgerEntryData.contractCode(
      new xdr.ContractCodeEntry({
        ext: new xdr.ContractCodeEntryExt(0),
        hash: c.contractCode().hash(),
        code: Buffer.alloc(64),
      }),
    ),
  );
  world.rpc.archived.add(id(d));
  world.rpc.archived.add(id(c));
}

// A funded wallet, with a second RPC provider at `second` that answers through `routed`.
async function funded(second?: { url: string; routed: (world: World) => FetchLike }) {
  const world = await createWorld();
  const alice = await openWallet(
    second === undefined ? world : { ...world, fetch: second.routed(world) },
    0,
    undefined,
    undefined,
    second === undefined ? {} : { secondRpcUrl: second.url },
  );
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  return { world, alice };
}

function payer(world: World, shown: NetworkFee[] = []): TransactionSigner {
  const account = world.signer("my account");
  return {
    publicKey: account.publicKey,
    signTransaction: (x, p) => account.signTransaction(x, p),
    confirmFee: (fee) => {
      shown.push(fee);
      return true;
    },
  };
}

function simulate(world: World, readWrite: xdr.LedgerKey[], fee = 1_000): void {
  world.rpc.simulated = {
    readOnly: [],
    readWrite,
    instructions: 1_000_000,
    readBytes: 1_000,
    writeBytes: 1_000,
    fee,
  };
}

const unshield = (world: World, alice: PrivateWallet, signer: TransactionSigner, caps = {}) =>
  alice.unshield({
    to: world.signer("merchant").publicKey,
    amount: 10n * XLM,
    selfRelay: signer,
    confirm: confirmAll,
    networkFeeCaps: caps,
  });

const ops = (world: World): string[] =>
  world.rpc.sent.map((tx: Transaction) => tx.operations[0]?.type ?? "none");

const details = (err: unknown): CyphrasError["details"] =>
  err instanceof CyphrasError ? err.details : {};

describe("restores an RPC asks for on entries that are not the vault's", () => {
  it("refuses a RestoreFootprint of another contract's code and data, and signs nothing", async () => {
    const { world, alice } = await funded();
    plant(world);
    world.rpc.preambleNext = [foreignCode(), foreignData()];
    simulate(world, [vaultData(world, "instance"), vaultData(world, "Roots")]);
    const shown: NetworkFee[] = [];
    await assert.rejects(
      unshield(world, alice, payer(world, shown), { restore: 200n * XLM }),
      isError("rpc_error"),
    );
    assert.deepEqual(shown, []);
    assert.deepEqual(ops(world), []);
    assert.equal(world.rpc.archived.has(id(foreignData())), true);
  });

  it("refuses a RestoreFootprint of a vault entry the call does not touch", async () => {
    const { world, alice } = await funded();
    const frontier = vaultData(world, "Frontier");
    world.rpc.extraEntries.set(
      id(frontier),
      xdr.LedgerEntryData.contractData(
        new xdr.ContractDataEntry({
          ext: new xdr.ExtensionPoint(0),
          contract: frontier.contractData().contract(),
          key: frontier.contractData().key(),
          durability: frontier.contractData().durability(),
          val: xdr.ScVal.scvVec([]),
        }),
      ),
    );
    world.rpc.archived.add(id(frontier));
    world.rpc.preambleNext = [frontier];
    simulate(world, [vaultData(world, "instance"), vaultData(world, "Roots")]);
    await assert.rejects(unshield(world, alice, payer(world)), isError("rpc_error"));
    assert.deepEqual(ops(world), []);
  });

  it("refuses marks on another contract's code or data in the call itself", async () => {
    for (const foreign of [foreignCode(), foreignData()]) {
      const { world, alice } = await funded();
      plant(world);
      simulate(world, [vaultData(world, "instance"), vaultData(world, "Roots"), foreign]);
      const shown: NetworkFee[] = [];
      await assert.rejects(unshield(world, alice, payer(world, shown)), isError("rpc_error"));
      assert.deepEqual(shown, []);
      assert.deepEqual(ops(world), []);
    }
  });

  it("refuses a mark on an entry of the asset contract other than its instance or a balance", async () => {
    const { world, alice } = await funded();
    const allowance = dataKey(
      world.deployment.asset.contract,
      xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Allowance")]),
    );
    simulate(world, [vaultData(world, "instance"), allowance]);
    world.rpc.simulatedMarks = [1];
    await assert.rejects(unshield(world, alice, payer(world)), isError("rpc_error"));
    assert.deepEqual(ops(world), []);
  });

  it("takes the restore the call needed first out of its own room for a restore", async () => {
    const { world, alice } = await funded();
    const instance = vaultData(world, "instance");
    const roots = vaultData(world, "Roots");
    world.rpc.archived.add(id(instance));
    world.rpc.archived.add(id(roots));
    world.rpc.preambleNext = [instance];
    world.rpc.restoreFee = 15_000_000;
    simulate(world, [instance, roots], 20_000_000);
    const shown: NetworkFee[] = [];
    // 1.5 XLM of the 2 XLM agreed went to the restore first, which leaves the call 1.5 XLM.
    const err = await unshield(world, alice, payer(world, shown), { restore: 2n * XLM }).catch(
      (e: unknown) => e,
    );
    assert.ok(isError("fee_above_cap")(err), String(err));
    assert.deepEqual(ops(world), ["restoreFootprint"]);
    assert.deepEqual(
      shown.map((f) => f.reason),
      ["restore"],
    );
  });
});

describe("network fee caps a caller gives", () => {
  it("keeps the caps a call leaves undefined, so an RPC's high fee is refused unsigned", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    simulate(world, [vaultData(world, "instance"), vaultData(world, "Roots")], 300 * Number(XLM));
    await assert.rejects(
      alice.shield({
        amount: 10n * XLM,
        signer: world.signer("alice depositor"),
        networkFeeCaps: { resource: undefined, inclusion: undefined } as never,
      }),
      isError("fee_above_cap"),
    );
    assert.deepEqual(world.rpc.sentFees, []);
  });

  it("refuses caps that are not bigints of at least 0, or name no cap, before anything", async () => {
    const bad: unknown[] = [
      { resource: Number.NaN },
      { resource: 5 },
      { restore: "5" },
      { inclusion: -1n },
      { inclusion: 5_000_000_000n },
      { other: 1n },
      "5",
    ];
    const { world, alice } = await funded();
    const signer = payer(world);
    const store = world.deployment;
    for (const caps of bad) {
      const c = caps as Partial<NetworkFeeCaps>;
      const calls: (() => Promise<unknown>)[] = [
        () => alice.shield({ amount: 10n * XLM, signer, networkFeeCaps: c }),
        () => unshield(world, alice, signer, c),
        () => alice.retry("missing", { selfRelay: signer, networkFeeCaps: c }),
        () => alice.cancelDeposit(1, signer, c),
        () => alice.refundDeposit(1, signer, c),
        () => alice.releaseExits(signer, 10, c),
        () => alice.claimExit(1, signer, c),
        () => alice.continueOperations(signer, c),
        () => alice.resumeOperation("missing", signer, c),
        () =>
          PrivateWallet.restoreVault(signer, {
            deployment: store,
            allowUnpinnedDeployment: true,
            rpcUrl: RPC,
            fetch: world.fetch,
            networkFeeCaps: c,
          }),
        () => openWallet(world, 1, undefined, undefined, { networkFeeCaps: c }),
      ];
      for (const [i, call] of calls.entries()) {
        await assert.rejects(
          call(),
          isError("invalid_argument"),
          `${JSON.stringify(String(c))} ${i}`,
        );
      }
    }
    assert.deepEqual(ops(world), []);
  });

  it("refuses a fee above what one transaction carries before the user is asked", async () => {
    const { world, alice } = await funded();
    world.rpc.archived.add(id(vaultData(world, "instance")));
    simulate(world, [vaultData(world, "instance"), vaultData(world, "Roots")], 5_000_000_000);
    const shown: NetworkFee[] = [];
    const err = await unshield(world, alice, payer(world, shown), { restore: 1_000n * XLM }).catch(
      (e: unknown) => e,
    );
    assert.ok(isError("fee_above_limit")(err), String(err));
    assert.equal(details(err)["limit"], "4294967295");
    assert.deepEqual(shown, []);
    assert.deepEqual(ops(world), []);
  });
});

describe("archival retries with a second provider", () => {
  const SECOND = "http://rpc2.test";

  // A second provider that reports every transaction a success.
  function landing(world: World): FetchLike {
    return async (input, init) => {
      const url = new URL(input);
      if (url.origin !== SECOND) return world.fetch(input, init);
      const res = await world.fetch(RPC, init);
      const body = JSON.parse(String(init?.body)) as { method: string };
      if (body.method !== "getTransaction") return res;
      const reply = (await res.json()) as { result: Record<string, unknown> };
      if (reply.result["status"] === "FAILED") {
        reply.result = { ...reply.result, status: "SUCCESS" };
        delete reply.result["resultXdr"];
        delete reply.result["diagnosticEventsXdr"];
      }
      return new Response(JSON.stringify(reply));
    };
  }

  it("sends a call that failed on an archived entry again only when the second provider agrees", async () => {
    const { world, alice } = await funded({ url: SECOND, routed: landing });
    simulate(world, [vaultData(world, "instance"), vaultData(world, "Roots")]);
    world.rpc.archiveNext = 1;
    const err = await unshield(world, alice, payer(world)).catch((e: unknown) => e);
    assert.ok(isError("transaction_failed")(err), String(err));
    assert.equal(details(err)["secondProvider"], "other_outcome");
    assert.deepEqual(ops(world), ["invokeHostFunction"]);
  });
});

describe("a split part whose proof an RPC lands itself", () => {
  // An RPC that, on the first simulation of a transact, lands the proof it was given from an
  // account of its own, then answers the user's simulation honestly, which the vault now refuses.
  function lander(world: World, armed: { on: boolean; landed: number }): FetchLike {
    return async (input, init) => {
      const url = new URL(input);
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        method?: string;
        params?: Record<string, unknown>;
      };
      if (url.origin === RPC && armed.on && body.method === "simulateTransaction") {
        const parsed = TransactionBuilder.fromXDR(
          body.params?.["transaction"] as string,
          world.deployment.networkPassphrase,
        ) as Transaction;
        const op = parsed.operations[0];
        if (
          op?.type === "invokeHostFunction" &&
          op.func.invokeContract().functionName().toString() === "transact"
        ) {
          armed.on = false;
          const args = op.func.invokeContract().args();
          const attacker = world.signer("attacker");
          const sequence = (world.rpc.accounts.get(attacker.publicKey)?.sequence ?? 0n).toString();
          const build = (
            data?: xdr.SorobanTransactionData,
            auth?: xdr.SorobanAuthorizationEntry[],
          ): Transaction =>
            new TransactionBuilder(new Account(attacker.publicKey, sequence), {
              fee: "100000",
              networkPassphrase: world.deployment.networkPassphrase,
              ...(data === undefined ? {} : { sorobanData: data }),
            })
              .addOperation(
                Operation.invokeContractFunction({
                  contract: world.vault.address,
                  function: "transact",
                  args: [
                    args[0] as xdr.ScVal,
                    args[1] as xdr.ScVal,
                    new Address(attacker.publicKey).toScVal(),
                  ],
                  ...(auth === undefined ? {} : { auth }),
                }),
              )
              .setTimeout(300)
              .build();
          const sim = world.rpc.handle("simulateTransaction", {
            transaction: build().toEnvelope().toXDR("base64"),
          }) as { transactionData: string; results: { auth: string[] }[] };
          const tx = build(
            xdr.SorobanTransactionData.fromXDR(sim.transactionData, "base64"),
            (sim.results[0]?.auth ?? []).map((a) =>
              xdr.SorobanAuthorizationEntry.fromXDR(a, "base64"),
            ),
          );
          tx.sign(attacker.keypair);
          const sent = world.rpc.handle("sendTransaction", { transaction: tx.toXDR() }) as {
            hash: string;
          };
          if (world.rpc.records.get(sent.hash)?.status === "SUCCESS") armed.landed++;
        }
      }
      return world.fetch(input, init);
    };
  }

  it("keeps the part and its operation, so the same request again pays no more than asked", async () => {
    const world = await createWorld({
      limits: { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 500n * XLM },
    });
    const armed = { on: false, landed: 0 };
    const alice = await openWallet({ ...world, fetch: lander(world, armed) }, 0, new MemoryStore());
    for (const amount of [60n * XLM, 70n * XLM, 100n * XLM]) {
      await alice.shield({ amount, signer: world.signer("alice depositor") });
    }
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const destination = world.signer("exchange").publicKey;
    const account = world.signer("my account");
    const request = {
      to: destination,
      amount: 90n * XLM,
      selfRelay: account,
      split: true,
      confirm: confirmAll,
    } as const;
    armed.on = true;
    const err = await alice.unshield(request).catch((e: unknown) => e);
    assert.equal(armed.landed, 1);
    assert.ok(err instanceof CyphrasError, String(err));
    const operationId = details(err)["operationId"];
    assert.equal(typeof operationId, "string");
    // The same request again continues that operation, whose first part the sync finds landed.
    const view = (await alice.unshield(request)) as OperationView;
    assert.equal(view.operationId, operationId);
    for (let round = 0; round < 4; round++) {
      world.advance(7 * 3600);
      world.fill(1);
      await alice.continueOperations(account).catch(() => undefined);
    }
    const owed =
      world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
      [...world.vault.exits.values()]
        .filter((e) => e.recipient === destination)
        .reduce((s, e) => s + e.payout, 0n);
    assert.equal(owed, 90n * XLM);
    const views = await alice.continueOperations(account);
    assert.deepEqual(
      views.map((v) => [v.operationId, v.state]),
      [[operationId, "done"]],
    );
  });
});
