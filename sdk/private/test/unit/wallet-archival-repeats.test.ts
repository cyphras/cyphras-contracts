import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Address, type Transaction, nativeToScVal, xdr } from "@stellar/stellar-base";
import type { FetchLike } from "../../src/net/http.ts";
import { MemoryStore } from "../../src/storage.ts";
import { balanceKey } from "../../src/vault/state.ts";
import {
  DEFAULT_NETWORK_FEE_CAPS,
  type NetworkFee,
  type TransactionSigner,
} from "../../src/vault/invoke.ts";
import { RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");
const STRANGER = "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA";
const SECOND = "http://rpc2.test";

const persistentKey = (contract: string, key: xdr.ScVal): xdr.LedgerKey =>
  xdr.LedgerKey.contractData(
    new xdr.LedgerKeyContractData({
      contract: new Address(contract).toScAddress(),
      key,
      durability: xdr.ContractDataDurability.persistent(),
    }),
  );

const instanceKey = (contract: string): xdr.LedgerKey =>
  persistentKey(contract, xdr.ScVal.scvLedgerKeyContractInstance());

const sentOps = (world: World): string[] =>
  world.rpc.sent.map((tx: Transaction) => {
    const op = tx.operations[0];
    return op?.type === "invokeHostFunction"
      ? op.func.invokeContract().functionName().toString()
      : (op?.type ?? "none");
  });

const entryData = (key: xdr.LedgerKey, val: xdr.ScVal): xdr.LedgerEntryData =>
  xdr.LedgerEntryData.contractData(
    new xdr.ContractDataEntry({
      ext: new xdr.ExtensionPoint(0),
      contract: key.contractData().contract(),
      key: key.contractData().key(),
      durability: key.contractData().durability(),
      val,
    }),
  );

// A balance entry in the asset contract that only the archival hooks model.
function plantBalance(world: World, holder: string): xdr.LedgerKey {
  const key = balanceKey(world.deployment.asset.contract, holder);
  world.rpc.extraEntries.set(id(key), entryData(key, nativeToScVal(1n, { type: "i128" })));
  return key;
}

function showing(world: World, label: string, shown: NetworkFee[]): TransactionSigner {
  const account = world.signer(label);
  return {
    publicKey: account.publicKey,
    signTransaction: (x, p) => account.signTransaction(x, p),
    confirmFee: (fee) => {
      shown.push(fee);
      return true;
    },
  };
}

// A wallet whose user rejects the first transaction it is asked to sign: with a reply that says so,
// as Freighter answers, or with a thrown error, as other wallets do.
function rejectingOnce(world: World, label: string, how: "reply" | "throw"): TransactionSigner {
  const account = world.signer(label);
  let rejected = false;
  return {
    publicKey: account.publicKey,
    async signTransaction(x, p) {
      if (!rejected) {
        rejected = true;
        if (how === "throw") throw new Error("User declined access");
        return { signedTxXdr: "", error: "User declined access" };
      }
      return account.signTransaction(x, p);
    },
  };
}

// What the vault paid a destination or owes it in its exit queue.
const owedTo = (world: World, destination: string): bigint =>
  world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === destination)
    .reduce((s, e) => s + e.payout, 0n);

async function funded(fetch?: (world: World) => FetchLike, secondRpcUrl?: string) {
  const world = await createWorld();
  const alice = await openWallet(
    fetch === undefined ? world : { ...world, fetch: fetch(world) },
    0,
    undefined,
    undefined,
    secondRpcUrl === undefined ? {} : { secondRpcUrl },
  );
  await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  return { world, alice };
}

describe("split unshields the user sends again after a stop", () => {
  const SPLIT = { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 350n * XLM };

  async function withNotes(fetch?: (world: World) => FetchLike) {
    const world = await createWorld({ limits: SPLIT });
    const alice = await openWallet(
      fetch === undefined ? world : { ...world, fetch: fetch(world) },
      0,
      new MemoryStore(),
    );
    for (const amount of [60n * XLM, 70n * XLM]) {
      await alice.shield({ amount, signer: world.signer("alice depositor") });
    }
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    world.rpc.sent = [];
    return { world, alice };
  }

  for (const how of ["reply", "throw"] as const) {
    it(`pays a split unshield once when its wallet rejected the first signature (${how})`, async () => {
      const { world, alice } = await withNotes();
      const destination = world.signer("exchange").publicKey;
      const signer = rejectingOnce(world, "my account", how);
      const request = {
        to: destination,
        amount: 90n * XLM,
        selfRelay: signer,
        split: true,
        confirm: confirmAll,
      } as const;
      await assert.rejects(alice.unshield(request));
      // The user presses send again and signs this time.
      await alice.unshield(request).catch(() => undefined);
      for (let round = 0; round < 5; round++) {
        world.advance(7 * 3600);
        world.fill(1);
        await alice.continueOperations(signer).catch(() => undefined);
      }
      const owed = owedTo(world, destination);
      assert.ok(owed <= 90n * XLM, `the destination is owed ${owed} stroops for a 90 XLM payment`);
      assert.equal(owed, 90n * XLM);
    });
  }

  it("sends a part once when the RPC's answer to its submission was lost", async () => {
    let lose = false;
    const losing = (world: World): FetchLike => {
      return async (input, init) => {
        const res = await world.fetch(input, init);
        const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
        if (lose && body?.method === "sendTransaction") {
          lose = false;
          throw new TypeError("network connection lost");
        }
        return res;
      };
    };
    const { world, alice } = await withNotes(losing);
    const destination = world.signer("exchange").publicKey;
    const account = world.signer("my account");
    await alice.unshield({
      to: destination,
      amount: 90n * XLM,
      selfRelay: account,
      split: true,
      confirm: confirmAll,
    });
    lose = true;
    for (let round = 0; round < 5; round++) {
      world.advance(7 * 3600);
      world.fill(1);
      await alice.continueOperations(account).catch(() => undefined);
    }
    assert.equal(owedTo(world, destination), 90n * XLM);
    assert.deepEqual(sentOps(world), ["transact", "transact"]);
    const [view] = await alice.continueOperations();
    assert.equal(view?.state, "done");
  });
});

describe("balances in the asset contract a call restores", () => {
  it("refuses to restore a stranger's balance the RPC slips into the call", async () => {
    const { world, alice } = await funded();
    const instance = instanceKey(world.vault.address);
    const roots = persistentKey(
      world.vault.address,
      xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Roots")]),
    );
    const stranger = plantBalance(world, STRANGER);
    world.rpc.archived.add(id(instance));
    world.rpc.archived.add(id(stranger));
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [instance, roots, stranger],
      instructions: 1_000_000,
      readBytes: 1_000,
      writeBytes: 1_000,
      fee: 1_000,
    };
    const shown: NetworkFee[] = [];
    await assert.rejects(
      alice.unshield({
        to: world.signer("merchant").publicKey,
        amount: 10n * XLM,
        selfRelay: showing(world, "my account", shown),
        confirm: confirmAll,
        networkFeeCaps: { restore: 200n * XLM },
      }),
      isError("rpc_error"),
    );
    assert.deepEqual(shown, []);
    assert.deepEqual(sentOps(world), []);
    assert.equal(world.rpc.archived.has(id(stranger)), true);
  });

  it("restores the balance of a contract the unshield pays", async () => {
    const { world, alice } = await funded();
    world.rpc.contracts.add(STRANGER);
    plantBalance(world, world.vault.address);
    const theirs = plantBalance(world, STRANGER);
    world.rpc.archived.add(id(theirs));
    const shown: NetworkFee[] = [];
    await alice.unshield({
      to: STRANGER,
      amount: 10n * XLM,
      selfRelay: showing(world, "my account", shown),
      confirm: confirmAll,
    });
    assert.deepEqual(sentOps(world), ["transact"]);
    assert.deepEqual(
      shown.map((f) => [f.reason, f.entries]),
      [["restore", ["asset Balance"]]],
    );
    assert.equal(world.rpc.archived.has(id(theirs)), false);
  });
  it("restores the pool asset contract's own instance", async () => {
    const { world, alice } = await funded();
    const asset = instanceKey(world.deployment.asset.contract);
    world.rpc.extraEntries.set(
      id(asset),
      entryData(
        asset,
        xdr.ScVal.scvContractInstance(
          new xdr.ScContractInstance({
            executable: xdr.ContractExecutable.contractExecutableStellarAsset(),
            storage: null,
          }),
        ),
      ),
    );
    world.rpc.archived.add(id(asset));
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [instanceKey(world.vault.address), asset],
      instructions: 1_000_000,
      readBytes: 1_000,
      writeBytes: 1_000,
      fee: 1_000,
    };
    const shown: NetworkFee[] = [];
    await alice.unshield({
      to: world.signer("merchant").publicKey,
      amount: 10n * XLM,
      selfRelay: showing(world, "my account", shown),
      confirm: confirmAll,
    });
    assert.deepEqual(
      shown.map((f) => [f.reason, f.entries]),
      [["restore", ["asset instance"]]],
    );
    assert.equal(world.rpc.archived.has(id(asset)), false);
  });
});

describe("the fee one transaction carries", () => {
  async function cancelAt(resource: bigint) {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    const { depositId } = await alice.shield({ amount: 10n * XLM, signer: depositor });
    world.rpc.sent = [];
    world.rpc.sentFees = [];
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [instanceKey(world.vault.address)],
      instructions: 1_000_000,
      readBytes: 1_000,
      writeBytes: 1_000,
      fee: Number(resource),
    };
    const err = await alice
      .cancelDeposit(depositId as number, depositor, { resource })
      .then(() => undefined)
      .catch((e: unknown) => e);
    return { world, err };
  }

  it("sends a fee of exactly 2^32 - 1 stroops and refuses one stroop more", async () => {
    // The network quotes 150 stroops for inclusion.
    let r = await cancelAt(4_294_967_295n - 150n);
    assert.equal(r.err, undefined, String(r.err));
    assert.deepEqual(r.world.rpc.sentFees, [4_294_967_295n]);
    r = await cancelAt(4_294_967_296n - 150n);
    assert.ok(isError("fee_above_limit")(r.err), String(r.err));
    assert.deepEqual(r.world.rpc.sentFees, []);
  });
});

describe("caps callers already pass", () => {
  it("takes frozen, complete and empty caps objects", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0, undefined, undefined, {
      networkFeeCaps: Object.freeze({ ...DEFAULT_NETWORK_FEE_CAPS }),
    });
    const depositor = world.signer("alice depositor");
    await alice.shield({ amount: 10n * XLM, signer: depositor, networkFeeCaps: {} });
    await alice.shield({
      amount: 10n * XLM,
      signer: depositor,
      networkFeeCaps: Object.freeze({ restore: 0n }),
      whileSubmitting: true,
    });
    assert.deepEqual(sentOps(world), ["shield", "shield"]);
  });
});

describe("deposits whose transaction an RPC reports dropped", () => {
  // Simulations that read and write the vault's instance, whose TTL sets the call's ledger bound.
  const simulateShared = (world: World): void => {
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [
        instanceKey(world.vault.address),
        persistentKey(world.vault.address, xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("Roots")])),
      ],
      instructions: 1_000_000,
      readBytes: 1_000,
      writeBytes: 1_000,
      fee: 1_000,
    };
  };

  it("keeps a deposit that landed though the RPC reported it dropped at its bound", async () => {
    const world = await createWorld();
    let lying = true;
    const liar: FetchLike = async (input, init) => {
      const res = await world.fetch(input, init);
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      if (!lying || body?.method !== "getTransaction") return res;
      const reply = (await res.json()) as { result: Record<string, unknown> };
      reply.result = {
        status: "NOT_FOUND",
        latestLedger: world.vault.ledger + 100,
        oldestLedger: world.rpc.oldestLedger,
      };
      return new Response(JSON.stringify(reply));
    };
    const alice = await openWallet({ ...world, fetch: liar }, 0);
    simulateShared(world);
    world.rpc.ttl.set(id(instanceKey(world.vault.address)), world.vault.ledger + 3);
    const depositor = world.signer("alice depositor");
    await assert.rejects(alice.shield({ amount: 10n * XLM, signer: depositor }));
    // The deposit is on chain, while the wallet took its transaction for dropped.
    assert.equal(world.vault.pending.size, 1);
    assert.equal((await alice.deposits())[0]?.state, "failed");
    lying = false;
    await alice.sync();
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "admitted");
    assert.equal((await alice.balance()).spendable, 10n * XLM);
  });

  it("sends a shield dropped at its bound again when the second provider agrees", async () => {
    const world = await createWorld();
    const routed: FetchLike = async (input, init) =>
      new URL(input).origin === SECOND ? world.fetch(RPC, init) : world.fetch(input, init);
    const alice = await openWallet({ ...world, fetch: routed }, 0, undefined, undefined, {
      secondRpcUrl: SECOND,
    });
    simulateShared(world);
    world.rpc.ttl.set(id(instanceKey(world.vault.address)), world.vault.ledger + 3);
    world.rpc.beforeApply = () => {
      world.vault.ledger += 10;
    };
    const { txHash } = await alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") });
    assert.deepEqual(sentOps(world), ["shield", "shield"]);
    assert.equal(world.rpc.records.get(txHash)?.status, "SUCCESS");
  });
});
