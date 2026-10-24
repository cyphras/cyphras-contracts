import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Address, nativeToScVal, xdr } from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { type KeyValueStore, MemoryStore } from "../../src/storage.ts";
import type { TransactionSigner } from "../../src/vault/invoke.ts";
import { balanceKey, exitKey } from "../../src/vault/state.ts";
import type { SpendReview } from "../../src/wallet/spend.ts";
import type { OperationView, PrivateWallet, UnshieldRequest } from "../../src/wallet/wallet.ts";
import { RELAYER, RPC, XLM, type World, createWorld } from "../support/network.ts";
import { confirmAll, isError, openWallet } from "../support/wallets.ts";

const SPLIT = { maxDailyOutflow: 50n * XLM, maxDeposit: 500n * XLM, tvlCap: 500n * XLM };
const CONTRACT_PAYEE = "CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA";

const id = (k: xdr.LedgerKey): string => k.toXDR("base64");

// What the vault paid a destination or owes it in its exit queue.
const owedTo = (world: World, destination: string): bigint =>
  world.vault.transfers.filter((t) => t.to === destination).reduce((s, t) => s + t.amount, 0n) +
  [...world.vault.exits.values()]
    .filter((e) => e.recipient === destination)
    .reduce((s, e) => s + e.payout, 0n);

const details = (err: unknown): Record<string, unknown> =>
  err instanceof CyphrasError ? (err.details as Record<string, unknown>) : {};

const caught = (p: Promise<unknown>): Promise<unknown> => p.then(() => undefined).catch((e) => e);

// A copy of a store as it is now, as an app killed at this moment leaves it.
async function snapshot(store: MemoryStore): Promise<MemoryStore> {
  const copy = new MemoryStore();
  for (const key of store.keys()) {
    const value = await store.get(key);
    if (value !== undefined) await copy.set(key, value);
  }
  return copy;
}

// A wallet whose user rejects the first transaction it is asked to sign.
function rejectingOnce(world: World, label: string): TransactionSigner {
  const account = world.signer(label);
  let rejected = false;
  return {
    publicKey: account.publicKey,
    async signTransaction(x, p) {
      if (!rejected) {
        rejected = true;
        return { signedTxXdr: "", error: "User declined access" };
      }
      return account.signTransaction(x, p);
    },
  };
}

async function withNotes(
  fetch?: (world: World) => FetchLike,
  store: KeyValueStore = new MemoryStore(),
): Promise<{ world: World; alice: PrivateWallet }> {
  const world = await createWorld({ limits: SPLIT });
  const alice = await openWallet(
    fetch === undefined ? world : { ...world, fetch: fetch(world) },
    0,
    store,
  );
  for (const amount of [60n * XLM, 70n * XLM, 100n * XLM]) {
    await alice.shield({ amount, signer: world.signer("alice depositor") });
  }
  world.advance(3_601);
  world.admitAll();
  await alice.sync();
  world.rpc.sent = [];
  return { world, alice };
}

// The wallet goes on with its operations over a day and a half, as an app does whenever it runs.
async function runFor(
  world: World,
  wallet: PrivateWallet,
  signer: TransactionSigner | undefined,
): Promise<void> {
  for (let round = 0; round < 6; round++) {
    world.advance(7 * 3600);
    world.fill(1);
    await wallet.continueOperations(signer).catch(() => undefined);
  }
}

describe("a split unshield its user did not go through with", () => {
  for (const route of ["self", "relayed"] as const) {
    it(`sends nothing once its user declined the first part's review (${route})`, async () => {
      const { world, alice } = await withNotes();
      const destination = world.signer("exchange").publicKey;
      const account = world.signer("my account");
      // The user agrees to the payment as a whole, then reads the first part's warnings and
      // declines it.
      const confirm = (review: SpendReview): boolean => review.amount === 90n * XLM;
      const request: UnshieldRequest =
        route === "self"
          ? { to: destination, amount: 90n * XLM, selfRelay: account, split: true, confirm }
          : { to: destination, amount: 90n * XLM, maxFee: 2n * XLM, split: true, confirm };
      await assert.rejects(alice.unshield(request), isError("not_confirmed"));
      await runFor(world, alice, route === "self" ? account : undefined);
      assert.equal(owedTo(world, destination), 0n);
      assert.deepEqual(world.rpc.sent, []);
      assert.deepEqual(world.relayer.submissions, []);
    });
  }

  it("sends nothing once the first part could not be paid from the pool", async () => {
    const world = await createWorld({ limits: SPLIT });
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 20n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const destination = world.signer("exchange").publicKey;
    const account = world.signer("my account");
    await assert.rejects(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        selfRelay: account,
        split: true,
        confirm: confirmAll,
      }),
      isError("vault_unavailable"),
    );
    // Funds arrive later, for something else; the refused payment must not go out by itself.
    await alice.shield({ amount: 200n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await runFor(world, alice, account);
    assert.equal(owedTo(world, destination), 0n);
  });
});

describe("a split unshield sent again another way after its first part stopped", () => {
  // The one request a user means, first as made, then as made again after the error.
  type Case = {
    readonly name: string;
    readonly setup: (world: World) => void;
    readonly first: (world: World) => UnshieldRequest;
    readonly again: (world: World) => UnshieldRequest;
    readonly bound: bigint;
  };
  const to = (world: World): string => world.signer("exchange").publicKey;
  const self = (world: World): TransactionSigner => world.signer("my account");
  const cases: Case[] = [
    {
      name: "self-relayed after the relayer refused the first part",
      setup: (world) => {
        world.relayer.failures.push({ error: "rate_limited" });
      },
      first: (world) => ({
        to: to(world),
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      again: (world) => ({
        to: to(world),
        amount: 90n * XLM,
        selfRelay: self(world),
        split: true,
        confirm: confirmAll,
      }),
      bound: 90n * XLM,
    },
    {
      name: "through a relayer after the wallet rejected the first part",
      setup: () => {},
      first: (world) => ({
        to: to(world),
        amount: 90n * XLM,
        selfRelay: rejectingOnce(world, "my account"),
        split: true,
        confirm: confirmAll,
      }),
      again: (world) => ({
        to: to(world),
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      bound: 90n * XLM,
    },
    {
      name: "with a lower relayer fee cap that makes it fit one transaction",
      setup: (world) => {
        world.relayer.failures.push({ error: "rate_limited" });
      },
      first: (world) => ({
        to: to(world),
        amount: 48n * XLM,
        maxFee: 5n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      again: (world) => ({
        to: to(world),
        amount: 48n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      bound: 48n * XLM,
    },
    {
      name: "for a corrected amount after the wallet rejected the first part",
      setup: () => {},
      first: (world) => ({
        to: to(world),
        amount: 90n * XLM,
        selfRelay: rejectingOnce(world, "my account"),
        split: true,
        confirm: confirmAll,
      }),
      again: (world) => ({
        to: to(world),
        amount: 89n * XLM,
        selfRelay: self(world),
        split: true,
        confirm: confirmAll,
      }),
      bound: 90n * XLM,
    },
  ];

  for (const c of cases) {
    it(`pays no more than one payment's amount when sent again ${c.name}`, async () => {
      const { world, alice } = await withNotes();
      c.setup(world);
      const first = await caught(alice.unshield(c.first(world)));
      assert.ok(first instanceof CyphrasError, String(first));
      // The new request either goes on with the first one's operation or is refused naming it.
      await caught(alice.unshield(c.again(world)));
      await runFor(world, alice, self(world));
      const owed = owedTo(world, to(world));
      assert.ok(owed <= c.bound, `the destination is owed ${owed} stroops for ${c.bound}`);
    });
  }

  it("pays no more than asked when the relayer took the first part but its answer was lost", async () => {
    let lose = true;
    const losing =
      (world: World): FetchLike =>
      async (input, init) => {
        const res = await world.fetch(input, init);
        if (lose && new URL(input).origin === RELAYER && new URL(input).pathname === "/v1/submit") {
          lose = false;
          throw new TypeError("network connection lost");
        }
        return res;
      };
    const { world, alice } = await withNotes(losing);
    const destination = world.signer("exchange").publicKey;
    const account = world.signer("my account");
    const err = await caught(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
    );
    assert.ok(err instanceof CyphrasError, String(err));
    // The relayer seems down, so the user pays from their own account instead, as the SDK's errors
    // about an unavailable relayer suggest.
    await caught(
      alice.unshield({
        to: destination,
        amount: 90n * XLM,
        selfRelay: account,
        split: true,
        confirm: confirmAll,
      }),
    );
    await runFor(world, alice, account);
    const owed = owedTo(world, destination);
    assert.ok(owed <= 90n * XLM, `the destination is owed ${owed} stroops for 90 XLM`);
  });
});

describe("a split unshield repeated alike across restarts and at once", () => {
  const request = (world: World, signer: TransactionSigner): UnshieldRequest => ({
    to: world.signer("exchange").publicKey,
    amount: 90n * XLM,
    selfRelay: signer,
    split: true,
    confirm: confirmAll,
  });

  it("pays once when two repeats of the same request race in one wallet", async () => {
    const { world, alice } = await withNotes();
    const signer = rejectingOnce(world, "my account");
    await assert.rejects(alice.unshield(request(world, signer)), isError("signer_rejected"));
    const [a, b] = await Promise.all([
      caught(alice.unshield(request(world, signer))),
      caught(alice.unshield(request(world, signer))),
    ]);
    assert.equal(a, undefined, String(a));
    assert.equal(b, undefined, String(b));
    await runFor(world, alice, signer);
    assert.equal(owedTo(world, world.signer("exchange").publicKey), 90n * XLM);
  });

  it("pays once when two wallet instances on one store repeat the same request at once", async () => {
    const store = new MemoryStore();
    const { world, alice } = await withNotes(undefined, store);
    const signer = rejectingOnce(world, "my account");
    await assert.rejects(alice.unshield(request(world, signer)), isError("signer_rejected"));
    const popup = await openWallet(world, 0, store);
    await Promise.all([
      caught(alice.unshield(request(world, signer))),
      caught(popup.unshield(request(world, signer))),
    ]);
    await runFor(world, popup, signer);
    await runFor(world, alice, signer);
    assert.equal(owedTo(world, world.signer("exchange").publicKey), 90n * XLM);
  });

  it("goes on with the same operation after the app restarts between the stop and the repeat", async () => {
    const store = new MemoryStore();
    const { world, alice } = await withNotes(undefined, store);
    const signer = rejectingOnce(world, "my account");
    const err = await caught(alice.unshield(request(world, signer)));
    const operationId = details(err)["operationId"];
    assert.equal(typeof operationId, "string");
    const reopened = await openWallet(world, 0, store);
    const view = (await reopened.unshield(request(world, signer))) as OperationView;
    assert.equal(view.operationId, operationId);
    await runFor(world, reopened, signer);
    assert.equal(owedTo(world, world.signer("exchange").publicKey), 90n * XLM);
  });

  it("pays once when the app was killed after the first part's simulation went out", async () => {
    const store = new MemoryStore();
    let frozen: MemoryStore | undefined;
    const freezing =
      (world: World): FetchLike =>
      async (input, init) => {
        const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
        if (
          frozen === undefined &&
          new URL(input).origin === RPC &&
          body?.method === "simulateTransaction"
        ) {
          frozen = await snapshot(store);
        }
        return world.fetch(input, init);
      };
    const { world, alice } = await withNotes(freezing, store);
    frozen = undefined;
    const signer = world.signer("my account");
    // The first part lands, while the store keeps what it held when its proof left for the RPC.
    await alice.unshield(request(world, signer));
    const reopened = await openWallet(world, 0, frozen as unknown as MemoryStore);
    const [part] = await reopened.plans();
    assert.equal(part?.state, "prepared");
    assert.equal(part?.txHash, undefined);
    await caught(reopened.unshield(request(world, signer)));
    await runFor(world, reopened, signer);
    assert.equal(owedTo(world, world.signer("exchange").publicKey), 90n * XLM);
  });

  it("pays once when the user repeats the request with raised caps after each stop", async () => {
    const { world, alice } = await withNotes();
    const signer = rejectingOnce(world, "my account");
    const base = request(world, signer);
    await caught(alice.unshield(base));
    await caught(alice.unshield({ ...base, networkFeeCaps: { resource: 20_000_000n } }));
    await caught(alice.unshield({ ...base, networkFeeCaps: { restore: 10n * XLM } }));
    await runFor(world, alice, signer);
    assert.equal(owedTo(world, world.signer("exchange").publicKey), 90n * XLM);
  });
});

describe("exits paid to a contract whose balance archived in the queue", () => {
  it("releases an exit whose contract payee's balance needs a restore", async () => {
    const world = await createWorld({ limits: { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM } });
    world.rpc.contracts.add(CONTRACT_PAYEE);
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    // Today's window is spent, so the payout waits in the exit queue.
    world.vault.outflowDay = world.vault.timestamp / 86_400n;
    world.vault.outflow = 50n * XLM;
    await alice.unshield({
      to: CONTRACT_PAYEE,
      amount: 10n * XLM,
      selfRelay: world.signer("my account"),
      confirm: confirmAll,
    });
    assert.equal(world.vault.exits.size, 1);
    world.advance(86_400);
    // While it waited, the payee's balance entry in the asset contract was archived.
    const theirs = balanceKey(world.deployment.asset.contract, CONTRACT_PAYEE);
    world.rpc.extraEntries.set(
      id(theirs),
      xdr.LedgerEntryData.contractData(
        new xdr.ContractDataEntry({
          ext: new xdr.ExtensionPoint(0),
          contract: new Address(world.deployment.asset.contract).toScAddress(),
          key: theirs.contractData().key(),
          durability: xdr.ContractDataDurability.persistent(),
          val: nativeToScVal(1n, { type: "i128" }),
        }),
      ),
    );
    world.rpc.archived.add(id(theirs));
    const head = [...world.vault.exits.keys()][0] as number;
    world.rpc.simulated = {
      readOnly: [],
      readWrite: [exitKey(world.vault.address, BigInt(head)), theirs],
      instructions: 1_000_000,
      readBytes: 1_000,
      writeBytes: 1_000,
      fee: 1_000,
    };
    const err = await caught(
      alice.releaseExits(world.signer("anyone"), 10, { restore: 10n * XLM }),
    );
    assert.equal(err, undefined, String(err));
    assert.equal(world.rpc.archived.has(id(theirs)), false);
    assert.equal(owedTo(world, CONTRACT_PAYEE), 10n * XLM);
    assert.equal(world.vault.exits.size, 0);
  });
});

describe("operations that go on side by side", () => {
  it("sends the next part of one operation while another one's relayer is down", async () => {
    const { world, alice } = await withNotes();
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const account = world.signer("my account");
    const relayed = world.signer("exchange").publicKey;
    const own = world.signer("merchant").publicKey;
    await alice.unshield({
      to: relayed,
      amount: 90n * XLM,
      maxFee: 2n * XLM,
      split: true,
      confirm: confirmAll,
    });
    await alice.unshield({
      to: own,
      amount: 90n * XLM,
      selfRelay: account,
      split: true,
      confirm: confirmAll,
    });
    world.relayer.paused = true;
    await runFor(world, alice, account);
    assert.equal(owedTo(world, own), 90n * XLM);
  });
});
