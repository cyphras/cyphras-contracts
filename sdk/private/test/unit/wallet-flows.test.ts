import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Account,
  MuxedAccount,
  Networks,
  StrKey,
  type Transaction,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-base";
import { CyphrasError } from "../../src/errors.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { type Deposit, type WalletState, loadState, saveState } from "../../src/wallet/state.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { INDEXER, RELAYER, RPC, XLM, createWorld, rewritingFetch } from "../support/network.ts";
import { keypairFor } from "../support/rpc.ts";
import { confirmAll, isError, openWallet, shielded, storeKeyOf } from "../support/wallets.ts";

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
        deployment: "mainnet/xlm",
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

// Whether a JSON-RPC request reads the vault's entry queue.
const readsQueue = (body: { method?: string; params?: { keys?: string[] } }): boolean =>
  body.method === "getLedgerEntries" &&
  (body.params?.keys ?? []).some((k) => {
    const key = xdr.LedgerKey.fromXDR(k, "base64");
    return (
      key.switch().name === "contractData" &&
      key.contractData().key().vec()?.[0]?.sym().toString() === "Pending"
    );
  });

// A busy RPC's reply to a JSON-RPC request.
const busyReply = (id: number): Response =>
  new Response(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32603, message: "busy" } }));

const bodyOf = (init: RequestInit | undefined) =>
  init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));

// An RPC's reply to a JSON-RPC request with this result.
const rpcResult = (id: number, result: unknown): Response =>
  new Response(JSON.stringify({ jsonrpc: "2.0", id, result }));

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
    const first = await shielded(alice, 10n * XLM, depositor);
    const second = await shielded(alice, 20n * XLM, depositor);
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
    assert.equal(flagged?.flag?.kind, "refused");
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

describe("wallet: a shield whose sending goes wrong", () => {
  // A fetch that answers the shield's first sendTransaction with `answer`, given the request and
  // the transaction's hash, and passes everything else to the world.
  function sending(
    world: Awaited<ReturnType<typeof createWorld>>,
    answer: (
      body: { id: number },
      hash: string,
      init: RequestInit | undefined,
    ) => Promise<Response>,
  ): FetchLike {
    let first = true;
    return async (input, init) => {
      const body = bodyOf(init);
      if (first && new URL(input).origin === RPC && body?.method === "sendTransaction") {
        first = false;
        const tx = TransactionBuilder.fromXDR(body.params.transaction, Networks.TESTNET);
        return answer(body, tx.hash().toString("hex"), init);
      }
      return world.fetch(input, init);
    };
  }

  it("stays submitting when the reply is lost after the envelope left, and a sync finds it", async () => {
    const world = await createWorld();
    const fetch = sending(world, async (_body, _hash, init) => {
      await world.fetch(RPC, init);
      throw new TypeError("connection reset");
    });
    const alice = await openWallet({ ...world, fetch }, 0);
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") }),
      isError("service_unavailable"),
    );
    let [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "submitting");
    assert.notEqual(deposit?.txHash, undefined);
    world.rpc.run("ab".repeat(32), () => world.vault.flag(1, 100));
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.id, 1);
    assert.equal(deposit?.flag?.kind, "legal_hold");
  });

  it("stays submitting when the RPC answers that the network refused the envelope, and fails once every provider shows it can no longer land", async () => {
    for (const answer of ["ERROR", "TRY_AGAIN_LATER"] as const) {
      const world = await createWorld();
      const second = "http://rpc2.test";
      // The first provider takes the shield to no one, and gives this answer every time.
      const fetch: FetchLike = async (input, init) => {
        const url = new URL(input);
        const body = bodyOf(init);
        if (url.origin === RPC && body?.method === "sendTransaction") {
          const tx = TransactionBuilder.fromXDR(body.params.transaction, Networks.TESTNET);
          const hash = tx.hash().toString("hex");
          return rpcResult(body.id, { status: answer, hash, latestLedger: world.vault.ledger });
        }
        return world.fetch(url.origin === second ? RPC : input, init);
      };
      const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
        secondRpcUrl: second,
        sleep: async (ms) => {
          world.advance(Math.ceil(ms / 1000));
        },
      });
      await assert.rejects(
        alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") }),
        (err: unknown) => err instanceof CyphrasError && err.details["refused"] === true,
      );
      assert.equal((await alice.deposits())[0]?.state, "submitting", answer);
      world.advance(121 * 5);
      await alice.sync();
      assert.equal((await alice.deposits())[0]?.state, "failed", answer);
    }
  });

  it("fails once every provider reports its transaction failed, past its proof's deadline", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    world.rpc.failNext = 1;
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") }),
      isError("transaction_failed"),
    );
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "submitting");
    world.advance(121 * 5);
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "failed");
  });

  it("does not fail on one provider's word while events cannot be checked", async () => {
    // The second provider cannot answer reads of events; the first then reports the shield's
    // transaction failed, or denies the transaction the second holds.
    for (const first of ["failed", "denied"] as const) {
      const world = await createWorld();
      const second = "http://rpc2.test";
      let shieldHash: string | undefined;
      let answered = false;
      const fetch: FetchLike = async (input, init) => {
        const url = new URL(input);
        const body = bodyOf(init);
        if (url.origin === second && body?.method === "getEvents") return busyReply(body.id);
        if (body?.method === "sendTransaction") {
          const tx = TransactionBuilder.fromXDR(body.params.transaction, Networks.TESTNET);
          shieldHash = tx.hash().toString("hex");
        }
        const asked = body?.method === "getTransaction" && body.params.hash === shieldHash;
        if (first === "denied" && asked && url.origin === RPC) {
          if (!answered) {
            answered = true;
            return world.fetch(input, init);
          }
          const ledger = world.vault.ledger;
          return rpcResult(body.id, { status: "NOT_FOUND", latestLedger: ledger, oldestLedger: 1 });
        }
        return world.fetch(url.origin === second ? RPC : input, init);
      };
      const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
        secondRpcUrl: second,
      });
      world.indexer.down = true;
      if (first === "failed") world.rpc.failNext = 1;
      await alice
        .shield({ amount: 10n * XLM, signer: world.signer("depositor") })
        .catch(() => undefined);
      world.advance(121 * 5);
      await alice.sync();
      const [deposit] = await alice.deposits();
      // A transaction every provider reports failed did fail; one only the first denies did not.
      assert.equal(deposit?.state, first === "failed" ? "failed" : "submitting", first);
    }
  });

  it("stays submitting while a provider does not hold every ledger the deposit could have been made in", async () => {
    const world = await createWorld();
    const fetch = sending(world, async (body, hash) =>
      rpcResult(body.id, { status: "ERROR", hash, latestLedger: world.vault.ledger }),
    );
    const alice = await openWallet({ ...world, fetch }, 0);
    await assert.rejects(alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") }));
    world.rpc.oldestLedger = world.vault.ledger + 2;
    world.advance(121 * 5);
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "submitting");
  });

  it("follows a shield the RPC took on though it answered that the network refused it", async () => {
    const world = await createWorld();
    const fetch = sending(world, async (body, hash, init) => {
      await world.fetch(RPC, init);
      return rpcResult(body.id, { status: "ERROR", hash, latestLedger: world.vault.ledger });
    });
    const alice = await openWallet({ ...world, fetch }, 0);
    const depositor = world.signer("depositor");
    await assert.rejects(alice.shield({ amount: 100n * XLM, signer: depositor }));
    assert.equal((await alice.deposits())[0]?.state, "submitting");
    // Another deposit goes only on the caller's word, while the first may yet land.
    await assert.rejects(
      alice.shield({ amount: 100n * XLM, signer: depositor }),
      isError("deposit_submitting"),
    );
    assert.equal(world.vault.pending.size, 1);
    world.rpc.run("ab".repeat(32), () => world.vault.flag(1, 100));
    for (let i = 0; i < 3; i++) {
      world.advance(3_600);
      world.fill(1);
      await alice.sync();
    }
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.id, 1);
    assert.equal(deposit?.flag?.kind, "legal_hold");
    assert.equal((await alice.history()).filter((h) => h.kind === "shield").length, 1);
  });

  it("makes another deposit while one is being submitted on the caller's word", async () => {
    const world = await createWorld();
    const fetch = sending(world, async (body, hash, init) => {
      await world.fetch(RPC, init);
      return rpcResult(body.id, { status: "ERROR", hash, latestLedger: world.vault.ledger });
    });
    const alice = await openWallet({ ...world, fetch }, 0);
    const depositor = world.signer("depositor");
    await assert.rejects(alice.shield({ amount: 10n * XLM, signer: depositor }));
    const again = await alice.shield({
      amount: 20n * XLM,
      signer: depositor,
      whileSubmitting: true,
    });
    assert.equal(again.depositId, 2);
    assert.equal(world.vault.pending.size, 2);
  });
});

describe("wallet: a deposit taken for failed", () => {
  it("is being submitted again once the vault's events show it made", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    let busy = false;
    let shieldHash: string | undefined;
    let answered = false;
    // Both providers deny the shield's transaction once the first has answered the shield's own
    // wait for it; the second cannot answer reads of events while busy.
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (body?.method === "sendTransaction") {
        const tx = TransactionBuilder.fromXDR(body.params.transaction, Networks.TESTNET);
        shieldHash = tx.hash().toString("hex");
      }
      const denied = body?.method === "getTransaction" && body.params.hash === shieldHash;
      if (denied && url.origin === RPC && !answered) {
        answered = true;
        return world.fetch(input, init);
      }
      if (denied) {
        return rpcResult(body.id, {
          status: "NOT_FOUND",
          latestLedger: world.vault.ledger,
          oldestLedger: 1,
        });
      }
      if (busy && url.origin === second && body?.method === "getEvents") return busyReply(body.id);
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    world.indexer.down = true;
    const receipt = await alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") });
    assert.equal(receipt.depositId, undefined);
    world.advance(121 * 5);
    busy = true;
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "failed");
    busy = false;
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.id, 1);
  });

  // A wallet whose only deposit is kept as failed and without its ID, as a sync that every provider
  // deceived would have left it, past the ledgers whose events show it made.
  async function keptFailed(world: Awaited<ReturnType<typeof createWorld>>) {
    const store = new MemoryStore();
    const alice = await openWallet(world, 0, store);
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    await alice.sync();
    const sealed = new SealedStore(store, storeKeyOf(0));
    const kept = (await loadState(sealed)) as WalletState;
    (kept.deposits[0] as Deposit).state = "failed";
    (kept.deposits[0] as Deposit).id = undefined;
    await saveState(sealed, kept);
    return openWallet(world, 0, store);
  }

  it("takes the ID the indexer gives once every provider's entry under it holds the deposit", async () => {
    const world = await createWorld();
    const alice = await keptFailed(world);
    world.fill(1);
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.id, 1);
  });

  it("is admitted once its notes are in the confirmed tree", async () => {
    const world = await createWorld();
    const store = new MemoryStore();
    const alice = await openWallet(world, 0, store);
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    // A deposit kept as failed, as a sync that every provider deceived would have left it.
    const sealed = new SealedStore(store, storeKeyOf(0));
    const kept = (await loadState(sealed)) as WalletState;
    (kept.deposits[0] as Deposit).state = "failed";
    (kept.deposits[0] as Deposit).id = undefined;
    await saveState(sealed, kept);
    const reopened = await openWallet(world, 0, store);
    world.advance(3_601);
    world.admitAll();
    await reopened.sync();
    const [deposit] = await reopened.deposits();
    assert.equal(deposit?.state, "admitted");
    assert.equal(deposit?.confirmed, true);
  });
});

describe("wallet: deposits seen through two RPC providers", () => {
  it("moves a deposit along only on what every RPC provider shows of it", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    let busy = false;
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (url.origin === second) {
        if (busy && body?.method === "getEvents") {
          const error = { code: -32603, message: "busy" };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }));
        }
        return world.fetch(RPC, init);
      }
      // The first provider reports every transaction as failed.
      if (url.origin === RPC && body?.method === "getTransaction") {
        const result = { status: "FAILED", latestLedger: world.vault.ledger };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: world.signer("alice depositor") }),
      isError("transaction_failed"),
    );
    // The deposit's event cannot be checked against the second provider, which reports the
    // transaction as a success, and no indexer names an ID to read the entry queue under.
    busy = true;
    world.indexer.down = true;
    assert.equal((await alice.sync()).crossChecked, false);
    let [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "submitting");
    busy = false;
    world.indexer.down = false;
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.id, 1);
  });
});

describe("wallet: a deposit's ID", () => {
  it("is taken from the shield only as every RPC provider reports it, and never shows another deposit", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    let lying = false;
    // While lying, the first provider reports every deposit's transaction as making deposit 1.
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      if (url.origin === second) return world.fetch(RPC, init);
      const res = await world.fetch(input, init);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (!lying || url.origin !== RPC || body?.method !== "getTransaction") return res;
      const reply = await res.json();
      if (reply.result?.status !== "SUCCESS") return new Response(JSON.stringify(reply));
      const meta = xdr.TransactionMeta.fromXDR(reply.result.resultMetaXdr, "base64");
      meta
        .v4()
        .sorobanMeta()
        ?.returnValue(xdr.ScVal.scvU64(new xdr.Uint64(1n)));
      reply.result.resultMetaXdr = meta.toXDR("base64");
      return new Response(JSON.stringify(reply));
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    // Someone else's deposit 1, which screening flagged.
    const other = await openWallet(world, 1);
    const { depositId: theirs } = await shielded(other, 50n * XLM, world.signer("someone"));
    world.rpc.run("ab".repeat(32), () => world.vault.flag(theirs, 1));
    lying = true;
    const receipt = await alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") });
    assert.equal(receipt.depositId, undefined);
    let [mine] = await alice.deposits();
    assert.equal(mine?.state, "submitting");
    assert.equal(mine?.id, undefined);
    await alice.sync();
    [mine] = await alice.deposits();
    assert.equal(mine?.state, "pending");
    assert.equal(mine?.id, 2);
    assert.equal(mine?.flag, undefined);
  });

  it("is taken from the shield once a provider that lags reports it within half a minute", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    let asked = 0;
    let first = 0;
    // The second provider has not taken in the deposit's ledger the first three times it is asked.
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (url.origin === RPC && body?.method === "getTransaction") first++;
      if (url.origin === second && body?.method === "getTransaction" && ++asked <= 3) {
        const result = { status: "NOT_FOUND", latestLedger: world.vault.ledger };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    const receipt = await alice.shield({ amount: 10n * XLM, signer: world.signer("depositor") });
    assert.equal(receipt.depositId, 1);
    assert.equal(asked, 4);
    // The first provider, which held the transaction at once, is not asked again.
    assert.equal(first, 2);
  });

  it("takes the indexer's account of a deposit only for its own depositor and amount", async () => {
    const world = await createWorld();
    let forged: Record<string, unknown> = {};
    // RPC cannot answer reads of the entry queue, so the indexer's account is all there is.
    let busy = true;
    const indexer = rewritingFetch(world, {
      "/v1/deposits": (body) => {
        const pending = body["pending"] as Record<string, unknown>[];
        return { ...body, pending: pending.map((d) => ({ ...d, ...forged })) };
      },
    });
    const fetch: FetchLike = async (input, init) => {
      const body = bodyOf(init);
      if (busy && body !== undefined && readsQueue(body)) return busyReply(body.id);
      return indexer(input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0);
    const { depositId } = await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.rpc.run("ab".repeat(32), () => world.vault.flag(depositId, 1));
    for (const field of [{ amount: "1" }, { depositor: world.signer("someone").publicKey }]) {
      forged = field;
      await alice.sync();
      const [mine] = await alice.deposits();
      assert.equal(mine?.flag, undefined);
    }
    forged = {};
    await alice.sync();
    let [mine] = await alice.deposits();
    assert.equal(mine?.flag?.reason, 1);
    assert.equal(mine?.confirmed, false);
    busy = false;
    await alice.sync();
    [mine] = await alice.deposits();
    assert.equal(mine?.flag?.reason, 1);
    assert.equal(mine?.confirmed, true);
  });
});

describe("wallet: a deposit whose ID the RPC providers did not report alike at once", () => {
  const second = "http://rpc2.test";

  // A wallet whose second provider has not yet taken in the ledger of the deposit it makes, so the
  // shield returns no ID; then neither provider holds that transaction any more. While `queue` is
  // "busy" the second provider fails its reads of the entry queue, and while it is "behind" it
  // shows no entry there.
  async function lagged(world: Awaited<ReturnType<typeof createWorld>>) {
    let lagging = true;
    const secondProvider = { queue: "honest" as "honest" | "busy" | "behind" };
    const dropped = new Set<string>();
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (url.origin === second && secondProvider.queue !== "honest" && readsQueue(body ?? {})) {
        const reply =
          secondProvider.queue === "busy"
            ? { error: { code: -32603, message: "busy" } }
            : { result: { entries: [], latestLedger: world.vault.ledger } };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, ...reply }));
      }
      if ((url.origin === RPC || url.origin === second) && body?.method === "getTransaction") {
        const hash = body.params.hash as string;
        if (dropped.has(hash) || (url.origin === second && lagging)) {
          const result = { status: "NOT_FOUND", latestLedger: world.vault.ledger };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
        }
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    const depositor = world.signer("depositor");
    const receipt = await alice.shield({ amount: 100n * XLM, signer: depositor });
    assert.equal(receipt.depositId, undefined);
    lagging = false;
    dropped.add(receipt.txHash);
    return { alice, depositor, second: secondProvider };
  }

  // Eight days pass with the app closed, longer than RPC keeps events and transactions.
  function closedForEightDays(world: Awaited<ReturnType<typeof createWorld>>): void {
    world.advance(8 * 86_400);
    world.rpc.oldestLedger = world.vault.ledger - 120_960;
  }

  it("is admitted once its notes are in the confirmed tree, and no longer counts as pending", async () => {
    const world = await createWorld();
    const { alice } = await lagged(world);
    closedForEightDays(world);
    world.admitAll();
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
    assert.equal(deposit?.confirmed, true);
    const balance = await alice.balance();
    assert.equal(balance.spendable, 100n * XLM);
    assert.equal(balance.pendingDeposits, 0n);
  });

  it("takes the ID the indexer gives once every provider's entry under it holds the deposit", async () => {
    const world = await createWorld();
    const { alice } = await lagged(world);
    closedForEightDays(world);
    world.rpc.run("ab".repeat(32), () => world.vault.flag(1, 100));
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.id, 1);
    assert.equal(deposit?.flag?.kind, "legal_hold");
    const entry = world.vault.pending.get(1);
    assert.equal(deposit?.earliestAdmission, Number(entry?.createdAt) + Number(entry?.delay));
    assert.equal(deposit?.confirmed, true);
  });

  it("takes the ID the indexer gives only on every provider's entry under it", async () => {
    const world = await createWorld();
    const { alice, second: provider } = await lagged(world);
    closedForEightDays(world);
    for (const queue of ["busy", "behind"] as const) {
      provider.queue = queue;
      await alice.sync();
      assert.equal((await alice.deposits())[0]?.state, "submitting", queue);
    }
    // An entry under the ID with another commitment is not this deposit's.
    const entry = world.vault.pending.get(1) as { commitments: [bigint, bigint] };
    const commitments = entry.commitments;
    entry.commitments = [commitments[0], commitments[1] + 1n];
    provider.queue = "honest";
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "submitting");
    entry.commitments = commitments;
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.id, 1);
  });

  it("takes no ID whose entry holds another deposit of the same depositor and amount", async () => {
    const world = await createWorld();
    const other = await openWallet(world, 1);
    await shielded(other, 100n * XLM, world.signer("depositor"));
    const { alice } = await lagged(world);
    closedForEightDays(world);
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.id, 2);
    assert.equal(deposit?.state, "pending");
  });

  it("takes the ID a refund names once every provider's entry under it holds the deposit, and no other", async () => {
    const world = await createWorld();
    const other = await openWallet(world, 1);
    const theirs = await shielded(other, 100n * XLM, world.signer("depositor"));
    const { alice, depositor } = await lagged(world);
    // A cancel of the other wallet's deposit names no ID of this one.
    await alice.cancelDeposit(theirs.depositId, depositor);
    assert.equal((await alice.deposits())[0]?.state, "submitting");
    world.rpc.run("ab".repeat(32), () => world.vault.flag(2, 1));
    world.advance(86_400);
    await alice.refundDeposit(2, world.signer("anyone"));
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.id, 2);
    assert.equal(deposit?.state, "refunded");
  });

  it("takes the ID a cancel names once every provider's entry under it holds the deposit", async () => {
    const world = await createWorld();
    const { alice, depositor } = await lagged(world);
    await alice.cancelDeposit(1, depositor);
    assert.equal(world.vault.pending.has(1), false);
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.id, 1);
    assert.equal(deposit?.state, "cancelled");
    assert.equal((await alice.balance()).pendingDeposits, 0n);
  });
});

describe("wallet: deposit status the indexer alone gives", () => {
  // A wallet whose indexer gives every pending deposit the resolution `lie` while it is set, and
  // whose RPC cannot answer reads of the entry queue while `busy` is.
  async function lied() {
    const world = await createWorld();
    const control: { lie: "refunded" | "admitted" | undefined; busy: boolean } = {
      lie: undefined,
      busy: false,
    };
    const indexer = rewritingFetch(world, {
      "/v1/deposits": (body) => {
        if (control.lie === undefined) return body;
        const pending = body["pending"] as Record<string, unknown>[];
        return {
          ...body,
          pending: [],
          resolved: pending.map((d) => ({ ...d, outcome: control.lie, reason: 1, resolved_at: 1 })),
        };
      },
    });
    const fetch: FetchLike = async (input, init) => {
      const body = bodyOf(init);
      if (control.busy && body !== undefined && readsQueue(body)) return busyReply(body.id);
      return indexer(input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0);
    return { world, alice, control };
  }

  it("is shown as unconfirmed, and the confirmed tree outweighs it", async () => {
    const { world, alice, control } = await lied();
    const depositor = world.signer("depositor");
    const byId = async () => new Map((await alice.deposits()).map((d) => [d.id, d]));
    const first = await shielded(alice, 10n * XLM, depositor);
    assert.equal((await byId()).get(first.depositId)?.confirmed, true);
    control.lie = "refunded";
    control.busy = true;
    await alice.sync();
    let deposits = await byId();
    assert.equal(deposits.get(first.depositId)?.state, "refunded");
    assert.equal(deposits.get(first.depositId)?.confirmed, false);
    control.lie = undefined;
    const second = await shielded(alice, 20n * XLM, depositor);
    assert.equal((await byId()).get(second.depositId)?.confirmed, true);
    await alice.sync();
    deposits = await byId();
    assert.equal(deposits.get(second.depositId)?.state, "pending");
    assert.equal(deposits.get(second.depositId)?.attested, false);
    assert.equal(deposits.get(second.depositId)?.confirmed, false);
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    deposits = await byId();
    for (const { depositId } of [first, second]) {
      assert.equal(deposits.get(depositId)?.state, "admitted");
      assert.equal(deposits.get(depositId)?.confirmed, true);
    }
  });

  it("gives way to every provider's entry in the entry queue, which shows the deposit still held", async () => {
    for (const lie of ["refunded", "admitted"] as const) {
      const { world, alice, control } = await lied();
      const { depositId } = await shielded(alice, 10n * XLM, world.signer("depositor"));
      world.rpc.run("ab".repeat(32), () => world.vault.flag(depositId, 100));
      control.lie = lie;
      control.busy = true;
      await alice.sync();
      let [deposit] = await alice.deposits();
      assert.equal(deposit?.state, lie);
      assert.equal(deposit?.confirmed, false);
      // The indexer lists the deposit again, while RPC still cannot answer.
      control.lie = undefined;
      await alice.sync();
      [deposit] = await alice.deposits();
      assert.equal(deposit?.state, "pending");
      assert.equal(deposit?.confirmed, false);
      // The indexer lies again; the entry queue every provider reads has the final word.
      control.lie = lie;
      control.busy = false;
      world.advance(3 * 86_400);
      await alice.sync();
      [deposit] = await alice.deposits();
      assert.equal(deposit?.state, "pending");
      assert.equal(deposit?.flag?.kind, "legal_hold");
      assert.equal(deposit?.attested, false);
      assert.equal(
        deposit?.earliestAdmission,
        Number(world.vault.pending.get(1)?.createdAt) + 3_600,
      );
      assert.equal(deposit?.confirmed, true);
    }
  });
});

describe("wallet: a cancel or refund every provider does not report", () => {
  const second = "http://rpc2.test";

  it("leaves a deposit whose cancel a first provider made up to the entry queue", async () => {
    const world = await createWorld();
    const swallowed = new Set<string>();
    // The first provider takes no cancel to the network, yet reports it a success.
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (url.origin === RPC && body?.method === "sendTransaction") {
        const tx = TransactionBuilder.fromXDR(body.params.transaction, Networks.TESTNET);
        const op = (tx as Transaction).operations[0];
        if (
          op?.type === "invokeHostFunction" &&
          op.func.invokeContract().functionName().toString() === "cancel"
        ) {
          const hash = tx.hash().toString("hex");
          swallowed.add(hash);
          const result = { status: "PENDING", hash, latestLedger: world.vault.ledger };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
        }
      }
      if (
        url.origin === RPC &&
        body?.method === "getTransaction" &&
        swallowed.has(body.params.hash)
      ) {
        const ledger = world.vault.ledger;
        const result = { status: "SUCCESS", ledger, latestLedger: ledger };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    const depositor = world.signer("depositor");
    const { depositId } = await shielded(alice, 10n * XLM, depositor);
    world.rpc.run("ab".repeat(32), () => world.vault.flag(depositId, 100));
    await alice.cancelDeposit(depositId, depositor);
    let [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "cancelled");
    assert.equal(deposit?.confirmed, false);
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(world.vault.pending.has(depositId), true);
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.flag?.kind, "legal_hold");
    assert.equal(deposit?.confirmed, true);
  });

  it("takes a deposit it cancelled, once gone from the entry queue and not in the confirmed tree, as cancelled", async () => {
    const world = await createWorld();
    let hiding = false;
    // While hiding, the second provider reports no transaction at all.
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (hiding && url.origin === second && body?.method === "getTransaction") {
        const result = { status: "NOT_FOUND", latestLedger: world.vault.ledger };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    const depositor = world.signer("depositor");
    const { depositId } = await shielded(alice, 10n * XLM, depositor);
    hiding = true;
    await alice.cancelDeposit(depositId, depositor);
    hiding = false;
    let [deposit] = await alice.deposits();
    assert.equal(deposit?.confirmed, false);
    // Past its proof's deadline, by which the deposit was made.
    world.advance(121 * 5);
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "cancelled");
    assert.equal(deposit?.refundKind, "cancelled");
    assert.equal(deposit?.confirmed, true);
  });
});

describe("wallet: a deposit gone from the entry queue", () => {
  const second = "http://rpc2.test";

  // A wallet with two providers, whose reads of the entry queue `answer` replaces, given the
  // provider, with no entry as of the ledger it returns, while it returns one.
  async function readsOfQueue(
    world: Awaited<ReturnType<typeof createWorld>>,
    answer: (provider: string) => number | undefined,
  ) {
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      const ledger = body !== undefined && readsQueue(body) ? answer(url.origin) : undefined;
      if (ledger !== undefined) return rpcResult(body.id, { entries: [], latestLedger: ledger });
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    return openWallet({ ...world, fetch }, 0, undefined, undefined, { secondRpcUrl: second });
  }

  it("is not gone on reads of providers behind the ledger it was last shown at", async () => {
    // Both providers answer from a ledger before the deposit, or the first claims it gone at the
    // latest ledger while the second answers from before it.
    for (const lying of [false, true]) {
      const world = await createWorld();
      let hideAt: number | undefined;
      const alice = await readsOfQueue(world, (provider) =>
        hideAt === undefined ? undefined : lying && provider === RPC ? world.vault.ledger : hideAt,
      );
      const before = world.vault.ledger;
      const { depositId } = await shielded(alice, 100n * XLM, world.signer("depositor"));
      world.rpc.run("ab".repeat(32), () => world.vault.flag(depositId, 100));
      world.advance(121 * 5);
      world.fill(1);
      await alice.sync();
      hideAt = before;
      world.fill(1);
      await alice.sync();
      hideAt = undefined;
      for (let i = 0; i < 3; i++) {
        world.fill(1);
        await alice.sync();
      }
      const [deposit] = await alice.deposits();
      assert.equal(deposit?.state, "pending");
      assert.equal(deposit?.flag?.kind, "legal_hold");
      assert.equal(deposit?.confirmed, true);
    }
  });

  it("is not gone on reads from before its proof's deadline, though no provider showed it yet", async () => {
    const world = await createWorld();
    let hideAt: number | undefined;
    const alice = await readsOfQueue(world, () => hideAt);
    hideAt = world.vault.ledger;
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    await alice.sync();
    assert.notEqual((await alice.deposits())[0]?.state, "refunded");
  });

  it("is not gone on reads from before the ledger it was last shown at, past its deadline", async () => {
    const world = await createWorld();
    let hideAt: number | undefined;
    const alice = await readsOfQueue(world, () => hideAt);
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    world.advance(121 * 5);
    world.fill(1);
    await alice.sync();
    hideAt = world.vault.ledger - 1;
    world.fill(1);
    await alice.sync();
    assert.notEqual((await alice.deposits())[0]?.state, "refunded");
  });

  it("is settled only by a sync whose reads still show it gone", async () => {
    const world = await createWorld();
    let mode: "gone" | "busy" | "honest" = "honest";
    let goneLedger = 0;
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (body !== undefined && readsQueue(body)) {
        if (mode === "gone") return rpcResult(body.id, { entries: [], latestLedger: goneLedger });
        if (mode === "busy" && url.origin === second) return busyReply(body.id);
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    world.advance(121 * 5);
    await alice.sync();
    // Both claim it gone as of a ledger the tree has not reached; then the tree passes it while
    // the second provider cannot answer.
    mode = "gone";
    goneLedger = world.vault.ledger + 50;
    await alice.sync();
    mode = "busy";
    for (let i = 0; i < 60; i++) world.fill(1);
    await alice.sync();
    assert.notEqual((await alice.deposits())[0]?.state, "refunded");
    mode = "honest";
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "pending");
  });

  it("is not gone while one provider shows it, though another provider once answered from behind it", async () => {
    const world = await createWorld();
    let firstLies = false;
    let secondStaleAt: number | undefined;
    let firstLedger = 0;
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (body !== undefined && readsQueue(body)) {
        if (url.origin === RPC && firstLies) {
          return rpcResult(body.id, { entries: [], latestLedger: firstLedger });
        }
        if (url.origin === second && secondStaleAt !== undefined) {
          const stale = secondStaleAt;
          secondStaleAt = undefined;
          return rpcResult(body.id, { entries: [], latestLedger: stale });
        }
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    const before = world.vault.ledger;
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    world.rpc.run("ab".repeat(32), () => world.vault.flag(1, 100));
    await alice.sync();
    // The first provider claims the deposit gone as of a ledger past the wallet's tree, while the
    // second answers once from a node behind the deposit, then shows it again.
    firstLies = true;
    firstLedger = world.vault.ledger + 50;
    secondStaleAt = before;
    await alice.sync();
    for (let i = 0; i < 60; i++) world.fill(1);
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.flag?.kind, "legal_hold");
  });

  it("is not gone once every provider showed it again, while they then disagree", async () => {
    const world = await createWorld();
    let mode: "gone" | "split" | "honest" = "honest";
    let goneLedger = 0;
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      const split = mode === "split" && url.origin === RPC;
      if (body !== undefined && readsQueue(body) && (mode === "gone" || split)) {
        return rpcResult(body.id, { entries: [], latestLedger: goneLedger });
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await shielded(alice, 100n * XLM, world.signer("depositor"));
    world.rpc.run("ab".repeat(32), () => world.vault.flag(1, 100));
    world.advance(121 * 5);
    await alice.sync();
    // Both show it gone as of a ledger the tree has not reached; then both show it again.
    mode = "gone";
    goneLedger = world.vault.ledger + 50;
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.confirmed, false);
    mode = "honest";
    await alice.sync();
    // Then they disagree while the tree passes the old ledger.
    mode = "split";
    goneLedger = world.vault.ledger;
    for (let i = 0; i < 60; i++) world.fill(1);
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.state, "pending");
  });

  it("is gone by the ledger of the read that shows it gone, not by one a later read undid", async () => {
    const world = await createWorld();
    let mode: "gone" | "split" | "honest" = "honest";
    let goneLedger = 0;
    let admitting = false;
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (body !== undefined && readsQueue(body)) {
        const split = mode === "split" && url.origin === RPC;
        if (mode === "gone" || split) {
          return rpcResult(body.id, { entries: [], latestLedger: goneLedger });
        }
        if (admitting) {
          admitting = false;
          world.admitAll();
        }
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.advance(121 * 5);
    await alice.sync();
    mode = "gone";
    goneLedger = world.vault.ledger + 50;
    await alice.sync();
    // The second provider shows it again, while the first still claims it gone.
    mode = "split";
    await alice.sync();
    mode = "honest";
    // The tree passes that ledger, and the deposit is admitted after a sync's views, before its
    // reads of the entry queue.
    for (let i = 0; i < 60; i++) world.fill(1);
    world.advance(3_601);
    admitting = true;
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.notEqual(deposit?.state, "refunded");
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
  });

  it("went back to its depositor when its notes are not in the confirmed tree of a later ledger", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const { depositId } = await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.rpc.run("ab".repeat(32), () => world.vault.flag(depositId, 1));
    await alice.sync();
    // Refunded by someone else, while no indexer gives the deposit's resolution.
    world.advance(86_400);
    world.rpc.run("ac".repeat(32), () => world.vault.refund(depositId));
    world.indexer.down = true;
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "refunded");
    assert.equal(deposit?.refundKind, "refused");
    assert.equal(deposit?.confirmed, true);
  });

  it("waits for the confirmed tree of the latest ledger any provider showed the deposit gone at", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    let reading = false;
    // The first provider shows the entry queue without the deposit while it is still there; the
    // deposit is admitted before the second provider reads the queue.
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (reading && body !== undefined && readsQueue(body)) {
        if (url.origin === RPC) {
          const result = { entries: [], latestLedger: world.vault.ledger };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
        }
        reading = false;
        world.admitAll();
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.advance(3_601);
    reading = true;
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.notEqual(deposit?.state, "refunded");
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
    assert.equal(deposit?.confirmed, true);
  });

  // A fetch that answers the vault reads of a sync, while `stale` names a ledger for a provider,
  // with what the vault showed when `capture` was last called, as of that ledger.
  function staleViews(world: Awaited<ReturnType<typeof createWorld>>, second: string) {
    const nextLeaf = xdr.ScVal.scvVec([xdr.ScVal.scvSymbol("NextLeaf")]);
    const isView = (body: { method?: string; params?: { keys?: string[] } }): boolean =>
      body.method === "getLedgerEntries" &&
      (body.params?.keys ?? []).some((k) => {
        const key = xdr.LedgerKey.fromXDR(k, "base64");
        return (
          key.switch().name === "contractData" &&
          key.contractData().key().toXDR("base64") === nextLeaf.toXDR("base64")
        );
      });
    let captured: Record<string, unknown> | undefined;
    const control = {
      stale: new Map<string, number>(),
      capture: async () => {
        const keys = (await lastView)?.params.keys;
        const res = await world.fetch(RPC, {
          method: "POST",
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: 0,
            method: "getLedgerEntries",
            params: { keys },
          }),
        });
        captured = ((await res.json()) as { result: Record<string, unknown> }).result;
      },
    };
    let lastView: Promise<{ params: { keys: string[] } } | undefined> = Promise.resolve(undefined);
    const fetch: FetchLike = async (input, init) => {
      const url = new URL(input);
      const body = bodyOf(init);
      if (body !== undefined && isView(body)) {
        lastView = Promise.resolve(body);
        const ledger = control.stale.get(url.origin);
        if (ledger !== undefined && captured !== undefined) {
          const result = { ...captured, latestLedger: ledger };
          return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
        }
      }
      return world.fetch(url.origin === second ? RPC : input, init);
    };
    return { fetch, control };
  }

  it("never takes a deposit gone from the queue for refunded on a tree an indexer that lags left short", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    await alice.sync();
    world.advance(3_601);
    // The indexer serves the leaves, and is complete to the ledgers, from before the admission.
    world.indexer.leafLimit = world.vault.tree.leafCount;
    world.indexer.completeTo = world.vault.ledger;
    world.admitAll();
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.notEqual(deposit?.state, "refunded");
    world.indexer.leafLimit = undefined;
    world.indexer.completeTo = undefined;
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
  });

  it("never takes a deposit gone from the queue for refunded on a tree that holds only part of a ledger", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    await alice.sync();
    world.advance(3_601);
    // One ledger adds another payment's pair, then the deposit's; the indexer serves the first.
    world.indexer.leafLimit = world.vault.tree.leafCount + 2;
    world.indexer.completeTo = world.vault.ledger;
    world.rpc.run("ad".repeat(32), () => {
      world.vault.insertFiller(1);
      world.vault.attest(1);
      world.vault.admit([1]);
    });
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.notEqual(deposit?.state, "refunded");
    world.indexer.leafLimit = undefined;
    world.indexer.completeTo = undefined;
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
  });

  it("takes a deposit as attested only once every provider's view shows it", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    const { fetch, control } = staleViews(world, second);
    const alice = await openWallet({ ...world, fetch }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    await alice.sync();
    await control.capture();
    world.rpc.run("ae".repeat(32), () => world.vault.attest(1));
    control.stale.set(second, world.vault.ledger);
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.attested, false);
    control.stale.clear();
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.attested, true);
  });

  it("takes a deposit gone from the queue, and not in a tree with a checked leaf of a later ledger, for refunded", async () => {
    const world = await createWorld();
    let refunding = false;
    const fetch: FetchLike = async (input, init) => {
      const body = bodyOf(init);
      if (refunding && body !== undefined && readsQueue(body)) {
        refunding = false;
        world.rpc.run("ac".repeat(32), () => world.vault.refund(1));
      }
      return world.fetch(input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0);
    const { depositId } = await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.rpc.run("ab".repeat(32), () => world.vault.flag(depositId, 1));
    world.advance(86_400);
    // Refunded after the views of a sync, which then sees the deposit gone from the queue.
    refunding = true;
    await alice.sync();
    assert.equal((await alice.deposits())[0]?.confirmed, false);
    // Other payments add leaves; the next sync checks the first of them, while the view already
    // shows more.
    world.fill(1);
    world.indexer.leafLimit = world.vault.tree.leafCount;
    world.indexer.completeTo = world.vault.ledger;
    world.fill(1);
    await alice.sync();
    const [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "refunded");
    assert.equal(deposit?.refundKind, "refused");
    assert.equal(deposit?.confirmed, true);
  });

  it("never takes a deposit gone from the queue for refunded on a view of the tree older than it", async () => {
    const world = await createWorld();
    const second = "http://rpc2.test";
    const { fetch, control } = staleViews(world, second);
    let admitting = false;
    const admitted: FetchLike = async (input, init) => {
      const body = bodyOf(init);
      if (admitting && body !== undefined && readsQueue(body)) {
        admitting = false;
        world.admitAll();
      }
      return fetch(input, init);
    };
    const alice = await openWallet({ ...world, fetch: admitted }, 0, undefined, undefined, {
      secondRpcUrl: second,
    });
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.advance(3_601);
    await alice.sync();
    await control.capture();
    // Admitted after the views of a sync, which then sees the deposit gone from the queue.
    const before = world.vault.ledger;
    admitting = true;
    await alice.sync();
    // The views of the tree as it was: the first provider's at a later ledger, the second's at the
    // ledger before the admission.
    control.stale.set(RPC, world.vault.ledger + 10);
    control.stale.set(second, before);
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.notEqual(deposit?.state, "refunded");
    control.stale.clear();
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
  });

  it("was admitted when it left the queue after the confirmed tree was read", async () => {
    const world = await createWorld();
    let admitting = false;
    // The deposit is admitted between the sync's reads of the tree and of the entry queue.
    const fetch: FetchLike = async (input, init) => {
      const body = bodyOf(init);
      if (admitting && body !== undefined && readsQueue(body)) {
        admitting = false;
        world.admitAll();
      }
      return world.fetch(input, init);
    };
    const alice = await openWallet({ ...world, fetch }, 0);
    await shielded(alice, 10n * XLM, world.signer("depositor"));
    world.advance(3_601);
    admitting = true;
    world.indexer.down = true;
    await alice.sync();
    let [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "pending");
    assert.equal(deposit?.confirmed, false);
    await alice.sync();
    [deposit] = await alice.deposits();
    assert.equal(deposit?.state, "admitted");
    assert.equal(deposit?.confirmed, true);
  });
});

describe("wallet: screening", () => {
  it("presents a deposit held for review, which may still be admitted, apart from refusals", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    const held = await shielded(alice, 10n * XLM, depositor);
    const refused = await shielded(alice, 20n * XLM, depositor);
    const ordered = await shielded(alice, 30n * XLM, depositor);
    world.rpc.run("ab".repeat(32), () => world.vault.flag(held.depositId, 6));
    world.rpc.run("ac".repeat(32), () => world.vault.flag(refused.depositId, 5));
    world.rpc.run("ad".repeat(32), () => world.vault.flag(ordered.depositId, 100));
    await alice.sync();
    const byId = async () => new Map((await alice.deposits()).map((d) => [d.id, d]));
    let deposits = await byId();
    assert.equal(deposits.get(held.depositId)?.flag?.kind, "held_for_review");
    assert.equal(deposits.get(held.depositId)?.flag?.reason, 6);
    assert.equal(
      deposits.get(held.depositId)?.refundableAt,
      Number(world.vault.timestamp) + 86_400,
    );
    assert.equal(deposits.get(refused.depositId)?.flag?.kind, "refused_by_reviewer");
    assert.equal(deposits.get(ordered.depositId)?.flag?.kind, "legal_hold");
    // The review clears the held deposit, which is then admitted.
    world.rpc.run("ae".repeat(32), () => world.vault.unflag(held.depositId));
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    deposits = await byId();
    assert.equal(deposits.get(held.depositId)?.state, "admitted");
    assert.equal(deposits.get(held.depositId)?.flag, undefined);
    // A refused deposit goes back with the reason it was refused for.
    world.advance(86_400);
    await alice.refundDeposit(refused.depositId, world.signer("anyone"));
    await alice.cancelDeposit(ordered.depositId, depositor);
    // Their own transactions, which every provider reports, now say what became of them.
    deposits = await byId();
    assert.equal(deposits.get(refused.depositId)?.confirmed, true);
    assert.equal(deposits.get(ordered.depositId)?.confirmed, true);
    await alice.sync();
    deposits = await byId();
    assert.equal(deposits.get(refused.depositId)?.state, "refunded");
    assert.equal(deposits.get(refused.depositId)?.refundKind, "refused_by_reviewer");
    assert.equal(deposits.get(ordered.depositId)?.state, "cancelled");
    assert.equal(deposits.get(ordered.depositId)?.refundKind, "cancelled");
  });

  it("presents every refusal code of the policy as a refusal, and a code it does not know as unknown", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const depositor = world.signer("alice depositor");
    const codes = [1, 2, 3, 4, 99, 7, 101];
    const ids: number[] = [];
    for (const [i, code] of codes.entries()) {
      const { depositId } = await shielded(alice, 10n * XLM, depositor);
      world.rpc.run(String(i).padStart(64, "f"), () => world.vault.flag(depositId, code));
      ids.push(depositId);
    }
    await alice.sync();
    const kinds = new Map((await alice.deposits()).map((d) => [d.id, d.flag?.kind]));
    assert.deepEqual(
      ids.map((id) => kinds.get(id)),
      ["refused", "refused", "refused", "refused", "refused", "unknown", "unknown"],
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
    // Like a relayed one, it is confirmed by the chain's evidence in a sync, not by RPC's word.
    assert.ok("planId" in result && result.state === "submitted");
    assert.equal(world.relayer.submissions.length, 0);
    // the spent note is locked at once; the change counts once a sync has found its leaf
    assert.equal((await alice.balance()).spendable, 0n);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
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
    // The relayer builds the transaction only when it sends it, so there is no hash yet; the
    // chain shows the payment once it lands.
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.txHash, undefined);
    world.advance(3_700);
    world.relayer.releaseHeld();
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.match(plan?.txHash ?? "", /^[0-9a-f]{64}$/);
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

  it("covers a long hold at the pace at which ledgers close", async () => {
    const world = await createWorld();
    // Ledgers close every four seconds, so the relayer predicts more of them for the hold.
    world.rpc.secondsPerLedger = 4;
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 3_600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    const [submission] = world.relayer.submissions;
    // an hour and the relayer's 10-minute window in four-second ledgers, and the usual 120
    assert.ok((submission?.ext.deadline as number) >= world.vault.ledger + 1_050 + 120);
    assert.equal((await alice.plans())[0]?.state, "submitted");
  });

  it("at most doubles a held payment's validity when close times claim faster ledgers", async () => {
    const world = await createWorld();
    // RPC's close times claim a ledger a second; the relayer goes by five.
    world.rpc.secondsPerLedger = 1;
    world.relayer.pace = 5;
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 3_600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    const deadline = world.relayer.submissions[0]?.ext.deadline as number;
    // the hold and the relayer's window at five seconds a ledger, twice over, and the usual 120
    assert.ok(deadline <= world.vault.ledger + 2 * 840 + 120);
  });

  it("follows a held payment by its ID, sends it again to a relayer that restarted, and takes its hash", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 3_600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.relayerStatus, "held");
    // A rescan rebuilds the plan's fate from the chain, and the relayer still holds the request.
    await alice.rescan();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    // A restarted relayer has forgotten the request: the same proof goes to it again, still held.
    world.relayer.restart();
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.relayerStatus, "held");
    const [first, again] = world.relayer.submissions;
    assert.equal(world.relayer.submissions.length, 2);
    assert.deepEqual(again?.proof, first?.proof);
    assert.equal(again?.notBefore, notBefore);
    // Once sent, the request has a hash, which the plan takes before the wallet sees it land: the
    // indexer has not served its leaves yet, and RPC is behind on events.
    world.advance(3_700);
    world.indexer.leafLimit = world.vault.leaves.length;
    world.relayer.releaseHeld();
    world.rpc.oldestLedger = world.vault.ledger + 1;
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.relayerStatus, "success");
    assert.match(plan?.txHash ?? "", /^[0-9a-f]{64}$/);
    world.indexer.leafLimit = undefined;
    world.rpc.oldestLedger = 1;
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(world.relayer.submissions.length, 2);
  });

  it("sends a forgotten held payment again only while its deadline allows", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.restart();
    // Past the deadline the vault refuses the proof, so it goes nowhere again. The indexer has
    // served neither the latest leaves nor the spends up to the deadline, so the plan stays open,
    // and a sync still asks about it.
    const deadline = world.relayer.submissions[0]?.ext.deadline as number;
    world.vault.ledger = deadline + 1;
    world.indexer.leafLimit = world.vault.leaves.length;
    world.indexer.completeTo = deadline - 1;
    world.fill(1);
    const submits = () => world.requests.filter((r) => r === `${RELAYER}/v1/submit`).length;
    const before = submits();
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "submitted");
    assert.equal(submits(), before);
  });

  it("asks the relayer about a held payment while the indexer is down", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.indexer.down = true;
    world.relayer.restart();
    assert.equal((await alice.sync()).source, "rpc");
    assert.equal((await alice.plans())[0]?.relayerStatus, "held");
    assert.equal(world.relayer.submissions.length, 2);
  });

  it("keeps following a held payment the relayer refuses again as a duplicate", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.forgetIds();
    await alice.sync();
    // The proof went again, and the relayer that still holds it answered duplicate.
    assert.equal(world.requests.filter((r) => r.endsWith("/v1/submit")).length, 2);
    assert.equal(world.relayer.submissions.length, 1);
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.relayerStatus, "held");
    world.advance(700);
    world.relayer.releaseHeld();
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
  });

  it("sends a forgotten held payment again in the next sync when the relayer is busy", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.restart();
    world.relayer.failures.push({ error: "unavailable" });
    await alice.sync();
    assert.equal((await alice.plans())[0]?.relayerStatus, "unknown");
    await alice.sync();
    assert.equal((await alice.plans())[0]?.relayerStatus, "held");
    assert.equal(world.relayer.submissions.length, 2);
  });

  it("gives a forgotten held payment whose moment has passed a new one at random", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.restart();
    world.advance(700);
    await alice.sync();
    const now = Number(world.vault.timestamp);
    const again = world.relayer.submissions[1]?.notBefore as number;
    // within the relayer's window, so that the deadline still covers it and the relayer's jitter
    assert.ok(again > now && again <= now + 401, `not_before ${again - now} s ahead`);
    assert.equal((await alice.plans())[0]?.relayerStatus, "held");
    // With no time left for a hold before the deadline, the payment waits for its fate instead.
    world.relayer.restart();
    world.advance(600);
    await alice.sync();
    assert.equal(world.relayer.submissions.length, 2);
  });

  it("leaves a forgotten held payment alone once its deadline cannot cover a new window at the pace of ledgers", async () => {
    const world = await createWorld();
    world.rpc.secondsPerLedger = 4;
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    const deadline = world.relayer.submissions[0]?.ext.deadline as number;
    world.relayer.restart();
    // 140 ledgers before the deadline and its margin: at four seconds a ledger, too few for the
    // relayer's 10-minute window, though five-second ledgers would leave room.
    world.advance(5 * (deadline - world.vault.ledger - 160));
    const submits = () => world.requests.filter((r) => r === `${RELAYER}/v1/submit`).length;
    const before = submits();
    await alice.sync();
    assert.equal(submits(), before);
    assert.equal((await alice.plans())[0]?.state, "submitted");
  });

  it("never pays twice when a held payment is sent again, its ID forgotten and then retried", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.restart();
    await alice.sync();
    // Another instance behind the same address knows no IDs, but still holds the request.
    world.relayer.forgetIds();
    await alice.sync();
    const [held] = await alice.plans();
    assert.equal(held?.mustRetry, true);
    // A retry spends the same notes, which the held request still claims.
    await assert.rejects(
      alice.retry(held?.planId as string, { maxFee: 2n * XLM, confirm: confirmAll }),
      (err: unknown) => err instanceof CyphrasError && err.details["code"] === "duplicate",
    );
    world.advance(700);
    world.relayer.releaseHeld();
    await alice.sync();
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 10n * XLM);
    const states = (await alice.plans()).map((p) => p.state).sort();
    assert.deepEqual(states, ["settled", "superseded"]);
  });

  it("stops following a held payment that was cancelled, and never sends it again", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.cancelHeld();
    await alice.sync();
    assert.equal((await alice.plans())[0]?.relayerStatus, "cancelled");
    world.relayer.restart();
    world.advance(700);
    world.relayer.releaseHeld();
    await alice.sync();
    assert.equal((await alice.plans())[0]?.relayerStatus, "cancelled");
    assert.equal(world.relayer.submissions.length, 1);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 0n);
  });

  it("stops following a held payment the relayer dropped when it was due", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM, notBefore });
    world.relayer.refuseHeld = 2;
    world.advance(700);
    world.relayer.releaseHeld();
    await alice.sync();
    let [plan] = await alice.plans();
    // The relayer saw the proof, so its notes stay with the plan until its deadline.
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.relayerStatus, "failed");
    assert.equal(plan?.mustRetry, true);
    // A request that failed is not sent again, even to a relayer that forgot it.
    world.relayer.restart();
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.relayerStatus, "failed");
    assert.equal(world.relayer.submissions.length, 1);
  });

  it("cancels a held payment, which no one sends then, and keeps its notes until its deadline", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    const sub = await alice.send({
      to: bob.generateAddress(),
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      notBefore,
    });
    assert.equal(await alice.cancelHeld(sub.planId), true);
    let [plan] = await alice.plans();
    assert.equal(plan?.relayerStatus, "cancelled");
    assert.equal(plan?.mustRetry, true);
    // Neither the relayer, once due, nor the wallet, after a restart of the relayer, sends it.
    world.advance(700);
    world.relayer.releaseHeld();
    world.relayer.restart();
    await alice.sync();
    assert.equal(world.relayer.submissions.length, 1);
    assert.equal((await alice.balance()).locked, 100n * XLM);
    world.advance(86_400);
    world.fill(1);
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    assert.equal((await alice.balance()).spendable, 100n * XLM);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 0n);
    await assert.rejects(alice.cancelHeld(sub.planId), isError("invalid_argument"));
    await assert.rejects(alice.cancelHeld("00".repeat(16)), isError("not_found"));
  });

  it("reports a held payment the relayer has sent already as not cancelled", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    const sub = await alice.send({
      to: bob.generateAddress(),
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      notBefore,
    });
    world.advance(700);
    world.relayer.releaseHeld();
    assert.equal(await alice.cancelHeld(sub.planId), false);
    const [plan] = await alice.plans();
    assert.equal(plan?.relayerStatus, "success");
    assert.match(plan?.txHash ?? "", /^[0-9a-f]{64}$/);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });

  it("never sends again a held payment the relayer lost once asked to cancel it", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    const sub = await alice.send({
      to: bob.generateAddress(),
      amount: 10n * XLM,
      maxFee: 2n * XLM,
      notBefore,
    });
    // A relayer that restarted no longer knows the request, so it cannot confirm the cancel.
    world.relayer.restart();
    assert.equal(await alice.cancelHeld(sub.planId), false);
    assert.equal((await alice.plans())[0]?.relayerStatus, "unknown");
    const submits = () => world.requests.filter((r) => r === `${RELAYER}/v1/submit`).length;
    const before = submits();
    await alice.sync();
    assert.equal(submits(), before);
    assert.equal((await alice.plans())[0]?.state, "submitted");
  });

  it("passes over a relayer that has paused relaying, for another one or for self-relay", async () => {
    const { world, alice } = await funded();
    const destination = keypairFor("payee").publicKey();
    world.rpc.account(keypairFor("payee"));
    world.relayer.paused = true;
    await assert.rejects(
      alice.unshield({ to: destination, amount: 5n * XLM, maxFee: 2n * XLM, confirm: confirmAll }),
      (err: unknown) =>
        isError("service_unavailable")(err) && (err as CyphrasError).details["paused"] === true,
    );
    // Another relayer takes the payment.
    const second = "http://relayer2.test";
    const both = await openWallet(
      {
        ...world,
        fetch: async (input, init) => {
          const url = new URL(input);
          if (url.origin !== second) return world.fetch(input, init);
          world.relayer.paused = false;
          try {
            return await world.fetch(`${RELAYER}${url.pathname}${url.search}`, init);
          } finally {
            world.relayer.paused = true;
          }
        },
      },
      0,
      new MemoryStore(),
      undefined,
      { relayers: [RELAYER, second] },
    );
    await both.sync();
    const relayed = await both.unshield({
      to: destination,
      amount: 5n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    assert.ok("planId" in relayed);
    // A self-relayed unshield needs no relayer.
    await alice.sync();
    const own = await alice.unshield({
      to: destination,
      amount: 5n * XLM,
      selfRelay: world.signer("my account"),
      confirm: confirmAll,
    });
    assert.ok("planId" in own);
    await alice.sync();
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === destination).map((t) => t.amount),
      [5n * XLM, 5n * XLM],
    );
  });

  it("unshields less than 1 XLM to an account that exists", async () => {
    const { world, alice } = await funded();
    const payee = world.signer("small payee").publicKey;
    await alice.unshield({ to: payee, amount: XLM / 2n, maxFee: 2n * XLM, confirm: confirmAll });
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === payee).map((t) => t.amount),
      [XLM / 2n],
    );
  });

  it("refuses a destination that does not exist unless the payout can create it, and the vault itself", async () => {
    const { world, alice } = await funded();
    const missing = keypairFor("nobody yet").publicKey();
    // Below the minimum balance of a new account, a payout cannot create it.
    await assert.rejects(
      alice.unshield({ to: missing, amount: XLM / 2n, maxFee: 2n * XLM, confirm: confirmAll }),
      (err: unknown) =>
        err instanceof CyphrasError &&
        err.code === "destination_invalid" &&
        err.details["minimum"] === XLM.toString(),
    );
    // No payment creates a contract.
    const noContract = StrKey.encodeContract(Buffer.alloc(32, 7));
    await assert.rejects(
      alice.unshield({ to: noContract, amount: 5n * XLM, maxFee: 2n * XLM, confirm: confirmAll }),
      isError("destination_invalid"),
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

  it("unshields to a native account that does not exist yet, which its payout creates", async () => {
    const { world, alice } = await funded();
    const fresh = keypairFor("fresh account").publicKey();
    const reviews: string[][] = [];
    const result = await alice.unshield({
      to: fresh,
      amount: 5n * XLM,
      maxFee: 2n * XLM,
      confirm: (review) => {
        reviews.push(review.warnings.map((w) => w.code));
        return true;
      },
    });
    assert.ok("planId" in result);
    // The pool funds the account, so no funder links it: the warning explains that instead.
    assert.ok(reviews[0]?.includes("destination_created_by_payout"));
    assert.ok(!reviews[0]?.includes("new_destination_account"));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    assert.ok(world.rpc.accounts.has(fresh));
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === fresh).map((t) => t.amount),
      [5n * XLM],
    );
    // A muxed address on a missing account creates its base account the same way.
    const base = keypairFor("fresh base account").publicKey();
    const muxed = new MuxedAccount(new Account(base, "0"), "7").accountId();
    await alice.unshield({ to: muxed, amount: 2n * XLM, maxFee: 2n * XLM, confirm: confirmAll });
    await alice.sync();
    assert.ok(world.rpc.accounts.has(base));
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

describe("wallet: a pool of an issued asset", () => {
  it("unshields only to an existing account whose authorized trustline has room", async () => {
    const issuer = keypairFor("issuer").publicKey();
    const world = await createWorld({ asset: `USDC:${issuer}` });
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const unshield = (to: string) =>
      alice.unshield({ to, amount: 5n * XLM, maxFee: 2n * XLM, confirm: confirmAll });
    // No payment of an issued asset creates an account, however large.
    await assert.rejects(
      unshield(keypairFor("nobody yet").publicKey()),
      isError("destination_invalid"),
    );
    const holder = world.signer("holder").publicKey;
    await assert.rejects(unshield(holder), isError("destination_invalid"));
    world.rpc.trustlines.set(holder, { authorized: false, limit: 1_000n * XLM, balance: 0n });
    await assert.rejects(unshield(holder), isError("destination_invalid"));
    world.rpc.trustlines.set(holder, { authorized: true, limit: 10n * XLM, balance: 6n * XLM });
    await assert.rejects(unshield(holder), isError("destination_invalid"));
    world.rpc.trustlines.set(holder, { authorized: true, limit: 10n * XLM, balance: 5n * XLM });
    assert.ok("planId" in (await unshield(holder)));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
  });

  it("burns a payout to the asset's issuer only when the caller agrees to it", async () => {
    const issuer = keypairFor("issuer").publicKey();
    const world = await createWorld({
      asset: `USDC:${issuer}`,
      limits: { maxDailyOutflow: 50n * XLM, tvlCap: 350n * XLM },
    });
    world.signer("issuer");
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const burned = (err: unknown) =>
      err instanceof CyphrasError &&
      err.code === "destination_is_issuer" &&
      err.details["payout"] === "burned";
    const unshield = (to: string, burnToIssuer?: boolean) =>
      alice.unshield({
        to,
        amount: 5n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
        ...(burnToIssuer === undefined ? {} : { burnToIssuer }),
      });
    await assert.rejects(unshield(issuer), burned);
    // A split is refused before its operation starts.
    await assert.rejects(
      alice.unshield({
        to: issuer,
        amount: 90n * XLM,
        maxFee: 2n * XLM,
        split: true,
        confirm: confirmAll,
      }),
      burned,
    );
    assert.deepEqual(await alice.continueOperations(), []);
    // Nor through a muxed address on the issuer's account.
    await assert.rejects(
      unshield(new MuxedAccount(new Account(issuer, "0"), "3").accountId()),
      burned,
    );
    assert.deepEqual(await alice.plans(), []);
    // The issuer holds no trustline for its own asset, so none is asked for.
    assert.ok("planId" in (await unshield(issuer, true)));
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    assert.deepEqual(
      world.vault.transfers.filter((t) => t.to === issuer).map((t) => t.amount),
      [5n * XLM],
    );
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
    assert.equal(check.confirmedBy, "chain");
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
    // Once RPC no longer holds the transaction, only an explicit choice accepts the indexer.
    world.rpc.records.delete(sent.txHash as string);
    await assert.rejects(
      PrivateWallet.verifyDisclosure(fromSender, options),
      isError("history_unavailable"),
    );
    const indexerOnly = await PrivateWallet.verifyDisclosure(fromSender, {
      ...options,
      acceptIndexerOnly: true,
    });
    assert.equal(indexerOnly.confirmedBy, "indexer");
    assert.equal(indexerOnly.senderProven, true);
  });
});
