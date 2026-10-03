import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  Address,
  TransactionBuilder,
  type Transaction,
  nativeToScVal,
  xdr,
} from "@stellar/stellar-base";
import { decodeAddress } from "../../src/address.ts";
import { bytesToHex, randomBytes } from "../../src/bytes.ts";
import { encryptOutput } from "../../src/encryption.ts";
import { CyphrasError } from "../../src/errors.ts";
import { noteCommitment, randomFieldElement, randomScalar } from "../../src/notes.ts";
import type { FetchLike } from "../../src/net/http.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { keySource } from "../../src/keysource.ts";
import { type Plan, type WalletState, loadState, saveState } from "../../src/wallet/state.ts";
import { PrivateWallet } from "../../src/wallet/wallet.ts";
import { RPC, XLM, createWorld, rewritingFetch, type World } from "../support/network.ts";
import { confirmAll, isError, openWallet, storeKeyOf } from "../support/wallets.ts";
import { TrapdoorProver, trapdoorArtifacts } from "../support/trapdoor.ts";
import { map } from "../support/vault.ts";
import { MNEMONIC } from "../helpers.ts";

// A commitment as the indexer serves it, with its lowest bit flipped.
const flipLowBit = (cm: string): string => (BigInt("0x" + cm) ^ 1n).toString(16).padStart(64, "0");

// A forged pair the indexer could append: a 1,000 XLM note to `to` and a random leaf.
function forgedPayment(to: string, value: bigint): Record<string, string>[] {
  const address = decodeAddress("testnet", to);
  const note = { d: address.d, gd: address.gd, pkd: address.pkd, value, rcm: randomFieldElement() };
  const hex32 = (x: bigint): string => x.toString(16).padStart(64, "0");
  return [
    {
      commitment: hex32(noteCommitment(note)),
      ciphertext: bytesToHex(encryptOutput(note, new Uint8Array(32), randomScalar())),
      tx_hash: "cd".repeat(32),
    },
    {
      commitment: hex32(randomFieldElement()),
      ciphertext: bytesToHex(randomBytes(181)),
      tx_hash: "cd".repeat(32),
    },
  ];
}

async function funded(world?: World, store = new MemoryStore()) {
  const w = world ?? (await createWorld());
  const alice = await openWallet(w, 0, store);
  await alice.shield({ amount: 100n * XLM, signer: w.signer("alice depositor") });
  w.advance(3_601);
  w.admitAll();
  await alice.sync();
  return { world: w, alice, store };
}

// A fetch whose RPC answers getEvents with an error while `down` is set, as a busy node does.
function flakyEvents(world: World): { fetch: FetchLike; down: boolean } {
  const control = {
    down: false,
    fetch: (async (input, init) => {
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (control.down && new URL(input).origin === RPC && body?.method === "getEvents") {
        const error = { code: -32603, message: "busy" };
        return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }), {
          status: 200,
        });
      }
      return world.fetch(input, init);
    }) as FetchLike,
  };
  return control;
}

type FakeEvent = { readonly topic: string; readonly fields: [string, xdr.ScVal][] };

// A fetch whose RPC adds fabricated vault events, all of one transaction, to its next getEvents
// reply, as a lying node could.
function lyingEvents(world: World): {
  fetch: FetchLike;
  inject(ledger: number, txHash: string, events: readonly FakeEvent[]): void;
} {
  let pending: { ledger: number; txHash: string; events: readonly FakeEvent[] } | undefined;
  return {
    fetch: async (input, init) => {
      const res = await world.fetch(input, init);
      const body =
        init?.body === undefined || init.body === null ? undefined : JSON.parse(String(init.body));
      if (pending === undefined || new URL(input).origin !== RPC || body?.method !== "getEvents") {
        return res;
      }
      const reply = await res.json();
      const { ledger, txHash, events } = pending;
      pending = undefined;
      reply.result.events.push(
        ...events.map((e, i) => ({
          type: "contract",
          ledger,
          ledgerClosedAt: "2026-10-03T00:00:00Z",
          contractId: world.vault.address,
          id: `${String(ledger).padStart(12, "0")}-${String(900 + i).padStart(8, "0")}`,
          pagingToken: "fake",
          txHash,
          inSuccessfulContractCall: true,
          topic: [xdr.ScVal.scvSymbol(e.topic).toXDR("base64")],
          value: map(e.fields).toXDR("base64"),
        })),
      );
      return new Response(JSON.stringify(reply), { status: 200 });
    },
    inject(ledger, txHash, events) {
      pending = { ledger, txHash, events };
    },
  };
}

const u256 = (n: bigint): xdr.ScVal => nativeToScVal(n, { type: "u256" });

const fakeLeaf = (index: number, commitment: bigint): FakeEvent => ({
  topic: "new_commitment",
  fields: [
    ["index", xdr.ScVal.scvU64(new xdr.Uint64(BigInt(index)))],
    ["commitment", u256(commitment)],
    ["encrypted_output", xdr.ScVal.scvBytes(Buffer.alloc(181, index % 256))],
  ],
});

const fakeSpend = (nullifier: bigint): FakeEvent => ({
  topic: "new_nullifier",
  fields: [["nullifier", u256(nullifier)]],
});

// The wallet's first plan, as its sealed store holds it.
async function storedPlan(store: MemoryStore): Promise<Plan> {
  const state = (await loadState(new SealedStore(store, storeKeyOf(0)))) as WalletState;
  return state.plans[0] as Plan;
}

describe("wallet safety: services that lie", () => {
  it("stops when the indexer changes a leaf it served before", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    world.indexer.tamperLeaf = (index, cm) => (index === 0 ? flipLowBit(cm) : cm);
    await assert.rejects(alice.sync(), isError("indexer_fault"));
  });

  it("refuses to spend from a tree the vault's root history does not contain", async () => {
    const world = await createWorld();
    await funded(world);
    world.indexer.tamperLeaf = (index, cm) => (index === 1 ? flipLowBit(cm) : cm);
    await assert.rejects((await openWallet(world, 0)).sync(), isError("indexer_fault"));
    // Past the RPC's window no cross-check is possible; the root check still catches it.
    world.rpc.oldestLedger = world.vault.ledger;
    const fresh = await openWallet(world, 0);
    await assert.rejects(fresh.sync(), isError("tree_unverified"));
    assert.equal(fresh.treeStatus().fault, true);
    await assert.rejects(
      fresh.unshield({
        to: world.signer("x").publicKey,
        amount: 1n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
      }),
      isError("tree_unverified"),
    );
    world.indexer.tamperLeaf = undefined;
    const summary = await fresh.rescan();
    assert.equal(summary.rootVerified, true);
    assert.equal(fresh.treeStatus().fault, false);
    assert.equal((await fresh.balance()).spendable, 100n * XLM);
  });

  it("counts no note from leaves past the vault's NextLeaf", async () => {
    const { world } = await funded();
    const bob = await openWallet(world, 1);
    const fake = forgedPayment(bob.generateAddress(), 1_000n * XLM);
    const real = world.vault.leaves.length;
    const lying = rewritingFetch(world, {
      "/v1/leaves": (body) => ({
        ...body,
        leaves: [
          ...(body["leaves"] as unknown[]),
          ...fake.map((leaf, i) => ({
            index: real + i,
            ...leaf,
            // a ledger past the indexer's complete-to, as if the cross-check could skip them
            ledger: world.vault.ledger + 1,
          })),
        ],
      }),
    });
    const fooled = await openWallet({ ...world, fetch: lying }, 1);
    const summary = await fooled.sync();
    assert.equal(summary.rootVerified, true);
    assert.equal(summary.crossChecked, true);
    assert.equal(summary.leafCount, real);
    assert.equal((await fooled.balance()).spendable, 0n);
    assert.deepEqual(await fooled.history(), []);
  });

  it("never counts a forged note, even once the vault has a leaf at its index", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const fake = forgedPayment(bob.generateAddress(), 1_000n * XLM);
    const base = world.vault.leaves.length;
    const lying = rewritingFetch(world, {
      "/v1/leaves": (body) => ({
        ...body,
        leaves: [
          ...(body["leaves"] as { index: number }[]).filter((l) => l.index < base),
          ...fake.map((leaf, i) => ({ index: base + i, ...leaf, ledger: world.vault.ledger })),
        ],
      }),
    });
    const fooled = await openWallet({ ...world, fetch: lying }, 1);
    await fooled.sync();
    assert.equal((await fooled.balance()).spendable, 0n);
    // Real activity adds a pair at the forged indices.
    await alice.send({ to: alice.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM });
    await assert.rejects(fooled.sync(), isError("indexer_fault"));
    assert.equal(fooled.treeStatus().fault, true);
    assert.equal(fooled.treeStatus().leafCount, base);
    assert.equal((await fooled.balance()).spendable, 0n);
  });

  it("refuses services that point at another vault or network", async () => {
    const world = await createWorld();
    world.indexer.identity = { vault: world.deployment.asset.contract, networkId: "00".repeat(32) };
    const wallet = await openWallet(world, 0);
    assert.equal(wallet.verification().state, "mismatch");
    assert.equal(wallet.verification().indexers[0]?.state, "mismatch");
    await assert.rejects(
      wallet.shield({ amount: 10n * XLM, signer: world.signer("d") }),
      isError("deployment_mismatch"),
    );

    const other = await createWorld();
    const lying = {
      ...other,
      deployment: {
        ...other.deployment,
        relayers: [
          {
            url: other.deployment.relayers[0]?.url as string,
            feeAddress: other.signer("someone else").publicKey,
          },
        ],
      },
    };
    const wallet2 = await openWallet(lying, 0);
    assert.equal(wallet2.verification().relayers[0]?.state, "mismatch");
  });

  it("refuses a vault with other code or another domain", async () => {
    const world = await createWorld();
    const wrongCode = {
      ...world,
      deployment: { ...world.deployment, vaultWasmHash: "11".repeat(32) },
    };
    const wallet = await openWallet(wrongCode, 0);
    assert.equal(wallet.verification().vault, "mismatch");
    await assert.rejects(wallet.sync(), isError("deployment_mismatch"));
  });

  it("does not sign when the simulation asks for an authorization the call does not make", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const thief = world.signer("thief").publicKey;
    world.rpc.injectAuth = new xdr.SorobanAuthorizationEntry({
      credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
      rootInvocation: new xdr.SorobanAuthorizedInvocation({
        function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
          new xdr.InvokeContractArgs({
            contractAddress: new Address(world.vault.token).toScAddress(),
            functionName: "transfer",
            args: [
              new Address(world.signer("victim").publicKey).toScVal(),
              new Address(thief).toScVal(),
            ],
          }),
        ),
        subInvocations: [],
      }),
    });
    let signed = false;
    const victim = world.signer("victim");
    const watched = {
      publicKey: victim.publicKey,
      signTransaction: async (envelope: string, passphrase: string) => {
        signed = true;
        return victim.signTransaction(envelope, passphrase);
      },
    };
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: watched }),
      isError("rpc_error"),
    );
    assert.equal(signed, false);
    assert.equal(world.vault.pending.size, 0);
  });

  it("refuses a signer that returns another transaction", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const honest = world.signer("depositor");
    const sneaky = {
      publicKey: honest.publicKey,
      signTransaction: async (envelope: string, passphrase: string) => {
        const tx = TransactionBuilder.fromXDR(envelope, passphrase) as Transaction;
        const other = TransactionBuilder.cloneFrom(tx, {
          fee: "999999",
          networkPassphrase: passphrase,
        }).build();
        other.sign(honest.keypair);
        return { signedTxXdr: other.toXDR() };
      },
    };
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: sneaky }),
      isError("signer_mismatch"),
    );
    assert.equal(world.vault.pending.size, 0);
    assert.equal((await alice.deposits())[0]?.state, "failed");
  });
});

describe("wallet safety: cross-checks with RPC events", () => {
  it("takes RPC events that stop short of the indexer's data as no cross-check, not a fault", async () => {
    const { world, store } = await funded();
    // More events in one ledger than one page holds.
    world.fill(600);
    const alice = await openWallet(world, 0, store, undefined, { syncLimits: { eventPages: 1 } });
    const summary = await alice.sync();
    assert.equal(summary.rootVerified, true);
    assert.equal(summary.crossChecked, false);
    assert.ok(summary.uncheckedLedgers > 0);
  });

  it("confirms the indexer's new leaves and nullifiers against the vault's events", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("d") });
    world.advance(3_601);
    world.admitAll();
    const summary = await alice.sync();
    assert.equal(summary.crossChecked, true);
  });

  it("treats a hidden nullifier as an indexer fault", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    world.indexer.hideNullifiers = true;
    const restored = await openWallet(world, 0);
    await assert.rejects(restored.sync(), isError("indexer_fault"));
    assert.equal(restored.treeStatus().fault, true);
  });

  it("treats withheld leaves as an indexer fault", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await bob.sync();
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    const served = world.vault.leaves.length - 2;
    world.indexer.tamperLeaf = undefined;
    const original = world.indexer.handle.bind(world.indexer);
    world.indexer.handle = (url) => {
      if (url.pathname !== "/v1/leaves") return original(url);
      const body = {
        page: 0,
        leaves: world.vault.leaves.slice(0, served).map((l) => ({
          index: l.index,
          commitment: l.cm.toString(16).padStart(64, "0"),
          ciphertext: Buffer.from(l.ciphertext).toString("hex"),
          ledger: l.ledger,
          tx_hash: l.txHash,
        })),
      };
      return new Response(JSON.stringify(body), { status: 200 });
    };
    await assert.rejects(bob.sync(), isError("indexer_fault"));
  });

  it("treats a swapped ciphertext as an indexer fault", async () => {
    const world = await createWorld();
    await funded(world);
    const leaf = world.vault.leaves[0];
    assert.ok(leaf !== undefined);
    const original = leaf.ciphertext;
    leaf.ciphertext = Uint8Array.from(original).reverse();
    const fresh = await openWallet(world, 1);
    const vaultEvents = world.vault.events;
    // the events keep the real ciphertext; only the indexer serves the swapped one
    assert.ok(vaultEvents.length > 0);
    await assert.rejects(fresh.sync(), isError("indexer_fault"));
  });
});

describe("wallet safety: an RPC that lies about the vault's events", () => {
  it("never takes a payment for landed on RPC events alone", async () => {
    const { world, store } = await funded();
    const rpc = lyingEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, store);
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM }),
    );
    // The relayer saw the proof, and so knows the commitments a node could claim landed.
    const [cm0, cm1] = (await storedPlan(store)).commitments;
    const next = world.vault.leaves.length;
    // An indexer one ledger behind, as is usual, leaves the newest ledger to RPC alone.
    world.indexer.completeTo = world.vault.ledger - 1;
    rpc.inject(world.vault.ledger, "ee".repeat(32), [fakeLeaf(next, cm0), fakeLeaf(next + 1, cm1)]);
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.mustRetry, true);
    assert.equal((await alice.balance()).locked, 100n * XLM);
    // Within the ledgers the indexer covers, the two disagree, and the sync keeps nothing.
    world.indexer.completeTo = undefined;
    rpc.inject(world.vault.ledger, "ee".repeat(32), [fakeLeaf(next, cm0), fakeLeaf(next + 1, cm1)]);
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    world.advance(121 * 5);
    world.fill(1);
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    assert.equal((await alice.balance()).spendable, 100n * XLM);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 0n);
  });

  it("never takes a live payment for superseded on RPC events alone", async () => {
    const { world, store } = await funded();
    const rpc = lyingEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, store);
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM, notBefore });
    const [input] = (await storedPlan(store)).inputs;
    const next = world.vault.leaves.length;
    const forged = [
      fakeSpend(input?.nf as bigint),
      fakeLeaf(next, 12_345n),
      fakeLeaf(next + 1, 67_890n),
    ];
    world.indexer.completeTo = world.vault.ledger - 1;
    rpc.inject(world.vault.ledger, "dd".repeat(32), forged);
    await alice.sync();
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.mustRetry, true);
    world.indexer.completeTo = undefined;
    rpc.inject(world.vault.ledger, "dd".repeat(32), forged);
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    // The payment's note stays locked, so no second payment can be made from it.
    await assert.rejects(
      alice.send({
        to: bob.generateAddress(),
        amount: 10n * XLM,
        maxFee: 2n * XLM,
        confirm: confirmAll,
      }),
      isError("insufficient_funds"),
    );
    world.advance(600);
    world.relayer.releaseHeld();
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 10n * XLM);
  });

  it("starts over on rescan a payment an earlier reading took for landed though its note is unspent", async () => {
    const { world, alice, store } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM }),
    );
    // A state written by an earlier release that took fabricated events for the landing.
    const sealed = new SealedStore(store, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const plan = state.plans[0] as Plan;
    const fake = { txHash: "ee".repeat(32), ledger: world.vault.ledger };
    Object.assign(plan, { ...fake, state: "settled" });
    plan.evidence = [
      { ...fake, outputs: [90, 91], nullifiers: [false, false], foreign: false, checked: true },
    ];
    await saveState(sealed, state);
    world.advance(121 * 5);
    world.fill(1);
    const reopened = await openWallet(world, 0, store);
    await reopened.sync();
    assert.equal((await reopened.plans())[0]?.state, "settled");
    assert.equal((await reopened.balance()).spendable, 0n);
    await reopened.rescan();
    const [rebuilt] = await reopened.plans();
    assert.equal(rebuilt?.state, "dead");
    assert.equal(rebuilt?.mustRetry, true);
    assert.equal((await reopened.balance()).spendable, 100n * XLM);
  });
});

describe("wallet safety: refusals before proving", () => {
  it("refuses to spend while the vault's view leaves the tree unconfirmed", async () => {
    const { world } = await funded();
    let stale: string | undefined;
    let mode: "capture" | "live" | "replay" = "capture";
    const isView = (body: { method?: string; params?: { keys?: unknown[] } } | undefined) =>
      body?.method === "getLedgerEntries" && body.params?.keys?.length === 3;
    const lagging: FetchLike = async (input, init) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      if (mode === "replay" && isView(body) && stale !== undefined) {
        return new Response(JSON.stringify({ ...JSON.parse(stale), id: body.id }), {
          status: 200,
        });
      }
      const res = await world.fetch(input, init);
      if (mode === "capture" && isView(body)) stale = await res.clone().text();
      return res;
    };
    const alice = await openWallet({ ...world, fetch: lagging }, 0);
    await alice.sync();
    mode = "live";
    world.fill(1);
    await alice.sync();
    // A node that lags behind the wallet's own tree cannot confirm its root.
    mode = "replay";
    const bob = await openWallet(world, 1);
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM }),
      isError("tree_unverified"),
    );
    assert.equal(world.relayer.submissions.length, 0);
  });

  it("refuses to spend while the vault is halted", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.vault.haltedUntil = world.vault.timestamp + 3_600n;
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM }),
      isError("vault_unavailable"),
    );
    assert.equal(world.relayer.submissions.length, 0);
  });

  it("refuses a quote that names a fee address other than the relayer's", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.quoteFeeAddress = world.signer("someone else").publicKey;
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM }),
      isError("quote_invalid"),
    );
  });

  it("treats leaves that end inside an inserted pair as an indexer fault", async () => {
    const { world } = await funded();
    world.fill(2);
    world.indexer.leafLimit = 3;
    // RPC no longer holds these ledgers, so only the leaves themselves show the cut.
    world.rpc.oldestLedger = world.vault.ledger + 1;
    const fresh = await openWallet(world, 0);
    await assert.rejects(fresh.sync(), isError("indexer_fault"));
  });
});

describe("wallet safety: syncs that fail", () => {
  it("keeps nothing of a sync whose nullifiers carry a forged transaction", async () => {
    const world = await createWorld();
    const store = new MemoryStore();
    const alice = await openWallet(world, 0, store);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    const lying = rewritingFetch(world, {
      "/v1/nullifiers": (body) => {
        const list = body["nullifiers"] as Record<string, unknown>[];
        return {
          ...body,
          nullifiers: list.map((n, i) =>
            i === list.length - 1 ? { ...n, tx_hash: "ab".repeat(32) } : n,
          ),
        };
      },
    });
    const session = await openWallet({ ...world, fetch: lying }, 0, store);
    await assert.rejects(session.sync(), isError("indexer_fault"));
    const next = await openWallet(world, 0, store);
    assert.deepEqual(
      (await next.plans()).map((p) => p.state),
      ["submitted"],
    );
    await next.rescan();
    assert.deepEqual(
      (await next.plans()).map((p) => p.state),
      ["settled"],
    );
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 10n * XLM);
  });

  it("rebuilds on rescan the fate of every plan the chain has not shown to land", async () => {
    const world = await createWorld();
    const backend = new MemoryStore();
    const alice = await openWallet(world, 0, backend);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    // A state written by an older release that took a forged spend for another plan's.
    const sealed = new SealedStore(backend, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const plan = state.plans[0] as Plan;
    plan.state = "superseded";
    plan.evidence = [
      {
        txHash: "ab".repeat(32),
        ledger: 1,
        nullifiers: [true, false],
        outputs: [undefined, undefined],
        foreign: true,
        checked: true,
      },
    ];
    await saveState(sealed, state);
    const reopened = await openWallet(world, 0, backend);
    await reopened.rescan();
    assert.deepEqual(
      (await reopened.plans()).map((p) => p.state),
      ["settled"],
    );
  });

  it("rebuilds on rescan the fate of a plan that never landed but was taken for superseded", async () => {
    const world = await createWorld();
    const backend = new MemoryStore();
    const alice = await openWallet(world, 0, backend);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM }),
    );
    // A state written by an older release that took a forged spend for another plan's.
    const sealed = new SealedStore(backend, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const plan = state.plans[0] as Plan;
    plan.state = "superseded";
    plan.evidence = [
      {
        txHash: "ab".repeat(32),
        ledger: 1,
        nullifiers: [true, false],
        outputs: [undefined, undefined],
        foreign: true,
        checked: true,
      },
    ];
    await saveState(sealed, state);
    world.advance(121 * 5);
    const reopened = await openWallet(world, 0, backend);
    await reopened.rescan();
    // Rebuilt from the chain alone, it never landed, and its deadline has passed.
    const [rebuilt] = await reopened.plans();
    assert.equal(rebuilt?.state, "dead");
    assert.equal(rebuilt?.mustRetry, true);
    assert.equal((await reopened.balance()).spendable, 100n * XLM);
  });
});

describe("wallet safety: availability", () => {
  it("syncs from the vault's RPC events when the indexer is down", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    world.indexer.down = true;
    const fresh = await openWallet(world, 1);
    const summary = await fresh.sync();
    assert.equal(summary.source, "rpc");
    assert.equal(summary.rootVerified, true);
    assert.equal((await fresh.balance()).spendable, 10n * XLM);
  });

  it("reports history beyond the RPC's window as unavailable", async () => {
    const { world } = await funded();
    world.indexer.down = true;
    world.rpc.oldestLedger = world.vault.ledger;
    const fresh = await openWallet(world, 0);
    await assert.rejects(fresh.sync(), isError("history_unavailable"));
  });

  it("pages through nullifiers with the indexer's cursor", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.indexer.nullifierPage = 1;
    for (let i = 0; i < 3; i++) {
      await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM });
    }
    const restored = await openWallet(world, 0);
    await restored.sync();
    assert.equal((await restored.balance()).spendable, 100n * XLM - 3n * (2n * XLM));
    assert.ok(world.indexer.requests.filter((r) => r.startsWith("/v1/nullifiers")).length > 8);
  });

  it("confirms a payment from its leaves before the indexer lists its spends", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    world.indexer.completeTo = world.vault.ledger - 1;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
    assert.equal((await alice.balance()).spendable, 89n * XLM);
    world.indexer.completeTo = undefined;
    await alice.sync();
    assert.equal((await alice.balance()).spendable, 89n * XLM);
  });
});

describe("wallet safety: bounded syncs", () => {
  it("holds leaves taken past its page cap aside until the vault confirms them", async () => {
    const { world } = await funded();
    // Enough leaves that one page leaves the tree too far behind for the vault's root history.
    world.fill(800);
    const capped = await openWallet(world, 0, new MemoryStore(), undefined, {
      syncLimits: { leafPages: 1 },
    });
    let summary = await capped.sync();
    assert.equal(summary.leafCount, 0);
    assert.equal(summary.staged, 1024);
    assert.equal(summary.rootVerified, false);
    assert.equal((await capped.balance()).spendable, 0n);
    summary = await capped.sync();
    assert.equal(summary.staged, 0);
    assert.equal(summary.leafCount, world.vault.leaves.length);
    assert.equal(summary.rootVerified, true);
    assert.equal((await capped.balance()).spendable, 100n * XLM);
  });

  it("drops staged leaves that the vault contradicts", async () => {
    const { world } = await funded();
    world.fill(800);
    const lying = rewritingFetch(world, {
      "/v1/leaves": (body) => ({
        ...body,
        leaves: (body["leaves"] as { index: number; commitment: string }[]).map((l) =>
          l.index === 5 ? { ...l, commitment: flipLowBit(l.commitment) } : l,
        ),
      }),
    });
    const store = new MemoryStore();
    const capped = await openWallet({ ...world, fetch: lying }, 0, store, undefined, {
      syncLimits: { leafPages: 1 },
    });
    // RPC no longer holds the events of these leaves, so only the root check can catch the lie.
    world.rpc.oldestLedger = world.vault.ledger + 1;
    assert.equal((await capped.sync()).staged, 1024);
    await assert.rejects(capped.sync(), isError("tree_unverified"));
    assert.equal(capped.treeStatus().fault, true);
    world.rpc.oldestLedger = 1;
    const honest = await openWallet(world, 0, store);
    const summary = await honest.sync();
    assert.equal(summary.rootVerified, true);
    assert.equal((await honest.balance()).spendable, 100n * XLM);
  });

  it("keeps a spend whose note an indexer that lags on leaves serves later", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    await bob.sync();
    // bob spends the note he received
    await bob.send({ to: alice.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM });
    const before = world.vault.leaves.findIndex((l) => l.txHash === world.vault.leaves[2]?.txHash);
    // A fresh copy of bob's wallet, served every nullifier but not the leaves of the note yet,
    // with RPC unable to cross-check.
    world.indexer.leafLimit = before;
    world.rpc.oldestLedger = world.vault.ledger + 1;
    const restored = await openWallet(world, 1);
    await restored.sync();
    world.indexer.leafLimit = undefined;
    await restored.sync();
    assert.equal((await restored.balance()).spendable, 10n * XLM - 5n * XLM - 1n * XLM);
  });
});

describe("wallet safety: the submission state machine", () => {
  it("keeps a refused proof's notes until its deadline, then frees them", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
      (err: unknown) => err instanceof CyphrasError && err.details["code"] === "unavailable",
    );
    const [stalled] = await alice.plans();
    assert.equal(stalled?.state, "prepared");
    assert.equal((await alice.balance()).locked, 100n * XLM);
    assert.equal((await alice.balance()).spendable, 0n);
    world.advance(121 * 5);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
    assert.equal((await alice.balance()).spendable, 100n * XLM);
  });

  it("retries a stalled payment with the same notes, so only one can land", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
    );
    const [stalled] = await alice.plans();
    const retried = await alice.retry(stalled?.planId as string, { maxFee: 2n * XLM });
    assert.equal(retried.state, "submitted");
    await alice.sync();
    const states = Object.fromEntries((await alice.plans()).map((p) => [p.planId, p.state]));
    assert.equal(states[retried.planId], "settled");
    assert.equal(states[stalled?.planId as string], "superseded");
    // the stalled proof can no longer land
    const replay = world.relayer.submissions.length;
    assert.equal(replay, 1);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 5n * XLM);
  });

  it("runs one operation at a time and never spends a note twice", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const [a, b] = await Promise.all([
      alice.send({ to: bob.generateAddress(), amount: 60n * XLM, maxFee: 2n * XLM }),
      alice.send({ to: bob.generateAddress(), amount: 30n * XLM, maxFee: 2n * XLM }),
    ]);
    // The second waited for the first, and its sync found the first payment's change to spend.
    await alice.sync();
    const plans = await alice.plans();
    assert.deepEqual(
      plans.map((p) => p.state),
      ["settled", "settled"],
    );
    assert.notEqual(a.txHash, b.txHash);
    const spent = world.relayer.submissions.flatMap((s) => s.proof.input_nullifiers);
    assert.equal(new Set(spent).size, spent.length);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 90n * XLM);
    assert.equal((await alice.balance()).spendable, 100n * XLM - 92n * XLM);
  });
});

describe("wallet safety: when a payment is dead", () => {
  it("keeps a held payment alive when the indexer claims to be complete past its deadline", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM, notBefore });
    world.indexer.completeTo = world.vault.ledger + 400;
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    let [plan] = await alice.plans();
    assert.equal(plan?.state, "submitted");
    assert.equal(plan?.mustRetry, true);
    // The relayer sends the held request in time, and it lands.
    world.advance(600);
    world.relayer.releaseHeld();
    world.indexer.completeTo = undefined;
    await alice.sync();
    [plan] = await alice.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.mustRetry, false);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 10n * XLM);
  });

  it("does not kill a live payment on a lagging RPC node's stale view of the vault", async () => {
    const world = await createWorld();
    let stale: string | undefined;
    let mode: "live" | "capture" | "replay" = "live";
    const isView = (body: { method?: string; params?: { keys?: unknown[] } } | undefined) =>
      body?.method === "getLedgerEntries" && body.params?.keys?.length === 3;
    const lagging: FetchLike = async (input, init) => {
      const body = init?.body === undefined ? undefined : JSON.parse(String(init.body));
      if (mode === "replay" && isView(body) && stale !== undefined) {
        return new Response(JSON.stringify({ ...JSON.parse(stale), id: body.id }), {
          status: 200,
        });
      }
      const res = await world.fetch(input, init);
      if (mode === "capture" && isView(body)) stale = await res.clone().text();
      return res;
    };
    const alice = await openWallet({ ...world, fetch: lagging }, 0);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    // A node's view of the vault from before the deposit was admitted.
    mode = "capture";
    await alice.sync();
    mode = "live";
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM, notBefore });
    mode = "replay";
    const summary = await alice.sync();
    mode = "live";
    assert.equal(summary.rootVerified, false);
    assert.deepEqual(
      (await alice.plans()).map((p) => p.state),
      ["submitted"],
    );
    world.advance(600);
    world.relayer.releaseHeld();
    await alice.sync();
    assert.deepEqual(
      (await alice.plans()).map((p) => p.state),
      ["settled"],
    );
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 10n * XLM);
  });

  it("declares a payment dead from the vault's whole tree past its deadline, though RPC could not cross-check it", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
    );
    world.advance(121 * 5);
    world.rpc.oldestLedger = world.vault.ledger + 1;
    assert.equal((await alice.sync()).crossChecked, false);
    // The vault's tree, confirmed by its root, holds every transaction up to the read, and the
    // payment's commitments are not among them: it never landed and now never will.
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    assert.equal(plan?.mustRetry, true);
    assert.equal((await alice.balance()).spendable, 100n * XLM);
  });

  it("keeps a payment open past its deadline while the wallet lacks part of the vault's tree and of its spends", async () => {
    const { world, alice, store } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
    );
    // Other users' leaves, past the deadline, and the spends up to it, which a lagging indexer
    // has not taken in yet.
    const { deadline } = await storedPlan(store);
    world.advance(121 * 5);
    world.indexer.leafLimit = world.vault.leaves.length;
    world.indexer.completeTo = deadline - 1;
    world.fill(2);
    const summary = await alice.sync();
    assert.equal(summary.rootVerified, true);
    assert.equal((await alice.plans())[0]?.state, "prepared");
    world.indexer.leafLimit = undefined;
    world.indexer.completeTo = undefined;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
  });

  it("declares a payment dead once its root has left the vault's history", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
    );
    // 256 pairs from other users push the plan's root out of the vault's last 256 roots, long
    // before its deadline.
    world.fill(256);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    assert.equal((await alice.balance()).spendable, 100n * XLM);
  });

  it("frees a refused payment's notes though the indexer always lags one pair behind", async () => {
    const { world, store } = await funded();
    // The indexer withholds the newest pair and reports its spends complete only up to the ledger
    // before it, as an ordinary lag looks, so the wallet never holds the vault's whole tree.
    const lagging = rewritingFetch(world, {
      "/v1/leaves": (body) => {
        const newest = new Set(world.vault.leaves.slice(-2).map((l) => l.index));
        const leaves = body["leaves"] as { index: number }[];
        return { ...body, leaves: leaves.filter((l) => !newest.has(l.index)) };
      },
      "/v1/nullifiers": (body) => {
        const before = (world.vault.leaves.at(-2)?.ledger as number) - 1;
        return { ...body, complete_to: Math.min(body["complete_to"] as number, before) };
      },
    });
    const alice = await openWallet({ ...world, fetch: lagging }, 0, store);
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "refused", reason: 3 });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM }),
      isError("service_rejected"),
    );
    world.advance(60);
    world.fill(1);
    let summary = await alice.sync();
    assert.equal(summary.crossChecked, true);
    assert.equal((await alice.plans())[0]?.state, "prepared");
    // Other users keep the pool busy; the spends the indexer reports soon pass the deadline.
    world.advance(121 * 5);
    world.fill(1);
    summary = await alice.sync();
    assert.equal(summary.rootVerified, true);
    assert.ok(summary.leafCount < world.vault.leaves.length);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    assert.equal(plan?.needsUserDecision, false);
    const balance = await alice.balance();
    assert.equal(balance.spendable, 100n * XLM);
    assert.equal(balance.locked, 0n);
  });

  it("confirms a payment marked dead once its own transaction shows it landed", async () => {
    const world = await createWorld();
    const backend = new MemoryStore();
    const alice = await openWallet(world, 0, backend);
    await alice.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await alice.sync();
    const bob = await openWallet(world, 1);
    const notBefore = Number(world.vault.timestamp) + 600;
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM, notBefore });
    // An earlier reading of the chain took it for dead.
    const sealed = new SealedStore(backend, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    (state.plans[0] as Plan).state = "dead";
    await saveState(sealed, state);
    const reopened = await openWallet(world, 0, backend);
    world.advance(600);
    world.relayer.releaseHeld();
    await reopened.sync();
    assert.deepEqual(
      (await reopened.plans()).map((p) => p.state),
      ["settled"],
    );
  });

  it("pays a dead payment again only with the same notes", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
    );
    world.advance(121 * 5);
    await alice.sync();
    const [dead] = await alice.plans();
    assert.equal(dead?.state, "dead");
    assert.equal(dead?.mustRetry, true);
    const retried = await alice.retry(dead?.planId as string, { maxFee: 2n * XLM });
    await alice.sync();
    // The retry spent the dead plan's notes: its landing supersedes the dead plan.
    const states = Object.fromEntries((await alice.plans()).map((p) => [p.planId, p.state]));
    assert.equal(states[retried.planId], "settled");
    assert.equal(states[dead?.planId as string], "superseded");
  });
});

describe("wallet safety: payments seen through held-back or unchecked syncs", () => {
  it("confirms a payment whose leaves first arrive in a batch held aside at the page cap", async () => {
    const { world, alice, store } = await funded();
    const bob = await openWallet(world, 1);
    const sent = await alice.send({
      to: bob.generateAddress(),
      amount: 10n * XLM,
      maxFee: 2n * XLM,
    });
    assert.equal(sent.state, "submitted");
    // Other users add enough leaves that one page of them leaves the tree too far behind for the
    // vault's root history, so the payment's leaves wait in a held-back batch.
    world.fill(800);
    const later = await openWallet(world, 0, store, undefined, { syncLimits: { leafPages: 1 } });
    assert.equal((await later.sync()).rootVerified, false);
    assert.equal((await later.plans())[0]?.state, "submitted");
    assert.equal((await later.sync()).rootVerified, true);
    const [plan] = await later.plans();
    assert.equal(plan?.state, "settled");
    assert.equal(plan?.mustRetry, false);
    assert.equal((await later.balance()).spendable, 89n * XLM);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 10n * XLM);
  });

  it("confirms payments synced while RPC could not cross-check, the last one or not", async () => {
    const { world, store } = await funded();
    const rpc = flakyEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, store);
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    rpc.down = true;
    assert.equal((await alice.sync()).crossChecked, false);
    rpc.down = false;
    assert.deepEqual(
      (await alice.plans()).map((p) => p.state),
      ["settled"],
    );
    // Another transaction follows the payment before the unchecked sync.
    await alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM });
    world.fill(3);
    rpc.down = true;
    assert.equal((await alice.sync()).crossChecked, false);
    rpc.down = false;
    world.advance(3600);
    world.fill(3);
    await alice.sync();
    const plans = await alice.plans();
    assert.deepEqual(
      plans.map((p) => [p.state, p.mustRetry]),
      [
        ["settled", false],
        ["settled", false],
      ],
    );
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 15n * XLM);
  });

  it("frees a refused payment's notes after one sync RPC could not cross-check", async () => {
    const { world, store } = await funded();
    const rpc = flakyEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, store);
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM }),
    );
    world.fill(2);
    rpc.down = true;
    await alice.sync();
    rpc.down = false;
    assert.equal((await alice.plans())[0]?.state, "prepared");
    world.advance(86_400);
    world.fill(2);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    const balance = await alice.balance();
    assert.equal(balance.spendable, 100n * XLM);
    assert.equal(balance.locked, 0n);
  });

  it("frees a refused payment's notes after a rescan past RPC's history", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM }),
    );
    world.advance(3600);
    world.fill(2);
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "dead");
    // RPC keeps about a week of events: the vault's early ledgers are gone.
    world.rpc.oldestLedger = world.vault.ledger - 5;
    const summary = await alice.rescan();
    assert.equal(summary.crossChecked, false);
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "dead");
    assert.equal(plan?.mustRetry, true);
    const balance = await alice.balance();
    assert.equal(balance.spendable, 100n * XLM);
    assert.equal(balance.locked, 0n);
  });
});

describe("wallet safety: unchecked ledgers", () => {
  it("cross-checks an unchecked sync's ledgers in the next sync RPC can serve", async () => {
    const { world, store } = await funded();
    const rpc = flakyEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, store);
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    rpc.down = true;
    const unchecked = await alice.sync();
    assert.equal(unchecked.crossChecked, false);
    assert.ok(unchecked.uncheckedLedgers > 0);
    rpc.down = false;
    world.fill(1);
    const next = await alice.sync();
    assert.equal(next.crossChecked, true);
    assert.equal(next.uncheckedLedgers, 0);
  });

  it("finds a spend an indexer hid while RPC could not check it", async () => {
    const { world, store } = await funded();
    const rpc = flakyEvents(world);
    let hiding = true;
    const lying = rewritingFetch(
      { ...world, fetch: rpc.fetch },
      {
        "/v1/nullifiers": (body) => (hiding ? { ...body, nullifiers: [] } : body),
      },
    );
    const alice = await openWallet({ ...world, fetch: lying }, 0, store);
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    rpc.down = true;
    await alice.sync();
    rpc.down = false;
    hiding = false;
    await assert.rejects(alice.sync(), isError("indexer_fault"));
    assert.equal(alice.treeStatus().fault, true);
  });

  it("finds a note an indexer hid while RPC could not check it", async () => {
    const { world, store } = await funded();
    const rpc = flakyEvents(world);
    const bob = await openWallet(world, 1);
    const alice = await openWallet(world, 0, store);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    let hiding = true;
    const lying = rewritingFetch(
      { ...world, fetch: rpc.fetch },
      {
        "/v1/leaves": (body) => {
          const leaves = body["leaves"] as Record<string, unknown>[];
          const swap = (l: Record<string, unknown>, i: number) =>
            hiding ? { ...l, ciphertext: leaves[(i + 1) % leaves.length]?.["ciphertext"] } : l;
          return { ...body, leaves: leaves.map(swap) };
        },
      },
    );
    const fooled = await openWallet({ ...world, fetch: lying }, 1);
    rpc.down = true;
    await fooled.sync();
    assert.equal((await fooled.balance()).spendable, 0n);
    rpc.down = false;
    hiding = false;
    await assert.rejects(fooled.sync(), isError("indexer_fault"));
  });

  it("keeps ledgers RPC no longer holds as unchecked, without asking for them again", async () => {
    const { world, store } = await funded();
    const rpc = flakyEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, store);
    world.fill(1);
    rpc.down = true;
    const unchecked = (await alice.sync()).uncheckedLedgers;
    rpc.down = false;
    // RPC now holds only the ledgers after that sync.
    world.rpc.oldestLedger = world.vault.ledger + 1;
    world.fill(1);
    assert.equal((await alice.sync()).uncheckedLedgers, unchecked);
    const asked = world.rpc.calls.filter((m) => m === "getEvents").length;
    world.fill(1);
    assert.equal((await alice.sync()).uncheckedLedgers, unchecked);
    // one page for the sync's own ledgers, none for the lost ones
    assert.equal(world.rpc.calls.filter((m) => m === "getEvents").length, asked + 1);
  });

  it("asks for a decision on a payment past its deadline whose fate it cannot tell yet", async () => {
    const { world, alice, store } = await funded();
    const bob = await openWallet(world, 1);
    world.relayer.failures.push({ error: "unavailable" });
    await assert.rejects(
      alice.send({ to: bob.generateAddress(), amount: 5n * XLM, maxFee: 2n * XLM }),
    );
    assert.equal((await alice.plans())[0]?.needsUserDecision, false);
    const { deadline } = await storedPlan(store);
    world.advance(121 * 5);
    world.indexer.leafLimit = world.vault.leaves.length;
    world.indexer.completeTo = deadline - 1;
    world.fill(2);
    await alice.sync();
    const [plan] = await alice.plans();
    assert.equal(plan?.state, "prepared");
    assert.equal(plan?.needsUserDecision, true);
    // The safe choice: a retry spends the same notes, so at most one of the two pays.
    world.indexer.leafLimit = undefined;
    world.indexer.completeTo = undefined;
    const retried = await alice.retry(plan?.planId as string, { maxFee: 2n * XLM });
    await alice.sync();
    const states = Object.fromEntries((await alice.plans()).map((p) => [p.planId, p]));
    assert.equal(states[retried.planId]?.state, "settled");
    assert.equal(states[plan?.planId as string]?.needsUserDecision, false);
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 5n * XLM);
  });
});

describe("wallet safety: instances sharing a store", () => {
  async function shared() {
    const world = await createWorld();
    const store = new MemoryStore();
    // An extension's popup and its service worker, each with its own wallet over one store.
    const popup = await openWallet(world, 0, store);
    await popup.shield({ amount: 100n * XLM, signer: world.signer("alice depositor") });
    world.advance(3_601);
    world.admitAll();
    await popup.sync();
    const worker = await openWallet(world, 0, store);
    const bob = await openWallet(world, 1);
    return { world, store, popup, worker, bob };
  }

  it("refuses to open without Web Locks unless the caller vouches for one instance", async () => {
    const world = await createWorld();
    const navigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    Object.defineProperty(globalThis, "navigator", { value: {}, configurable: true });
    try {
      await assert.rejects(openWallet(world, 0), isError("locks_unavailable"));
      const sole = await openWallet(world, 0, new MemoryStore(), undefined, {
        singleInstance: true,
      });
      assert.equal((await sole.sync()).rootVerified, true);
    } finally {
      Object.defineProperty(globalThis, "navigator", navigator as PropertyDescriptor);
    }
  });

  it("keeps the plan one instance saved when another one syncs", async () => {
    const { world, store, popup, worker, bob } = await shared();
    const notBefore = Number(world.vault.timestamp) + 600;
    await popup.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM, notBefore });
    await worker.sync();
    assert.equal((await worker.plans()).length, 1);
    const reopened = await openWallet(world, 0, store);
    const plans = await reopened.plans();
    assert.equal(plans.length, 1);
    assert.equal((await reopened.balance()).locked, 100n * XLM);
  });

  it("runs one operation at a time across them and never spends a note twice", async () => {
    const { world, popup, worker, bob } = await shared();
    await Promise.all([
      popup.send({ to: bob.generateAddress(), amount: 60n * XLM, maxFee: 2n * XLM }),
      worker.send({ to: bob.generateAddress(), amount: 30n * XLM, maxFee: 2n * XLM }),
    ]);
    const spent = world.relayer.submissions.flatMap((s) => s.proof.input_nullifiers);
    assert.equal(spent.length, 4);
    assert.equal(new Set(spent).size, 4);
    await popup.sync();
    assert.deepEqual(
      (await popup.plans()).map((p) => p.state),
      ["settled", "settled"],
    );
    await bob.sync();
    assert.equal((await bob.balance()).spendable, 90n * XLM);
  });
});

describe("wallet safety: a damaged store", () => {
  it("starts afresh from an unreadable store only when asked, and rebuilds from the chain", async () => {
    const { world } = await funded();
    const backend = new MemoryStore();
    const alice = await openWallet(world, 0, backend);
    await alice.sync();
    for (const key of backend.keys()) await backend.set(key, randomBytes(64));
    await assert.rejects(openWallet(world, 0, backend), isError("storage_unreadable"));
    const fresh = await PrivateWallet.open({
      deployment: world.deployment,
      allowUnpinnedDeployment: true,
      keys: keySource.mnemonic(MNEMONIC, { account: 0 }),
      prover: new TrapdoorProver(),
      artifacts: trapdoorArtifacts,
      storage: backend,
      rpcUrl: RPC,
      fetch: world.fetch,
      clock: world.clock,
      sleep: async () => {},
      resetUnreadableState: true,
    });
    assert.equal((await fresh.balance()).spendable, 0n);
    await fresh.sync();
    assert.equal((await fresh.balance()).spendable, 100n * XLM);
  });

  it("finds a deposit whose submission was cut off by its commitments, and fails one that never landed", async () => {
    const world = await createWorld();
    const backend = new MemoryStore();
    const alice = await openWallet(world, 0, backend);
    const receipt = await alice.shield({ amount: 40n * XLM, signer: world.signer("depositor") });
    // As if the wallet had stopped before it learned the transaction of the first deposit, and the
    // second never reached the network.
    const sealed = new SealedStore(backend, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const landed = state.deposits[0] as WalletState["deposits"][0];
    Object.assign(landed, { id: undefined, txHash: undefined, state: "submitting" });
    state.deposits.push({
      ...landed,
      commitments: [randomFieldElement(), randomFieldElement()],
    });
    await saveState(sealed, state);
    const reopened = await openWallet(world, 0, backend);
    await reopened.sync();
    let deposits = await reopened.deposits();
    assert.equal(deposits[0]?.state, "pending");
    assert.equal(deposits[0]?.id, receipt.depositId);
    assert.equal(deposits[0]?.txHash, receipt.txHash);
    assert.equal(deposits[1]?.state, "submitting");
    world.advance(121 * 5);
    await reopened.sync();
    deposits = await reopened.deposits();
    assert.equal(deposits[1]?.state, "failed");
    assert.equal((await reopened.balance()).pendingDeposits, 40n * XLM);
  });

  it("fails a deposit that never landed only once the ledgers up to its deadline are checked", async () => {
    const world = await createWorld();
    const backend = new MemoryStore();
    const rpc = flakyEvents(world);
    const alice = await openWallet({ ...world, fetch: rpc.fetch }, 0, backend);
    await alice.shield({ amount: 40n * XLM, signer: world.signer("depositor") });
    const sealed = new SealedStore(backend, storeKeyOf(0));
    const state = (await loadState(sealed)) as WalletState;
    const landed = state.deposits[0] as WalletState["deposits"][0];
    state.deposits.push({
      ...landed,
      id: undefined,
      txHash: undefined,
      state: "submitting",
      commitments: [randomFieldElement(), randomFieldElement()],
    });
    await saveState(sealed, state);
    const reopened = await openWallet({ ...world, fetch: rpc.fetch }, 0, backend);
    world.advance(121 * 5);
    rpc.down = true;
    await reopened.sync();
    assert.equal((await reopened.deposits())[1]?.state, "submitting");
    rpc.down = false;
    await reopened.sync();
    assert.equal((await reopened.deposits())[1]?.state, "failed");
  });
});

describe("wallet safety: what services learn", () => {
  // Every request the wallet makes, as "service method" lines.
  function tapped(world: World): { fetch: FetchLike; calls: string[] } {
    const calls: string[] = [];
    return {
      calls,
      fetch: async (input, init) => {
        const url = new URL(input);
        if (url.origin === RPC) {
          const body = JSON.parse(String(init?.body)) as { method: string };
          calls.push(`rpc ${body.method}`);
        } else {
          calls.push(`${url.origin} ${url.pathname}`);
        }
        return world.fetch(input, init);
      },
    };
  }

  it("sends a payment with no request to RPC or the indexer beyond a sync's", async () => {
    const { world } = await funded();
    const bob = await openWallet(world, 1);
    const tap = tapped(world);
    const alice = await openWallet({ ...world, fetch: tap.fetch }, 0);
    await alice.sync();
    tap.calls.length = 0;
    await alice.sync();
    const sync = tap.calls.filter((c) => !c.includes("relayer"));
    tap.calls.length = 0;
    await alice.send({ to: bob.generateAddress(), amount: 1n * XLM, maxFee: 2n * XLM });
    const send = tap.calls.filter((c) => !c.includes("relayer"));
    assert.deepEqual(send, sync);
  });

  it("unshields with only the destination's ledger entries read beyond a sync's", async () => {
    const { world } = await funded();
    const tap = tapped(world);
    const alice = await openWallet({ ...world, fetch: tap.fetch }, 0);
    await alice.sync();
    tap.calls.length = 0;
    await alice.sync();
    const sync = tap.calls.filter((c) => !c.includes("relayer"));
    tap.calls.length = 0;
    await alice.unshield({
      to: world.signer("exchange").publicKey,
      amount: 1n * XLM,
      maxFee: 2n * XLM,
      confirm: confirmAll,
    });
    const unshield = tap.calls.filter((c) => !c.includes("relayer"));
    assert.deepEqual(unshield, [...sync, "rpc getLedgerEntries"]);
  });
});

describe("wallet safety: network fees", () => {
  it("pays the simulated resource fee once, on top of the inclusion fee", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    await alice.shield({ amount: 10n * XLM, signer: world.signer("d") });
    // the mock RPC quotes 150 stroops for inclusion and simulates 1,000 for resources
    assert.deepEqual(world.rpc.sentFees, [1_150n]);
  });

  it("shows the fee to a signer that confirms it, and signs nothing it declines", async () => {
    const world = await createWorld();
    const alice = await openWallet(world, 0);
    const honest = world.signer("d");
    const shown: bigint[] = [];
    let signed = false;
    const declining = {
      publicKey: honest.publicKey,
      confirmFee: (fee: { total: bigint }) => {
        shown.push(fee.total);
        return false;
      },
      signTransaction: async (envelope: string, passphrase: string) => {
        signed = true;
        return honest.signTransaction(envelope, passphrase);
      },
    };
    await assert.rejects(
      alice.shield({ amount: 10n * XLM, signer: declining }),
      isError("not_confirmed"),
    );
    assert.deepEqual(shown, [1_150n]);
    assert.equal(signed, false);
    assert.equal(world.vault.pending.size, 0);
  });

  it("refuses a network fee above its caps before signing", async () => {
    const world = await createWorld();
    const capped = await PrivateWallet.open({
      deployment: world.deployment,
      allowUnpinnedDeployment: true,
      keys: keySource.mnemonic(MNEMONIC, { account: 0 }),
      prover: new TrapdoorProver(),
      artifacts: trapdoorArtifacts,
      storage: new MemoryStore(),
      rpcUrl: RPC,
      fetch: world.fetch,
      clock: world.clock,
      sleep: async () => {},
      networkFeeCaps: { resource: 999n },
    });
    await assert.rejects(
      capped.shield({ amount: 10n * XLM, signer: world.signer("d") }),
      isError("fee_above_cap"),
    );
    assert.deepEqual(world.rpc.sentFees, []);
  });
});

describe("wallet safety: secrets", () => {
  it("keeps the private balance out of errors", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    const err = await alice
      .send({ to: bob.generateAddress(), amount: 500n * XLM, maxFee: 2n * XLM })
      .then(
        () => assert.fail("the send went through"),
        (e: unknown) => e as CyphrasError,
      );
    assert.equal(err.code, "insufficient_funds");
    assert.deepEqual(err.details, {});
    assert.ok(!err.message.includes((100n * XLM).toString()));
  });

  it("keeps keys out of errors and of the store", async () => {
    const world = await createWorld();
    const storage = new MemoryStore();
    const failing = new TrapdoorProver();
    failing.prove = async () => {
      throw new Error(`witness ${MNEMONIC}`);
    };
    const alice = await openWallet(world, 0, storage, failing);
    let message = "";
    try {
      await alice.shield({ amount: 10n * XLM, signer: world.signer("d") });
    } catch (err) {
      message = `${(err as Error).message} ${JSON.stringify((err as CyphrasError).details)}`;
    }
    assert.match(message, /prover/);
    assert.ok(!message.includes("abandon"));
    for (const key of storage.keys()) {
      const value = Buffer.from((await storage.get(key)) as Uint8Array).toString("latin1");
      assert.ok(!value.includes("abandon"));
      assert.ok(!key.includes(alice.generateAddress()));
    }
  });
});
