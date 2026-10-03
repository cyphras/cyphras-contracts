import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Address, TransactionBuilder, type Transaction, xdr } from "@stellar/stellar-base";
import { decodeAddress } from "../../src/address.ts";
import { bytesToHex, randomBytes } from "../../src/bytes.ts";
import { encryptOutput } from "../../src/encryption.ts";
import { CyphrasError } from "../../src/errors.ts";
import { noteCommitment, randomFieldElement, randomScalar } from "../../src/notes.ts";
import { MemoryStore, SealedStore } from "../../src/storage.ts";
import { type Plan, type WalletState, loadState, saveState } from "../../src/wallet/state.ts";
import { XLM, createWorld, rewritingFetch, type World } from "../support/network.ts";
import { confirmAll, isError, openWallet, storeKeyOf } from "../support/wallets.ts";
import { TrapdoorProver } from "../support/trapdoor.ts";
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

async function funded(world?: World) {
  const w = world ?? (await createWorld());
  const alice = await openWallet(w, 0);
  await alice.shield({ amount: 100n * XLM, signer: w.signer("alice depositor") });
  w.advance(3_601);
  w.admitAll();
  await alice.sync();
  return { world: w, alice };
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

  it("takes a nullifier listed past the indexer's complete-to ledger in the next sync", async () => {
    const { world, alice } = await funded();
    const bob = await openWallet(world, 1);
    await alice.send({ to: bob.generateAddress(), amount: 10n * XLM, maxFee: 2n * XLM });
    world.indexer.completeTo = world.vault.ledger - 1;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "submitted");
    world.indexer.completeTo = undefined;
    await alice.sync();
    assert.equal((await alice.plans())[0]?.state, "settled");
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

describe("wallet safety: secrets", () => {
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
