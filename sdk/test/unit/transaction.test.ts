import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mnemonicToSeedSync } from "@scure/bip39";
import { PinnedArtifacts } from "../../src/artifacts.ts";
import { L } from "../../src/babyjub.ts";
import { computeDomain } from "../../src/domain.ts";
import { decryptIncoming, recoverOutgoing } from "../../src/encryption.ts";
import { CyphrasError } from "../../src/errors.ts";
import { extDataHash, publicAmount } from "../../src/extdata.ts";
import { P } from "../../src/field.ts";
import { defaultAddressKey, deriveSpendingKeys } from "../../src/keys.ts";
import { CommitmentTree, EMPTY_ROOT, ZEROS } from "../../src/merkle.ts";
import type { Prover } from "../../src/prover.ts";
import { proveTransaction } from "../../src/proving.ts";
import {
  type BuiltTransaction,
  type TransactionRequest,
  buildTransaction,
} from "../../src/transaction.ts";
import { violations } from "../support/circuit-model.ts";
import { TrapdoorProver, trapdoorArtifacts, trapdoorPins } from "../support/trapdoor.ts";
import { MNEMONIC, fixture, testScalar } from "../helpers.ts";

const FIXTURE = fixture<{ vault: string; accounts: Record<string, string> }>("vault-proofs.json");
const seed = mnemonicToSeedSync(MNEMONIC);
const alice = deriveSpendingKeys(seed, "testnet", 0);
const bob = deriveSpendingKeys(seed, "testnet", 1);
const self = defaultAddressKey(alice);
const bobAddress = defaultAddressKey(bob);
const depositor = FIXTURE.accounts["alice"] as string;
const relayer = FIXTURE.accounts["relayer"] as string;

function shieldRequest(amount: bigint): TransactionRequest {
  return {
    keys: alice,
    self,
    root: EMPTY_ROOT,
    domain: computeDomain("testnet", "native"),
    inputs: [],
    outputs: [
      { address: self, value: amount },
      { address: self, value: 0n },
    ],
    ext: {
      vault: FIXTURE.vault,
      networkId: new Uint8Array(32).fill(7),
      deadline: 500,
      extAmount: amount,
      fee: 0n,
      recipient: depositor,
      relayer: depositor,
    },
  };
}

function spendable(tx: BuiltTransaction): { tree: CommitmentTree; slot: number; pos: number } {
  const tree = CommitmentTree.empty();
  const leaves = [testScalar("tx/leaf", 0, P), testScalar("tx/leaf", 1, P), ...tx.commitments];
  tree.applyPage(leaves);
  const slot = tx.outputs.findIndex((o) => o.value > 0n);
  return { tree, slot, pos: 2 + slot };
}

describe("transaction building", () => {
  it("builds a shield the circuit accepts", () => {
    const tx = buildTransaction(shieldRequest(1_000n));
    assert.deepEqual(violations(tx.witness), []);
    assert.equal(tx.realSlots.length, 0);
    assert.equal(tx.witness.publicAmount, 1_000n);
    assert.equal(tx.witness.extDataHash, extDataHash(tx.ext));
    assert.deepEqual(tx.witness.inValue, [0n, 0n]);
    for (const [i, out] of tx.outputs.entries()) {
      const blob = i === 0 ? tx.ext.encryptedOutput0 : tx.ext.encryptedOutput1;
      assert.equal(decryptIncoming(alice, out.cm, blob)?.value, out.value);
      assert.equal(recoverOutgoing(alice.ovk, out.cm, blob)?.esk, out.esk);
      assert.ok(out.esk > 0n && out.esk < L);
    }
  });

  it("builds a transfer and an unshield of real notes", () => {
    const shield = buildTransaction(shieldRequest(1_000_000n));
    const { tree, slot, pos } = spendable(shield);
    const funds = shield.outputs[slot] as BuiltTransaction["outputs"][0];
    const input = {
      ...funds.address,
      value: funds.value,
      rcm: funds.rcm,
      pos,
      path: tree.partialPath(pos),
    };
    const transfer = buildTransaction({
      ...shieldRequest(0n),
      root: tree.root(),
      inputs: [input],
      outputs: [
        { address: bobAddress, value: 600_000n },
        { address: self, value: 399_000n },
      ],
      ext: { ...shieldRequest(0n).ext, extAmount: 0n, fee: 1_000n, recipient: relayer, relayer },
    });
    assert.deepEqual(violations(transfer.witness), []);
    assert.equal(transfer.realSlots.length, 1);
    assert.equal(transfer.witness.publicAmount, publicAmount(0n, 1_000n));
    assert.equal(transfer.witness.publicAmount, P - 1_000n);

    const unshield = buildTransaction({
      ...shieldRequest(0n),
      root: tree.root(),
      inputs: [input],
      outputs: [
        { address: self, value: 1_000n },
        { address: self, value: 0n },
      ],
      ext: {
        ...shieldRequest(0n).ext,
        extAmount: -998_000n,
        fee: 1_000n,
        recipient: FIXTURE.accounts["exchange_muxed"] as string,
        relayer,
      },
    });
    assert.deepEqual(violations(unshield.witness), []);
    // spending the same note twice gives the same nullifier, so at most one can land
    const real = (t: BuiltTransaction): bigint => t.nullifiers[t.realSlots[0] as number] as bigint;
    assert.equal(real(transfer), real(unshield));
  });

  it("orders inputs and outputs at random", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 40 && seen.size < 2; i++) {
      const tx = buildTransaction(shieldRequest(5n));
      seen.add(tx.outputs[0].value === 5n ? "first" : "second");
    }
    assert.equal(seen.size, 2);
    const flips = new Set<number>();
    const shield = buildTransaction(shieldRequest(9n));
    const { tree, slot, pos } = spendable(shield);
    const funds = shield.outputs[slot] as BuiltTransaction["outputs"][0];
    for (let i = 0; i < 40 && flips.size < 2; i++) {
      const tx = buildTransaction({
        ...shieldRequest(0n),
        root: tree.root(),
        inputs: [{ ...funds.address, value: 9n, rcm: funds.rcm, pos, path: tree.partialPath(pos) }],
        outputs: [
          { address: self, value: 9n },
          { address: self, value: 0n },
        ],
        ext: { ...shieldRequest(0n).ext, extAmount: 0n, fee: 0n, recipient: relayer, relayer },
      });
      flips.add(tx.realSlots[0] as number);
    }
    assert.equal(flips.size, 2);
  });

  it("refuses unbalanced, overlong or wrongly placed spends", () => {
    const fail = (request: TransactionRequest, code: string): void => {
      assert.throws(
        () => buildTransaction(request),
        (err: unknown) => err instanceof CyphrasError && err.code === code,
      );
    };
    fail(
      {
        ...shieldRequest(10n),
        outputs: [
          { address: self, value: 11n },
          { address: self, value: 0n },
        ],
      },
      "invalid_argument",
    );
    const shield = buildTransaction(shieldRequest(10n));
    const { tree, slot, pos } = spendable(shield);
    const funds = shield.outputs[slot] as BuiltTransaction["outputs"][0];
    const input = {
      ...funds.address,
      value: 10n,
      rcm: funds.rcm,
      pos,
      path: tree.partialPath(pos),
    };
    const spend = (overrides: Partial<TransactionRequest>): TransactionRequest => ({
      ...shieldRequest(0n),
      root: tree.root(),
      inputs: [input],
      outputs: [
        { address: self, value: 10n },
        { address: self, value: 0n },
      ],
      ext: { ...shieldRequest(0n).ext, extAmount: 0n, fee: 0n, recipient: relayer, relayer },
      ...overrides,
    });
    assert.doesNotThrow(() => buildTransaction(spend({})));
    fail(spend({ inputs: [{ ...input, path: ZEROS.slice(0, 32) }] }), "tree_unverified");
    fail(spend({ inputs: [{ ...input, pos: pos + 1 }] }), "tree_unverified");
    fail(spend({ inputs: [input, input] }), "invalid_argument");
    fail(spend({ inputs: [input, input, input] }), "invalid_argument");
    fail(spend({ inputs: [{ ...input, value: 0n }] }), "invalid_argument");
    fail(spend({ inputs: [{ ...input, path: input.path.slice(1) }] }), "invalid_argument");
  });
});

describe("proving pipeline", () => {
  it("returns a verified proof with the witness's public inputs", async () => {
    const tx = buildTransaction(shieldRequest(77n));
    const prover = new TrapdoorProver();
    const artifacts = new PinnedArtifacts(trapdoorArtifacts, await trapdoorPins());
    const proof = await proveTransaction(tx.witness, prover, artifacts);
    assert.equal(prover.proofs, 1);
    assert.deepEqual(proof.inputNullifiers, tx.nullifiers);
    assert.deepEqual(proof.outputCommitments, tx.commitments);
    assert.equal(proof.publicAmount, 77n);
    assert.equal(proof.proof.a.length, 64);
    assert.equal(proof.proof.b.length, 128);
  });

  it("refuses a prover that lies about the inputs or returns a bad proof", async () => {
    const tx = buildTransaction(shieldRequest(77n));
    const artifacts = new PinnedArtifacts(trapdoorArtifacts, await trapdoorPins());
    const honest = new TrapdoorProver();
    const lying: Prover = {
      prove: async (w, a) => {
        const p = await honest.prove(w, a);
        return { ...p, publicSignals: [...p.publicSignals.slice(0, 7), 1n] };
      },
    };
    const forging: Prover = {
      prove: async (w, a) => {
        const p = await honest.prove(w, a);
        return { ...p, c: p.a };
      },
    };
    const failing: Prover = {
      prove: async () => {
        throw new Error("witness signal inAsk[0] = 0x1234");
      },
    };
    for (const [prover, code] of [
      [lying, "proof_invalid"],
      [forging, "proof_invalid"],
      [failing, "prover_failed"],
    ] as const) {
      await assert.rejects(proveTransaction(tx.witness, prover, artifacts), (err: unknown) => {
        assert.ok(err instanceof CyphrasError && err.code === code);
        assert.ok(!err.message.includes("0x1234"));
        return true;
      });
    }
  });

  it("refuses artifacts that do not match their pins", async () => {
    const pins = { ...(await trapdoorPins()), wasm: "ab".repeat(32) };
    const artifacts = new PinnedArtifacts(trapdoorArtifacts, pins);
    await assert.rejects(
      proveTransaction(
        buildTransaction(shieldRequest(1n)).witness,
        new TrapdoorProver(),
        artifacts,
      ),
      (err: unknown) => err instanceof CyphrasError && err.code === "artifact_mismatch",
    );
  });
});
