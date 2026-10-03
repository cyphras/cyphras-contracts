import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import * as snarkjs from "snarkjs";
import { F } from "../reference/babyjub.mjs";
import { PUBLIC_SIGNALS, transactionInput, transfer, unshield } from "./fixtures.mjs";
import { ROOT, transactionCircuit } from "./helpers.mjs";

const PTAU = join(ROOT, "build", "ptau", "powersOfTau28_hez_final_16.ptau");

describe("Groth16 proof", () => {
  let circuit;
  let zkey;
  let vk;
  let valid;

  before(async () => {
    if (!existsSync(PTAU)) throw new Error(`missing ${PTAU}, run: npm run ptau`);
    circuit = await transactionCircuit();
    // phase 2 skipped: anyone can forge with this key, which is fine for a test fixture
    zkey = join(ROOT, "build", "test", "transaction.zkey");
    await snarkjs.zKey.newZKey(circuit.r1csPath, PTAU, zkey);
    vk = await snarkjs.zKey.exportVerificationKey(zkey);
  });

  after(async () => {
    await globalThis.curve_bn128?.terminate();
  });

  it("proves and verifies a transfer and an unshield", async () => {
    for (const s of [transfer(), unshield()]) {
      const input = transactionInput(s);
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        circuit.wasmPath,
        zkey,
      );
      const head = [input.root, input.publicAmount, input.extDataHash, input.domain];
      assert.deepEqual(publicSignals.map(BigInt), [...head, ...input.nf, ...input.cmOut]);
      assert.ok(await snarkjs.groth16.verify(vk, publicSignals, proof));
      valid = { proof, publicSignals };
    }
  });

  it("does not verify with any two public inputs swapped", async () => {
    const { proof, publicSignals } = valid;
    for (let i = 0; i < PUBLIC_SIGNALS.length; i++) {
      for (let j = i + 1; j < PUBLIC_SIGNALS.length; j++) {
        const swapped = [...publicSignals];
        [swapped[i], swapped[j]] = [swapped[j], swapped[i]];
        const pair = `${PUBLIC_SIGNALS[i]} <-> ${PUBLIC_SIGNALS[j]}`;
        assert.equal(await snarkjs.groth16.verify(vk, swapped, proof), false, pair);
      }
    }
  });

  it("does not verify with any public input changed", async () => {
    const { proof, publicSignals } = valid;
    for (let i = 0; i < PUBLIC_SIGNALS.length; i++) {
      const changed = [...publicSignals];
      changed[i] = F.add(BigInt(changed[i]), 1n).toString();
      assert.equal(await snarkjs.groth16.verify(vk, changed, proof), false, PUBLIC_SIGNALS[i]);
    }
  });
});
