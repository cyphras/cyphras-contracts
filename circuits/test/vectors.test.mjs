import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bip39Seed, defaultAddress, deriveKeys } from "../reference/keys.mjs";
import { MNEMONIC, keyVectors, noteVectors } from "../reference/vectors.mjs";
import { dummy, note, populatedTree, scenario, spend, transactionInput } from "./fixtures.mjs";
import { ROOT, transactionCircuit } from "./helpers.mjs";

const VECTORS = join(ROOT, "test", "vectors");
const committed = (name) => JSON.parse(readFileSync(join(VECTORS, name), "utf8"));

describe("test vectors", () => {
  it("keys.json matches the reference implementation", () => {
    assert.deepEqual(committed("keys.json"), keyVectors());
  });

  it("notes.json matches the reference implementation", () => {
    assert.deepEqual(committed("notes.json"), noteVectors());
  });

  // The circuit recomputes ivk, pkd, cm, the Merkle root and nf for each vector note.
  it("the circuit derives every note vector's commitment and nullifier", async () => {
    const circuit = await transactionCircuit();
    const keys = deriveKeys(bip39Seed(MNEMONIC), "mainnet", 0);
    const owner = { keys, address: defaultAddress(keys) };
    for (const v of committed("notes.json").notes) {
      const n = note(BigInt(v.value), owner.address, BigInt(v.rcm));
      const pos = BigInt(v.pos);
      const tree = populatedTree([[pos, n]]);
      assert.equal(tree.node(0, pos), BigInt(v.cm));
      const spends = [spend(owner, n, pos, tree.path(pos)), dummy(owner)];
      const outputs = [n, note(0n, owner.address)];
      const input = transactionInput(scenario(spends, outputs, 0n, tree));
      assert.equal(input.nf[0], BigInt(v.nf));
      const w = await circuit.witness(input);
      assert.equal(circuit.violations(w), 0);
    }
  });
});
