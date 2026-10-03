import assert from "node:assert/strict";
import { F, L, P, add, mul } from "../reference/babyjub.mjs";
import { noteCommitment } from "../reference/notes.mjs";
import { FROZEN, sha256 } from "../scripts/circom.mjs";
import { REJECTED, T2, T4, T8 } from "./cases.mjs";
import {
  MAX_POS,
  MAX_VALUE,
  PUBLIC_SIGNALS,
  alice,
  bob,
  dummy,
  note,
  populatedTree,
  randomPath,
  scenario,
  shield,
  spend,
  spendView,
  transactionInput,
  transfer,
  twoInputs,
  unshield,
} from "./fixtures.mjs";
import { ASSERT_FAILED, transactionCircuit } from "./helpers.mjs";

const NUM_PUBLIC = 8;

describe("Transaction(32, 2, 2)", () => {
  let circuit;
  before(async () => {
    circuit = await transactionCircuit();
  });

  async function accepts(s) {
    const input = transactionInput(s);
    const w = await circuit.witness(input);
    assert.equal(circuit.violations(w), 0);
    return { input, w };
  }

  it("is the frozen circuit", () => {
    assert.equal(circuit.nConstraints, FROZEN.constraints);
    assert.equal(sha256(circuit.r1csPath), FROZEN.r1csSha256);
  });

  // snarkjs needs nConstraints + nPublic + 1 <= 2^power, so the power-15 ptau allows 32,759
  it("fits the power-15 ptau", () => {
    assert.ok(circuit.nConstraints + NUM_PUBLIC + 1 <= 1 << 15);
  });

  describe("accepts", () => {
    it("a shield: two dummy inputs and outputs [v, 0]", () => accepts(shield()));

    it("a transfer: one real input plus a dummy, paying a recipient with change", () =>
      accepts(transfer()));

    it("a spend of two real inputs", () => accepts(twoInputs()));

    it("an unshield, whose publicAmount is negative", async () => {
      const s = unshield();
      assert.ok(F.e(s.publicAmount) > P / 2n);
      await accepts(s);
    });

    it("exposes the public inputs in the specified order", async () => {
      const { input, w } = await accepts(transfer());
      PUBLIC_SIGNALS.forEach((name, i) => assert.equal(circuit.index(`main.${name}`), i + 1));
      const expected = [input.root, input.publicAmount, input.extDataHash, input.domain];
      assert.deepEqual(w.slice(1, NUM_PUBLIC + 1), [...expected, ...input.nf, ...input.cmOut]);
    });

    // Only 8q enters the circuit, so q's torsion part cannot be used to vary a nullifier.
    it("a q shifted by any torsion point, with the same nullifiers", async () => {
      const s = transfer();
      const { nf } = (await accepts(s)).input;
      for (const t of [T2, T4, T8, mul(T8, 3n)]) {
        s.spends[0].q = add(alice.address.q, t);
        assert.deepEqual((await accepts(s)).input.nf, nf);
      }
    });
  });

  describe("rejects", () => {
    for (const [name, attempts] of Object.entries(REJECTED)) {
      it(name, async () => {
        for (const input of attempts()) {
          await assert.rejects(circuit.witness(input), ASSERT_FAILED);
        }
      });
    }
  });

  // Witnesses edited after generation, as a prover bypassing the witness generator would.
  describe("constraint system", () => {
    let valid;
    before(async () => {
      valid = (await accepts(transfer())).w;
    });

    it("constrains every public input", () => {
      for (let i = 1; i <= NUM_PUBLIC; i++) {
        const tampered = [...valid];
        tampered[i] = F.add(valid[i], 1n);
        assert.ok(circuit.violations(tampered) > 0, PUBLIC_SIGNALS[i - 1]);
      }
    });

    // the multiplier's output survives simplification under the commitment's input name
    it("rejects a pkd other than ivk * gd", () => {
      const [x, y] = bob.address.pkd;
      const t = circuit.patch(valid, {
        "main.spend[0].cm.pkd[0]": x,
        "main.spend[0].cm.pkd[1]": y,
      });
      assert.ok(circuit.violations(t) > 0);
    });

    it("rejects an ivk other than the reduction of its hash", () => {
      const ivk = circuit.read(valid, "main.spend[0].ivk.out");
      for (const other of [ivk + L, F.sub(ivk, L), ivk + 1n]) {
        assert.ok(circuit.violations(circuit.patch(valid, { "main.spend[0].ivk.out": other })) > 0);
      }
    });
  });

  describe("edge cases", () => {
    it("spends the note at the last leaf, 2^32 - 1", () => accepts(transfer(MAX_POS)));

    it("moves the maximum value 2^64 - 1", async () => {
      await accepts(shield(MAX_VALUE));
      const a = note(MAX_VALUE, alice.address);
      const b = note(MAX_VALUE, alice.address);
      const tree = populatedTree([
        [0n, a],
        [MAX_POS, b],
      ]);
      const spends = [
        spend(alice, a, 0n, tree.path(0n)),
        spend(alice, b, MAX_POS, tree.path(MAX_POS)),
      ];
      const outputs = [note(MAX_VALUE, bob.address), note(MAX_VALUE, alice.address)];
      await accepts(scenario(spends, outputs, 0n, tree));
      const zero = [note(0n, alice.address), note(0n, alice.address)];
      await accepts(scenario(spends, zero, -2n * MAX_VALUE, tree));
    });

    it("accepts a dummy input with a random path at any position", async () => {
      for (const pos of [0n, MAX_POS, 12345n]) {
        const s = transfer();
        s.spends[1] = { ...dummy(alice), pos, pathElements: randomPath() };
        await accepts(s);
      }
    });
  });

  describe("nullifiers", () => {
    it("are the same for the same note at the same position", async () => {
      const s = transfer();
      const first = (await accepts(s)).input.nf[0];
      s.outputs = [note(600_000_000n, bob.address), note(400_000_000n, alice.address)];
      const second = (await accepts(s)).input.nf[0];
      assert.equal(first, second);
    });

    it("differ for the same note at two positions", async () => {
      const n = note(500_000_000n, alice.address);
      const tree = populatedTree([
        [3n, n],
        [7n, n],
      ]);
      assert.equal(tree.node(0, 3n), tree.node(0, 7n));
      const spends = [spend(alice, n, 3n, tree.path(3n)), spend(alice, n, 7n, tree.path(7n))];
      const outputs = [note(1_000_000_000n, bob.address), note(0n, alice.address)];
      const { input } = await accepts(scenario(spends, outputs, 0n, tree));
      assert.notEqual(input.nf[0], input.nf[1]);
      assert.equal(spendView(spends[0]).cm, noteCommitment(n));
    });

    it("bind the position of a dummy input too", async () => {
      const s = transfer();
      const first = (await accepts(s)).input.nf[1];
      s.spends[1] = { ...s.spends[1], pos: s.spends[1].pos ^ 1n };
      const second = (await accepts(s)).input.nf[1];
      assert.notEqual(first, second);
    });
  });
});
