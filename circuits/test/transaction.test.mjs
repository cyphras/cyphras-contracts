import assert from "node:assert/strict";
import { F1Field } from "ffjavascript";
import { BASE8, F, GENERATOR, IDENTITY, L, P, add, mul, onCurve } from "../reference/babyjub.mjs";
import { addressAt } from "../reference/keys.mjs";
import { MerkleTree, noteCommitment } from "../reference/notes.mjs";
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
import { ASSERT_FAILED, randomField, transactionCircuit } from "./helpers.mjs";

const NUM_PUBLIC = 8;
const T8 = mul(GENERATOR, L);
const FL = new F1Field(L);
const randomScalar = () => randomField() % L;

describe("Transaction(20, 2, 2)", () => {
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

  const rejectsInput = (input) => assert.rejects(circuit.witness(input), ASSERT_FAILED);
  const rejects = (s) => rejectsInput(transactionInput(s));

  // A real input whose note sits in the tree under whatever (gd, pkd) the attacker chose.
  function spendOfCommitted({ value, gd, q, pkd }) {
    const n = { value, gd, pkd, rcm: randomField() };
    const tree = populatedTree([[4n, n]]);
    const s = spend(alice, { ...n, q }, 4n, tree.path(4n));
    const outputs = [note(value, bob.address), note(0n, alice.address)];
    return scenario([s, dummy(alice)], outputs, 0n, tree);
  }

  // snarkjs needs nConstraints + nPublic + 1 <= 2^power, so the power-16 ptau allows 65,527
  it("stays within the 65,527-constraint budget of the power-16 ptau", () => {
    assert.equal(circuit.nConstraints, 55_617);
    assert.ok(circuit.nConstraints + NUM_PUBLIC + 1 <= 1 << 16);
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
  });

  describe("rejects", () => {
    it("a wrong ask", () => {
      const s = transfer();
      s.spends[0].ask = randomScalar();
      return rejects(s);
    });

    it("a wrong nsk", () => {
      const s = transfer();
      s.spends[0].nsk = randomScalar();
      return rejects(s);
    });

    it("a non-canonical ask or nsk, although it names the same point", async () => {
      for (const key of ["ask", "nsk"]) {
        const s = transfer();
        const k = s.spends[0][key];
        assert.deepEqual(mul(BASE8, k + L), mul(BASE8, k));
        s.spends[0][key] = k + L;
        await rejects(s);
      }
    });

    it("a gd that is not 8 * q", () => {
      const s = transfer();
      s.spends[0].q = bob.address.q;
      return rejects(s);
    });

    it("a gd at the identity, on a real note or a dummy", async () => {
      await rejects(spendOfCommitted({ value: 10n, gd: IDENTITY, q: T8, pkd: IDENTITY }));
      const s = shield();
      Object.assign(s.spends[1], { gd: IDENTITY, q: IDENTITY });
      await rejects(s);
    });

    // With gd of order 8, pkd = ivk * gd depends only on ivk mod 8, so any key would match.
    it("a low-order or mixed-order gd", async () => {
      const r = mul(BASE8, randomScalar());
      for (const gd of [T8, add(T8, T8), add(r, T8)]) {
        const pkd = mul(gd, alice.keys.ivk);
        for (const q of [gd, T8, r]) await rejects(spendOfCommitted({ value: 10n, gd, q, pkd }));
      }
    });

    // If gd were not committed, anyone could spend with gd' = (1 / ivk') * pkd for their own ivk'.
    it("a gd swapped for one that maps another key onto the note's pkd", () => {
      const s = transfer();
      const gd = mul(alice.address.pkd, FL.inv(bob.keys.ivk));
      assert.deepEqual(mul(gd, bob.keys.ivk), alice.address.pkd);
      const q = mul(gd, FL.inv(8n));
      Object.assign(s.spends[0], { ask: bob.keys.ask, nsk: bob.keys.nsk, gd, q });
      return rejects(s);
    });

    it("a note whose pkd is not ivk * gd", () => {
      const { gd, q } = alice.address;
      return rejects(spendOfCommitted({ value: 10n, gd, q, pkd: addressAt(alice.keys, 1).pkd }));
    });

    it("a wrong rcm or value on an input", async () => {
      const s = transfer();
      s.spends[0].rcm = randomField();
      await rejects(s);
      const t = transfer();
      t.spends[0].value += 1n;
      t.outputs[1].value += 1n;
      await rejects(t);
    });

    it("a wrong rcm or value on an output", async () => {
      const input = transactionInput(transfer());
      await rejectsInput({ ...input, outRcm: [randomField(), input.outRcm[1]] });
      const value = [input.outValue[0] + 1n, input.outValue[1]];
      await rejectsInput({ ...input, outValue: value, publicAmount: 1n });
    });

    it("an output gd or pkd off the curve", async () => {
      for (const key of ["gd", "pkd"]) {
        const s = transfer();
        s.outputs[0][key] = [1n, 2n];
        assert.ok(!onCurve(s.outputs[0][key]));
        await rejects(s);
      }
    });

    it("an output value of 2^64", () => rejects(shield(1n << 64n)));

    it("an input value of 2^64", () => {
      const s = transfer();
      const n = note(1n << 64n, alice.address);
      const tree = populatedTree([[5n, n]]);
      s.root = tree.root();
      s.spends[0] = spend(alice, n, 5n, tree.path(5n));
      s.outputs = [note(MAX_VALUE, bob.address), note(1n, alice.address)];
      return rejects(s);
    });

    it("output values that wrap the field to balance", () => {
      const s = shield(100n);
      s.outputs = [note(101n, alice.address), note(P - 1n, alice.address)];
      return rejects(s);
    });

    it("a pos other than the note's leaf", () => {
      const s = transfer(5n);
      s.spends[0].pos = 6n;
      return rejects(s);
    });

    // pos and pos + 2^20 share their low bits, so the path would verify; without the range
    // check one note would have two nullifiers.
    it("a pos of 2^20 or more, even when its low 20 bits match the path", async () => {
      for (const extra of [1n << 20n, 1n << 200n]) {
        const s = transfer(5n);
        s.spends[0].pos += extra;
        await rejects(s);
      }
    });

    it("a wrong root while value is nonzero", async () => {
      const s = transfer();
      s.root = randomField();
      await rejects(s);
      const stale = transfer();
      stale.root = new MerkleTree().root();
      await rejects(stale);
    });

    it("two equal nullifiers", async () => {
      const n = note(700_000_000n, alice.address);
      const tree = populatedTree([[3n, n]]);
      const twice = spend(alice, n, 3n, tree.path(3n));
      const outputs = [note(1_400_000_000n, bob.address), note(0n, alice.address)];
      await rejects(scenario([twice, { ...twice }], outputs, 0n, tree));
      const s = shield();
      s.spends[1] = { ...s.spends[0] };
      await rejects(s);
    });

    it("a balance off by one in either direction", async () => {
      for (const delta of [1n, -1n]) {
        const s = transfer();
        s.publicAmount += delta;
        await rejects(s);
      }
    });

    it("swapped nullifiers or output commitments", async () => {
      const input = transactionInput(twoInputs());
      await rejectsInput({ ...input, nf: [...input.nf].reverse() });
      await rejectsInput({ ...input, cmOut: [...input.cmOut].reverse() });
    });
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

    it("rejects a pos that disagrees with its path bits", () => {
      const pos = circuit.read(valid, "main.inPos[0]");
      for (const other of [pos + 1n, pos + (1n << 20n)]) {
        assert.ok(circuit.violations(circuit.patch(valid, { "main.inPos[0]": other })) > 0);
      }
    });
  });

  describe("edge cases", () => {
    it("spends the note at the last leaf, 2^20 - 1", () => accepts(transfer(MAX_POS)));

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
