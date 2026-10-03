import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BASE8, IDENTITY, L, mul } from "../reference/babyjub.mjs";
import { TAG, fold } from "../reference/keys.mjs";
import { noteCommitment, nullifier } from "../reference/notes.mjs";
import { hash } from "../reference/poseidon2.mjs";
import { implication, loadSubstitutions, loadSystem } from "../scripts/check-o2.mjs";
import { circom } from "../scripts/circom.mjs";
import { REJECTED, T4, T8 } from "./cases.mjs";
import {
  alice,
  bob,
  dummy,
  note,
  populatedTree,
  scenario,
  shield,
  spend,
  transactionInput,
  transfer,
  twoInputs,
  unshield,
} from "./fixtures.mjs";
import { OUT, transactionCircuit } from "./helpers.mjs";
import { generator, transplant } from "./transplant.mjs";

describe("R1CS against a prover that ignores the witness generator", () => {
  let circuit;
  let plain;
  before(async () => {
    circuit = await transactionCircuit();
    plain = await generator("plain");
  });

  const violated = async (gen, input) => circuit.violated(await transplant(gen, circuit, input));

  it("accepts the valid transactions, so the transplant itself is sound", async () => {
    for (const s of [shield(), transfer(), twoInputs(), unshield()]) {
      assert.deepEqual(await violated(plain, transactionInput(s)), []);
    }
  });

  describe("rejects", () => {
    for (const [name, attempts] of Object.entries(REJECTED)) {
      it(name, async () => {
        for (const input of attempts()) assert.ok((await violated(plain, input)).length > 0);
      });
    }
  });

  describe("with forged hints", () => {
    // Alice spends Bob's note with her own keys by forcing ReduceModL to output Bob's ivk.
    it("refuses another wallet's ivk, which only the range check on k stands against", async () => {
      const ivk = bob.keys.ivk;
      const gen = await generator("ivk-theft", {
        "lib/keys.circom": (text) =>
          text
            .replace("out <-- in % SUBGROUP_ORDER();", `out <-- ${ivk};`)
            .replace(
              "signal k <-- in \\ SUBGROUP_ORDER();",
              `signal k <-- (in - ${ivk}) / SUBGROUP_ORDER();`,
            ),
      });
      const n = note(500_000_000n, bob.address);
      const tree = populatedTree([[5n, n]]);
      const outputs = [note(500_000_000n, alice.address), note(0n, alice.address)];
      const s = scenario([spend(alice, n, 5n, tree.path(5n)), dummy(alice)], outputs, 0n, tree);
      const input = transactionInput(s);
      // the forged ivk applies to the dummy input as well
      const d = s.spends[1];
      const dummyCm = noteCommitment({ value: 0n, gd: d.gd, pkd: mul(d.gd, ivk), rcm: d.rcm });
      input.nf = [
        nullifier(noteCommitment(n), 5n, alice.keys.nkFold),
        nullifier(dummyCm, d.pos, alice.keys.nkFold),
      ];
      const bad = await violated(gen, input);
      assert.ok(bad.length > 0);
      const elsewhere = circuit
        .components(bad)
        .filter((c) => !/^main\.spend\[[01]\]\.ivk(\.check\.kBits)?$/.test(c));
      assert.deepEqual(elsewhere, []);
    });

    it("refuses ivk + L with k - 1, which only the bound out < L stands against", async () => {
      const gen = await generator("ivk-alias", {
        "lib/keys.circom": (text) =>
          text
            .replace(
              "out <-- in % SUBGROUP_ORDER();",
              "out <-- in % SUBGROUP_ORDER() + SUBGROUP_ORDER();",
            )
            .replace(
              "signal k <-- in \\ SUBGROUP_ORDER();",
              "signal k <-- in \\ SUBGROUP_ORDER() - 1;",
            ),
      });
      // k - 1 must not go negative for Alice's keys, which both inputs use
      assert.ok(hash([fold(mul(BASE8, alice.keys.ask), TAG.ak), alice.keys.nkFold], TAG.ivk) >= L);
      const bad = await violated(gen, transactionInput(transfer()));
      assert.ok(bad.length > 0);
      const elsewhere = circuit
        .components(bad)
        .filter((c) => !/^main\.spend\[[01]\]\.ivk(\.check\.outLtL(\.\w+)*)?$/.test(c));
      assert.deepEqual(elsewhere, []);
    });
  });

  describe("leaves to the wallet", () => {
    it("accepts outputs to low-order or identity points, which the address parser refuses", async () => {
      for (const [gd, pkd] of [
        [T8, T4],
        [IDENTITY, IDENTITY],
      ]) {
        const s = transfer();
        s.outputs[0] = { ...s.outputs[0], gd, pkd };
        assert.deepEqual(await violated(plain, transactionInput(s)), []);
      }
    });

    it("accepts a zero-value input under any keys, at any position, in no tree", async () => {
      const s = transfer();
      s.spends[1] = { ...dummy(bob), pos: 77n };
      assert.deepEqual(await violated(plain, transactionInput(s)), []);
    });
  });
});

describe("check-o2", () => {
  let o0;
  let o2;
  let substitutions;
  before(async () => {
    const dir = join(OUT, "check-o2");
    mkdirSync(join(dir, "o0"), { recursive: true });
    mkdirSync(join(dir, "o2"), { recursive: true });
    const source = join(dir, "merkle.circom");
    writeFileSync(
      source,
      'pragma circom 2.2.3;\ninclude "merkleProof.circom";\ncomponent main = MerkleProof(4);\n',
    );
    circom(source, join(dir, "o0"), { optimization: "--O0" });
    circom(source, join(dir, "o2"), { extra: ["--simplification_substitution"] });
    o0 = await loadSystem(join(dir, "o0"), "merkle");
    o2 = await loadSystem(join(dir, "o2"), "merkle");
    substitutions = loadSubstitutions(join(dir, "o2"), "merkle");
  });

  it("finds every --O0 constraint of a small circuit in its --O2 form", () => {
    const r = implication(o0, o2, substitutions);
    assert.deepEqual(r.missing, []);
    assert.ok(r.vanished > 0 && r.matched > 0);
    assert.equal(r.o2Used, o2.constraints.length);
  });

  it("reports a --O2 system that lost a constraint", () => {
    for (const drop of [0, Math.floor(o2.constraints.length / 2), o2.constraints.length - 1]) {
      const damaged = { ...o2, constraints: o2.constraints.filter((_, i) => i !== drop) };
      assert.ok(implication(o0, damaged, substitutions).missing.length > 0, `dropped ${drop}`);
    }
  });
});
