import assert from "node:assert/strict";
import {
  BASE8,
  F,
  GENERATOR,
  IDENTITY,
  L,
  P,
  add,
  inPrimeSubgroup,
  mul,
  neg,
  onCurve,
  timesCofactor,
} from "../reference/babyjub.mjs";
import { addressAt } from "../reference/keys.mjs";
import { LEVELS, MerkleTree, noteCommitment } from "../reference/notes.mjs";
import { alice, bob, MAX_POS, MAX_VALUE } from "./fixtures.mjs";
import { ASSERT_FAILED, harness, randomField } from "./helpers.mjs";

const P_MINUS_7L = P - 7n * L;
const randomScalar = () => randomField() % L;

const T8 = mul(GENERATOR, L);
const T4 = add(T8, T8);
const T2 = add(T4, T4);
const LOW_ORDER = [T2, T4, T8, mul(T8, 3n)];
// L is 1 mod 8, so (7L + 1) / 8 is the inverse of 8 mod L
const EIGHTH = (7n * L + 1n) / 8n;

async function accepts(circuit, input) {
  const w = await circuit.witness(input);
  assert.equal(circuit.violations(w), 0);
  return w;
}

describe("gadgets", () => {
  it("builds torsion points of orders 2, 4 and 8", () => {
    assert.deepEqual(T2, [0n, P - 1n]);
    assert.deepEqual(timesCofactor(T8), IDENTITY);
    assert.equal((8n * EIGHTH) % L, 1n);
  });

  describe("AssertLtL", () => {
    let circuit;
    before(async () => {
      circuit = await harness("assert_lt_l", "keys.circom", "AssertLtL()");
    });

    for (const [name, s] of [
      ["0", 0n],
      ["1", 1n],
      ["L - 1", L - 1n],
    ]) {
      it(`accepts ${name}`, () => accepts(circuit, { s }));
    }

    for (const [name, s] of [
      ["L", L],
      ["L + 1", L + 1n],
      ["2^251 - 1", (1n << 251n) - 1n],
      ["2^251", 1n << 251n],
      ["p - 1", P - 1n],
    ]) {
      it(`rejects ${name}`, () => assert.rejects(circuit.witness({ s }), ASSERT_FAILED));
    }
  });

  describe("ReduceModL", () => {
    let reduce;
    let check;
    before(async () => {
      reduce = await harness("reduce_mod_l", "keys.circom", "ReduceModL()");
      check = await harness("reduce_mod_l_check", "keys.circom", "ReduceModLCheck()");
    });

    it("reduces edge inputs and random field elements", async () => {
      const inputs = [0n, 1n, L - 1n, L, L + 1n, 2n * L, 7n * L - 1n, 7n * L, P - 1n];
      inputs.push(8n * L - P - 1n, randomField(), randomField());
      for (const x of inputs) {
        const w = await accepts(reduce, { in: x });
        assert.equal(reduce.read(w, "main.out"), x % L);
      }
    });

    it("accepts only the canonical (out, k)", async () => {
      for (const x of [0n, 5n, L + 3n, 7n * L + 2n, randomField()]) {
        await accepts(check, { in: x, out: x % L, k: x / L });
        if (x >= L) {
          const alias = { in: x, out: (x % L) + L, k: x / L - 1n };
          await assert.rejects(check.witness(alias), ASSERT_FAILED);
        }
        const k8 = { in: x, out: F.sub(x, 8n * L), k: 8n };
        await assert.rejects(check.witness(k8), ASSERT_FAILED);
      }
    });

    // For in < 8L - p, (in + p - 7L, 7) satisfies in == out + k * L mod p with out < L and k < 8;
    // only the no-wrap bound at k = 7 tells it apart from the canonical (in, 0).
    it("rejects the wrapping witness at k = 7", async () => {
      for (const x of [0n, 1n, 5n, 8n * L - P - 1n]) {
        const wrap = { in: x, out: x + P_MINUS_7L, k: 7n };
        assert.ok(wrap.out < L);
        assert.equal(F.e(wrap.out + 7n * L), x);
        await assert.rejects(check.witness(wrap), ASSERT_FAILED);
      }
    });
  });

  describe("AssertNonZero", () => {
    let circuit;
    before(async () => {
      circuit = await harness("assert_non_zero", "keys.circom", "AssertNonZero()");
    });

    it("accepts nonzero values", async () => {
      for (const x of [1n, P - 1n, randomField()]) await accepts(circuit, { in: x });
    });

    it("rejects zero", () => assert.rejects(circuit.witness({ in: 0n }), ASSERT_FAILED));

    it("has no satisfying assignment for zero, whatever the inverse hint", async () => {
      const w = await circuit.witness({ in: 7n });
      for (const inv of [0n, 1n, randomField()]) {
        assert.ok(circuit.violations(circuit.patch(w, { "main.in": 0n, "main.inv": inv })) > 0);
      }
    });
  });

  describe("AssertPrimeOrder", () => {
    let circuit;
    before(async () => {
      circuit = await harness("assert_prime_order", "keys.circom", "AssertPrimeOrder()");
    });

    it("accepts 8 * q for q of every order", async () => {
      const r = mul(BASE8, randomScalar());
      for (const q of [r, add(r, T2), add(r, T4), add(r, T8), BASE8, alice.address.q]) {
        const p = timesCofactor(q);
        assert.ok(inPrimeSubgroup(p));
        await accepts(circuit, { p, q });
      }
    });

    it("rejects the identity, reached from any low-order q", async () => {
      for (const q of [IDENTITY, ...LOW_ORDER]) {
        await assert.rejects(circuit.witness({ p: IDENTITY, q }), ASSERT_FAILED);
      }
    });

    it("rejects a p that is not 8 * q", async () => {
      const q = alice.address.q;
      const others = [add(timesCofactor(q), BASE8), q, neg(timesCofactor(q)), bob.address.gd];
      for (const p of others) await assert.rejects(circuit.witness({ p, q }), ASSERT_FAILED);
    });

    it("rejects low-order and mixed-order points for every candidate q", async () => {
      const r = mul(BASE8, randomScalar());
      const candidates = [IDENTITY, ...LOW_ORDER, r, mul(r, EIGHTH), add(r, T8)];
      for (const p of [...LOW_ORDER, add(r, T8), add(r, T4)]) {
        for (const q of candidates) {
          await assert.rejects(circuit.witness({ p, q }), ASSERT_FAILED);
        }
      }
    });

    it("rejects an off-curve q", async () => {
      const q = [1n, 2n];
      assert.ok(!onCurve(q));
      await assert.rejects(circuit.witness({ p: timesCofactor(q), q }), ASSERT_FAILED);
    });
  });

  describe("ScalarMulAny", () => {
    let circuit;
    before(async () => {
      circuit = await harness("scalar_mul_any", "keys.circom", "ScalarMulAny()");
    });

    // ivk ranges over [0, L); these hit both 148-bit segments of EscalarMulAny(253), their
    // boundaries, and long runs of set bits.
    const scalars = [
      0n,
      1n,
      2n,
      3n,
      7n,
      8n,
      (1n << 147n) - 1n,
      1n << 147n,
      (1n << 147n) + 1n,
      (1n << 148n) - 1n,
      1n << 148n,
      (1n << 148n) + 1n,
      (1n << 200n) + (1n << 148n) - 1n,
      1n << 250n,
      (L - 1n) / 2n,
      (L + 1n) / 2n,
      L - 2n,
      L - 1n,
      randomScalar(),
      randomScalar(),
    ];

    // gd is any prime-order point other than the identity
    const points = [
      ["Base8", BASE8],
      ["-Base8", neg(BASE8)],
      ["2 * Base8", add(BASE8, BASE8)],
      ["a DiversifyHash output", alice.address.gd],
      ["another DiversifyHash output", addressAt(bob.keys, 1).gd],
      ["a random prime-order point", mul(BASE8, randomScalar())],
    ];

    for (const [name, p] of points) {
      it(`matches the reference on ${name} for edge scalars`, async () => {
        for (const s of scalars) {
          const w = await accepts(circuit, { s, p });
          const out = [circuit.read(w, "main.out[0]"), circuit.read(w, "main.out[1]")];
          assert.deepEqual(out, mul(p, s), `s = ${s}`);
        }
      });
    }
  });

  describe("NoteCommitment", () => {
    it("matches the reference", async () => {
      const circuit = await harness("note_commitment", "note.circom", "NoteCommitment()");
      for (const value of [0n, 1n, MAX_VALUE]) {
        const n = { value, gd: alice.address.gd, pkd: alice.address.pkd, rcm: randomField() };
        const w = await accepts(circuit, n);
        assert.equal(circuit.read(w, "main.out"), noteCommitment(n));
      }
    });
  });

  describe("MerkleProof", () => {
    let circuit;
    const tree = new MerkleTree();
    before(async () => {
      circuit = await harness("merkle_proof", "merkleProof.circom", `MerkleProof(${LEVELS})`);
      for (const pos of [0n, 1n, 2n, 1000n, MAX_POS]) tree.set(pos, randomField());
    });

    it("recomputes the root for leaves across the whole index range", async () => {
      for (const pos of [0n, 1n, 2n, 1000n, MAX_POS]) {
        const input = { leaf: tree.node(0, pos), index: pos, pathElements: tree.path(pos) };
        const w = await accepts(circuit, input);
        assert.equal(circuit.read(w, "main.root"), tree.root());
      }
    });

    it("rejects an index of 2^levels or more, even with the right low bits", async () => {
      const pos = 1000n;
      for (const index of [pos + (1n << BigInt(LEVELS)), P - 1n]) {
        const input = { leaf: tree.node(0, pos), index, pathElements: tree.path(pos) };
        await assert.rejects(circuit.witness(input), ASSERT_FAILED);
      }
    });
  });
});
