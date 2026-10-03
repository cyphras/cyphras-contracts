import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { NON_RESIDUE, P, inv, mod, mul, pow, sqrt, square } from "../../src/field.ts";
import { testScalar } from "../helpers.ts";

const legendre = (x: bigint): bigint => pow(x, (P - 1n) / 2n);

describe("field", () => {
  it("uses the smallest quadratic non-residue", () => {
    for (let n = 2n; n < NON_RESIDUE; n++) assert.equal(legendre(n), 1n);
    assert.equal(legendre(NON_RESIDUE), P - 1n);
  });

  it("finds a root of every square and none of a non-square", () => {
    for (let i = 0; i < 64; i++) {
      const x = testScalar("field/sqrt", i, P);
      const root = sqrt(square(x));
      assert.ok(root === x || root === mod(-x));
      assert.equal(sqrt(mul(square(x === 0n ? 1n : x), NON_RESIDUE)), undefined);
    }
    assert.equal(sqrt(0n), 0n);
  });

  it("inverts every non-zero element", () => {
    for (let i = 0; i < 64; i++) {
      const x = testScalar("field/inv", i, P - 1n) + 1n;
      assert.equal(mul(x, inv(x)), 1n);
    }
    assert.throws(() => inv(0n));
    assert.throws(() => inv(P));
  });

  it("reduces negative and oversized integers", () => {
    assert.equal(mod(-1n), P - 1n);
    assert.equal(mod(P + 5n), 5n);
    assert.equal(mod(-P), 0n);
  });
});
