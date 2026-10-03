import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  A,
  BASE8,
  D,
  IDENTITY,
  L,
  type Point,
  addPoints,
  inPrimeSubgroup,
  isIdentity,
  isPrimeOrderPoint,
  negate,
  onCurve,
  packPoint,
  scalarMul,
  timesCofactor,
  unpackPoint,
} from "../../src/babyjub.ts";
import { bigIntToBytesLE } from "../../src/bytes.ts";
import { P, pow } from "../../src/field.ts";
import { testScalar } from "../helpers.ts";

// circomlibjs Generator, which generates the whole group of order 8 * L.
const GENERATOR: Point = [
  995203441582195749578291179787384436505546430278305826713579947235728471134n,
  5472060717959818805561601436314318772137091100104008585924551046643952123905n,
];
const ORDER_8 = scalarMul(GENERATOR, L);

function slowMul(p: Point, s: bigint): Point {
  let acc = IDENTITY;
  let base = p;
  for (let k = s; k > 0n; k >>= 1n) {
    if (k & 1n) acc = addPoints(acc, base);
    base = addPoints(base, base);
  }
  return acc;
}

describe("Baby Jubjub", () => {
  it("has a square A and a non-square D, so its addition law is complete", () => {
    assert.equal(pow(A, (P - 1n) / 2n), 1n);
    assert.equal(pow(D, (P - 1n) / 2n), P - 1n);
  });

  it("uses Base8 = 8 * Generator, a prime-order point", () => {
    assert.ok(onCurve(GENERATOR) && onCurve(BASE8));
    assert.deepEqual(timesCofactor(GENERATOR), BASE8);
    assert.ok(isPrimeOrderPoint(BASE8));
    assert.ok(!inPrimeSubgroup(GENERATOR));
    assert.ok(!isIdentity(ORDER_8) && isIdentity(scalarMul(ORDER_8, 8n)));
  });

  it("multiplies like double-and-add, for scalars of every size", () => {
    for (let i = 0; i < 16; i++) {
      const s = testScalar("babyjub/mul", i, 1n << BigInt(8 + 16 * i));
      assert.deepEqual(scalarMul(BASE8, s), slowMul(BASE8, s));
    }
    assert.deepEqual(scalarMul(BASE8, 0n), IDENTITY);
    assert.deepEqual(scalarMul(BASE8, 1n), BASE8);
    assert.deepEqual(scalarMul(BASE8, L - 1n), negate(BASE8));
  });

  it("is a group: (a + b) P = a P + b P", () => {
    for (let i = 0; i < 8; i++) {
      const a = testScalar("babyjub/a", i, L);
      const b = testScalar("babyjub/b", i, L);
      const lhs = scalarMul(GENERATOR, a + b);
      assert.deepEqual(lhs, addPoints(scalarMul(GENERATOR, a), scalarMul(GENERATOR, b)));
    }
  });

  it("packs and unpacks every point, including the low-order ones", () => {
    const points: Point[] = [IDENTITY, ORDER_8, scalarMul(ORDER_8, 4n), negate(BASE8)];
    for (let i = 0; i < 16; i++) points.push(scalarMul(GENERATOR, testScalar("babyjub/p", i, L)));
    for (const p of points) assert.deepEqual(unpackPoint(packPoint(p)), p);
  });

  it("decodes only canonical encodings", () => {
    const p = scalarMul(BASE8, 12345n);
    const packed = packPoint(p);
    const plusP = bigIntToBytesLE(p[1] + P, 32);
    plusP[31] = (plusP[31] as number) | ((packed[31] as number) & 0x80);
    assert.equal(unpackPoint(plusP), undefined);
    const negativeZero = packPoint(IDENTITY);
    negativeZero[31] = (negativeZero[31] as number) | 0x80;
    assert.equal(unpackPoint(negativeZero), undefined);
    assert.equal(unpackPoint(packed.subarray(0, 31)), undefined);
  });

  it("rejects a y with no point", () => {
    let found = 0;
    for (let y = 2n; found < 4; y++) {
      const bytes = bigIntToBytesLE(y, 32);
      const p = unpackPoint(bytes);
      if (p === undefined) found++;
      else assert.ok(onCurve(p));
    }
  });
});
