import { bigIntToBytesLE, bytesToBigIntLE } from "./bytes.ts";
import { P, add, div, isCanonical, isHigh, mul, neg, sqrt, square, sub } from "./field.ts";

// Baby Jubjub: a * x^2 + y^2 = 1 + D * x^2 * y^2 over Fr. A is a square and D is not, so the
// extended-coordinate formulas below are complete: no input needs special casing.
export const A = 168700n;
export const D = 168696n;
// Order of the prime-order subgroup; the full group has order 8 * L.
export const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

export type Point = readonly [bigint, bigint];

export const IDENTITY: Point = [0n, 1n];
export const BASE8: Point = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];

interface Extended {
  x: bigint;
  y: bigint;
  z: bigint;
  t: bigint;
}

const toExtended = ([x, y]: Point): Extended => ({ x, y, z: 1n, t: mul(x, y) });

function toAffine(p: Extended): Point {
  return [div(p.x, p.z), div(p.y, p.z)];
}

function addExtended(p: Extended, q: Extended): Extended {
  const a = mul(p.x, q.x);
  const b = mul(p.y, q.y);
  const c = mul(mul(D, p.t), q.t);
  const d = mul(p.z, q.z);
  const e = sub(sub(mul(add(p.x, p.y), add(q.x, q.y)), a), b);
  const f = sub(d, c);
  const g = add(d, c);
  const h = sub(b, mul(A, a));
  return { x: mul(e, f), y: mul(g, h), z: mul(f, g), t: mul(e, h) };
}

function doubleExtended(p: Extended): Extended {
  const a = square(p.x);
  const b = square(p.y);
  const z2 = square(p.z);
  const c = add(z2, z2);
  const d = mul(A, a);
  const e = sub(sub(square(add(p.x, p.y)), a), b);
  const g = add(d, b);
  const f = sub(g, c);
  const h = sub(d, b);
  return { x: mul(e, f), y: mul(g, h), z: mul(f, g), t: mul(e, h) };
}

export function addPoints(p: Point, q: Point): Point {
  return toAffine(addExtended(toExtended(p), toExtended(q)));
}

export function negate([x, y]: Point): Point {
  return [neg(x), y];
}

export function equalPoints(p: Point, q: Point): boolean {
  return p[0] === q[0] && p[1] === q[1];
}

export function isIdentity(p: Point): boolean {
  return equalPoints(p, IDENTITY);
}

export function onCurve([x, y]: Point): boolean {
  if (!isCanonical(x) || !isCanonical(y)) return false;
  const x2 = square(x);
  const y2 = square(y);
  return add(mul(A, x2), y2) === add(1n, mul(mul(D, x2), y2));
}

const WINDOW = 4;

// A fixed 4-bit window: every scalar of the same bit length takes the same sequence of doublings
// and additions, including additions of the identity for zero windows.
export function scalarMul(p: Point, scalar: bigint): Point {
  if (scalar < 0n) throw new RangeError("negative scalar");
  const base = toExtended(p);
  const table: Extended[] = [toExtended(IDENTITY), base];
  for (let i = 2; i < 1 << WINDOW; i++) table.push(addExtended(table[i - 1] as Extended, base));
  const windows = Math.max(1, Math.ceil(scalar.toString(2).length / WINDOW));
  let acc = toExtended(IDENTITY);
  for (let w = windows - 1; w >= 0; w--) {
    for (let i = 0; i < WINDOW; i++) acc = doubleExtended(acc);
    const digit = Number((scalar >> BigInt(w * WINDOW)) & 0xfn);
    acc = addExtended(acc, table[digit] as Extended);
  }
  return toAffine(acc);
}

// Three doublings: the steps the circuit's AssertPrimeOrder constrains for gd = 8 * q.
export function timesCofactor(p: Point): Point {
  let e = toExtended(p);
  for (let i = 0; i < 3; i++) e = doubleExtended(e);
  return toAffine(e);
}

export function inPrimeSubgroup(p: Point): boolean {
  return onCurve(p) && isIdentity(scalarMul(p, L));
}

// A prime-order point other than the identity: what every key, address and ephemeral point must be.
export function isPrimeOrderPoint(p: Point): boolean {
  return !isIdentity(p) && inPrimeSubgroup(p);
}

// 32 bytes: y little-endian, with the top bit set when x > (P - 1) / 2.
export function packPoint([x, y]: Point): Uint8Array {
  const out = bigIntToBytesLE(y, 32);
  if (isHigh(x)) out[31] = (out[31] as number) | 0x80;
  return out;
}

// Only the canonical encoding decodes: y below P and no sign bit when x = 0. Otherwise a point
// would have several encodings, which circomlibjs unpackPoint allows by accepting y + P.
export function unpackPoint(bytes: Uint8Array): Point | undefined {
  if (bytes.length !== 32) return undefined;
  const sign = ((bytes[31] as number) & 0x80) !== 0;
  const yBytes = Uint8Array.from(bytes);
  yBytes[31] = (yBytes[31] as number) & 0x7f;
  const y = bytesToBigIntLE(yBytes);
  if (y >= P) return undefined;
  const y2 = square(y);
  const den = sub(A, mul(D, y2));
  if (den === 0n) return undefined;
  const x = sqrt(div(sub(1n, y2), den));
  if (x === undefined || (x === 0n && sign)) return undefined;
  return [isHigh(x) === sign ? x : neg(x), y];
}
