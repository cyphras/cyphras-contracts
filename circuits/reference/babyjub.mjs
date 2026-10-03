import { buildBabyjub } from "circomlibjs";
import { F1Field } from "ffjavascript";

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
export const A = 168700n;
export const D = 168696n;
export const F = new F1Field(P);
export const IDENTITY = [0n, 1n];

const bj = await buildBabyjub();

// circomlibjs works on Montgomery-form elements; everything outside this module uses BigInt.
const toBj = (p) => [bj.F.e(p[0]), bj.F.e(p[1])];
const fromBj = (p) => [bj.F.toObject(p[0]), bj.F.toObject(p[1])];

export const BASE8 = fromBj(bj.Base8);
// Generates the whole group of order 8 * L; L * GENERATOR has order 8.
export const GENERATOR = fromBj(bj.Generator);

export function add(p, q) {
  return fromBj(bj.addPoint(toBj(p), toBj(q)));
}

export function mul(p, s) {
  return fromBj(bj.mulPointEscalar(toBj(p), s));
}

export function onCurve(p) {
  return bj.inCurve(toBj(p));
}

export function isIdentity(p) {
  return p[0] === IDENTITY[0] && p[1] === IDENTITY[1];
}

export function neg(p) {
  return [F.neg(p[0]), p[1]];
}

// Three doublings, the same steps AssertPrimeOrder constrains.
export function timesCofactor(p) {
  let r = p;
  for (let i = 0; i < 3; i++) r = add(r, r);
  return r;
}

export function inPrimeSubgroup(p) {
  return onCurve(p) && isIdentity(mul(p, L));
}

// 32 bytes: y little-endian, top bit set when x > (p - 1) / 2.
export function packPoint(p) {
  return Uint8Array.from(bj.packPoint(toBj(p)));
}
