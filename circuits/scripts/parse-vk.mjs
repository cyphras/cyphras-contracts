import { readFileSync, writeFileSync } from "node:fs";

// Converts a snarkjs Groth16 verification_key.json into the big-endian hex form
// the Soroban verifier contract consumes at init. Each field coordinate becomes a
// 32-byte (64 hex char) big-endian string. G1 points keep affine (x, y); G2 points
// keep affine (x, y) where each is a pair (c0, c1).
//
// TWO FOOTGUNS the verifier contract (Issue #3) must resolve against the host
// function, both flagged here because they cannot be settled without the contract:
//   1. G2 coordinate ordering. This file preserves snarkjs (c0, c1). EIP-197 style
//      pairing checks often expect (c1, c0). The contract owns the final byte order
//      and must test against bn254_multi_pairing_check vectors.
//   2. alpha negation / pairing-equation sign. snarkjs alpha_g1 is emitted un-negated.
//      Depending on whether the host checks product == 1 or uses an explicit negation,
//      the contract may need to negate alpha_g1 (or beta). Decide and test on #3.

const [, , inPath, outPath] = process.argv;

if (!inPath || !outPath) {
  console.error("usage: node parse-vk.mjs <verification_key.json> <vk_parsed.json>");
  process.exit(1);
}

const FIELD_BYTES = 32;

// BN254 base field modulus (Fq). Coordinates must be canonical (< q).
const FQ = BigInt(
  "21888242871839275222246405745257275088696311157297823662689037894645226208583"
);

function toHexBE(dec) {
  const value = BigInt(dec);
  if (value < 0n || value >= FQ) {
    throw new Error(`coordinate not in [0, q): ${dec}`);
  }
  return value.toString(16).padStart(FIELD_BYTES * 2, "0");
}

// snarkjs stores points in projective form with a trailing "1" (G1) or ["1","0"]
// (G2). Anything else means the point is not normalized to affine and the x/y read
// below would be wrong.
function assertAffineG1(point) {
  if (point[2] !== "1") {
    throw new Error(`G1 point is not affine (z=${point[2]})`);
  }
}

function assertAffineG2(point) {
  if (point[2][0] !== "1" || point[2][1] !== "0") {
    throw new Error(`G2 point is not affine (z=${JSON.stringify(point[2])})`);
  }
}

function g1(point) {
  assertAffineG1(point);
  return { x: toHexBE(point[0]), y: toHexBE(point[1]) };
}

function g2(point) {
  assertAffineG2(point);
  return {
    x: [toHexBE(point[0][0]), toHexBE(point[0][1])],
    y: [toHexBE(point[1][0]), toHexBE(point[1][1])],
  };
}

const vk = JSON.parse(readFileSync(inPath, "utf-8"));

if (vk.protocol !== "groth16") {
  throw new Error(`expected groth16 protocol, got ${vk.protocol}`);
}

const parsed = {
  protocol: vk.protocol,
  curve: vk.curve,
  nPublic: vk.nPublic,
  alpha_g1: g1(vk.vk_alpha_1),
  beta_g2: g2(vk.vk_beta_2),
  gamma_g2: g2(vk.vk_gamma_2),
  delta_g2: g2(vk.vk_delta_2),
  ic: vk.IC.map(g1),
};

writeFileSync(outPath, JSON.stringify(parsed, null, 2) + "\n", "utf-8");
console.log(`wrote ${outPath} (nPublic=${parsed.nPublic}, ic=${parsed.ic.length})`);
