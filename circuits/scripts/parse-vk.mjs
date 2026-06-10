import { readFileSync, writeFileSync } from "node:fs";

// Converts a snarkjs Groth16 verification_key.json into the exact byte blobs the Soroban
// verifier contract's init_vk consumes. Output is deployment-ready hex:
//   G1 point = x || y                         (64 bytes / 128 hex chars)
//   G2 point = x_c1 || x_c0 || y_c1 || y_c0   (128 bytes / 256 hex chars, EIP-197 order)
//
// Byte order for both is fixed and verified against a real proof:
//   1. G2 ordering is (c1, c0) per coordinate (EIP-197), i.e. snarkjs (c0, c1) swapped.
//   2. alpha_g1 is stored un-negated; the contract negates pi_a in the pairing check.
// This matches gen-proof-fixture.mjs byte for byte.

const [, , inPath, outPath] = process.argv;

if (!inPath || !outPath) {
  console.error("usage: node parse-vk.mjs <verification_key.json> <vk_parsed.json>");
  process.exit(1);
}

const FIELD_BYTES = 32;

// BN254 base field modulus (Fq). Coordinates must be canonical (< q).
const FQ = BigInt("21888242871839275222246405745257275088696311157297823662689037894645226208583");

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

// G1 = x || y
function g1(point) {
  assertAffineG1(point);
  return toHexBE(point[0]) + toHexBE(point[1]);
}

// G2 = x_c1 || x_c0 || y_c1 || y_c0 (swap each coordinate pair to c1, c0)
function g2(point) {
  assertAffineG2(point);
  return toHexBE(point[0][1]) + toHexBE(point[0][0]) + toHexBE(point[1][1]) + toHexBE(point[1][0]);
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
