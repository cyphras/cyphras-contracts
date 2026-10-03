import { bn254 } from "@noble/curves/bn254.js";
import * as snarkjs from "snarkjs";
import { PUBLIC_INPUTS, quiet } from "./common.mjs";

// Byte for byte what `snarkjs zkey export verificationkey` writes: one-space indentation and no
// trailing newline. The vault build pins the SHA-256 of exactly these bytes.
export async function exportVerificationKey(zkey) {
  const vk = await snarkjs.zKey.exportVerificationKey(zkey, quiet);
  return Buffer.from(JSON.stringify(vk, null, 1));
}

function fq(v) {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw new Error("a coordinate is not a decimal string");
  }
  const n = BigInt(v);
  if (n >= bn254.fields.Fp.ORDER) throw new Error("a coordinate is not below the field modulus");
  return n;
}

function fq2(v) {
  if (!Array.isArray(v) || v.length !== 2) throw new Error("a G2 coordinate is not in Fq2");
  return bn254.fields.Fp2.fromBigTuple([fq(v[0]), fq(v[1])]);
}

// snarkjs writes affine points with a last coordinate of 1; its point at infinity has 0 there.
function affine(p, one) {
  if (!Array.isArray(p) || p.length !== 3 || JSON.stringify(p[2]) !== JSON.stringify(one)) {
    throw new Error("a key point is not an affine point");
  }
}

function checked(point, error) {
  try {
    point.assertValidity();
  } catch {
    throw new Error(error);
  }
  // noble reads (0, 0) as the point at infinity and accepts it; the vault build rejects it.
  if (point.is0()) throw new Error(error);
  return point;
}

function g1(p) {
  affine(p, "1");
  const point = bn254.G1.Point.fromAffine({ x: fq(p[0]), y: fq(p[1]) });
  return checked(point, "a G1 point is not on the curve");
}

function g2(p) {
  affine(p, ["1", "0"]);
  const point = bn254.G2.Point.fromAffine({ x: fq2(p[0]), y: fq2(p[1]) });
  return checked(point, "a G2 point is not in G2");
}

// The rules the vault build applies before it compiles a key in (check.rs in the verifier), so a
// bad ceremony output fails here before anyone pins it.
export function checkVerificationKey(bytes) {
  const vk = JSON.parse(bytes);
  if (vk.protocol !== "groth16" || vk.curve !== "bn128") {
    throw new Error("the key must be Groth16 over BN254");
  }
  if (vk.nPublic !== PUBLIC_INPUTS) {
    throw new Error(`the key must have ${PUBLIC_INPUTS} public inputs`);
  }
  if (!Array.isArray(vk.IC) || vk.IC.length !== PUBLIC_INPUTS + 1) {
    throw new Error(`the key must have ${PUBLIC_INPUTS + 1} IC points`);
  }
  const gamma = g2(vk.vk_gamma_2);
  const delta = g2(vk.vk_delta_2);
  // snarkjs fixes gamma to the generator and the setup starts delta there too, so a delta still at
  // the generator, or equal to gamma, never received a phase-2 contribution.
  if (delta.equals(gamma) || delta.equals(bn254.G2.Point.BASE)) {
    throw new Error("delta was never changed by a phase-2 contribution");
  }
  g1(vk.vk_alpha_1);
  g2(vk.vk_beta_2);
  vk.IC.forEach(g1);
}
