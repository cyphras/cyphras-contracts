import { bn254 } from "@noble/curves/bn254";
import { fail } from "./errors.ts";
import type { AffineProof } from "./extdata.ts";
import { P } from "./field.ts";

const { Fp2, Fp12 } = bn254.fields;
const G1 = bn254.G1.ProjectivePoint;
const G2 = bn254.G2.ProjectivePoint;
type G1Point = ReturnType<typeof G1.fromAffine>;
type G2Point = ReturnType<typeof G2.fromAffine>;

// BN254 base field modulus.
const Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const PUBLIC_INPUTS = 8;

export interface VerifyingKey {
  readonly alpha: G1Point;
  readonly beta: G2Point;
  readonly gamma: G2Point;
  readonly delta: G2Point;
  readonly ic: readonly G1Point[];
}

function coordinate(value: unknown): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(value)) {
    throw new TypeError("a coordinate is a decimal string");
  }
  const x = BigInt(value);
  if (x >= Q) throw new RangeError("a coordinate is not below the field modulus");
  return x;
}

function g1(value: unknown): G1Point {
  if (!Array.isArray(value) || value.length !== 3 || value[2] !== "1") {
    throw new TypeError("a G1 point is [x, y, 1]");
  }
  const p = G1.fromAffine({ x: coordinate(value[0]), y: coordinate(value[1]) });
  p.assertValidity();
  return p;
}

function fp2(value: unknown): ReturnType<typeof Fp2.fromBigTuple> {
  if (!Array.isArray(value) || value.length !== 2)
    throw new TypeError("an Fq2 element is [c0, c1]");
  return Fp2.fromBigTuple([coordinate(value[0]), coordinate(value[1])]);
}

function g2(value: unknown): G2Point {
  if (!Array.isArray(value) || value.length !== 3) throw new TypeError("a G2 point is [x, y, 1]");
  const z = value[2] as unknown;
  if (!Array.isArray(z) || z[0] !== "1" || z[1] !== "0") throw new TypeError("affine G2 expected");
  const p = G2.fromAffine({ x: fp2(value[0]), y: fp2(value[1]) });
  p.assertValidity();
  if (!p.isTorsionFree()) throw new RangeError("a G2 point is outside the prime-order subgroup");
  return p;
}

// Parses a snarkjs verification_key.json for this circuit. The release pins its SHA-256, so this
// guards against a malformed file rather than a malicious one.
export function parseVerifyingKey(json: unknown): VerifyingKey {
  try {
    const vk = json as Record<string, unknown>;
    if (vk["protocol"] !== "groth16" || vk["curve"] !== "bn128") {
      throw new TypeError("not a Groth16 key over BN254");
    }
    const ic = vk["IC"];
    if (vk["nPublic"] !== PUBLIC_INPUTS || !Array.isArray(ic) || ic.length !== PUBLIC_INPUTS + 1) {
      throw new TypeError("the key does not have 8 public inputs");
    }
    const key: VerifyingKey = {
      alpha: g1(vk["vk_alpha_1"]),
      beta: g2(vk["vk_beta_2"]),
      gamma: g2(vk["vk_gamma_2"]),
      delta: g2(vk["vk_delta_2"]),
      ic: ic.map(g1),
    };
    // snarkjs fixes gamma to the generator and starts delta there, so a delta still equal to
    // either never received a phase-2 contribution. The vault's build refuses the same keys.
    if (key.delta.equals(key.gamma) || key.delta.equals(G2.BASE)) {
      throw new RangeError("the key comes from a setup without a phase-2 contribution");
    }
    return key;
  } catch (err) {
    return fail("invalid_argument", `invalid verifying key: ${(err as Error).message}`);
  }
}

export function verifyGroth16(
  vk: VerifyingKey,
  proof: AffineProof,
  inputs: readonly bigint[],
): boolean {
  if (inputs.length !== vk.ic.length - 1) return false;
  if (inputs.some((x) => x < 0n || x >= P)) return false;
  try {
    const a = G1.fromAffine({ x: proof.a[0], y: proof.a[1] });
    const c = G1.fromAffine({ x: proof.c[0], y: proof.c[1] });
    const b = G2.fromAffine({
      x: Fp2.fromBigTuple([proof.b[0][0], proof.b[0][1]]),
      y: Fp2.fromBigTuple([proof.b[1][0], proof.b[1][1]]),
    });
    a.assertValidity();
    c.assertValidity();
    b.assertValidity();
    if (!b.isTorsionFree()) return false;
    let vkX = vk.ic[0] as G1Point;
    inputs.forEach((x, i) => {
      vkX = vkX.add((vk.ic[i + 1] as G1Point).multiplyUnsafe(x));
    });
    const product = bn254.pairingBatch([
      { g1: a.negate(), g2: b },
      { g1: vk.alpha, g2: vk.beta },
      { g1: vkX, g2: vk.gamma },
      { g1: c, g2: vk.delta },
    ]);
    return Fp12.eql(product, Fp12.ONE);
  } catch {
    return false;
  }
}
