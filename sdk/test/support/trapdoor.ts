// A Groth16 verifying key whose trapdoor the tests know, and a prover that forges proofs for it
// after checking the witness against the circuit model. It stands in for snarkjs in unit tests,
// so everything above the prover runs fast while verification stays real.
import { bn254 } from "@noble/curves/bn254";
import { sha256 } from "@noble/hashes/sha2";
import { type ArtifactName, type ArtifactSource, sha256Hex } from "../../src/artifacts.ts";
import { bytesToBigIntBE, utf8 } from "../../src/bytes.ts";
import { P } from "../../src/field.ts";
import {
  type CircuitArtifacts,
  type Groth16Proof,
  type Prover,
  type TransactionWitness,
  publicInputs,
} from "../../src/prover.ts";
import { violations } from "./circuit-model.ts";

const G1 = bn254.G1.ProjectivePoint;
const G2 = bn254.G2.ProjectivePoint;
const scalar = (label: string): bigint =>
  (bytesToBigIntBE(sha256(utf8(`cyphras/v2/test/trapdoor/${label}`))) % (P - 1n)) + 1n;

const ALPHA = scalar("alpha");
const BETA = scalar("beta");
const GAMMA = scalar("gamma");
const DELTA = scalar("delta");
const IC = Array.from({ length: 9 }, (_, i) => scalar(`ic/${i}`));

const s = (x: bigint): string => x.toString();
const g1Json = (k: bigint): string[] => {
  const p = G1.BASE.multiply(k).toAffine();
  return [s(p.x), s(p.y), "1"];
};
const g2Json = (k: bigint): string[][] => {
  const p = G2.BASE.multiply(k).toAffine();
  return [
    [s(p.x.c0), s(p.x.c1)],
    [s(p.y.c0), s(p.y.c1)],
    ["1", "0"],
  ];
};

export const TRAPDOOR_VK = utf8(
  JSON.stringify({
    protocol: "groth16",
    curve: "bn128",
    nPublic: 8,
    vk_alpha_1: g1Json(ALPHA),
    vk_beta_2: g2Json(BETA),
    vk_gamma_2: g2Json(GAMMA),
    vk_delta_2: g2Json(DELTA),
    IC: IC.map(g1Json),
  }),
);

const FILES: Record<ArtifactName, Uint8Array> = {
  wasm: utf8("trapdoor wasm"),
  zkey: utf8("trapdoor zkey"),
  vkey: TRAPDOOR_VK,
};

export const trapdoorArtifacts: ArtifactSource = {
  load: async (name) => FILES[name],
};

export async function trapdoorPins(): Promise<Record<ArtifactName, string>> {
  return {
    wasm: await sha256Hex(FILES.wasm),
    zkey: await sha256Hex(FILES.zkey),
    vkey: await sha256Hex(FILES.vkey),
  };
}

const inverse = (x: bigint): bigint => {
  let [a, b, u, v] = [((x % P) + P) % P, P, 1n, 0n];
  while (a > 1n) {
    const q = b / a;
    [a, b, u, v] = [b - q * a, a, v - q * u, u];
  }
  return ((u % P) + P) % P;
};

export class TrapdoorProver implements Prover {
  proofs = 0;
  witnesses: TransactionWitness[] = [];

  async prove(witness: TransactionWitness, artifacts: CircuitArtifacts): Promise<Groth16Proof> {
    if (new TextDecoder().decode(artifacts.zkey) !== "trapdoor zkey") {
      throw new Error("unexpected proving key");
    }
    const broken = violations(witness);
    if (broken.length > 0) throw new Error(`unsatisfied: ${broken.join(", ")}`);
    this.proofs++;
    this.witnesses.push(witness);
    const inputs = publicInputs(witness);
    const vkX = inputs.reduce(
      (acc, x, i) => (acc + x * (IC[i + 1] as bigint)) % P,
      IC[0] as bigint,
    );
    const a = scalar(`a/${this.proofs}`);
    const b = scalar(`b/${this.proofs}`);
    // a * b = alpha * beta + vkX * gamma + c * delta
    const c = ((((a * b - ALPHA * BETA - vkX * GAMMA) % P) + P) * inverse(DELTA)) % P;
    const A = G1.BASE.multiply(a).toAffine();
    const B = G2.BASE.multiply(b).toAffine();
    const C = G1.BASE.multiply(c).toAffine();
    return {
      a: [A.x, A.y],
      b: [
        [B.x.c0, B.x.c1],
        [B.y.c0, B.y.c1],
      ],
      c: [C.x, C.y],
      publicSignals: inputs,
    };
  }
}
