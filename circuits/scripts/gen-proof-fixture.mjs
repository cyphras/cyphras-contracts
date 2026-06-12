import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Generates a real proof from the withdraw circuit and serializes it into the byte
// layout the Soroban verifier expects, so the contract test can confirm on-chain
// Groth16 verification works end to end. Serialization mirrors the proven testnet
// format: G1 = x||y (64 bytes); G2 = x_c1||x_c0||y_c1||y_c0 (128 bytes, EIP-197 order).

const here = dirname(fileURLToPath(import.meta.url));
const BUILD = join(here, "..", "build");
const WASM = join(BUILD, "withdraw_js", "withdraw.wasm");
const ZKEY = join(BUILD, "withdraw_final.zkey");
const VKEY = JSON.parse(readFileSync(join(BUILD, "verification_key.json"), "utf-8"));
const OUT_DIR = join(here, "..", "..", "stellar", "verifier", "tests");
const OUT = join(OUT_DIR, "proof_fixture.json");

const LEVELS = 20;

function be32(dec) {
  const hex = BigInt(dec).toString(16);
  if (hex.length > 64) throw new Error(`value exceeds 32 bytes: ${dec}`);
  return hex.padStart(64, "0");
}

const poseidon = await buildPoseidon();
const F = poseidon.F;
const hash = (vals) => F.toObject(poseidon(vals));

// deterministic note so the fixture is reproducible
const secret = 111111111111111111n;
const nullifier = 222222222222222222n;
const amountBlinding = 333333333333333333n;
const amount = 1000000n;
const relayerFee = 100000n;
const assetId = 123456789012345678901234567890n;

const nullifierHash = hash([nullifier, secret]);
const amountHash = hash([amount, amountBlinding]);
const commitment = hash([nullifier, secret, amountHash, assetId]);
const leaf = hash([commitment, relayerFee]);

const pathElements = [];
const pathIndices = [];
let current = leaf;
for (let i = 0; i < LEVELS; i++) {
  const sibling = hash([BigInt(i + 1), BigInt(i * 7 + 3)]);
  const index = i % 2;
  pathElements.push(sibling.toString());
  pathIndices.push(index);
  current = index === 0 ? hash([current, sibling]) : hash([sibling, current]);
}
const root = current;

const recipient = 1234567890n;
const relayer = 9876543210n;

const input = {
  secret: secret.toString(),
  nullifier: nullifier.toString(),
  amount: amount.toString(),
  relayerFee: relayerFee.toString(),
  amountBlinding: amountBlinding.toString(),
  pathElements,
  pathIndices: pathIndices.map(String),
  root: root.toString(),
  nullifierHash: nullifierHash.toString(),
  recipient: recipient.toString(),
  relayer: relayer.toString(),
  amountHash: amountHash.toString(),
  assetId: assetId.toString(),
};

const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

const ok = await snarkjs.groth16.verify(VKEY, publicSignals, proof);
if (!ok) throw new Error("snarkjs could not verify its own proof - aborting");

function g1(point) {
  return be32(point[0]) + be32(point[1]);
}

// G2: swap each coordinate pair to (c1, c0)
function g2(point) {
  return be32(point[0][1]) + be32(point[0][0]) + be32(point[1][1]) + be32(point[1][0]);
}

const proofBytes = g1(proof.pi_a) + g2(proof.pi_b) + g1(proof.pi_c);

const fixture = {
  note: "Real proof from withdraw circuit. proof/vk bytes are hex in the verifier's expected layout (G1 x||y, G2 x_c1||x_c0||y_c1||y_c0).",
  publicInputOrder: [
    "root",
    "nullifierHash",
    "recipient",
    "relayer",
    "relayerFee",
    "amountHash",
    "assetId",
  ],
  publicSignals: publicSignals.map((s) => be32(s)),
  proof: proofBytes,
  vk: {
    alpha_g1: g1(VKEY.vk_alpha_1),
    beta_g2: g2(VKEY.vk_beta_2),
    gamma_g2: g2(VKEY.vk_gamma_2),
    delta_g2: g2(VKEY.vk_delta_2),
    ic: VKEY.IC.map(g1),
  },
};

mkdirSync(OUT_DIR, { recursive: true });
writeFileSync(OUT, JSON.stringify(fixture, null, 2) + "\n", "utf-8");
console.log(`wrote ${OUT}`);
console.log(
  `proof: ${proofBytes.length / 2} bytes, publicSignals: ${publicSignals.length}, ic: ${fixture.vk.ic.length}`,
);

// snarkjs leaves worker threads alive, so exit explicitly once the fixture is written.
process.exit(0);
