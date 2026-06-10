import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { StrKey } from "@stellar/stellar-sdk";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Builds one private-send note and proof for the deployed testnet XLM pool, mirroring the
// exact field derivations the pool performs on-chain, then writes the commit and reveal
// arguments to build/integration.json for the CLI to consume.
//
// Usage: node integration-testnet.mjs <recipientG> <relayerG> <feeStroops> <denomination> <poolAddress>

const here = dirname(fileURLToPath(import.meta.url));
const BUILD = join(here, "..", "build");
const WASM = join(BUILD, "withdraw_js", "withdraw.wasm");
const ZKEY = join(BUILD, "withdraw_final.zkey");
const DEPLOY = JSON.parse(
  readFileSync(join(here, "..", "..", "deployments", "testnet.json"), "utf-8"),
);

const R = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const LEVELS = 20;

const [, , recipientG, relayerG, feeStr, denomStr, poolAddr] = process.argv;
if (!recipientG || !relayerG || !feeStr || !denomStr || !poolAddr) {
  console.error(
    "usage: node integration-testnet.mjs <recipientG> <relayerG> <feeStroops> <denomination> <poolAddress>",
  );
  process.exit(1);
}

const poolEntry = DEPLOY.pools.find((p) => p.pool === poolAddr);
if (!poolEntry) {
  throw new Error(`pool ${poolAddr} not found in deployments/testnet.json`);
}
const tokenSac = poolEntry.token;
const denomination = BigInt(denomStr);
const fee = BigInt(feeStr);
if (fee < 0n || fee >= 1n << 64n) {
  throw new Error("fee must be in [0, 2^64)");
}

function be32(n) {
  const hex = n.toString(16);
  if (hex.length > 64) throw new Error(`value exceeds 32 bytes: ${n}`);
  return hex.padStart(64, "0");
}

function bytesToField(bytes) {
  return BigInt("0x" + Buffer.from(bytes).toString("hex")) % R;
}

// Matches the contract's address_to_field: raw ed25519 key (G) or contract hash (C) mod r.
function addressToField(addr) {
  const raw = addr.startsWith("C")
    ? StrKey.decodeContract(addr)
    : StrKey.decodeEd25519PublicKey(addr);
  return bytesToField(raw);
}

function rand31() {
  const b = new Uint8Array(31);
  globalThis.crypto.getRandomValues(b);
  return BigInt("0x" + Buffer.from(b).toString("hex"));
}

const poseidon = await buildPoseidon();
const F = poseidon.F;
const H = (xs) => F.toObject(poseidon(xs));

const recipientField = addressToField(recipientG);
const relayerField = addressToField(relayerG);
const assetIdField = addressToField(tokenSac);
const relayerFeeField = fee; // i128 fee as field element (fee < 2^64 < r)

const secret = rand31();
const nullifier = rand31();
const amountBlinding = rand31();

const nullifierHash = H([nullifier, secret]);
const amountHash = H([denomination, fee, amountBlinding]);
const commitment = H([nullifier, secret, amountHash, assetIdField]);

// Tree state for a leaf inserted at index 0 of an empty pool: all siblings are the cached
// zero values, all path indices are 0 (left). Mirrors the pool's insert_leaf.
const zeros = [0n];
for (let i = 0; i < LEVELS; i++) zeros.push(H([zeros[i], zeros[i]]));

const pathElements = [];
const pathIndices = [];
let cur = commitment;
for (let i = 0; i < LEVELS; i++) {
  pathElements.push(zeros[i]);
  pathIndices.push(0);
  cur = H([cur, zeros[i]]);
}
const root = cur;

const input = {
  secret: secret.toString(),
  nullifier: nullifier.toString(),
  amount: denomination.toString(),
  relayerFee: fee.toString(),
  amountBlinding: amountBlinding.toString(),
  pathElements: pathElements.map(String),
  pathIndices: pathIndices.map(String),
  root: root.toString(),
  nullifierHash: nullifierHash.toString(),
  recipient: recipientField.toString(),
  relayer: relayerField.toString(),
  relayerFee: relayerFeeField.toString(),
  amountHash: amountHash.toString(),
  assetId: assetIdField.toString(),
};

const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
const vkey = JSON.parse(readFileSync(join(BUILD, "verification_key.json"), "utf-8"));
if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
  throw new Error("proof failed local verification");
}

const g1 = (p) => be32(BigInt(p[0])) + be32(BigInt(p[1]));
const g2 = (p) =>
  be32(BigInt(p[0][1])) + be32(BigInt(p[0][0])) + be32(BigInt(p[1][1])) + be32(BigInt(p[1][0]));
const proofHex = g1(proof.pi_a) + g2(proof.pi_b) + g1(proof.pi_c);

const out = {
  pool: poolAddr,
  commit: { commitment: be32(commitment), xlmFee: fee.toString() },
  reveal: {
    proof: proofHex,
    root: be32(root),
    nullifierHash: be32(nullifierHash),
    amountHash: be32(amountHash),
    recipient: recipientG,
    relayer: relayerG,
    xlmFee: fee.toString(),
  },
};

writeFileSync(join(BUILD, "integration.json"), JSON.stringify(out, null, 2) + "\n", "utf-8");
console.log(JSON.stringify(out, null, 2));
