import { buildPoseidon } from "circomlibjs";
import * as snarkjs from "snarkjs";
import { StrKey } from "@stellar/stellar-sdk";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// Builds a note and proof for a NON-empty pool by fetching the pool's existing leaves from the
// relayer, inserting the new leaf at the real next index, and building the actual Merkle path and
// root over all leaves. This exercises the production withdrawal path (a reveal at index > 0) that
// the empty-pool integration script never covers.
//
// Usage: node multinote-test.mjs <recipientG> <relayerG> <feeStroops> <denomination> <poolAddress> <relayerBaseUrl>

const here = dirname(fileURLToPath(import.meta.url));
const BUILD = join(here, "..", "build");
const NET = process.env.NET || "testnet";
const NETDIR = join(BUILD, NET);
const WASM = join(BUILD, "withdraw_js", "withdraw.wasm");
const ZKEY = join(NETDIR, "withdraw_final.zkey");
const DEPLOY = JSON.parse(
  readFileSync(join(here, "..", "..", "deployments", "testnet.json"), "utf-8"),
);

const R = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const LEVELS = 20;

const [, , recipientG, relayerG, feeStr, denomStr, poolAddr, relayerUrl] = process.argv;
if (!recipientG || !relayerG || !feeStr || !denomStr || !poolAddr || !relayerUrl) {
  console.error(
    "usage: node multinote-test.mjs <recipientG> <relayerG> <feeStroops> <denomination> <poolAddress> <relayerBaseUrl>",
  );
  process.exit(1);
}

const poolEntry = DEPLOY.pools.find((p) => p.pool === poolAddr);
if (!poolEntry) throw new Error(`pool ${poolAddr} not in deployments/testnet.json`);
const tokenSac = poolEntry.token;
const denomination = BigInt(denomStr);
const fee = BigInt(feeStr);

function be32(n) {
  const hex = n.toString(16);
  if (hex.length > 64) throw new Error(`value exceeds 32 bytes: ${n}`);
  return hex.padStart(64, "0");
}

function bytesToField(bytes) {
  return BigInt("0x" + Buffer.from(bytes).toString("hex")) % R;
}

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

// The relayer's `commitment` field actually holds the tree leaf.
const res = await fetch(`${relayerUrl}/v1/info/leaves/${poolAddr}?from=0&limit=10000`);
if (!res.ok) throw new Error(`leaves fetch failed: ${res.status}`);
const body = await res.json();
const existing = body.leaves
  .slice()
  .sort((a, b) => a.leaf_index - b.leaf_index)
  .map((l) => BigInt("0x" + l.commitment));
const myIndex = existing.length;
if (myIndex === 0)
  throw new Error("pool is empty; use integration-testnet.mjs for an index-0 reveal");

const recipientField = addressToField(recipientG);
const relayerField = addressToField(relayerG);
const assetIdField = addressToField(tokenSac);

const secret = rand31();
const nullifier = rand31();
const amountBlinding = rand31();

const nullifierHash = H([nullifier, secret]);
const amountHash = H([denomination, amountBlinding]);
const innerCommitment = H([nullifier, secret, amountHash, assetIdField]);
const leaf = H([innerCommitment, fee]);

// Pad empty slots at each level with that level's zero-subtree hash, mirroring the pool's incremental insert.
const zeros = [0n];
for (let i = 0; i < LEVELS; i++) zeros.push(H([zeros[i], zeros[i]]));

let layer = [...existing, leaf];
let idx = myIndex;
const pathElements = [];
const pathIndices = [];
for (let lvl = 0; lvl < LEVELS; lvl++) {
  const isRight = idx & 1;
  const sibIdx = isRight ? idx - 1 : idx + 1;
  const sibling = sibIdx < layer.length ? layer[sibIdx] : zeros[lvl];
  pathElements.push(sibling);
  pathIndices.push(isRight);
  const next = [];
  for (let i = 0; i < layer.length; i += 2) {
    const l = layer[i];
    const r = i + 1 < layer.length ? layer[i + 1] : zeros[lvl];
    next.push(H([l, r]));
  }
  layer = next;
  idx >>= 1;
}
const root = layer[0];

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
  relayerFee: fee.toString(),
  amountHash: amountHash.toString(),
  assetId: assetIdField.toString(),
};

const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
const vkey = JSON.parse(readFileSync(join(NETDIR, "verification_key.json"), "utf-8"));
if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof))) {
  throw new Error("proof failed local verification");
}

const g1 = (p) => be32(BigInt(p[0])) + be32(BigInt(p[1]));
const g2 = (p) =>
  be32(BigInt(p[0][1])) + be32(BigInt(p[0][0])) + be32(BigInt(p[1][1])) + be32(BigInt(p[1][0]));
const proofHex = g1(proof.pi_a) + g2(proof.pi_b) + g1(proof.pi_c);

const out = {
  pool: poolAddr,
  leafIndex: myIndex,
  commit: { innerCommitment: be32(innerCommitment), relayerFee: fee.toString() },
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
console.log(`built proof for leaf index ${myIndex} (pool had ${existing.length} leaves)`);

process.exit(0);
