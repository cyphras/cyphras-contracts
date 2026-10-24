// A proof made with the mainnet ceremony key, for the verifier test built with the mainnet
// feature. The zkey and the circuit wasm are the ceremony release files, which this repository
// does not hold; their hashes must match deployments/mainnet.json.
//
//   MAINNET_ZKEY=.../transaction_final.zkey MAINNET_WASM=.../transaction.wasm \
//     node scripts/mainnet-proof-fixture.mjs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import * as snarkjs from "snarkjs";
import { domain } from "../reference/domain.mjs";
import { transactionInput, transfer } from "../test/fixtures.mjs";

const ROOT = join(import.meta.dirname, "..");
const CONTRACTS = join(ROOT, "..", "contracts");
const DEPLOYMENT = join(ROOT, "..", "deployments", "mainnet.json");
const VK = join(CONTRACTS, "verifier", "keys", "mainnet", "verification_key.json");
const OUT = join(CONTRACTS, "verifier", "tests", "mainnet_proof.json");

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const hex32 = (x) => "0x" + BigInt(x).toString(16).padStart(64, "0");
const g1 = (p) => hex32(p[0]).slice(2) + hex32(p[1]).slice(2);
// The host orders each Fq2 coordinate as c1 || c0; snarkjs writes [c0, c1].
const g2 = (p) => [p[0][1], p[0][0], p[1][1], p[1][0]].map((c) => hex32(c).slice(2)).join("");

const zkey = process.env.MAINNET_ZKEY;
const wasm = process.env.MAINNET_WASM;
assert.ok(zkey && wasm, "set MAINNET_ZKEY and MAINNET_WASM to the ceremony release files");

const vault = JSON.parse(readFileSync(DEPLOYMENT, "utf8")).vaults.find((v) => v.asset === "native");
assert.equal(sha256(zkey), vault.artifacts.zkey, "the zkey is not the deployed ceremony key");
assert.equal(sha256(wasm), vault.artifacts.wasm, "the circuit wasm is not the deployed one");
assert.equal(sha256(VK), vault.artifacts.vkey, "keys/mainnet is not the deployed verifying key");

const vk = JSON.parse(readFileSync(VK, "utf8"));
assert.deepEqual(await snarkjs.zKey.exportVerificationKey(zkey), vk, "zkey does not match the VK");

const input = transactionInput({ ...transfer(), domain: domain("mainnet", "native") });
const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
assert.ok(await snarkjs.groth16.verify(vk, publicSignals, proof));

writeFileSync(
  OUT,
  JSON.stringify(
    { a: g1(proof.pi_a), b: g2(proof.pi_b), c: g1(proof.pi_c), inputs: publicSignals.map(hex32) },
    null,
    2,
  ) + "\n",
);
console.log(`wrote ${OUT}`);
process.exit(0);
