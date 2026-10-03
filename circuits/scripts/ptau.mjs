import { createHash } from "node:crypto";
import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

// Hermez phase-1 powers of tau, power 16; the hash is the blake2b-512 the snarkjs README publishes.
const URL = "https://circom.info/powersOfTau28_hez_final_16.ptau";
const BLAKE2B =
  "6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf4" +
  "3eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125";
const PTAU = join(import.meta.dirname, "..", "build", "ptau", "powersOfTau28_hez_final_16.ptau");

if (!existsSync(PTAU)) {
  mkdirSync(dirname(PTAU), { recursive: true });
  const res = await fetch(URL);
  if (!res.ok) throw new Error(`download of ${URL} failed: HTTP ${res.status}`);
  await pipeline(Readable.fromWeb(res.body), createWriteStream(`${PTAU}.part`));
  renameSync(`${PTAU}.part`, PTAU);
}

const hash = createHash("blake2b512");
for await (const chunk of createReadStream(PTAU)) hash.update(chunk);
if (hash.digest("hex") !== BLAKE2B) {
  throw new Error(`${PTAU} does not match the published blake2b hash; delete it and retry`);
}
console.log(`${PTAU}: blake2b ok`);
