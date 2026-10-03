import { createHash } from "node:crypto";
import { createReadStream, createWriteStream, existsSync, mkdirSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import { ROOT } from "./circom.mjs";

// Hermez phase-1 powers of tau, power 15, which fits the circuit with its public inputs; the hash
// is the blake2b-512 the snarkjs README publishes for this file.
const NAME = "powersOfTau28_hez_final_15.ptau";
export const PTAU = join(ROOT, "build", "ptau", NAME);
export const PTAU_BLAKE2B =
  "982372c867d229c236091f767e703253249a9b432c1710b4f326306bfa2428a1" +
  "7b06240359606cfe4d580b10a5a1f63fbed499527069c18ae17060472969ae6e";

async function main() {
  if (!existsSync(PTAU)) {
    mkdirSync(dirname(PTAU), { recursive: true });
    const url = `https://circom.info/${NAME}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`download of ${url} failed: HTTP ${res.status}`);
    await pipeline(Readable.fromWeb(res.body), createWriteStream(`${PTAU}.part`));
    renameSync(`${PTAU}.part`, PTAU);
  }
  const hash = createHash("blake2b512");
  for await (const chunk of createReadStream(PTAU)) hash.update(chunk);
  if (hash.digest("hex") !== PTAU_BLAKE2B) {
    throw new Error(`${PTAU} does not match the published blake2b hash; delete it and retry`);
  }
  console.log(`${PTAU}: blake2b ok`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
