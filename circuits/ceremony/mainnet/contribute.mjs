import * as snarkjs from "snarkjs";
import { randomBytes, createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { argv, env, exit } from "node:process";

// Phase-2 Groth16 contribution for the Cyphras mainnet withdraw proving key. Each participant
// runs this on their own machine:
//   node contribute.mjs <input.zkey> <output.zkey> "Your Name <handle>"
//
// The intermediate zkey is public; only the random entropy generated here is secret (the
// "toxic waste"). The entropy is created in-process with the OS CSPRNG, never written to disk,
// never passed on the command line, and zeroed before exit, so its destruction is guaranteed by
// the process ending. The ceremony stays secure as long as a single participant's entropy is
// secret and discarded, which this script enforces by construction.

const logger = {
  info: (m) => console.log(m),
  debug: () => {},
  warn: (m) => console.warn(m),
  error: (m) => console.error(m),
};

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function fail(msg) {
  console.error(`\nERROR: ${msg}\n`);
  exit(1);
}

const [, , input, output, name] = argv;
if (!input || !output || !name) {
  console.error('usage: node contribute.mjs <input.zkey> <output.zkey> "Your Name <handle>"');
  exit(1);
}
if (!existsSync(input)) fail(`input zkey not found: ${input}`);
if (existsSync(output)) fail(`output already exists, refusing to overwrite: ${output}`);

console.log("Cyphras mainnet Phase-2 contribution\n");
console.log(`  contributor : ${name}`);
console.log(`  input       : ${input}`);
console.log(`  output      : ${output}\n`);

const inputSha = sha256(input);
console.log(`Received zkey sha256:\n  ${inputSha}\n`);

const expected = env.EXPECTED_INPUT_SHA256;
if (expected) {
  if (expected.trim().toLowerCase() !== inputSha.toLowerCase()) {
    fail(
      "received zkey sha256 does not match EXPECTED_INPUT_SHA256.\n" +
        `  expected: ${expected.trim()}\n  got:      ${inputSha}\n` +
        "Do NOT contribute. Re-download from the coordinator and check again.",
    );
  }
  console.log("Input sha256 matches the coordinator-published value. OK.\n");
} else {
  console.log(
    "No EXPECTED_INPUT_SHA256 set. Confirm the sha256 above matches what the coordinator\n" +
      "published for your slot before trusting this input.\n",
  );
}

// Optional independent verification of the received zkey against the circuit and the Hermez
// powers of tau. Recommended for the contributor outside the founder's circle. The coordinator
// and the final public transcript verify the whole chain regardless.
const r1cs = env.R1CS;
const ptau = env.PTAU;
if (r1cs && ptau) {
  if (!existsSync(r1cs)) fail(`R1CS not found: ${r1cs}`);
  if (!existsSync(ptau)) fail(`PTAU not found: ${ptau}`);
  console.log("Verifying the received zkey against r1cs + ptau (this can take a minute)...");
  const ok = await snarkjs.zKey.verifyFromR1cs(r1cs, ptau, input, logger);
  if (!ok) fail("received zkey verification FAILED. Do NOT contribute.");
  console.log("\nReceived zkey verifies against the circuit and powers of tau. OK.\n");
} else {
  console.log(
    "Skipping full r1cs+ptau verification (set R1CS and PTAU to enable it).\n",
  );
}

const entropy = randomBytes(64);
let contributionHash;
try {
  contributionHash = await snarkjs.zKey.contribute(input, output, name, entropy, logger);
} finally {
  entropy.fill(0);
}

const outputSha = sha256(output);
const hashHex = contributionHash
  ? Buffer.from(contributionHash).toString("hex")
  : "(re-derive with verify.mjs - see README)";

console.log("\n========================================");
console.log("Contribution complete.\n");
console.log("Publish this attestation (sign it) so anyone can match it in the transcript:\n");
console.log(`  contributor        : ${name}`);
console.log(`  contribution hash  : ${hashHex}`);
console.log(`  output zkey sha256 : ${outputSha}`);
console.log("========================================\n");

console.log("Next steps:");
console.log(`  1. Send ${output} back to the coordinator.`);
console.log("  2. Post the attestation above, signed, where the ceremony records it (issue #9).");
console.log(`  3. Delete your local copies of ${input} and ${output} once the coordinator confirms.`);
console.log("     The secret entropy was generated in memory only and is already gone.\n");

// snarkjs leaves worker threads alive, so the process will not exit on its own.
exit(0);
