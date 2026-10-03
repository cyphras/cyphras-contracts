import { createHash, randomBytes } from "node:crypto";
import { existsSync, renameSync, rmSync } from "node:fs";
import { parseArgs } from "node:util";
import * as snarkjs from "snarkjs";
import {
  PTAU_BLAKE2B,
  PTAU_NAME,
  R1CS_SHA256,
  checkName,
  expectHash,
  hashFile,
  newContribution,
  parseHex,
  quiet,
  readZkey,
  run,
  show,
  step,
} from "./common.mjs";

const USAGE = `Adds your contribution to the Cyphras v2 phase-2 trusted-setup ceremony.

Usage:
  node contribute.mjs <input.zkey> <output.zkey> "<Name (github: handle)>" --expect <sha256>
      [--r1cs transaction.r1cs --ptau ${PTAU_NAME}] [--extra-entropy]

  --expect <sha256>  the SHA-256 the coordinator announced for <input.zkey>; nothing is
                     contributed unless the file matches it
  --r1cs, --ptau     first verify the whole chain in <input.zkey> against the frozen circuit and
                     the Hermez powers of tau (recommended, takes about a minute)
  --extra-entropy    also mix in text you type, which is not shown, or whatever is piped to
                     stdin, on top of 64 bytes from the operating system's random generator

The secret randomness exists only in the memory of this process. It is never printed, passed on a
command line or written to disk, and it is gone once the process exits. The name is stored in the
zkey and published forever: use a public handle, never an email address.`;

run(USAGE, async (argv) => {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      expect: { type: "string" },
      r1cs: { type: "string" },
      ptau: { type: "string" },
      "extra-entropy": { type: "boolean" },
    },
  });
  if (positionals.length !== 3) {
    throw new Error("expected <input.zkey> <output.zkey> <name>; run with --help");
  }
  const [input, output, name] = positionals;
  checkName(name);
  if (values.expect === undefined) {
    throw new Error("--expect is required: the SHA-256 the coordinator announced for the input");
  }
  const expected = parseHex(values.expect, 32, "--expect");
  if (!values.r1cs !== !values.ptau) throw new Error("give both --r1cs and --ptau, or neither");
  if (existsSync(output)) throw new Error(`${output} already exists; refusing to overwrite it`);

  console.log(`Contributor: ${name}\nInput:       ${input}\nOutput:      ${output}\n`);
  const inputSha256 = await hashFile(input);
  if (inputSha256 !== expected) {
    throw new Error(
      `${input} has sha256 ${inputSha256}, not the announced ${expected}. ` +
        "Do not contribute: download the file again and check with the coordinator.",
    );
  }
  console.log(`Input sha256 ${inputSha256} matches the announced value.`);

  if (values.r1cs) {
    await expectHash(values.r1cs, "sha256", R1CS_SHA256, "frozen v2 r1cs");
    await expectHash(values.ptau, "blake2b512", PTAU_BLAKE2B, PTAU_NAME);
    await step(
      "Verifying the input against the r1cs and the ptau (snarkjs zkey verify)",
      async () => {
        if (!(await snarkjs.zKey.verifyFromR1cs(values.r1cs, values.ptau, input, quiet))) {
          throw new Error(`snarkjs zkey verify rejects ${input}. Do not contribute.`);
        }
      },
    );
  } else {
    console.log("Skipping the chain check; pass --r1cs and --ptau to verify the input first.");
  }

  const before = readZkey(input);
  if (before.contributions.some((c) => c.type !== 0)) {
    throw new Error(`${input} already holds the final beacon`);
  }
  console.log(`\nContributions so far (compare them with the published attestations):`);
  before.contributions.forEach((c, i) =>
    console.log(`  #${i + 1} ${show(c.name)}\n     ${c.hash}`),
  );
  if (before.contributions.length === 0) console.log("  none, you are the first");

  const extra = values["extra-entropy"] ? await readExtraEntropy() : Buffer.alloc(0);
  const part = `${output}.part`;
  let hash;
  try {
    console.log("");
    hash = await step("Contributing", () => contribute(input, part, name, extra));
    const c = newContribution(before, readZkey(part));
    if (c.type !== 0 || c.name !== name || c.hash !== hash) {
      throw new Error("the written contribution does not match the one just made");
    }
    renameSync(part, output);
  } finally {
    rmSync(part, { force: true });
  }
  const outputSha256 = await hashFile(output);

  console.log(`
Contribution complete. Publish this attestation from your own account, signed:

  I contributed to the Cyphras v2 trusted-setup ceremony.
  Name: ${name}
  Contribution hash (blake2b-512): ${hash}
  Input zkey sha256: ${inputSha256}
  Output zkey sha256: ${outputSha256}
  Machine: <the machine you used, and whether it was offline>
  Entropy: <how you destroyed it, for example: process exited, machine powered off>

Next:
  1. Send ${output} to the coordinator.
  2. Post the signed attestation in the public ceremony thread.
  3. Once the coordinator confirms receipt, delete ${input} and ${output} and power off this
     machine. The secret was never written to disk; powering off clears it from memory.
`);
});

async function contribute(input, part, name, extra) {
  const os = randomBytes(64);
  const entropy = createHash("blake2b512").update(os).update(extra).digest();
  os.fill(0);
  extra.fill(0);
  try {
    // snarkjs UTF-8 encodes the entropy it is given, so hex keeps every bit. It hashes it with 64
    // more bytes from the OS generator to seed the contribution's secret.
    const hash = await snarkjs.zKey.contribute(input, part, name, entropy.toString("hex"), quiet);
    return Buffer.from(hash).toString("hex");
  } finally {
    entropy.fill(0);
  }
}

// Typed text is never echoed and piped input is read whole; either one only adds to the OS
// entropy, so even a guessable text cannot weaken the contribution.
async function readExtraEntropy() {
  const { stdin, stderr } = process;
  if (!stdin.isTTY) {
    const chunks = [];
    for await (const chunk of stdin) chunks.push(chunk);
    const all = Buffer.concat(chunks);
    for (const chunk of chunks) chunk.fill(0);
    return all;
  }
  stderr.write("Type random text, then press Enter (nothing is shown): ");
  return new Promise((resolve, reject) => {
    const typed = [];
    const done = (error) => {
      stdin.off("data", onData);
      stdin.setRawMode(false);
      stdin.pause();
      stderr.write("\n");
      const out = Buffer.from(typed);
      typed.fill(0);
      if (error) {
        out.fill(0);
        reject(error);
      } else {
        resolve(out);
      }
    };
    const onData = (chunk) => {
      try {
        for (const byte of chunk) {
          if (byte === 3) return done(new Error("cancelled"));
          if (byte === 4 || byte === 10 || byte === 13) return done();
          if (byte === 8 || byte === 127) typed.pop();
          else typed.push(byte);
        }
      } finally {
        chunk.fill(0);
      }
    };
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}
