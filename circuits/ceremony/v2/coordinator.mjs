import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import * as snarkjs from "snarkjs";
import {
  BEACON_ITERATIONS_EXP,
  MIN_CONTRIBUTIONS,
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
import { QUICKNET, fetchRound, firstRoundAt, parseRound, roundTime } from "./drand.mjs";
import { checkVerificationKey, exportVerificationKey } from "./vk.mjs";

const CIRCUITS = resolve(import.meta.dirname, "..", "..");
const STATE = "ceremony-state.json";
const FINAL = "transaction_final.zkey";
const VK = "verification_key.json";
const zkeyFile = (n) => `transaction_${String(n).padStart(4, "0")}.zkey`;

const USAGE = `Coordinator of the Cyphras v2 phase-2 trusted-setup ceremony. Each command
verifies before it records anything; the record (paths and hashes, no secrets) is
<dir>/${STATE}.

Usage:
  node coordinator.mjs init [--r1cs <file>] [--ptau <file>]
      Check the frozen r1cs and the Hermez ptau, run snarkjs powersoftau verify (about 20
      minutes), create transaction_0000.zkey with snarkjs groth16 setup and verify it.
  node coordinator.mjs receive <zkey> "<name>" <contribution hash>
      Accept a returned zkey only if it extends the last accepted one by exactly one
      contribution named <name>, whose hash is the one in the contributor's attestation, and
      snarkjs zkey verify passes. It is filed as the next transaction_NNNN.zkey.
  node coordinator.mjs round <time>
      Print the first drand quicknet round produced at or after <time> (ISO 8601 with a zone,
      such as 2026-10-20T12:00:00Z), to announce at least 24 hours before it is produced.
  node coordinator.mjs beacon <round>
      Fetch the announced round from the drand relays, check it against the quicknet public
      key, apply it to the last contribution with numIterationsExp ${BEACON_ITERATIONS_EXP},
      verify ${FINAL}, then export and check ${VK}.
  node coordinator.mjs status
      Recompute and print every recorded hash, and the next step.

Options:
  --dir <dir>    the ceremony directory (default: circuits/build/ceremony-v2)
  --r1cs <file>  init only (default: circuits/build/transaction.r1cs)
  --ptau <file>  init only (default: circuits/build/ptau/${PTAU_NAME})`;

const ARITY = { init: 0, receive: 3, round: 1, beacon: 1, status: 0 };

run(USAGE, async (argv) => {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: { dir: { type: "string" }, r1cs: { type: "string" }, ptau: { type: "string" } },
  });
  const [command, ...args] = positionals;
  if (!Object.hasOwn(ARITY, command) || args.length !== ARITY[command]) {
    throw new Error("unknown command or wrong arguments; run with --help");
  }
  if (command !== "init" && (values.r1cs || values.ptau)) {
    throw new Error("only init takes --r1cs and --ptau");
  }
  const dir = resolve(values.dir ?? join(CIRCUITS, "build", "ceremony-v2"));
  if (command === "init") {
    await init(
      dir,
      resolve(values.r1cs ?? join(CIRCUITS, "build", "transaction.r1cs")),
      resolve(values.ptau ?? join(CIRCUITS, "build", "ptau", PTAU_NAME)),
    );
  } else if (command === "receive") {
    await receive(dir, ...args);
  } else if (command === "round") {
    announce(args[0]);
  } else if (command === "beacon") {
    await beacon(dir, args[0]);
  } else {
    await report(dir, load(dir));
  }
});

function load(dir) {
  const path = join(dir, STATE);
  if (!existsSync(path)) throw new Error(`no ceremony recorded in ${dir}; run init first`);
  return JSON.parse(readFileSync(path, "utf8"));
}

function save(dir, state) {
  const path = join(dir, STATE);
  writeFileSync(`${path}.part`, `${JSON.stringify(state, null, 2)}\n`);
  renameSync(`${path}.part`, path);
}

// Inputs are re-hashed before every step, so nothing an earlier step verified can change unseen.
async function inputs(dir, state) {
  await expectHash(state.r1cs.path, "sha256", state.r1cs.sha256, "recorded r1cs");
  await expectHash(state.ptau.path, "sha256", state.ptau.sha256, "recorded ptau");
  const last = state.zkeys.at(-1);
  await expectHash(join(dir, last.file), "sha256", last.sha256, `recorded ${last.file}`);
  return { r1cs: state.r1cs.path, ptau: state.ptau.path, last: join(dir, last.file) };
}

async function zkeyVerify(r1cs, ptau, zkey) {
  await step(
    `Verifying ${basename(zkey)} against the r1cs and the ptau (snarkjs zkey verify)`,
    async () => {
      if (!(await snarkjs.zKey.verifyFromR1cs(r1cs, ptau, zkey, quiet))) {
        throw new Error(`snarkjs zkey verify rejects ${zkey}`);
      }
      console.log("  ZKey Ok!");
    },
  );
}

async function init(dir, r1cs, ptau) {
  if (existsSync(join(dir, STATE))) throw new Error(`${dir} already holds a ceremony`);
  mkdirSync(dir, { recursive: true });
  const state = {
    r1cs: { path: r1cs, sha256: await expectHash(r1cs, "sha256", R1CS_SHA256, "frozen v2 r1cs") },
    ptau: {
      path: ptau,
      blake2b: await expectHash(ptau, "blake2b512", PTAU_BLAKE2B, PTAU_NAME),
      sha256: await hashFile(ptau),
    },
  };
  console.log(`r1cs sha256 matches the frozen circuit; ptau blake2b matches the published value.`);
  await step("Verifying the ptau (snarkjs powersoftau verify, about 20 minutes)", async () => {
    if (!(await snarkjs.powersOfTau.verify(ptau, quiet))) {
      throw new Error("snarkjs powersoftau verify rejects the ptau");
    }
    console.log("  Powers of Tau Ok!");
  });

  const file = zkeyFile(0);
  const part = join(dir, `${file}.part`);
  try {
    const csHash = await step(`Creating ${file} (snarkjs groth16 setup)`, () =>
      snarkjs.zKey.newZKey(r1cs, ptau, part, quiet),
    );
    if (!(csHash instanceof Uint8Array)) throw new Error("snarkjs groth16 setup failed");
    await zkeyVerify(r1cs, ptau, part);
    renameSync(part, join(dir, file));
    state.circuitHash = Buffer.from(csHash).toString("hex");
  } finally {
    rmSync(part, { force: true });
  }
  state.zkeys = [{ file, sha256: await hashFile(join(dir, file)) }];
  save(dir, state);
  await report(dir, state);
}

async function receive(dir, incoming, name, attested) {
  checkName(name);
  const claimed = parseHex(attested, 64, "the attested contribution hash");
  const state = load(dir);
  if (state.final) throw new Error("the ceremony is finalized");
  const { r1cs, ptau, last } = await inputs(dir, state);
  const file = zkeyFile(state.zkeys.length);
  const dest = join(dir, file);
  const part = `${dest}.part`;
  try {
    // Everything is checked on a private copy, so the file filed is the file verified.
    copyFileSync(incoming, part);
    const c = newContribution(readZkey(last), readZkey(part));
    if (c.type !== 0) throw new Error("the new contribution is a beacon");
    if (c.name !== name) {
      throw new Error(`the contribution is named ${show(c.name)}, not ${show(name)}`);
    }
    if (c.hash !== claimed) {
      throw new Error(`the contribution hash is ${c.hash}, not the attested ${claimed}`);
    }
    console.log(`${basename(incoming)} extends ${basename(last)} by one contribution,`);
    console.log(`named ${show(name)}, with the attested hash ${c.hash}.`);
    await zkeyVerify(r1cs, ptau, part);
    renameSync(part, dest);
    state.zkeys.push({
      file,
      contributor: name,
      contributionHash: c.hash,
      sha256: await hashFile(dest),
    });
  } finally {
    rmSync(part, { force: true });
  }
  save(dir, state);
  await report(dir, state);
}

function announce(time) {
  const date = new Date(time);
  if (!/(Z|[+-]\d\d:\d\d)$/.test(time) || Number.isNaN(date.getTime())) {
    throw new Error(`give the time in ISO 8601 with a zone, such as 2026-10-20T12:00:00Z`);
  }
  const round = firstRoundAt(date);
  const at = roundTime(round);
  const hours = (at.getTime() - Date.now()) / 3_600_000;
  console.log(`drand quicknet round ${round} is produced at ${at.toISOString()},`);
  console.log(
    hours < 0 ? `${(-hours).toFixed(1)} hours ago.` : `${hours.toFixed(1)} hours from now.`,
  );
  if (hours < 24) {
    console.log("WARNING: the plan announces the round at least 24 hours before it is produced.");
  }
  console.log(`
Announcement:
  The beacon of the Cyphras v2 ceremony is drand quicknet (chain ${QUICKNET.hash})
  round ${round}, produced at ${at.toISOString()}. It is applied to the last verified
  contribution with snarkjs zkey beacon and numIterationsExp ${BEACON_ITERATIONS_EXP}.`);
}

async function beacon(dir, roundArg) {
  const round = parseRound(roundArg);
  const state = load(dir);
  if (state.final) throw new Error("the ceremony is already finalized");
  const contributions = state.zkeys.length - 1;
  if (contributions < MIN_CONTRIBUTIONS) {
    throw new Error(
      `the beacon needs ${MIN_CONTRIBUTIONS} contributions first, there are ${contributions}`,
    );
  }
  const { r1cs, ptau, last } = await inputs(dir, state);
  const drand = await step(`Fetching drand quicknet round ${round}`, () => fetchRound(round));
  console.log(`  produced at ${drand.time}, agreed by ${drand.relays.join(", ")}`);
  console.log(`  signature verified under the quicknet key; randomness ${drand.randomness}`);

  const finalPath = join(dir, FINAL);
  const part = `${finalPath}.part`;
  try {
    const hash = await step(`Applying the beacon to ${basename(last)} (snarkjs zkey beacon)`, () =>
      snarkjs.zKey.beacon(
        last,
        part,
        `drand quicknet round ${round}`,
        drand.randomness,
        BEACON_ITERATIONS_EXP,
        quiet,
      ),
    );
    if (!(hash instanceof Uint8Array)) throw new Error("snarkjs zkey beacon failed");
    const c = newContribution(readZkey(last), readZkey(part));
    if (
      c.type !== 1 ||
      c.beaconHash !== drand.randomness ||
      c.iterationsExp !== BEACON_ITERATIONS_EXP ||
      c.hash !== Buffer.from(hash).toString("hex")
    ) {
      throw new Error("the written beacon contribution does not match the one just made");
    }
    await zkeyVerify(r1cs, ptau, part);
    const vk = await exportVerificationKey(part);
    checkVerificationKey(vk);
    console.log(`${VK} passes the vault build's key checks.`);
    renameSync(part, finalPath);
    writeFileSync(join(dir, VK), vk);
    state.beacon = {
      ...drand,
      chain: QUICKNET.hash,
      iterationsExp: BEACON_ITERATIONS_EXP,
      contributionHash: c.hash,
    };
    state.final = { file: FINAL, sha256: await hashFile(finalPath) };
    state.verificationKey = { file: VK, sha256: createHash("sha256").update(vk).digest("hex") };
  } finally {
    rmSync(part, { force: true });
  }
  save(dir, state);
  await report(dir, state);
}

// The record to copy into the transcript. Every file hash is recomputed, not read back.
async function report(dir, state) {
  const files = [...state.zkeys, state.final, state.verificationKey].filter(Boolean);
  for (const f of files) {
    await expectHash(join(dir, f.file), "sha256", f.sha256, `recorded ${f.file}`);
  }
  await expectHash(state.r1cs.path, "sha256", state.r1cs.sha256, "recorded r1cs");
  await expectHash(state.ptau.path, "sha256", state.ptau.sha256, "recorded ptau");

  const out = [`\nCeremony record (${dir}), every hash recomputed:\n`];
  out.push(`r1cs ${state.r1cs.path}`, `  sha256 ${state.r1cs.sha256}`);
  out.push(`ptau ${state.ptau.path}`, `  sha256 ${state.ptau.sha256}`);
  out.push(`  blake2b ${state.ptau.blake2b}`);
  out.push(`circuit hash (blake2b-512) ${state.circuitHash}`, "");
  state.zkeys.forEach((z, i) => {
    out.push(i === 0 ? `#0 ${z.file}, groth16 setup` : `#${i} ${z.file}, ${show(z.contributor)}`);
    if (i > 0) out.push(`  contribution hash ${z.contributionHash}`);
    out.push(`  sha256 ${z.sha256}`);
  });
  const b = state.beacon;
  if (b) {
    out.push("", `beacon: drand quicknet round ${b.round}, produced at ${b.time}`);
    out.push(`  chain ${b.chain}`, `  randomness ${b.randomness}`, `  signature ${b.signature}`);
    out.push(`  relays ${b.relays.join(", ")}`, `  numIterationsExp ${b.iterationsExp}`);
    out.push(`  contribution hash ${b.contributionHash}`);
    out.push(`final ${state.final.file}`, `  sha256 ${state.final.sha256}`);
    out.push(`${state.verificationKey.file}`, `  sha256 ${state.verificationKey.sha256}`);
  }
  console.log(out.join("\n"));

  const last = state.zkeys.at(-1);
  const n = state.zkeys.length;
  if (state.final) {
    console.log("\nFINALIZED. Publish the files and this record; verify.mjs checks them all.");
    return;
  }
  console.log(`\nNEXT: send ${last.file} with its sha256 ${last.sha256}`);
  console.log(`to contributor ${n}, then: node coordinator.mjs receive <zkey> "<name>" <hash>`);
  if (n - 1 >= MIN_CONTRIBUTIONS) {
    console.log(
      "Or, once the announced drand round is produced: node coordinator.mjs beacon <round>",
    );
  }
}
