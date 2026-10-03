import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
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
  digest,
  expectHash,
  mem,
  newContribution,
  parseHex,
  parseTime,
  quiet,
  readZkey,
  refuseExisting,
  run,
  sameContributor,
  show,
  step,
  writeNew,
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
  node coordinator.mjs receive <zkey> "<name>" <contribution hash> [--resolve "<name>"]
      Run it only after checking that the signed attestation was posted from the
      contributor's own account and states this name and contribution hash. It accepts the
      zkey only if it extends the last accepted one by exactly one contribution with this
      name and hash and snarkjs zkey verify passes, and files it as the next
      transaction_NNNN.zkey. A contributor already in the chain is refused. A hash already in
      the chain under another name is refused, naming both claimants: check both signed
      attestations in the thread, then run receive again with --resolve and the rightful
      name. If that is the new claimant, its file replaces the last accepted zkey, which is
      kept as <file>.superseded. Every call is logged in the record.
  node coordinator.mjs round <time>
      Print the first drand quicknet round produced at or after <time> (ISO 8601 with a zone,
      such as 2026-10-20T12:00:00Z) and the text to announce, at least 24 hours before the
      round is produced.
  node coordinator.mjs announce <round> <link> <time>
      Record that <round> was announced in the public post at <link>, published at <time>.
      The round must be produced after that time and after the last accepted contribution.
  node coordinator.mjs beacon <round>
      Fetch the last announced round from the drand relays, check it against the quicknet
      public key and that it was produced after the last accepted contribution, apply it with
      numIterationsExp ${BEACON_ITERATIONS_EXP}, verify ${FINAL}, then export and check ${VK}.
  node coordinator.mjs status
      Recompute and print every recorded hash, and the next step.

Options:
  --dir <dir>    the ceremony directory (default: circuits/build/ceremony-v2)
  --r1cs <file>  init only (default: circuits/build/transaction.r1cs)
  --ptau <file>  init only (default: circuits/build/ptau/${PTAU_NAME})`;

const ARITY = { init: 0, receive: 3, round: 1, announce: 3, beacon: 1, status: 0 };

run(USAGE, async (argv) => {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      dir: { type: "string" },
      r1cs: { type: "string" },
      ptau: { type: "string" },
      resolve: { type: "string" },
    },
  });
  const [command, ...args] = positionals;
  if (!Object.hasOwn(ARITY, command) || args.length !== ARITY[command]) {
    throw new Error("unknown command or wrong arguments; run with --help");
  }
  if (command !== "init" && (values.r1cs || values.ptau)) {
    throw new Error("only init takes --r1cs and --ptau");
  }
  if (command !== "receive" && values.resolve !== undefined) {
    throw new Error("only receive takes --resolve");
  }
  const dir = resolve(values.dir ?? join(CIRCUITS, "build", "ceremony-v2"));
  if (command === "init") {
    await init(
      dir,
      resolve(values.r1cs ?? join(CIRCUITS, "build", "transaction.r1cs")),
      resolve(values.ptau ?? join(CIRCUITS, "build", "ptau", PTAU_NAME)),
    );
  } else if (command === "receive") {
    await receive(dir, ...args, values.resolve);
  } else if (command === "round") {
    roundAt(args[0]);
  } else if (command === "announce") {
    announce(dir, ...args);
  } else if (command === "beacon") {
    await beacon(dir, args[0]);
  } else {
    report(dir, load(dir));
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

// The recorded inputs are read and re-hashed before every step, so nothing an earlier step
// verified can change unseen.
function inputs(dir, state, last = state.zkeys.at(-1)) {
  const read = (path, sha256) => {
    const data = readFileSync(path);
    expectHash(data, "sha256", sha256, `${path} changed since it was recorded`);
    return data;
  };
  return {
    r1cs: read(state.r1cs.path, state.r1cs.sha256),
    ptau: read(state.ptau.path, state.ptau.sha256),
    last: read(join(dir, last.file), last.sha256),
    lastFile: last.file,
  };
}

async function zkeyVerify(r1cs, ptau, zkey, label) {
  await step(`Verifying ${label} against the r1cs and the ptau (snarkjs zkey verify)`, async () => {
    if (!(await snarkjs.zKey.verifyFromR1cs(mem(r1cs), mem(ptau), mem(zkey), quiet))) {
      throw new Error(`snarkjs zkey verify rejects ${label}`);
    }
    console.log("  ZKey Ok!");
  });
}

async function init(dir, r1csPath, ptauPath) {
  if (existsSync(join(dir, STATE))) throw new Error(`${dir} already holds a ceremony`);
  mkdirSync(dir, { recursive: true });
  const r1cs = readFileSync(r1csPath);
  const ptau = readFileSync(ptauPath);
  const state = {
    r1cs: {
      path: r1csPath,
      sha256: expectHash(r1cs, "sha256", R1CS_SHA256, `${r1csPath} is not the frozen v2 r1cs`),
    },
    ptau: {
      path: ptauPath,
      blake2b: expectHash(ptau, "blake2b512", PTAU_BLAKE2B, `${ptauPath} is not the ${PTAU_NAME}`),
      sha256: digest(ptau),
    },
  };
  console.log(`r1cs sha256 matches the frozen circuit; ptau blake2b matches the published value.`);
  await step("Verifying the ptau (snarkjs powersoftau verify, about 20 minutes)", async () => {
    if (!(await snarkjs.powersOfTau.verify(mem(ptau), quiet))) {
      throw new Error("snarkjs powersoftau verify rejects the ptau");
    }
    console.log("  Powers of Tau Ok!");
  });

  const file = zkeyFile(0);
  const out = { type: "mem" };
  const csHash = await step(`Creating ${file} (snarkjs groth16 setup)`, () =>
    snarkjs.zKey.newZKey(mem(r1cs), mem(ptau), out, quiet),
  );
  if (!(csHash instanceof Uint8Array)) throw new Error("snarkjs groth16 setup failed");
  const zkey = Buffer.from(out.data);
  await zkeyVerify(r1cs, ptau, zkey, file);
  writeNew(join(dir, file), zkey);
  state.circuitHash = Buffer.from(csHash).toString("hex");
  state.zkeys = [{ file, sha256: digest(zkey), at: new Date().toISOString() }];
  state.attestations = [];
  state.superseded = [];
  state.announcements = [];
  save(dir, state);
  report(dir, state);
}

// A name is not covered by the contribution hash, so anyone holding a contributor's file can
// rename the contribution and claim it. Only files that fully verify enter the chain, and a hash
// in the chain that a second name claims waits for the coordinator to decide, from the two signed
// attestations in the thread, whose it is. Returns the chain position the file would fill.
function slotFor(state, name, hash, rightful) {
  const next = state.zkeys.length;
  const held = state.zkeys.findIndex((z) => z.contributionHash === hash);
  const holder = state.zkeys[held]?.contributor;
  let slot = next;
  if (held === -1) {
    if (rightful !== undefined) throw new Error(`no one else claims contribution hash ${hash}`);
  } else if (holder === name) {
    throw new Error(`contribution hash ${hash} is already in the chain as #${held}`);
  } else if (rightful === undefined) {
    throw new Error(
      `contribution hash ${hash} is #${held} in the chain, filed for ${show(holder)}, and ` +
        `${show(name)} claims it too; check both signed attestations in the thread, then run ` +
        "receive again with --resolve and the rightful name",
    );
  } else if (rightful === holder) {
    throw new Error(`resolved for ${show(holder)}, who keeps #${held}; ${show(name)} is refused`);
  } else if (rightful !== name) {
    throw new Error(`--resolve must name ${show(holder)} or ${show(name)}`);
  } else if (held !== next - 1) {
    throw new Error(
      `#${held} already has contributions built on it; the chain must restart from ` +
        `${state.zkeys[held - 1].file}`,
    );
  } else {
    slot = held;
  }
  state.zkeys.forEach((z, i) => {
    if (i > 0 && i !== slot && sameContributor(z.contributor, name)) {
      throw new Error(`${show(name)} is the contributor of #${i}, ${show(z.contributor)}`);
    }
  });
  return slot;
}

async function receive(dir, incoming, name, attested, rightful) {
  checkName(name);
  const claimed = parseHex(attested, 64, "the attested contribution hash");
  const state = load(dir);
  if (state.final) throw new Error("the ceremony is finalized");
  const entry = { at: new Date().toISOString(), name, hash: claimed, file: basename(incoming) };
  try {
    const slot = slotFor(state, name, claimed, rightful);
    const { r1cs, ptau, last, lastFile } = inputs(dir, state, state.zkeys[slot - 1]);
    const data = readFileSync(incoming);
    const c = newContribution(readZkey(last, lastFile), readZkey(data, incoming));
    if (c.type !== 0) throw new Error("the new contribution is a beacon");
    if (c.name !== name) {
      throw new Error(`the contribution is named ${show(c.name)}, not ${show(name)}`);
    }
    if (c.hash !== claimed) {
      throw new Error(`the contribution hash is ${c.hash}, not the attested ${claimed}`);
    }
    console.log(`${basename(incoming)} extends ${lastFile} by one contribution,`);
    console.log(`named ${show(name)}, with the attested hash ${c.hash}.`);
    await zkeyVerify(r1cs, ptau, data, basename(incoming));
    const file = zkeyFile(slot);
    const now = new Date().toISOString();
    entry.result = `accepted as #${slot}`;
    if (slot < state.zkeys.length) {
      const old = state.zkeys[slot];
      const kept = `${file}.superseded`;
      refuseExisting(join(dir, kept));
      renameSync(join(dir, file), join(dir, kept));
      try {
        writeNew(join(dir, file), data);
      } catch (e) {
        renameSync(join(dir, kept), join(dir, file));
        throw e;
      }
      state.superseded.push({ ...old, file: kept, supersededAt: now, supersededBy: name });
      entry.result += `, superseding ${show(old.contributor)}`;
    } else {
      writeNew(join(dir, file), data);
    }
    const sha256 = digest(data);
    state.zkeys[slot] = { file, contributor: name, contributionHash: c.hash, sha256, at: now };
  } catch (e) {
    entry.result = `refused: ${e.message}`;
    throw e;
  } finally {
    state.attestations.push(entry);
    save(dir, state);
  }
  report(dir, state);
}

function roundAt(time) {
  const round = firstRoundAt(parseTime(time, "the time"));
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
  contribution with snarkjs zkey beacon and numIterationsExp ${BEACON_ITERATIONS_EXP}.

Once it is posted: node coordinator.mjs announce ${round} <link to the post> <time of the post>`);
}

// A beacon is unpredictable to every contributor only if drand produced it after the last
// contribution was accepted.
function producedAfterLast(state, round) {
  const produced = roundTime(round);
  const last = state.zkeys.at(-1);
  if (produced <= new Date(last.at)) {
    throw new Error(
      `drand round ${round} was produced at ${produced.toISOString()}, before ` +
        `${last.file} was accepted at ${last.at}; announce a later round`,
    );
  }
  return produced;
}

function announce(dir, roundArg, link, time) {
  const round = parseRound(roundArg);
  if (!/^https:\/\/\S+$/.test(link)) throw new Error("the link must be an https:// address");
  const at = parseTime(time, "the time of the announcement");
  const state = load(dir);
  if (state.final) throw new Error("the ceremony is finalized");
  const produced = producedAfterLast(state, round);
  if (produced <= at) {
    throw new Error(
      `drand round ${round} was produced at ${produced.toISOString()}, before the ` +
        `announcement at ${at.toISOString()}`,
    );
  }
  if (produced - at < 24 * 3_600_000) {
    console.log("WARNING: the plan announces the round at least 24 hours before it is produced.");
  }
  state.announcements.push({ round, produced: produced.toISOString(), link, at: at.toISOString() });
  save(dir, state);
  report(dir, state);
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
  const announced = state.announcements.at(-1);
  if (announced?.round !== round) {
    throw new Error(
      announced
        ? `the last announced round is ${announced.round}, not ${round}`
        : "no round is announced yet; record the announcement with the announce command",
    );
  }
  producedAfterLast(state, round);
  const { r1cs, ptau, last, lastFile } = inputs(dir, state);
  const drand = await step(`Fetching drand quicknet round ${round}`, () => fetchRound(round));
  console.log(`  produced at ${drand.time}, agreed by ${drand.relays.join(", ")}`);
  console.log(`  signature verified under the quicknet key; randomness ${drand.randomness}`);

  const out = { type: "mem" };
  const hash = await step(`Applying the beacon to ${lastFile} (snarkjs zkey beacon)`, () =>
    snarkjs.zKey.beacon(
      mem(last),
      out,
      `drand quicknet round ${round}`,
      drand.randomness,
      BEACON_ITERATIONS_EXP,
      quiet,
    ),
  );
  if (!(hash instanceof Uint8Array)) throw new Error("snarkjs zkey beacon failed");
  const final = Buffer.from(out.data);
  const c = newContribution(readZkey(last, lastFile), readZkey(final, FINAL));
  if (
    c.type !== 1 ||
    c.beaconHash !== drand.randomness ||
    c.iterationsExp !== BEACON_ITERATIONS_EXP ||
    c.hash !== Buffer.from(hash).toString("hex")
  ) {
    throw new Error("the new zkey does not hold the beacon contribution just made");
  }
  await zkeyVerify(r1cs, ptau, final, FINAL);
  const vk = await exportVerificationKey(final);
  checkVerificationKey(vk);
  console.log(`${VK} passes the vault build's key checks.`);
  writeNew(join(dir, FINAL), final);
  writeNew(join(dir, VK), vk);
  state.beacon = {
    ...drand,
    chain: QUICKNET.hash,
    iterationsExp: BEACON_ITERATIONS_EXP,
    contributionHash: c.hash,
  };
  state.final = { file: FINAL, sha256: digest(final) };
  state.verificationKey = { file: VK, sha256: digest(vk) };
  save(dir, state);
  report(dir, state);
}

// The record to copy into the transcript. Every file hash is recomputed, not read back.
function report(dir, state) {
  const files = [...state.zkeys, ...state.superseded, state.final, state.verificationKey];
  const paths = [
    ...files.filter(Boolean).map((f) => [join(dir, f.file), f.sha256]),
    [state.r1cs.path, state.r1cs.sha256],
    [state.ptau.path, state.ptau.sha256],
  ];
  for (const [path, sha256] of paths) {
    expectHash(readFileSync(path), "sha256", sha256, `${path} changed since it was recorded`);
  }

  const out = [`\nCeremony record (${dir}), every hash recomputed:\n`];
  out.push(`r1cs ${state.r1cs.path}`, `  sha256 ${state.r1cs.sha256}`);
  out.push(`ptau ${state.ptau.path}`, `  sha256 ${state.ptau.sha256}`);
  out.push(`  blake2b ${state.ptau.blake2b}`);
  out.push(`circuit hash (blake2b-512) ${state.circuitHash}`, "");
  state.zkeys.forEach((z, i) => {
    out.push(i === 0 ? `#0 ${z.file}, groth16 setup` : `#${i} ${z.file}, ${show(z.contributor)}`);
    if (i > 0) out.push(`  contribution hash ${z.contributionHash}`);
    out.push(`  sha256 ${z.sha256}`, `  ${i === 0 ? "created" : "accepted"} at ${z.at}`);
  });
  if (state.superseded.length > 0) out.push("", "Superseded by --resolve:");
  for (const z of state.superseded) {
    out.push(`  ${z.file}, ${show(z.contributor)}, accepted at ${z.at}`);
    out.push(`    contribution hash ${z.contributionHash}`, `    sha256 ${z.sha256}`);
    out.push(`    superseded at ${z.supersededAt} by ${show(z.supersededBy)}`);
  }
  if (state.attestations.length > 0) out.push("", "Attestations given to receive:");
  for (const a of state.attestations) {
    out.push(`  ${a.at} ${show(a.name)}, ${a.file}`, `    hash ${a.hash}`, `    ${a.result}`);
  }
  if (state.announcements.length > 0) out.push("", "Beacon announcements:");
  for (const a of state.announcements) {
    out.push(
      `  round ${a.round}, produced at ${a.produced}`,
      `    announced at ${a.at}, ${a.link}`,
    );
  }
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
    console.log("Or finish: node coordinator.mjs round <time>, post the announcement, record it");
    console.log("with node coordinator.mjs announce, and once the round is produced, run");
    console.log("node coordinator.mjs beacon <round>.");
  }
}
