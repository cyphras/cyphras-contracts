import { bn254 } from "@noble/curves/bn254.js";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import * as snarkjs from "snarkjs";
import { BEACON_ITERATIONS_EXP, PTAU_NAME, mem, quiet, readZkey, run } from "./common.mjs";
import { fetchRound, firstRoundAt, roundTime, verifyRound } from "./drand.mjs";
import { checkVerificationKey } from "./vk.mjs";

const USAGE = `Runs the whole ceremony on this machine and checks that the kit refuses bad input.

Usage:
  node dry-run.mjs [--r1cs <file>] [--ptau <file>]

A coordinator initializes the ceremony, three contributors each install the kit with npm ci and
contribute from their own directory, the coordinator announces a drand quicknet round a few
seconds ahead and applies it as the beacon once drand has produced it, and a verifier checks the
result. Every negative check must then fail with its expected reason. Everything is written to a
temporary directory that is deleted at the end: one machine made all of it, so none of it may
ever be used.`;

const KIT = import.meta.dirname;
const CIRCUITS = resolve(KIT, "..", "..");
const FINAL = "transaction_final.zkey";
const VK = "verification_key.json";
const timings = [];
const refusals = [];

function exec(cwd, args, input) {
  const started = Date.now();
  const r = spawnSync(process.execPath, args, { cwd, input, encoding: "utf8" });
  const seconds = (Date.now() - started) / 1000;
  const shown = args.map((a) => (/^[\w./:=-]+$/.test(a) ? a : JSON.stringify(a))).join(" ");
  console.log(`\n$ node ${shown}\n  (in ${cwd}, ${seconds.toFixed(1)} s, exit ${r.status})`);
  const output = `${r.stdout}${r.stderr}`;
  console.log(output.trimEnd().replace(/^/gm, "  | "));
  return { status: r.status, output, seconds };
}

function pass(label, cwd, args, input) {
  const r = exec(cwd, args, input);
  if (r.status !== 0) throw new Error(`${label} failed`);
  timings.push([label, r.seconds]);
  return r.output;
}

// A negative check passes only if the step fails for the expected reason.
function refuse(label, cwd, args, reason) {
  const r = exec(cwd, args);
  const error = r.output.match(/ERROR: (.*)/)?.[1] ?? "";
  if (r.status === 0 || !error.includes(reason)) {
    throw new Error(`"${label}" must fail with "${reason}", got exit ${r.status}: ${error}`);
  }
  refusals.push([label, error]);
}

async function refuseCall(label, work, reason) {
  let error = "";
  try {
    await work();
  } catch (e) {
    error = e.message;
  }
  if (!error.includes(reason)) throw new Error(`"${label}" must fail with "${reason}": ${error}`);
  refusals.push([label, error]);
}

async function timed(label, work) {
  const started = Date.now();
  const out = await work();
  timings.push([label, (Date.now() - started) / 1000]);
  return out;
}

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const attested = (out) => out.match(/Contribution hash \(blake2b-512\): ([0-9a-f]{128})/)[1];
const flipLast = (hex) => `${hex.slice(0, -1)}${hex.endsWith("0") ? "1" : "0"}`;

// Each person gets their own copy of the kit, installed from the lockfile, and the public inputs.
function person(root, name, r1cs, ptau) {
  const dir = join(root, name);
  mkdirSync(dir);
  for (const f of readdirSync(KIT).filter((f) => /^(\.npmrc|[\w-]+\.(mjs|json))$/.test(f))) {
    copyFileSync(join(KIT, f), join(dir, f));
  }
  copyFileSync(r1cs, join(dir, "transaction.r1cs"));
  copyFileSync(ptau, join(dir, PTAU_NAME));
  const npm = spawnSync("npm", ["ci", "--no-audit", "--no-fund"], { cwd: dir, encoding: "utf8" });
  if (npm.status !== 0) throw new Error(`npm ci failed in ${dir}:\n${npm.stderr}`);
  return dir;
}

function sectionOffset(data, wanted) {
  let pos = 12;
  for (let i = data.readUInt32LE(8); i > 0; i--) {
    if (data.readUInt32LE(pos) === wanted) return pos + 12;
    pos += 12 + Number(data.readBigUInt64LE(pos + 4));
  }
  throw new Error(`no section ${wanted}`);
}

// Contribution records follow the 64-byte circuit hash and the 4-byte count.
function recordOffset(data, index) {
  let at = sectionOffset(data, 10) + 68;
  for (const c of readZkey(data, "fixture").contributions.slice(0, index)) at += c.raw.length;
  return at;
}

function tamper(src, dest, change) {
  const data = Buffer.from(readFileSync(src));
  writeFileSync(dest, change(data) ?? data);
  return dest;
}

const flip = (offset) => (data) => {
  data[offset] ^= 1;
};

// A record holds 384 bytes of points and transcript, its type and its parameter length, then
// the name's parameter id and length. Names are not covered by the contribution hash, so a
// rename of the same length keeps the chain valid for snarkjs.
const rename = (index, name) => (data) => {
  const at = recordOffset(data, index) + 394;
  if (data[at - 1] !== name.length) throw new Error("a rename must keep the name's length");
  data.write(name, at, "latin1");
};

const appendSection = (data) => {
  const extra = Buffer.alloc(16);
  extra.writeUInt32LE(11, 0);
  extra.writeBigUInt64LE(4n, 4);
  const out = Buffer.concat([data, extra]);
  out.writeUInt32LE(data.readUInt32LE(8) + 1, 8);
  return out;
};

// A point on the G2 twist outside the order-r subgroup, which the vault build refuses.
function pointOutsideG2() {
  const { Fp2 } = bn254.fields;
  const b = Fp2.div(Fp2.fromBigTuple([3n, 0n]), Fp2.fromBigTuple([9n, 1n]));
  for (let i = 1n; ; i++) {
    const x = Fp2.fromBigTuple([i, 0n]);
    let y;
    try {
      y = Fp2.sqrt(Fp2.add(Fp2.mul(Fp2.sqr(x), x), b));
    } catch {
      continue;
    }
    if (!bn254.G2.Point.fromAffine({ x, y }).isTorsionFree()) {
      return [
        [`${x.c0}`, `${x.c1}`],
        [`${y.c0}`, `${y.c1}`],
        ["1", "0"],
      ];
    }
  }
}

async function refuseBadKeys(vk) {
  const key = JSON.parse(vk);
  const changed = (change) => JSON.stringify({ ...key, ...change });
  const cases = [
    ["delta equal to gamma", changed({ vk_delta_2: key.vk_gamma_2 }), "never changed"],
    [
      "delta at the G2 generator",
      changed({ vk_gamma_2: key.vk_delta_2, vk_delta_2: key.vk_gamma_2 }),
      "never changed",
    ],
    ["7 public inputs", changed({ nPublic: 7 }), "8 public inputs"],
    ["nPublic written as 8.0", vk.replace('"nPublic": 8', '"nPublic": 8.0'), "as an integer"],
    ["8 IC points", changed({ IC: key.IC.slice(0, 8) }), "9 IC points"],
    ["PLONK", changed({ protocol: "plonk" }), "Groth16 over BN254"],
    [
      "a G1 point off the curve",
      changed({ vk_alpha_1: [key.vk_alpha_1[0], "5", "1"] }),
      "not on the curve",
    ],
    [
      "a G1 point at (0, 0)",
      changed({ IC: [["0", "0", "1"], ...key.IC.slice(1)] }),
      "not on the curve",
    ],
    ["the point at infinity", changed({ vk_alpha_1: ["0", "1", "0"] }), "not an affine point"],
    [
      "a coordinate equal to p",
      changed({ vk_alpha_1: [`${bn254.fields.Fp.ORDER}`, "1", "1"] }),
      "below the field modulus",
    ],
    [
      "a coordinate with a leading zero",
      changed({ vk_alpha_1: [`0${key.vk_alpha_1[0]}`, key.vk_alpha_1[1], "1"] }),
      "not a decimal string",
    ],
    ["a G2 point on the twist outside G2", changed({ vk_beta_2: pointOutsideG2() }), "not in G2"],
  ];
  for (const [label, text, reason] of cases) {
    await refuseCall(`vk rules: ${label}`, () => checkVerificationKey(Buffer.from(text)), reason);
  }
}

async function dryRun(root, r1cs, ptau) {
  const names = ["contributor-1", "contributor-2", "contributor-3", "mallory", "verifier"];
  const people = await timed("npm ci in 5 separate kit copies", () =>
    names.map((name) => person(root, name, r1cs, ptau)),
  );
  const [one, two, three, mallory, verifier] = people;
  const coordinator = join(root, "coordinator");
  const coord = (dir, ...args) => [join(KIT, "coordinator.mjs"), ...args, "--dir", dir];
  const record = (dir) => JSON.parse(readFileSync(join(dir, "ceremony-state.json"), "utf8"));
  const badR1cs = tamper(r1cs, join(root, "other.r1cs"), flip(1000));
  const badPtau = tamper(ptau, join(root, "other.ptau"), flip(1000));

  const elsewhere = join(root, "coordinator-refused");
  refuse(
    "init: a different r1cs",
    KIT,
    coord(elsewhere, "init", "--r1cs", badR1cs, "--ptau", ptau),
    "is not the frozen v2 r1cs",
  );
  refuse(
    "init: a different ptau",
    KIT,
    coord(elsewhere, "init", "--r1cs", r1cs, "--ptau", badPtau),
    `is not the ${PTAU_NAME}`,
  );
  pass("coordinator init", KIT, coord(coordinator, "init", "--r1cs", r1cs, "--ptau", ptau));

  // The coordinator hands out the last accepted zkey and announces its sha256.
  const handOut = (dir) => {
    const last = record(coordinator).zkeys.at(-1);
    copyFileSync(join(coordinator, last.file), join(dir, last.file));
    return ["contribute.mjs", last.file, "--expect", last.sha256];
  };
  const checked = ["--r1cs", "transaction.r1cs", "--ptau", PTAU_NAME];
  const name1 = "Dry Run 1 (github: dry-run-1)";
  const name2 = "Dry Run 2 (github: dry-run-2)";
  const name3 = "Dry Run 3 (github: dry-run-3)";

  const [script, input, , expect] = handOut(one);
  const out1 = join(one, "transaction_0001.zkey");
  const args1 = [script, input, out1, name1];
  refuse(
    "contribute: input differs from the announced sha256",
    one,
    [...args1, "--expect", "f".repeat(64)],
    "not the announced",
  );
  refuse(
    "contribute: a different r1cs",
    one,
    [...args1, "--expect", expect, "--r1cs", badR1cs, "--ptau", PTAU_NAME],
    "is not the frozen v2 r1cs",
  );
  refuse(
    "contribute: an email address as the name",
    one,
    [script, input, "x.zkey", "Dry Run (dry@run.example)", "--expect", expect],
    "looks like an email address",
  );
  writeFileSync(`${out1}.part`, "left over");
  refuse(
    "contribute: the output's part file exists",
    one,
    [...args1, "--expect", expect],
    "already exists",
  );
  rmSync(`${out1}.part`);
  const label1 = "contributor 1: verify the input, contribute";
  const h1 = attested(pass(label1, one, [...args1, "--expect", expect, ...checked]));
  refuse(
    "receive: wrong attested hash",
    KIT,
    coord(coordinator, "receive", out1, name1, "a".repeat(128)),
    "not the attested",
  );
  refuse(
    "receive: wrong name",
    KIT,
    coord(coordinator, "receive", out1, "Someone Else", h1),
    "is named",
  );
  pass("coordinator receive #1", KIT, coord(coordinator, "receive", out1, name1, h1));

  const out2 = join(two, "transaction_0002.zkey");
  const args2 = [...handOut(two), ...checked, "--extra-entropy"];
  args2.splice(2, 0, out2, name2);
  const label2 = "contributor 2: verify the input, contribute with piped extra entropy";
  const h2 = attested(pass(label2, two, args2, randomBytes(32)));
  const renamedFirst = tamper(
    out2,
    join(two, "renamed.zkey"),
    rename(0, "Dry Run X (github: dry-run-x)"),
  );
  refuse(
    "receive: #2 with contribution #1 renamed, the count still right",
    KIT,
    coord(coordinator, "receive", renamedFirst, name2, h2),
    "contribution #1 differs from the one in the previous zkey",
  );
  pass("coordinator receive #2", KIT, coord(coordinator, "receive", out2, name2, h2));

  for (const [label, name] of [
    ["receive: contributor 1 again under the same name", name1],
    ["receive: contributor 1 again under the same handle", "Dry Run Uno (github: dry-run-1)"],
  ]) {
    const again = [...handOut(one)];
    again.splice(2, 0, join(one, "again.zkey"), name);
    const hash = attested(pass(`${label.slice(9)}: contribute`, one, again));
    refuse(
      label,
      KIT,
      coord(coordinator, "receive", join(one, "again.zkey"), name, hash),
      "is the contributor of #1",
    );
    rmSync(join(one, "again.zkey"));
  }

  const first = join(coordinator, "transaction_0001.zkey");
  copyFileSync(first, join(mallory, "transaction_0001.zkey"));
  const skip = [
    "contribute.mjs",
    "transaction_0001.zkey",
    "skip.zkey",
    "Mallory (github: mallory)",
  ];
  const hSkip = attested(
    pass("mallory: contribute on 0001, skipping 0002", mallory, [
      ...skip,
      "--expect",
      sha256(readFileSync(first)),
    ]),
  );
  refuse(
    "receive: zkey that skips contribution #2",
    KIT,
    coord(coordinator, "receive", join(mallory, "skip.zkey"), skip[3], hSkip),
    "must hold the 2 earlier contributions plus one, but holds 2",
  );
  refuse(
    "receive: contribution #1 again as #3",
    KIT,
    coord(coordinator, "receive", out1, name1, h1),
    "is already in the chain as #1",
  );
  refuse(
    "beacon: only 2 contributions",
    KIT,
    coord(coordinator, "beacon", "1"),
    "the beacon needs 3 contributions first",
  );

  const out3 = join(three, "transaction_0003.zkey");
  const args3 = [...handOut(three), ...checked];
  args3.splice(2, 0, out3, name3);
  const h3 = attested(pass("contributor 3: verify the input, contribute", three, args3));
  const data3 = readFileSync(out3);
  const corrupt = tamper(out3, join(three, "corrupt.zkey"), flip(sectionOffset(data3, 9) + 1000));
  const thief = "Thieves 3 (github: thieves-3)";
  const stolen = tamper(out3, join(mallory, "stolen.zkey"), rename(2, thief));
  refuse(
    "receive: #3 with a corrupted H section",
    KIT,
    coord(coordinator, "receive", corrupt, name3, h3),
    "snarkjs zkey verify rejects",
  );
  refuse(
    "receive: #3 renamed by a thief after its owner's file arrived",
    KIT,
    coord(coordinator, "receive", stolen, thief, h3),
    `was already shown under "${name3}"`,
  );
  pass("coordinator receive #3", KIT, coord(coordinator, "receive", out3, name3, h3));
  refuse(
    "receive: the thief's copy after #3 is accepted",
    KIT,
    coord(coordinator, "receive", stolen, thief, h3),
    "is already in the chain as #3",
  );

  // A real ceremony announces the round at least a day ahead; here drand produces it in seconds.
  const lastAccepted = new Date(record(coordinator).zkeys.at(-1).at);
  const round = firstRoundAt(new Date(Date.now() + 15_000));
  const produced = roundTime(round);
  const link = "https://example.invalid/cyphras-ceremony-dry-run";
  const old = firstRoundAt(new Date(lastAccepted - 60_000));
  refuse(
    "announce: a round produced before the last accepted contribution",
    KIT,
    coord(
      coordinator,
      "announce",
      `${old}`,
      link,
      new Date(roundTime(old) - 86_400_000).toISOString(),
    ),
    "before transaction_0003.zkey was accepted",
  );
  refuse(
    "announce: a round produced before its announcement",
    KIT,
    coord(
      coordinator,
      "announce",
      `${round}`,
      link,
      new Date(produced.getTime() + 1000).toISOString(),
    ),
    "before the announcement",
  );
  refuse(
    "beacon: no round announced",
    KIT,
    coord(coordinator, "beacon", `${round}`),
    "no round is announced yet",
  );
  pass("coordinator round", KIT, coord(coordinator, "round", produced.toISOString()));
  pass(
    "coordinator announce",
    KIT,
    coord(coordinator, "announce", `${round}`, link, new Date().toISOString()),
  );
  refuse(
    "beacon: a round other than the announced one",
    KIT,
    coord(coordinator, "beacon", `${round + 1}`),
    `the last announced round is ${round}`,
  );
  // A copy of the ceremony in which one more contribution arrives after the announced round.
  const late = join(root, "coordinator-late");
  cpSync(coordinator, late, { recursive: true });
  await new Promise((done) => setTimeout(done, produced - Date.now() + 5_000));
  pass(
    `coordinator beacon (drand quicknet round ${round})`,
    KIT,
    coord(coordinator, "beacon", `${round}`),
  );
  pass("coordinator status", KIT, coord(coordinator, "status"));
  const lateArgs = [
    "contribute.mjs",
    "transaction_0003.zkey",
    "late.zkey",
    "Late Four (github: late-4)",
  ];
  const hLate = attested(
    pass("late copy: contribute after the announced round", three, [
      ...lateArgs,
      "--expect",
      sha256(data3),
    ]),
  );
  pass(
    "late copy: receive #4 after the announced round",
    KIT,
    coord(late, "receive", join(three, "late.zkey"), lateArgs[3], hLate),
  );
  refuse(
    "beacon: the announced round was produced before the last accepted contribution",
    KIT,
    coord(late, "beacon", `${round}`),
    "before transaction_0004.zkey was accepted",
  );

  // The verifier takes the published files and the transcript's values from the coordinator, and
  // the hashes and names from the contributors' attestations.
  copyFileSync(join(coordinator, FINAL), join(verifier, FINAL));
  copyFileSync(join(coordinator, VK), join(verifier, VK));
  const transcript = record(coordinator);
  const attestations = [`${h1} ${name1}`, `${h2} ${name2}`, `${h3} ${name3}`];
  const list = (lines) =>
    writeFileSync(join(verifier, "contributions.txt"), `${lines.join("\n")}\n`);
  list(attestations);
  const { randomness, signature } = await fetchRound(round);
  const next = await fetchRound(round + 1);
  const verify = (
    { r1cs = "transaction.r1cs", ptau = PTAU_NAME, zkey = FINAL, n = round },
    ...more
  ) => [
    "verify.mjs",
    r1cs,
    ptau,
    zkey,
    "--contributions",
    "contributions.txt",
    "--vk",
    VK,
    "--drand-round",
    `${n}`,
    ...more,
  ];
  const offline = (files, ...more) => verify(files, "--drand-signature", signature, ...more);
  pass(
    "verify (online, every pin)",
    verifier,
    verify(
      {},
      "--vk-sha256",
      sha256(readFileSync(join(verifier, VK))),
      "--zkey-sha256",
      transcript.final.sha256,
      "--not-before",
      transcript.zkeys.at(-1).at,
    ),
  );
  pass("verify (offline)", verifier, offline({}, "--beacon", randomness));

  const bin = join(verifier, "node_modules", ".bin", "snarkjs");
  spawnSync(bin, ["zkey", "export", "verificationkey", FINAL, "cli.json"], { cwd: verifier });
  if (!readFileSync(join(verifier, "cli.json")).equals(readFileSync(join(verifier, VK)))) {
    throw new Error("snarkjs zkey export verificationkey writes other bytes than the kit");
  }
  console.log(`\nsnarkjs zkey export verificationkey writes the same bytes as ${VK}.`);

  const finalPath = join(verifier, FINAL);
  const final = readFileSync(finalPath);
  const fixture = (name, change) => tamper(finalPath, join(verifier, name), change);
  const second = recordOffset(final, 1);
  refuse(
    "verify: final zkey with one byte flipped in its H section",
    verifier,
    offline({ zkey: fixture("h.zkey", flip(sectionOffset(final, 9) + 1000)) }),
    "snarkjs zkey verify rejects the final zkey",
  );
  refuse(
    "verify: final zkey with a point of contribution #2 changed",
    verifier,
    offline({ zkey: fixture("point.zkey", flip(second + 74)) }),
    "is not in G1",
  );
  refuse(
    "verify: final zkey with the transcript of contribution #2 changed",
    verifier,
    offline({ zkey: fixture("transcript.zkey", flip(second + 330)) }),
    "contribution #2 has hash",
  );
  refuse(
    "verify: final zkey with an extra section",
    verifier,
    offline({ zkey: fixture("section.zkey", appendSection) }),
    "has an unknown section 11",
  );
  refuse(
    "verify: final zkey with bytes after its last section",
    verifier,
    offline({ zkey: fixture("trailing.zkey", (data) => Buffer.concat([data, Buffer.alloc(37)])) }),
    "has bytes after its last section",
  );
  const renamed = fixture("renamed.zkey", rename(0, "Dry Run X (github: dry-run-x)"));
  const alone = await timed("snarkjs zkey verify alone, on the final zkey with #1 renamed", () =>
    snarkjs.zKey.verifyFromR1cs(
      mem(readFileSync(r1cs)),
      mem(readFileSync(ptau)),
      mem(readFileSync(renamed)),
      quiet,
    ),
  );
  console.log(
    `\nsnarkjs zkey verify alone, final zkey with #1 renamed: ${alone ? "ZKey Ok!" : "no"}`,
  );
  refuse(
    "verify: final zkey with contribution #1 renamed",
    verifier,
    offline({ zkey: renamed }),
    `contribution #1 is named "Dry Run X (github: dry-run-x)", not "${name1}"`,
  );
  refuse(
    "verify: wrong --zkey-sha256",
    verifier,
    offline({}, "--zkey-sha256", "0".repeat(64)),
    "is not the final zkey of the transcript",
  );
  refuse(
    "verify: a different r1cs",
    verifier,
    offline({ r1cs: badR1cs }),
    "is not the frozen v2 r1cs",
  );
  refuse(
    "verify: a different ptau",
    verifier,
    offline({ ptau: badPtau }),
    `is not the ${PTAU_NAME}`,
  );

  const beacon = async (
    from,
    to,
    { value = randomness, exp = BEACON_ITERATIONS_EXP, label } = {},
  ) => {
    const out = { type: "mem" };
    const name = label ?? `drand quicknet round ${round}`;
    await snarkjs.zKey.beacon(mem(readFileSync(from)), out, name, value, exp, quiet);
    writeFileSync(join(verifier, to), out.data);
    return to;
  };
  const zkeyN = (n) => join(coordinator, `transaction_000${n}.zkey`);
  const skipFinal = await beacon(join(mallory, "skip.zkey"), "skip.zkey");
  const skipAlone = await timed("snarkjs zkey verify alone, on the chain that skips #2", () =>
    snarkjs.zKey.verifyFromR1cs(
      mem(readFileSync(r1cs)),
      mem(readFileSync(ptau)),
      mem(readFileSync(join(verifier, skipFinal))),
      quiet,
    ),
  );
  console.log(`\nsnarkjs zkey verify alone, chain that skips #2: ${skipAlone ? "ZKey Ok!" : "no"}`);
  refuse(
    "verify: final zkey on a chain that skips contribution #2",
    verifier,
    offline({ zkey: skipFinal }),
    "the zkey holds 3 contributions, but 3 are attested",
  );
  refuse(
    "verify: final zkey made with the next round's randomness",
    verifier,
    offline({ zkey: await beacon(zkeyN(3), "next.zkey", { value: next.randomness }) }),
    `the zkey must end with the beacon ${randomness}`,
  );
  refuse(
    "verify: final zkey with numIterationsExp 11",
    verifier,
    offline({ zkey: await beacon(zkeyN(3), "iterations.zkey", { exp: 11 }) }),
    "the beacon must use numIterationsExp 10",
  );
  refuse(
    "verify: final zkey whose beacon is labeled with another round",
    verifier,
    offline({ zkey: await beacon(zkeyN(3), "label.zkey", { label: "drand quicknet round 1" }) }),
    `the beacon is labeled "drand quicknet round 1"`,
  );
  list(attestations.slice(0, 2));
  refuse(
    "verify: final zkey with only 2 contributions",
    verifier,
    offline({ zkey: await beacon(zkeyN(2), "two.zkey") }),
    "the plan needs 3 contributions, there are 2",
  );
  list(attestations);
  refuse(
    "verify: honest final zkey against the next round",
    verifier,
    verify({ n: round + 1 }),
    `the zkey must end with the beacon ${next.randomness}`,
  );
  refuse(
    "verify: --beacon that is not the round's randomness",
    verifier,
    verify({}, "--beacon", flipLast(randomness)),
    `is not the randomness of drand round ${round}`,
  );
  refuse(
    "verify: offline with the next round's signature",
    verifier,
    verify({}, "--drand-signature", next.signature),
    "does not verify under the quicknet key",
  );
  refuse(
    "verify: beacon round produced before --not-before",
    verifier,
    offline({}, "--not-before", new Date(produced.getTime() + 1000).toISOString()),
    `drand round ${round} was produced before`,
  );
  await refuseCall(
    "drand: a round's signature checked as the next round",
    () => verifyRound(round + 1, signature, randomness),
    "does not verify under the quicknet key",
  );
  await refuseCall(
    "drand: a signature with one bit flipped",
    () => verifyRound(round, flipLast(signature), randomness),
    "does not verify under the quicknet key",
  );
  await refuseCall(
    "drand: randomness that is not the signature's hash",
    () => verifyRound(round, signature, next.randomness),
    "is not the hash of its signature",
  );

  const vk = readFileSync(join(verifier, VK), "utf8");
  const digit = vk.indexOf('"IC"') + vk.slice(vk.indexOf('"IC"')).search(/[0-9]/);
  writeFileSync(
    join(verifier, VK),
    `${vk.slice(0, digit)}${vk[digit] === "1" ? "2" : "1"}${vk.slice(digit + 1)}`,
  );
  const size = Buffer.byteLength(vk);
  refuse(
    `verify: ${VK} with one digit changed, same length`,
    verifier,
    offline({}),
    `first at byte ${digit} (${size} bytes exported, ${size} published)`,
  );
  writeFileSync(join(verifier, VK), `${vk}\n`);
  refuse(
    `verify: ${VK} with one byte appended`,
    verifier,
    offline({}),
    `first at byte ${size} (${size} bytes exported, ${size + 1} published)`,
  );
  writeFileSync(join(verifier, VK), vk);
  refuse(
    "verify: wrong vk pin",
    verifier,
    offline({}, "--vk-sha256", "0".repeat(64)),
    "the vault build pins",
  );

  const [a, b, c] = attestations;
  const lists = [
    ["hashes without names", [a, b, c].map((l) => l.slice(0, 128)), "<128 hex characters> <name>"],
    [
      "one hex digit changed in hash #2",
      [a, flipLast(b.slice(0, 128)) + b.slice(128), c],
      "not the attested",
    ],
    ["hashes #1 and #2 swapped", [b, a, c], "not the attested"],
    ["contribution #2 missing", [a, c], "the zkey holds 4 contributions, but 2 are attested"],
    ["name of #1 changed", [`${a.slice(0, 128)} Someone Else`, b, c], "contribution #1 is named"],
    [
      "#3 under #1's handle",
      [a, b, `${c.slice(0, 128)} Dry Run Three (github: dry-run-1)`],
      "is the same contributor as",
    ],
    ["an email address as a name", [a, b, `${c.slice(0, 128)} dry [at] run`], "email address"],
  ];
  for (const [label, lines, reason] of lists) {
    list(lines);
    refuse(`verify: attestation list with ${label}`, verifier, offline({}), reason);
  }

  await refuseBadKeys(vk);
}

run(USAGE, async (argv) => {
  const { values } = parseArgs({
    args: argv,
    options: { r1cs: { type: "string" }, ptau: { type: "string" } },
  });
  const r1cs = resolve(values.r1cs ?? join(CIRCUITS, "build", "transaction.r1cs"));
  const ptau = resolve(values.ptau ?? join(CIRCUITS, "build", "ptau", PTAU_NAME));

  const root = mkdtempSync(join(tmpdir(), "cyphras-ceremony-dry-run-"));
  console.log(`Dry run in ${root}, deleted at the end.`);
  try {
    await dryRun(root, r1cs, ptau);
  } finally {
    rmSync(root, { recursive: true, force: true });
    console.log(`\nDeleted ${root} and everything in it.`);
  }

  console.log("\nStep timings:");
  for (const [label, s] of timings) console.log(`  ${s.toFixed(1).padStart(7)} s  ${label}`);
  console.log(`\nNegative checks, each refused for its expected reason (${refusals.length}):`);
  for (const [label, reason] of refusals) console.log(`  ${label}\n    -> ${reason}`);
  console.log("\nDRY RUN PASSED");
});
