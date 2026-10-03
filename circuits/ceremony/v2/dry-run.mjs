import { bn254 } from "@noble/curves/bn254.js";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  closeSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  readdirSync,
  rmSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import * as snarkjs from "snarkjs";
import { BEACON_ITERATIONS_EXP, PTAU_NAME, mem, quiet, readZkey, run } from "./common.mjs";
import { fetchRound, firstRoundAt, parseRound, roundTime } from "./drand.mjs";
import { checkVerificationKey } from "./vk.mjs";

const USAGE = `Runs the whole ceremony on this machine and checks that the kit refuses bad input.

Usage:
  node dry-run.mjs [--r1cs <file>] [--ptau <file>] [--round <n>]

A coordinator initializes the ceremony, three contributors each install the kit with npm ci and
contribute from their own directory, a past drand quicknet round is applied as the beacon
(default: the first round of the current UTC day) and a verifier checks the result. Then every
negative check must fail. Everything is written to a temporary directory that is deleted at the
end: one machine made all of it, so none of it may ever be used.`;

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

function refuse(label, cwd, args) {
  const r = exec(cwd, args);
  if (r.status === 0) throw new Error(`negative check passed when it must fail: ${label}`);
  refusals.push([label, r.output.match(/ERROR: (.*)/)?.[1] ?? `exit ${r.status}`]);
}

async function timed(label, work) {
  const started = Date.now();
  const out = await work();
  timings.push([label, (Date.now() - started) / 1000]);
  return out;
}

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const attested = (out) => out.match(/Contribution hash \(blake2b-512\): ([0-9a-f]{128})/)[1];

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

function sectionOffset(path, wanted) {
  const buf = readFileSync(path);
  let pos = 12;
  for (let i = buf.readUInt32LE(8); i > 0; i--) {
    if (buf.readUInt32LE(pos) === wanted) return pos + 12;
    pos += 12 + Number(buf.readBigUInt64LE(pos + 4));
  }
  throw new Error(`no section ${wanted} in ${path}`);
}

function flipByte(src, dest, offset) {
  copyFileSync(src, dest);
  const fd = openSync(dest, "r+");
  const b = Buffer.alloc(1);
  readSync(fd, b, 0, 1, offset);
  b[0] ^= 1;
  writeSync(fd, b, 0, 1, offset);
  closeSync(fd);
}

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
    if (!bn254.G2.Point.fromAffine({ x, y }).isTorsionFree()) return g2Json({ x, y });
  }
}

const g2Json = (p) => [
  [`${p.x.c0}`, `${p.x.c1}`],
  [`${p.y.c0}`, `${p.y.c1}`],
  ["1", "0"],
];

function refuseBadKeys(vk) {
  const key = JSON.parse(vk);
  const changes = [
    ["delta equal to gamma", { vk_delta_2: key.vk_gamma_2 }],
    ["delta at the G2 generator", { vk_gamma_2: key.vk_delta_2, vk_delta_2: key.vk_gamma_2 }],
    ["7 public inputs", { nPublic: 7 }],
    ["8 IC points", { IC: key.IC.slice(0, 8) }],
    ["PLONK", { protocol: "plonk" }],
    ["a G1 point off the curve", { vk_alpha_1: [key.vk_alpha_1[0], "5", "1"] }],
    ["a G1 point at (0, 0)", { IC: [["0", "0", "1"], ...key.IC.slice(1)] }],
    ["the point at infinity", { vk_alpha_1: ["0", "1", "0"] }],
    ["a coordinate equal to p", { vk_alpha_1: [`${bn254.fields.Fp.ORDER}`, "1", "1"] }],
    ["a G2 point on the twist outside G2", { vk_beta_2: pointOutsideG2() }],
  ];
  for (const [label, change] of changes) {
    try {
      checkVerificationKey(Buffer.from(JSON.stringify({ ...key, ...change })));
    } catch (e) {
      refusals.push([`vk rules: ${label}`, e.message]);
      continue;
    }
    throw new Error(`negative check passed when it must fail: vk rules: ${label}`);
  }
}

async function dryRun(root, r1cs, ptau, round) {
  const names = ["contributor-1", "contributor-2", "contributor-3", "mallory", "verifier"];
  const people = await timed("npm ci in 5 separate kit copies", () =>
    names.map((name) => person(root, name, r1cs, ptau)),
  );
  const [mallory, verifier] = people.slice(3);
  const coordinator = join(root, "coordinator");
  const coord = (...args) => [join(KIT, "coordinator.mjs"), ...args, "--dir", coordinator];
  const announced = () =>
    JSON.parse(readFileSync(join(coordinator, "ceremony-state.json"), "utf8")).zkeys.at(-1);

  pass("coordinator init", KIT, coord("init", "--r1cs", r1cs, "--ptau", ptau));

  const attestations = [];
  for (let i = 1; i <= 3; i++) {
    const dir = people[i - 1];
    const name = `Dry Run ${i} (github: dry-run-${i})`;
    const input = announced().file;
    copyFileSync(join(coordinator, input), join(dir, input));
    const output = `transaction_000${i}.zkey`;
    const args = ["contribute.mjs", input, output, name, "--r1cs", "transaction.r1cs"];
    args.push("--ptau", PTAU_NAME, "--expect");
    if (i === 1) {
      refuse("contribute: input differs from the announced sha256", dir, [...args, "f".repeat(64)]);
    }
    args.push(announced().sha256);
    const label = `contributor ${i}: verify the input, contribute`;
    const out =
      i === 2
        ? pass(label, dir, [...args, "--extra-entropy"], randomBytes(32))
        : pass(label, dir, args);
    const hash = attested(out);
    attestations.push(`${hash} ${name}`);
    const returned = join(dir, output);

    if (i === 1) {
      refuse(
        "receive: wrong attested hash",
        KIT,
        coord("receive", returned, name, "a".repeat(128)),
      );
      refuse("receive: wrong name", KIT, coord("receive", returned, "Someone Else", hash));
    }
    if (i === 3) {
      const first = join(coordinator, "transaction_0001.zkey");
      copyFileSync(first, join(mallory, "transaction_0001.zkey"));
      const skip = [
        "contribute.mjs",
        "transaction_0001.zkey",
        "skip.zkey",
        "Mallory (github: mallory)",
      ];
      const out = pass("mallory: contribute on 0001, skipping 0002", mallory, [
        ...skip,
        "--expect",
        sha256(first),
      ]);
      refuse(
        "receive: zkey that skips contribution #2",
        KIT,
        coord("receive", join(mallory, "skip.zkey"), skip[3], attested(out)),
      );
      const [hash1, ...name1] = attestations[0].split(" ");
      refuse(
        "receive: contribution #1 again as #3",
        KIT,
        coord("receive", join(people[0], "transaction_0001.zkey"), name1.join(" "), hash1),
      );
      refuse("beacon: only 2 contributions", KIT, coord("beacon", String(round)));
    }
    pass(`coordinator receive #${i}`, KIT, coord("receive", returned, name, hash));
  }

  pass("coordinator round", KIT, coord("round", roundTime(round).toISOString()));
  pass(`coordinator beacon (drand quicknet round ${round})`, KIT, coord("beacon", String(round)));
  pass("coordinator status", KIT, coord("status"));

  // The verifier gets the published files from the coordinator and the hashes from the
  // contributors' attestations, never from the coordinator.
  copyFileSync(join(coordinator, FINAL), join(verifier, FINAL));
  copyFileSync(join(coordinator, VK), join(verifier, VK));
  const list = join(verifier, "contributions.txt");
  writeFileSync(list, `${attestations.join("\n")}\n`);
  const verify = (zkey, ...extra) => [
    "verify.mjs",
    "transaction.r1cs",
    PTAU_NAME,
    zkey,
    "--contributions",
    "contributions.txt",
    "--vk",
    VK,
    ...extra,
  ];
  const { randomness, signature } = await fetchRound(round);
  const online = (zkey, ...extra) => verify(zkey, "--drand-round", `${round}`, ...extra);
  const offline = (zkey, ...extra) => online(zkey, "--drand-signature", signature, ...extra);
  const pin = sha256(join(verifier, VK));
  pass("verify (online)", verifier, online(FINAL, "--vk-sha256", pin));
  pass("verify (offline)", verifier, offline(FINAL, "--beacon", randomness));

  const bin = join(verifier, "node_modules", ".bin", "snarkjs");
  spawnSync(bin, ["zkey", "export", "verificationkey", FINAL, "cli.json"], { cwd: verifier });
  if (!readFileSync(join(verifier, "cli.json")).equals(readFileSync(join(verifier, VK)))) {
    throw new Error("snarkjs zkey export verificationkey writes other bytes than the kit");
  }
  console.log(`\nsnarkjs zkey export verificationkey writes the same bytes as ${VK}.`);

  const final = join(verifier, FINAL);
  flipByte(final, join(verifier, "h.zkey"), sectionOffset(final, 9) + 1000);
  refuse("verify: final zkey with one byte flipped in its H section", verifier, online("h.zkey"));
  const first = readZkey(readFileSync(final), final).contributions[0];
  const second = sectionOffset(final, 10) + 68 + first.raw.length;
  flipByte(final, join(verifier, "c2.zkey"), second + 74);
  refuse(
    "verify: final zkey with one byte flipped in contribution #2",
    verifier,
    online("c2.zkey"),
  );

  const beacon = async (from, to, value) => {
    const out = { type: "mem" };
    const label = `drand quicknet round ${round}`;
    await snarkjs.zKey.beacon(
      mem(readFileSync(from)),
      out,
      label,
      value,
      BEACON_ITERATIONS_EXP,
      quiet,
    );
    writeFileSync(join(verifier, to), out.data);
  };
  await beacon(join(mallory, "skip.zkey"), "skip.zkey", randomness);
  const alone = await timed("snarkjs zkey verify alone, on the chain that skips #2", () =>
    snarkjs.zKey.verifyFromR1cs(
      mem(readFileSync(r1cs)),
      mem(readFileSync(ptau)),
      mem(readFileSync(join(verifier, "skip.zkey"))),
      quiet,
    ),
  );
  console.log(
    `\nsnarkjs zkey verify alone, on the chain that skips #2: ${alone ? "ZKey Ok!" : "rejected"}`,
  );
  refuse("verify: final zkey on a chain that skips contribution #2", verifier, online("skip.zkey"));

  await beacon(
    join(coordinator, "transaction_0003.zkey"),
    "beacon.zkey",
    (await fetchRound(round + 1)).randomness,
  );
  refuse(
    "verify: final zkey made with the next round's randomness",
    verifier,
    online("beacon.zkey"),
  );
  refuse(
    "verify: honest final zkey against the next round",
    verifier,
    verify(FINAL, "--drand-round", `${round + 1}`),
  );
  const altered = `${randomness.slice(0, -1)}${randomness.endsWith("0") ? "1" : "0"}`;
  refuse(
    "verify: honest final zkey against altered randomness",
    verifier,
    online(FINAL, "--beacon", altered),
  );

  const vk = readFileSync(join(verifier, VK), "utf8");
  const digit = vk.indexOf('"IC"') + vk.slice(vk.indexOf('"IC"')).search(/[0-9]/);
  writeFileSync(
    join(verifier, VK),
    `${vk.slice(0, digit)}${vk[digit] === "1" ? "2" : "1"}${vk.slice(digit + 1)}`,
  );
  refuse(`verify: ${VK} with one digit changed`, verifier, online(FINAL));
  writeFileSync(join(verifier, VK), `${vk}\n`);
  refuse(`verify: ${VK} with one byte appended`, verifier, online(FINAL));
  writeFileSync(join(verifier, VK), vk);
  refuse("verify: wrong vk pin", verifier, offline(FINAL, "--vk-sha256", "0".repeat(64)));

  const [a, b, c] = attestations;
  const lists = {
    "one hex digit changed in hash #2": [a, `${b[0] === "a" ? "b" : "a"}${b.slice(1)}`, c],
    "hashes #1 and #2 swapped": [b, a, c],
    "contribution #2 missing": [a, c],
    "name of #1 changed": [`${a.slice(0, 128)} Someone Else`, b, c],
  };
  for (const [label, lines] of Object.entries(lists)) {
    writeFileSync(list, `${lines.join("\n")}\n`);
    refuse(`verify: attestation list with ${label}`, verifier, offline(FINAL));
  }

  refuseBadKeys(vk);
}

run(USAGE, async (argv) => {
  const { values } = parseArgs({
    args: argv,
    options: { r1cs: { type: "string" }, ptau: { type: "string" }, round: { type: "string" } },
  });
  const r1cs = resolve(values.r1cs ?? join(CIRCUITS, "build", "transaction.r1cs"));
  const ptau = resolve(values.ptau ?? join(CIRCUITS, "build", "ptau", PTAU_NAME));
  const today = new Date(`${new Date().toISOString().slice(0, 10)}T00:00:00Z`);
  const round = parseRound(values.round ?? firstRoundAt(today));

  const root = mkdtempSync(join(tmpdir(), "cyphras-ceremony-dry-run-"));
  console.log(`Dry run in ${root}, deleted at the end.`);
  try {
    await dryRun(root, r1cs, ptau, round);
  } finally {
    rmSync(root, { recursive: true, force: true });
    console.log(`\nDeleted ${root} and everything in it.`);
  }

  console.log("\nStep timings:");
  for (const [label, s] of timings) console.log(`  ${s.toFixed(1).padStart(7)} s  ${label}`);
  console.log(`\nNegative checks, each refused as required (${refusals.length}):`);
  for (const [label, reason] of refusals) console.log(`  ${label}\n    -> ${reason}`);
  console.log("\nDRY RUN PASSED");
});
