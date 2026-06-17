import * as snarkjs from "snarkjs";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, copyFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve, basename } from "node:path";
import { argv, env, exit } from "node:process";

// Coordinator helper for the mainnet Phase-2 ceremony. Tracks the relay so the coordinator never
// loses which file is which: it records every contribution in order, verifies each returned zkey
// against the circuit and powers of tau before accepting it, names the files canonically, and always
// prints the next action. State lives in build/mainnet/ceremony-state.json (operational, gitignored;
// the public record is TRANSCRIPT.md, rendered with the `transcript` command). No secrets are stored.
//
//   node coordinator.mjs init                       record r1cs/ptau/withdraw_0000 hashes, start tracking
//   node coordinator.mjs receive <file> "Name"      verify a returned zkey, file it as the next step
//   node coordinator.mjs status                     show the chain so far and the next action
//   node coordinator.mjs beacon <beaconHashHex>     apply the final public beacon and verify
//   node coordinator.mjs transcript                 print the filled transcript table to paste into TRANSCRIPT.md

const here = dirname(fileURLToPath(import.meta.url));
const CIRCUITS = resolve(here, "..", "..");
const MAINNET = env.MAINNET_DIR ? resolve(env.MAINNET_DIR) : join(CIRCUITS, "build", "mainnet");
const R1CS = env.R1CS ? resolve(env.R1CS) : join(CIRCUITS, "build", "withdraw.r1cs");
const DEFAULT_PTAU = join(MAINNET, "powersOfTau28_hez_final_14.ptau");
const STATE = join(MAINNET, "ceremony-state.json");
const FINAL = join(MAINNET, "withdraw_final.zkey");

const quietLogger = { info: () => {}, debug: () => {}, warn: () => {}, error: (m) => console.error(m) };

function sha256(p) {
  return createHash("sha256").update(readFileSync(p)).digest("hex");
}

function pad(n) {
  return String(n).padStart(4, "0");
}

function zkeyPath(n) {
  return join(MAINNET, `withdraw_${pad(n)}.zkey`);
}

function fail(m) {
  console.error(`\nERROR: ${m}\n`);
  exit(1);
}

function loadState() {
  if (!existsSync(STATE)) fail("no ceremony in progress. Run `node coordinator.mjs init` first.");
  return JSON.parse(readFileSync(STATE, "utf8"));
}

function saveState(s) {
  writeFileSync(STATE, JSON.stringify(s, null, 2) + "\n");
}

// snarkjs logs each contribution as ONE message string: "contribution #N <name>:" followed by the
// blake2b-512 hash as four newline-separated rows of hex groups. Contributions print newest-first,
// so collect every block and return the hash of the highest-numbered one (the newest contribution).
function captureLogger() {
  const lines = [];
  const cap = (m) => {
    if (typeof m === "string") lines.push(m);
  };
  return { logger: { info: cap, debug: () => {}, warn: cap, error: (m) => console.error(m) }, lines };
}

function parseLastContributionHash(lines) {
  let best = -1;
  let bestHash = null;
  for (const m of lines) {
    const head = /contribution #(\d+)[^\n]*:([\s\S]*)/i.exec(m);
    if (!head) continue;
    const num = parseInt(head[1], 10);
    const hex = (head[2].match(/[0-9a-f]{8}/gi) || []).join("").toLowerCase();
    if (hex.length === 128 && num > best) {
      best = num;
      bestHash = hex;
    }
  }
  return bestHash;
}

async function verifyAgainst(ptau, zkey) {
  const { logger, lines } = captureLogger();
  const ok = await snarkjs.zKey.verifyFromR1cs(R1CS, ptau, zkey, logger);
  return { ok, contributionHash: parseLastContributionHash(lines) };
}

function nextActionLine(state) {
  const last = state.contributions[state.contributions.length - 1];
  const n = state.contributions.length; // next step index
  if (state.final) return "Ceremony finalized. Run `npm run mainnet:export-vk && npm run mainnet:parse-vk`, then `node coordinator.mjs transcript`.";
  return (
    `NEXT: send ${last.file} (sha256 ${last.sha256}) to contributor ${n},\n` +
    `      or run \`node coordinator.mjs beacon <beaconHashHex>\` to finalize if contributions are done.`
  );
}

async function cmdInit() {
  if (existsSync(STATE)) fail(`a ceremony is already tracked at ${STATE}. Remove it to start over.`);
  const ptau = env.PTAU ? resolve(env.PTAU) : DEFAULT_PTAU;
  if (!existsSync(R1CS)) fail(`r1cs not found: ${R1CS} (compile the circuit first)`);
  if (!existsSync(ptau)) fail(`ptau not found: ${ptau} (download + verify the Hermez ptau first)`);
  if (!existsSync(zkeyPath(0)))
    fail(`withdraw_0000.zkey not found in ${MAINNET}. Run \`npm run mainnet:setup\` first.`);

  const v = await verifyAgainst(ptau, zkeyPath(0));
  if (!v.ok) fail("withdraw_0000.zkey does not verify against the r1cs + ptau. Re-run mainnet:setup.");

  const state = {
    network: "mainnet",
    startedNote: "Phase-2 ceremony for the Cyphras withdraw proving key",
    r1cs: { path: R1CS, sha256: sha256(R1CS) },
    ptau: { path: ptau, sha256: sha256(ptau) },
    contributions: [
      {
        step: 0,
        contributor: "coordinator (groth16 setup)",
        file: zkeyPath(0),
        sha256: sha256(zkeyPath(0)),
        contributionHash: null,
      },
    ],
    beacon: null,
    final: null,
  };
  saveState(state);
  console.log("Ceremony initialized.\n");
  console.log(`  r1cs  sha256: ${state.r1cs.sha256}`);
  console.log(`  ptau  sha256: ${state.ptau.sha256}`);
  console.log(`  0000  sha256: ${state.contributions[0].sha256}\n`);
  console.log(nextActionLine(state));
}

async function cmdReceive(incoming, name, reportedHash) {
  if (!incoming || !name) fail('usage: node coordinator.mjs receive <file.zkey> "Contributor Name" [reportedContributionHash]');
  if (!existsSync(incoming)) fail(`file not found: ${incoming}`);
  const state = loadState();
  if (state.final) fail("ceremony already finalized; cannot accept more contributions.");
  const n = state.contributions.length; // step index for this contribution

  console.log(`Verifying ${basename(incoming)} as contribution #${n} from "${name}"...\n`);
  const v = await verifyAgainst(state.ptau.path, incoming);
  if (!v.ok)
    fail(`verification FAILED. Do NOT accept this file. Ask "${name}" to re-run and resend.`);

  const dest = zkeyPath(n);
  if (existsSync(dest)) fail(`${dest} already exists; refusing to overwrite. Check the state.`);
  copyFileSync(incoming, dest);
  const sha = sha256(dest);

  if (reportedHash && v.contributionHash && reportedHash.toLowerCase() !== v.contributionHash) {
    console.warn(
      `WARNING: the contributor-reported hash does not match the verified one.\n` +
        `  reported: ${reportedHash}\n  verified: ${v.contributionHash}\n` +
        "Recording the verified hash. Confirm with the contributor before trusting the attestation.\n",
    );
  }

  state.contributions.push({
    step: n,
    contributor: name,
    file: dest,
    sha256: sha,
    contributionHash: v.contributionHash ?? reportedHash ?? null,
  });
  saveState(state);

  console.log(`Contribution #${n} from "${name}" verified and filed as ${dest}.`);
  console.log(`  output sha256     : ${sha}`);
  console.log(`  contribution hash : ${v.contributionHash ?? "(could not parse; use the contributor's reported hash)"}\n`);
  console.log(nextActionLine(state));
}

function cmdStatus() {
  const state = loadState();
  console.log(`Cyphras ${state.network} ceremony - ${state.contributions.length - 1} contribution(s) so far\n`);
  console.log(`  r1cs sha256: ${state.r1cs.sha256}`);
  console.log(`  ptau sha256: ${state.ptau.sha256}\n`);
  for (const c of state.contributions) {
    const who = c.step === 0 ? c.contributor : `#${c.step} ${c.contributor}`;
    console.log(`  ${who}\n    zkey sha256: ${c.sha256}` + (c.contributionHash ? `\n    contrib hash: ${c.contributionHash}` : ""));
  }
  if (state.beacon) console.log(`\n  beacon: ${state.beacon.hash} (numIterationsExp ${state.beacon.numIterationsExp})`);
  if (state.final) console.log(`  final zkey sha256: ${state.final.sha256}`);
  console.log("\n" + nextActionLine(state));
}

async function cmdBeacon(beaconHash) {
  if (!beaconHash || !/^[0-9a-f]+$/i.test(beaconHash))
    fail("usage: node coordinator.mjs beacon <beaconHashHex>  (the announced public beacon randomness, hex)");
  const state = loadState();
  if (state.final) fail("ceremony already finalized.");
  if (state.contributions.length < 2)
    fail("no contributions yet. At least one contributor must run before the beacon.");
  const last = state.contributions[state.contributions.length - 1];

  console.log(`Applying beacon to ${basename(last.file)} -> ${basename(FINAL)}...\n`);
  await snarkjs.zKey.beacon(last.file, FINAL, "Cyphras mainnet beacon", beaconHash, 10, quietLogger);

  const v = await verifyAgainst(state.ptau.path, FINAL);
  if (!v.ok) fail("final zkey FAILED verification after the beacon. Do not proceed.");

  state.beacon = { hash: beaconHash.toLowerCase(), numIterationsExp: 10 };
  state.final = { file: FINAL, sha256: sha256(FINAL), contributionHash: v.contributionHash };
  saveState(state);

  console.log(`Beacon applied and final zkey verified (ZKey Ok!).`);
  console.log(`  final zkey sha256: ${state.final.sha256}\n`);
  console.log("NEXT: from circuits/, run `npm run mainnet:export-vk && npm run mainnet:parse-vk`,");
  console.log("      then `node coordinator.mjs transcript` to render the public record.");
}

function cmdTranscript() {
  const state = loadState();
  const rows = state.contributions.map((c) =>
    c.step === 0
      ? `| 0 | withdraw_0000.zkey | ${c.contributor} | n/a | ${c.sha256} | n/a |`
      : `| ${c.step} | withdraw_${pad(c.step)}.zkey | ${c.contributor} | ${c.contributionHash ?? "<fill>"} | ${c.sha256} | <link to signed attestation> |`,
  );
  console.log("Paste the filled values into TRANSCRIPT.md:\n");
  console.log(`r1cs sha256: ${state.r1cs.sha256}`);
  console.log(`ptau sha256: ${state.ptau.sha256}\n`);
  console.log("| # | zkey | contributor | contribution hash (blake2b-512) | output sha256 | attestation |");
  console.log("|---|------|-------------|---------------------------------|---------------|-------------|");
  console.log(rows.join("\n"));
  if (state.beacon) console.log(`\nbeacon value: ${state.beacon.hash} (numIterationsExp ${state.beacon.numIterationsExp})`);
  if (state.final) console.log(`final zkey sha256: ${state.final.sha256}`);
}

const [, , cmd, ...rest] = argv;
switch (cmd) {
  case "init":
    await cmdInit();
    break;
  case "receive":
    await cmdReceive(rest[0], rest[1], rest[2]);
    break;
  case "status":
    cmdStatus();
    break;
  case "beacon":
    await cmdBeacon(rest[0]);
    break;
  case "transcript":
    cmdTranscript();
    break;
  default:
    console.error("usage: node coordinator.mjs <init|receive|status|beacon|transcript> ...");
    exit(1);
}

// snarkjs leaves worker threads alive, so exit explicitly.
exit(0);
