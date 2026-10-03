import { readFileSync } from "node:fs";
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
  parseHex,
  quiet,
  readZkey,
  run,
  sameContributor,
  show,
  step,
} from "./common.mjs";
import { fetchRound, parseRound } from "./drand.mjs";
import { checkVerificationKey, exportVerificationKey } from "./vk.mjs";

const USAGE = `Checks the Cyphras v2 phase-2 ceremony from its public files. Every value is
recomputed here rather than read from a published hash, and any mismatch exits non-zero.

Usage:
  node verify.mjs <transaction.r1cs> <${PTAU_NAME}> <transaction_final.zkey>
      --contributions <file> --vk <verification_key.json> (--drand-round <n> | --beacon <hex>)
      [--vk-sha256 <hex>] [--zkey-sha256 <hex>]

  --contributions <file>  one line per signed attestation, in contribution order: the contribution
                          hash, a space and the contributor's name exactly as attested; blank
                          lines and lines starting with # are skipped
  --vk <file>             the published verification_key.json, compared byte for byte with the
                          key exported here from the final zkey
  --drand-round <n>       the announced beacon round, fetched from the drand relays and checked
                          against the quicknet public key
  --beacon <hex>          the beacon randomness, to check offline; it must match --drand-round
                          when both are given
  --vk-sha256 <hex>       the SHA-256 the vault build pins (MAINNET_SHA256 in the verifier's
                          build/check.rs), compared with the one recomputed here
  --zkey-sha256 <hex>     the SHA-256 of the final zkey in the transcript, compared with the one
                          recomputed here

It checks that the r1cs is the frozen circuit and the ptau the published Hermez file; that the
zkey holds exactly the attested contributions, in order, followed by the beacon; that snarkjs
zkey verify re-derives the whole chain, beacon included, from the r1cs and the ptau; and that the
exported key passes the vault build's checks and equals the published one.`;

function readAttested(path) {
  const attested = [];
  readFileSync(path, "utf8")
    .split("\n")
    .forEach((raw, i) => {
      const line = raw.trim();
      if (!line || line.startsWith("#")) return;
      const at = `${path} line ${i + 1}`;
      const m = /^([0-9a-fA-F]{128})\s+(\S.*)$/.exec(line);
      if (!m) throw new Error(`${at} is not "<128 hex characters> <name>"`);
      const [, hash, name] = m;
      try {
        checkName(name);
      } catch (e) {
        throw new Error(`${at}: ${e.message}`);
      }
      const same = attested.find((a) => sameContributor(a.name, name));
      if (same)
        throw new Error(`${at}: ${show(name)} is the same contributor as ${show(same.name)}`);
      attested.push({ hash: hash.toLowerCase(), name });
    });
  return attested;
}

function firstDifference(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}

run(USAGE, async (argv) => {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      contributions: { type: "string" },
      vk: { type: "string" },
      "drand-round": { type: "string" },
      beacon: { type: "string" },
      "vk-sha256": { type: "string" },
      "zkey-sha256": { type: "string" },
    },
  });
  const beaconGiven = values.beacon !== undefined || values["drand-round"] !== undefined;
  if (positionals.length !== 3 || !values.contributions || !values.vk || !beaconGiven) {
    throw new Error("missing arguments; run with --help");
  }
  const [r1csPath, ptauPath, zkeyPath] = positionals;
  const [r1cs, ptau, zkey] = positionals.map((path) => readFileSync(path));
  const published = readFileSync(values.vk);
  const attested = readAttested(values.contributions);
  let beacon = values.beacon && parseHex(values.beacon, 32, "--beacon");
  const pin = values["vk-sha256"] && parseHex(values["vk-sha256"], 32, "--vk-sha256");
  const zkeyPin = values["zkey-sha256"] && parseHex(values["zkey-sha256"], 32, "--zkey-sha256");

  const r1csSha256 = expectHash(
    r1cs,
    "sha256",
    R1CS_SHA256,
    `${r1csPath} is not the frozen v2 r1cs`,
  );
  const ptauBlake2b = expectHash(
    ptau,
    "blake2b512",
    PTAU_BLAKE2B,
    `${ptauPath} is not the ${PTAU_NAME}`,
  );
  console.log(`r1cs ${r1csPath}\n  sha256 ${r1csSha256}, the frozen circuit`);
  console.log(`ptau ${ptauPath}\n  blake2b ${ptauBlake2b}, the published value`);
  console.log(`  sha256 ${digest(ptau)}`);
  console.log(`zkey ${zkeyPath}\n  sha256 ${digest(zkey)}`);
  if (zkeyPin) {
    expectHash(zkey, "sha256", zkeyPin, `${zkeyPath} is not the final zkey of the transcript`);
    console.log("  equal to the transcript's value");
  }

  if (values["drand-round"] !== undefined) {
    const round = parseRound(values["drand-round"]);
    const drand = await fetchRound(round);
    if (beacon && beacon !== drand.randomness) {
      throw new Error(`--beacon ${beacon} is not the randomness of drand round ${round}`);
    }
    beacon = drand.randomness;
    console.log(`drand quicknet round ${round}, produced at ${drand.time}`);
    console.log(`  randomness ${beacon}`);
    console.log(`  signature verified, the same from ${drand.relays.join(", ")}`);
  }

  const { contributions } = readZkey(zkey, zkeyPath);
  console.log("\nContributions in the zkey:");
  contributions.forEach((c, i) => {
    const beaconParams = c.type === 1 ? `, beacon ${c.beaconHash} (2^${c.iterationsExp})` : "";
    console.log(`  #${i + 1} ${show(c.name)}${beaconParams}\n     ${c.hash}`);
  });
  if (contributions.length !== attested.length + 1) {
    throw new Error(
      `the zkey holds ${contributions.length} contributions, but ${attested.length} are ` +
        "attested and the beacon must follow them",
    );
  }
  attested.forEach((a, i) => {
    const c = contributions[i];
    if (c.type !== 0) throw new Error(`contribution #${i + 1} is a beacon, not an attested one`);
    if (c.hash !== a.hash) {
      throw new Error(`contribution #${i + 1} has hash ${c.hash}, not the attested ${a.hash}`);
    }
    if (c.name !== a.name) {
      throw new Error(`contribution #${i + 1} is named ${show(c.name)}, not ${show(a.name)}`);
    }
  });
  if (attested.length < MIN_CONTRIBUTIONS) {
    throw new Error(
      `the plan needs ${MIN_CONTRIBUTIONS} contributions, there are ${attested.length}`,
    );
  }
  const last = contributions.at(-1);
  if (last.type !== 1 || last.beaconHash !== beacon) {
    throw new Error(`the zkey must end with the beacon ${beacon}, but it does not`);
  }
  if (last.iterationsExp !== BEACON_ITERATIONS_EXP) {
    throw new Error(`the beacon must use numIterationsExp ${BEACON_ITERATIONS_EXP}`);
  }
  console.log(`All ${attested.length} attested contributions match, then the expected beacon.\n`);

  await step(
    "Re-deriving the chain and the beacon from the r1cs and the ptau (snarkjs zkey verify)",
    async () => {
      if (!(await snarkjs.zKey.verifyFromR1cs(mem(r1cs), mem(ptau), mem(zkey), quiet))) {
        throw new Error("snarkjs zkey verify rejects the final zkey");
      }
      console.log("  ZKey Ok!");
    },
  );

  const exported = await exportVerificationKey(zkey);
  checkVerificationKey(exported);
  console.log("\nThe exported verification key passes the vault build's key checks.");
  if (!exported.equals(published)) {
    const at = firstDifference(exported, published);
    throw new Error(
      `${values.vk} differs from the key exported from the zkey, first at byte ${at} ` +
        `(${exported.length} bytes exported, ${published.length} published)`,
    );
  }
  const sha256 = digest(exported);
  console.log(`${values.vk} equals the exported key byte for byte.`);
  console.log(`  sha256 ${sha256}`);
  if (pin && pin !== sha256) throw new Error(`the vault build pins ${pin}, not ${sha256}`);
  if (pin) console.log("  equal to the pinned value");
  console.log("\nVERIFIED");
});
