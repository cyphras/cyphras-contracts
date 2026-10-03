import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import * as snarkjs from "snarkjs";
import {
  BEACON_ITERATIONS_EXP,
  MIN_CONTRIBUTIONS,
  PTAU_BLAKE2B,
  PTAU_NAME,
  R1CS_SHA256,
  expectHash,
  hashFile,
  parseHex,
  quiet,
  readZkey,
  run,
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
      [--vk-sha256 <hex>]

  --contributions <file>  the contribution hashes from the signed attestations, one per line in
                          contribution order, each optionally followed by the contributor's name;
                          blank lines and lines starting with # are skipped
  --vk <file>             the published verification_key.json, compared byte for byte with the
                          key exported here from the final zkey
  --drand-round <n>       the announced beacon round, fetched from the drand relays and checked
                          against the quicknet public key
  --beacon <hex>          the beacon randomness, to check offline; it must match --drand-round
                          when both are given
  --vk-sha256 <hex>       the SHA-256 the vault build pins (MAINNET_SHA256 in the verifier's
                          build/check.rs), compared with the one recomputed here

It checks that the r1cs is the frozen circuit and the ptau the published Hermez file; that the
zkey holds exactly the attested contributions, in order, followed by the beacon; that snarkjs
zkey verify re-derives the whole chain, beacon included, from the r1cs and the ptau; and that the
exported key passes the vault build's checks and equals the published one.`;

function readAttested(path) {
  const lines = readFileSync(path, "utf8").split("\n");
  const attested = [];
  lines.forEach((raw, i) => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;
    const m = /^([0-9a-fA-F]{128})(?:\s+(.*))?$/.exec(line);
    if (!m) throw new Error(`${path} line ${i + 1} is not "<128 hex characters> [name]"`);
    attested.push({ hash: m[1].toLowerCase(), name: m[2] });
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
    },
  });
  const beaconGiven = values.beacon !== undefined || values["drand-round"] !== undefined;
  if (positionals.length !== 3 || !values.contributions || !values.vk || !beaconGiven) {
    throw new Error("missing arguments; run with --help");
  }
  const [r1cs, ptau, zkey] = positionals;
  const attested = readAttested(values.contributions);
  let beacon = values.beacon && parseHex(values.beacon, 32, "--beacon");
  const pin = values["vk-sha256"] && parseHex(values["vk-sha256"], 32, "--vk-sha256");

  const r1csSha256 = await expectHash(r1cs, "sha256", R1CS_SHA256, "frozen v2 r1cs");
  const ptauBlake2b = await expectHash(ptau, "blake2b512", PTAU_BLAKE2B, PTAU_NAME);
  console.log(`r1cs ${r1cs}\n  sha256 ${r1csSha256}, the frozen circuit`);
  console.log(`ptau ${ptau}\n  blake2b ${ptauBlake2b}, the published value`);
  console.log(`  sha256 ${await hashFile(ptau)}`);
  console.log(`zkey ${zkey}\n  sha256 ${await hashFile(zkey)}`);

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

  const { contributions } = readZkey(zkey);
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
    if (a.name !== undefined && c.name !== a.name) {
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
      if (!(await snarkjs.zKey.verifyFromR1cs(r1cs, ptau, zkey, quiet))) {
        throw new Error("snarkjs zkey verify rejects the final zkey");
      }
      console.log("  ZKey Ok!");
    },
  );

  const exported = await exportVerificationKey(zkey);
  checkVerificationKey(exported);
  console.log("\nThe exported verification key passes the vault build's key checks.");
  const published = readFileSync(values.vk);
  if (!exported.equals(published)) {
    const at = firstDifference(exported, published);
    throw new Error(
      `${values.vk} differs from the key exported from the zkey, first at byte ${at} ` +
        `(${exported.length} bytes exported, ${published.length} published)`,
    );
  }
  const sha256 = createHash("sha256").update(exported).digest("hex");
  console.log(`${values.vk} equals the exported key byte for byte.`);
  console.log(`  sha256 ${sha256}`);
  if (pin && pin !== sha256) throw new Error(`the vault build pins ${pin}, not ${sha256}`);
  if (pin) console.log("  equal to the pinned value");
  console.log("\nVERIFIED");
});
