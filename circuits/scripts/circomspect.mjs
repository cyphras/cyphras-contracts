import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { ROOT } from "./circom.mjs";

const SOURCES = [
  "src/transaction.circom",
  "lib/keys.circom",
  "lib/note.circom",
  "lib/merkleProof.circom",
  "lib/poseidon2/poseidon2_compress.circom",
  "lib/poseidon2/poseidon2_hash.circom",
  "lib/poseidon2/poseidon2_perm.circom",
];

// Reviewed findings, keyed by rule, file and flagged line so that edits elsewhere keep them valid.
const ACCEPTED = [
  // each square exists only to place a public input in a constraint
  "CS0017 src/transaction.circom: signal extDataHashSquare <== extDataHash * extDataHash;",
  "CS0017 src/transaction.circom: signal domainSquare <== domain * domain;",
  // hints whose values the next statements constrain: in * inv === 1, and ReduceModLCheck
  "CS0005 lib/keys.circom: signal inv <-- in != 0 ? 1 / in : 0;",
  "CS0017 lib/keys.circom: signal inv <-- in != 0 ? 1 / in : 0;",
  "CS0005 lib/keys.circom: out <-- in % SUBGROUP_ORDER();",
  "CS0005 lib/keys.circom: signal k <-- in \\ SUBGROUP_ORDER();",
  // LessThan(251) operands: constants below 2^251, or signals already bounded by Num2Bits(251)
  "CS0014 lib/keys.circom: lt.in[1] <== SUBGROUP_ORDER();",
  "CS0014 lib/keys.circom: outNoWrap.in[0] <== out;",
  "CS0014 lib/keys.circom: outNoWrap.in[1] <== P_MINUS_7L;",
  // a levels-bit decomposition cannot alias for levels far below the 254-bit field
  "CS0010 lib/merkleProof.circom: component indexBits = Num2Bits(levels);",
];

const sarif = join(ROOT, "build", "circomspect.sarif");
mkdirSync(join(ROOT, "build"), { recursive: true });
const found = new Set();
for (const source of SOURCES) {
  rmSync(sarif, { force: true });
  const args = ["-L", join(ROOT, "lib"), "-L", join(ROOT, "node_modules"), "-l", "WARNING"];
  try {
    execFileSync("circomspect", [...args, "-s", sarif, join(ROOT, source)], { stdio: "pipe" });
  } catch {
    // circomspect exits 1 whenever it reports a finding; the SARIF file says what it found
  }
  for (const run of JSON.parse(readFileSync(sarif, "utf8")).runs) {
    for (const result of run.results) {
      const { artifactLocation, region } = result.locations[0].physicalLocation;
      const path = fileURLToPath(artifactLocation.uri);
      const line = readFileSync(path, "utf8").split("\n")[region.startLine - 1].trim();
      found.add(`${result.ruleId} ${relative(ROOT, path)}: ${line}`);
    }
  }
}

const unexpected = [...found].filter((f) => !ACCEPTED.includes(f));
const stale = ACCEPTED.filter((f) => !found.has(f));
for (const f of unexpected) console.error(`new finding: ${f}`);
for (const f of stale) console.error(`reviewed finding no longer reported: ${f}`);
if (unexpected.length > 0 || stale.length > 0) process.exit(1);
console.log(`circomspect: only the ${ACCEPTED.length} reviewed findings`);
