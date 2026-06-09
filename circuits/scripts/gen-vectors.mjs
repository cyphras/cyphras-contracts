import { buildPoseidon } from "circomlibjs";
import { writeFileSync } from "node:fs";

// Produces Poseidon test vectors for arities 2, 3, and 4 using the SAME circomlib
// Poseidon the circuit uses. The verifier/pool work (Issue #3) must feed these exact
// inputs through the Stellar Protocol 25 Poseidon host function and assert byte-equal
// outputs. If they differ, on-chain Merkle roots will never match circuit roots and no
// proof will ever verify. Arity 4 is the highest risk: some host functions only expose
// 2-to-1 compression and cannot reproduce circomlib's native t=5 instance.

const [, , outPath] = process.argv;
if (!outPath) {
  console.error("usage: node gen-vectors.mjs <vectors.json>");
  process.exit(1);
}

const poseidon = await buildPoseidon();
const F = poseidon.F;

function hash(inputs) {
  return F.toObject(poseidon(inputs.map(BigInt))).toString();
}

const cases = [
  { arity: 2, inputs: ["1", "2"] },
  { arity: 2, inputs: ["0", "0"] },
  { arity: 2, inputs: [
    "12345678901234567890123456789012345678901234567890",
    "98765432109876543210987654321098765432109876543210",
  ] },
  { arity: 3, inputs: ["1", "2", "3"] },
  { arity: 3, inputs: ["1000000", "100000", "42"] },
  { arity: 4, inputs: ["1", "2", "3", "4"] },
  { arity: 4, inputs: [
    "111111111111111111111", "222222222222222222222",
    "333333333333333333333", "444444444444444444444",
  ] },
];

const vectors = cases.map((c) => ({ arity: c.arity, inputs: c.inputs, output: hash(c.inputs) }));

writeFileSync(
  outPath,
  JSON.stringify(
    {
      note: "circomlib Poseidon over BN254. Issue #3 must reproduce these with the Stellar host Poseidon and assert equality before any deployment.",
      curve: "bn254",
      vectors,
    },
    null,
    2
  ) + "\n",
  "utf-8"
);

console.log(`wrote ${outPath} (${vectors.length} vectors, arities 2/3/4)`);
