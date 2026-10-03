import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { readR1cs } from "r1csfile";
import { F, P } from "../reference/babyjub.mjs";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "build", "test");
const require = createRequire(import.meta.url);

export const randomField = () => BigInt("0x" + randomBytes(64).toString("hex")) % P;

class Circuit {
  constructor(dir, name, calculator, r1cs, symbols) {
    this.r1csPath = join(dir, `${name}.r1cs`);
    this.wasmPath = join(dir, `${name}_js`, `${name}.wasm`);
    this.calculator = calculator;
    this.nConstraints = r1cs.nConstraints;
    // [signal, coefficient] pairs evaluate far faster than the sparse objects r1csfile returns
    this.constraints = r1cs.constraints.map((c) =>
      c.map((lc) => Object.entries(lc).map(([i, k]) => [Number(i), k])),
    );
    this.symbols = symbols;
  }

  static async load(dir, name) {
    const builder = require(join(dir, `${name}_js`, "witness_calculator.js"));
    const calculator = await builder(readFileSync(join(dir, `${name}_js`, `${name}.wasm`)));
    const r1cs = await readR1cs(join(dir, `${name}.r1cs`), { loadConstraints: true, F });
    const symbols = new Map();
    for (const line of readFileSync(join(dir, `${name}.sym`), "utf8").split("\n")) {
      const [, witnessIndex, , signal] = line.split(",");
      if (signal) symbols.set(signal, Number(witnessIndex));
    }
    return new Circuit(dir, name, calculator, r1cs, symbols);
  }

  witness(input) {
    return this.calculator.calculateWitness(input, true);
  }

  // Number of R1CS constraints the witness violates, independent of the witness generator.
  violations(witness) {
    const evaluate = (lc) => lc.reduce((acc, [i, k]) => F.add(acc, F.mul(k, witness[i])), 0n);
    let count = 0;
    for (const [a, b, c] of this.constraints) {
      if (F.sub(F.mul(evaluate(a), evaluate(b)), evaluate(c)) !== 0n) count++;
    }
    return count;
  }

  index(signal) {
    const i = this.symbols.get(signal);
    if (i === undefined || i < 0) throw new Error(`${signal} is not in the witness`);
    return i;
  }

  read(witness, signal) {
    return witness[this.index(signal)];
  }

  patch(witness, changes) {
    const out = [...witness];
    for (const [signal, value] of Object.entries(changes)) out[this.index(signal)] = F.e(value);
    return out;
  }
}

const compiled = new Map();

// Same flags as `npm run compile`, so the tests exercise the constraint system that ships.
function compile(source, name) {
  if (!compiled.has(name)) {
    const dir = join(OUT, name);
    mkdirSync(dir, { recursive: true });
    const lib = ["-l", join(ROOT, "lib"), "-l", join(ROOT, "node_modules")];
    execFileSync("circom", [source, "--r1cs", "--wasm", "--sym", ...lib, "-o", dir], {
      stdio: "pipe",
    });
    // circom emits a CommonJS witness calculator; this package is ESM by default
    writeFileSync(join(dir, `${name}_js`, "package.json"), '{ "type": "commonjs" }\n');
    compiled.set(name, Circuit.load(dir, name));
  }
  return compiled.get(name);
}

export function transactionCircuit() {
  return compile(join(ROOT, "src", "transaction.circom"), "transaction");
}

// A throwaway main component around one library template.
export function harness(name, include, main) {
  const dir = join(OUT, name);
  mkdirSync(dir, { recursive: true });
  const source = join(dir, `${name}.circom`);
  writeFileSync(source, `pragma circom 2.2.3;\ninclude "${include}";\ncomponent main = ${main};\n`);
  return compile(source, name);
}

// Matching the message keeps a malformed test input from passing as a rejection.
export const ASSERT_FAILED = /Assert Failed/;
