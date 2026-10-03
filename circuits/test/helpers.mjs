import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { basename, join } from "node:path";
import { F, P } from "../reference/babyjub.mjs";
import { ROOT, circom, loadR1cs } from "../scripts/circom.mjs";

export { ROOT };
export const OUT = join(ROOT, "build", "test");
const require = createRequire(import.meta.url);

export const randomField = () => BigInt("0x" + randomBytes(64).toString("hex")) % P;

export class Circuit {
  constructor(dir, name, calculator, r1cs, symbols, names) {
    this.r1csPath = join(dir, `${name}.r1cs`);
    this.wasmPath = join(dir, `${name}_js`, `${name}.wasm`);
    this.calculator = calculator;
    this.nConstraints = r1cs.nConstraints;
    // [wire, coefficient] pairs evaluate far faster than the sparse objects r1csfile returns
    this.constraints = r1cs.constraints.map((c) =>
      c.map((lc) => Object.entries(lc).map(([i, k]) => [Number(i), k])),
    );
    this.labels = r1cs.map;
    this.symbols = symbols;
    this.names = names;
  }

  static async load(dir, name) {
    const builder = require(join(dir, `${name}_js`, "witness_calculator.js"));
    const calculator = await builder(readFileSync(join(dir, `${name}_js`, `${name}.wasm`)));
    const r1cs = await loadR1cs(join(dir, `${name}.r1cs`), {
      loadConstraints: true,
      loadMap: true,
    });
    const symbols = new Map();
    const names = new Map();
    for (const line of readFileSync(join(dir, `${name}.sym`), "utf8").split("\n")) {
      const [label, wire, , signal] = line.split(",");
      if (!signal) continue;
      symbols.set(signal, Number(wire));
      names.set(Number(label), signal);
    }
    return new Circuit(dir, name, calculator, r1cs, symbols, names);
  }

  witness(input) {
    return this.calculator.calculateWitness(input, true);
  }

  // Indexes of the R1CS constraints the witness violates, independent of the witness generator.
  violated(witness) {
    const evaluate = (lc) => lc.reduce((acc, [i, k]) => F.add(acc, F.mul(k, witness[i])), 0n);
    const out = [];
    this.constraints.forEach(([a, b, c], i) => {
      if (F.sub(F.mul(evaluate(a), evaluate(b)), evaluate(c)) !== 0n) out.push(i);
    });
    return out;
  }

  violations(witness) {
    return this.violated(witness).length;
  }

  // The components whose signals appear in the given constraints.
  components(indexes) {
    const out = new Set();
    for (const i of indexes) {
      for (const lc of this.constraints[i]) {
        for (const [wire] of lc) {
          if (wire !== 0) out.add(this.names.get(this.labels[wire]).replace(/\.[^.]*$/, ""));
        }
      }
    }
    return [...out].sort();
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

// The circom wrapper pins the compiler version and flags, so tests exercise the shipped system.
export function compile(source, name, options) {
  if (!compiled.has(name)) {
    const dir = join(OUT, name);
    const stem = basename(source, ".circom");
    mkdirSync(dir, { recursive: true });
    circom(source, dir, options);
    // circom emits a CommonJS witness calculator; this package is ESM by default
    writeFileSync(join(dir, `${stem}_js`, "package.json"), '{ "type": "commonjs" }\n');
    compiled.set(name, Circuit.load(dir, stem));
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
