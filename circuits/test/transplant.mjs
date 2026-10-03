import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { OUT, ROOT, compile } from "./helpers.mjs";

// A malicious prover is not bound by the witness generator's asserts or hints. generator() builds
// one from a copy of the sources with every === statement removed and, optionally, hint code
// replaced; transplant() moves its witness onto the shipped R1CS by signal label. --O0 keeps every
// signal, so the generator has a value for each label the shipped system uses.

const ASSERTION = /^(\s*)[^/\n][^\n]*?===[^\n]*?;/gm;

export function generator(tag, edits = {}) {
  const dir = join(OUT, `generator-${tag}`);
  const applied = new Set();
  const copy = (from, to) => {
    mkdirSync(to, { recursive: true });
    for (const entry of readdirSync(from, { withFileTypes: true })) {
      const source = join(from, entry.name);
      if (entry.isDirectory()) {
        copy(source, join(to, entry.name));
        continue;
      }
      if (!entry.name.endsWith(".circom")) continue;
      const rel = relative(ROOT, source);
      let text = readFileSync(source, "utf8");
      if (edits[rel]) {
        const edited = edits[rel](text);
        if (edited === text) throw new Error(`edit of ${rel} changed nothing`);
        text = edited;
        applied.add(rel);
      }
      writeFileSync(join(to, entry.name), text.replace(ASSERTION, "$1"));
    }
  };
  copy(join(ROOT, "src"), join(dir, "src"));
  copy(join(ROOT, "lib"), join(dir, "lib"));
  const circomlib = join("node_modules", "circomlib", "circuits");
  copy(join(ROOT, circomlib), join(dir, circomlib));
  for (const rel of Object.keys(edits)) {
    if (!applied.has(rel)) throw new Error(`no source ${rel} to edit`);
  }
  return compile(join(dir, "src", "transaction.circom"), `generator-${tag}`, {
    optimization: "--O0",
    libs: [join(dir, "lib"), join(dir, "node_modules")],
  });
}

export async function transplant(gen, target, input) {
  const witness = await gen.witness(input);
  const byLabel = new Map(gen.labels.map((label, wire) => [label, witness[wire]]));
  return target.labels.map((label) => {
    if (gen.names.get(label) !== target.names.get(label)) {
      throw new Error(
        `label ${label} is ${gen.names.get(label)} here, ${target.names.get(label)} there`,
      );
    }
    return byLabel.get(label);
  });
}
