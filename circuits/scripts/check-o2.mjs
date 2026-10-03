import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { FIELD as F, FROZEN, ROOT, circom, loadR1cs, sha256 } from "./circom.mjs";

// --O2 drops signals and rewrites constraints. This proves the result is not weaker than the
// unsimplified --O0 system of the same source: every --O0 constraint, rewritten onto the signals
// --O2 keeps through circom's own substitution, must vanish identically or be a multiple of an
// --O2 constraint. A witness of --O2 then extends through the substitution to a witness of --O0
// with the same public inputs, so --O2 accepts nothing --O0 rejects.

function add(lc, label, k) {
  const sum = F.add(lc.get(label) ?? 0n, k);
  if (sum === 0n) lc.delete(label);
  else lc.set(label, sum);
}

export async function loadSystem(dir, name) {
  const r1cs = await loadR1cs(join(dir, `${name}.r1cs`), { loadConstraints: true, loadMap: true });
  const constraints = r1cs.constraints.map((c) =>
    c.map((lc) => {
      const out = new Map();
      for (const [wire, k] of Object.entries(lc)) add(out, r1cs.map[wire], k);
      return out;
    }),
  );
  return { constraints, labels: r1cs.map, nPublic: 1 + r1cs.nOutputs + r1cs.nPubInputs };
}

export function loadSubstitutions(dir, name) {
  const raw = JSON.parse(readFileSync(join(dir, `${name}_substitutions.json`), "utf8"));
  return new Map(
    Object.entries(raw).map(([label, lc]) => [
      Number(label),
      new Map(Object.entries(lc).map(([l, k]) => [Number(l), F.e(BigInt(k))])),
    ]),
  );
}

// circom's substitutions may refer to other substituted labels; rewrite each onto kept labels.
function resolve(raw, kept) {
  const removed = (label) => label !== 0 && !kept.has(label) && raw.has(label);
  const done = new Map();
  for (const start of raw.keys()) {
    if (done.has(start)) continue;
    const path = [start];
    const pending = [raw.get(start).keys()];
    const active = new Set(path);
    while (path.length) {
      const next = pending.at(-1).next();
      if (!next.done) {
        const label = next.value;
        if (removed(label) && !done.has(label)) {
          if (active.has(label)) throw new Error(`substitution cycle at label ${label}`);
          path.push(label);
          pending.push(raw.get(label).keys());
          active.add(label);
        }
        continue;
      }
      const label = path.pop();
      pending.pop();
      active.delete(label);
      const out = new Map();
      for (const [l, k] of raw.get(label)) {
        if (removed(l)) for (const [l2, k2] of done.get(l)) add(out, l2, F.mul(k, k2));
        else add(out, l, k);
      }
      done.set(label, out);
    }
  }
  return done;
}

const monomial = (i, j) =>
  [i, j]
    .filter((l) => l !== 0)
    .sort((x, y) => x - y)
    .join(",");

// A * B - C as a polynomial over labels, scaled so equal constraints compare equal as strings.
function canonical(a, b, c) {
  const terms = new Map();
  const put = (key, k) => {
    const sum = F.add(terms.get(key) ?? 0n, k);
    if (sum === 0n) terms.delete(key);
    else terms.set(key, sum);
  };
  for (const [i, x] of a) for (const [j, y] of b) put(monomial(i, j), F.mul(x, y));
  for (const [l, z] of c) put(l === 0 ? "" : String(l), F.neg(z));
  if (terms.size === 0) return null;
  const keys = [...terms.keys()].sort();
  const scale = F.inv(terms.get(keys[0]));
  return keys.map((key) => `${key}:${F.mul(terms.get(key), scale)}`).join(" ");
}

export function implication(o0, o2, substitutions) {
  const kept = new Set(o2.labels);
  if (o0.nPublic !== o2.nPublic) throw new Error("the two systems have different public signals");
  for (let w = 0; w < o0.nPublic; w++) {
    if (o0.labels[w] !== o2.labels[w]) throw new Error(`public wire ${w} names different labels`);
  }
  for (const label of substitutions.keys()) {
    if (kept.has(label)) throw new Error(`label ${label} is both kept and substituted`);
  }
  const subs = resolve(substitutions, kept);
  // A removed label with no substitution stays free; a constraint using it can then only vanish
  // or be reported missing, never match.
  const unresolved = new Set();
  const rewrite = (lc) => {
    const out = new Map();
    const put = (label, k) => {
      if (label !== 0 && !kept.has(label)) unresolved.add(label);
      add(out, label, k);
    };
    for (const [label, k] of lc) {
      if (subs.has(label)) for (const [l, k2] of subs.get(label)) put(l, F.mul(k, k2));
      else put(label, k);
    }
    return out;
  };

  const target = new Map(o2.constraints.map((c, i) => [canonical(...c), i]));
  const used = new Set();
  let vanished = 0;
  const missing = [];
  o0.constraints.forEach((c, i) => {
    const key = canonical(...c.map(rewrite));
    if (key === null) vanished++;
    else if (target.has(key)) used.add(target.get(key));
    else missing.push(i);
  });
  return {
    o0: o0.constraints.length,
    o2: o2.constraints.length,
    vanished,
    matched: o0.constraints.length - vanished - missing.length,
    o2Used: used.size,
    missing,
    unresolved: unresolved.size,
  };
}

async function main() {
  const source = join(ROOT, "src", "transaction.circom");
  const o0Dir = join(ROOT, "build", "check-o2", "o0");
  const o2Dir = join(ROOT, "build", "check-o2", "o2");
  mkdirSync(o0Dir, { recursive: true });
  mkdirSync(o2Dir, { recursive: true });
  circom(source, o0Dir, { optimization: "--O0" });
  circom(source, o2Dir, { extra: ["--simplification_substitution"] });
  const digest = sha256(join(o2Dir, "transaction.r1cs"));
  if (digest !== FROZEN.r1csSha256) throw new Error(`--O2 r1cs ${digest} is not the frozen one`);

  const r = implication(
    await loadSystem(o0Dir, "transaction"),
    await loadSystem(o2Dir, "transaction"),
    loadSubstitutions(o2Dir, "transaction"),
  );
  console.log(`--O2 r1cs sha256 ${digest} (frozen)`);
  console.log(`--O0: ${r.o0} constraints, --O2: ${r.o2} constraints`);
  console.log(`--O0 constraints vanishing under the substitution: ${r.vanished}`);
  console.log(`--O0 constraints found in --O2: ${r.matched}, covering ${r.o2Used} of ${r.o2}`);
  console.log(`removed signals without a substitution: ${r.unresolved}`);
  console.log(`--O0 constraints missing from --O2: ${r.missing.length}`);
  if (r.missing.length > 0) {
    console.error(`first missing --O0 constraints: ${r.missing.slice(0, 10).join(", ")}`);
    process.exit(1);
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
