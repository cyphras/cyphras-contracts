import { readFileSync } from "node:fs";
import { F } from "./babyjub.mjs";

// The constants are read from the circuit library so the two cannot drift apart; the
// permutation vectors in the tests pin them to independent implementations.
const SOURCE = readFileSync(
  new URL("../lib/poseidon2/poseidon2_const.circom", import.meta.url),
  "utf8",
);

function constants(fn, t) {
  const body = SOURCE.slice(SOURCE.indexOf(`function ${fn}(t)`));
  const start = body.indexOf(`if (t==${t})`);
  const end = body.indexOf("} else", start);
  return [...body.slice(start, end).matchAll(/0x[0-9a-fA-F]+/g)].map((m) => BigInt(m[0]));
}

const FULL_ROUNDS = 8;
const PARTIAL_ROUNDS = 56;

const PARAMS = new Map(
  [2, 3, 4].map((t) => {
    const full = constants("POSEIDON_FULL_ROUNDS", t);
    return [
      t,
      {
        full: Array.from({ length: FULL_ROUNDS }, (_, r) => full.slice(r * t, (r + 1) * t)),
        partial: constants("POSEIDON_PARTIAL_ROUNDS", t),
        diagMinusOne: constants("POSEIDON_INTERNAL_MAT_DIAG", t),
      },
    ];
  }),
);

const sbox = (x) => F.mul(x, F.square(F.square(x)));
const sum = (s) => s.reduce((acc, x) => F.add(acc, x), 0n);

function externalLayer(s) {
  if (s.length === 4) {
    const t0 = F.add(s[0], s[1]);
    const t1 = F.add(s[2], s[3]);
    const t2 = F.add(F.add(s[1], s[1]), t1);
    const t3 = F.add(F.add(s[3], s[3]), t0);
    const t4 = F.add(F.mul(4n, t1), t3);
    const t5 = F.add(F.mul(4n, t0), t2);
    return [F.add(t3, t5), t5, F.add(t2, t4), t4];
  }
  const total = sum(s);
  return s.map((x) => F.add(total, x));
}

function internalLayer(s, diagMinusOne) {
  const total = sum(s);
  return s.map((x, i) => F.add(total, F.mul(x, diagMinusOne[i])));
}

function fullRound(s, rc) {
  return externalLayer(s.map((x, i) => sbox(F.add(x, rc[i]))));
}

function partialRound(s, rc, diagMinusOne) {
  return internalLayer([sbox(F.add(s[0], rc)), ...s.slice(1)], diagMinusOne);
}

export function permute(input) {
  const { full, partial, diagMinusOne } = PARAMS.get(input.length);
  let s = externalLayer(input.map((x) => F.e(x)));
  for (let r = 0; r < FULL_ROUNDS / 2; r++) s = fullRound(s, full[r]);
  for (const rc of partial) s = partialRound(s, rc, diagMinusOne);
  for (let r = FULL_ROUNDS / 2; r < FULL_ROUNDS; r++) s = fullRound(s, full[r]);
  return s;
}

// P2_n(inputs; tag): hash mode with the tag in the capacity element.
export function hash(inputs, tag) {
  return permute([...inputs, BigInt(tag)])[0];
}

// Compression mode, used only for Merkle nodes.
export function compress(left, right) {
  return F.add(permute([left, right])[0], F.e(left));
}
