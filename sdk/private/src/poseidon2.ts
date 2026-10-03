import { add, mod, mul, square } from "./field.ts";
import { POSEIDON2_CONSTANTS, type Poseidon2Width } from "./poseidon2-constants.ts";

const HALF_FULL_ROUNDS = 4;

const sbox = (x: bigint): bigint => mul(x, square(square(x)));

function sum(state: bigint[]): bigint {
  let total = 0n;
  for (const x of state) total = add(total, x);
  return total;
}

function externalLayer(s: bigint[]): bigint[] {
  if (s.length === 4) {
    const [s0, s1, s2, s3] = s as [bigint, bigint, bigint, bigint];
    const t0 = add(s0, s1);
    const t1 = add(s2, s3);
    const t2 = add(add(s1, s1), t1);
    const t3 = add(add(s3, s3), t0);
    const t4 = add(mul(4n, t1), t3);
    const t5 = add(mul(4n, t0), t2);
    return [add(t3, t5), t5, add(t2, t4), t4];
  }
  const total = sum(s);
  return s.map((x) => add(total, x));
}

function internalLayer(s: bigint[], diag: readonly bigint[]): bigint[] {
  const total = sum(s);
  return s.map((x, i) => add(total, mul(x, diag[i] as bigint)));
}

function fullRound(s: bigint[], rc: readonly bigint[]): bigint[] {
  return externalLayer(s.map((x, i) => sbox(add(x, rc[i] as bigint))));
}

export function permute(input: readonly bigint[]): bigint[] {
  const width = input.length;
  if (width !== 2 && width !== 3 && width !== 4) throw new RangeError("unsupported width");
  const { full, partial, diag }: Poseidon2Width = POSEIDON2_CONSTANTS[width];
  let s = externalLayer(input.map(mod));
  for (let r = 0; r < HALF_FULL_ROUNDS; r++) s = fullRound(s, full[r] as bigint[]);
  for (const rc of partial) {
    s[0] = sbox(add(s[0] as bigint, rc));
    s = internalLayer(s, diag);
  }
  for (let r = HALF_FULL_ROUNDS; r < 2 * HALF_FULL_ROUNDS; r++) {
    s = fullRound(s, full[r] as bigint[]);
  }
  return s;
}

// P2_n(inputs; tag): hash mode, with the tag in the last state element.
export function hash(inputs: readonly bigint[], tag: number): bigint {
  return permute([...inputs, BigInt(tag)])[0] as bigint;
}

// The t = 2 compression for Merkle nodes. It takes no tag, so a node never equals a keyed hash.
export function compress(left: bigint, right: bigint): bigint {
  return add(permute([left, right])[0] as bigint, mod(left));
}
