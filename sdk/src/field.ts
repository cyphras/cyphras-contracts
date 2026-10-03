// The BN254 scalar field, which is also the base field of Baby Jubjub. add, sub, neg and mul expect
// canonical inputs (0 <= x < P); mod and pow accept any integer.

export const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const HALF = (P - 1n) / 2n;

export function mod(x: bigint): bigint {
  const r = x % P;
  return r < 0n ? r + P : r;
}

export function isCanonical(x: bigint): boolean {
  return x >= 0n && x < P;
}

export function add(a: bigint, b: bigint): bigint {
  const s = a + b;
  return s >= P ? s - P : s;
}

export function sub(a: bigint, b: bigint): bigint {
  const d = a - b;
  return d < 0n ? d + P : d;
}

export function neg(a: bigint): bigint {
  return a === 0n ? 0n : P - a;
}

export function mul(a: bigint, b: bigint): bigint {
  return (a * b) % P;
}

export function square(a: bigint): bigint {
  return (a * a) % P;
}

export function pow(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}

export function inv(a: bigint): bigint {
  let low = mod(a);
  if (low === 0n) throw new RangeError("zero has no inverse");
  let high = P;
  let lm = 1n;
  let hm = 0n;
  while (low > 1n) {
    const r = high / low;
    [lm, hm] = [hm - lm * r, lm];
    [low, high] = [high - low * r, low];
  }
  return mod(lm);
}

export function div(a: bigint, b: bigint): bigint {
  return mul(a, inv(b));
}

// The canonical integer of x is above (P - 1) / 2: the sign bit packPoint stores for x.
export function isHigh(x: bigint): boolean {
  return x > HALF;
}

// Tonelli-Shanks with P - 1 = 2^28 * ODD.
const TWO_ADICITY = 28;
const ODD = (P - 1n) >> BigInt(TWO_ADICITY);
// The smallest quadratic non-residue mod P.
export const NON_RESIDUE = 5n;
const ROOT_OF_UNITY = pow(NON_RESIDUE, ODD);

export function sqrt(x: bigint): bigint | undefined {
  const n = mod(x);
  if (n === 0n) return 0n;
  let m = TWO_ADICITY;
  let c = ROOT_OF_UNITY;
  let t = pow(n, ODD);
  let r = pow(n, (ODD + 1n) / 2n);
  while (t !== 1n) {
    let i = 0;
    let t2 = t;
    while (t2 !== 1n) {
      t2 = square(t2);
      i++;
      if (i === m) return undefined;
    }
    let b = c;
    for (let j = 0; j < m - i - 1; j++) b = square(b);
    m = i;
    c = square(b);
    t = mul(t, c);
    r = mul(r, b);
  }
  return r;
}
