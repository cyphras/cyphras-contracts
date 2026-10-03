// The constraints of circuits/src/transaction.circom, restated with the SDK's primitives. Unit
// tests run witnesses through it instead of the real circuit; test/proof checks the real one.
import { BASE8, L, type Point, onCurve, scalarMul, timesCofactor } from "../../src/babyjub.ts";
import { P, mod } from "../../src/field.ts";
import { TAG, deriveIvk, fold } from "../../src/keys.ts";
import { LEVELS, rootFromPath } from "../../src/merkle.ts";
import { MAX_VALUE, noteCommitment, nullifier } from "../../src/notes.ts";
import type { TransactionWitness } from "../../src/prover.ts";

const equal = (a: Point, b: Point): boolean => a[0] === b[0] && a[1] === b[1];

export function violations(w: TransactionWitness): string[] {
  const out: string[] = [];
  const check = (ok: boolean, name: string): void => {
    if (!ok) out.push(name);
  };
  for (let i = 0; i < 2; i++) {
    const value = w.inValue[i] as bigint;
    const ask = w.inAsk[i] as bigint;
    const nsk = w.inNsk[i] as bigint;
    const gd = w.inGd[i] as Point;
    const q = w.inQ[i] as Point;
    const pos = w.inPos[i] as bigint;
    check(ask >= 0n && ask < L && nsk >= 0n && nsk < L, `in${i}: canonical keys`);
    const nkFold = fold(scalarMul(BASE8, nsk), TAG.nk);
    const ivk = deriveIvk(fold(scalarMul(BASE8, ask), TAG.ak), nkFold);
    check(onCurve(q) && equal(timesCofactor(q), gd) && gd[0] !== 0n, `in${i}: prime-order gd`);
    check(pos >= 0n && pos < 2n ** BigInt(LEVELS), `in${i}: 32-bit position`);
    check(value >= 0n && value <= MAX_VALUE, `in${i}: 64-bit value`);
    if (out.length > 0) continue;
    const cm = noteCommitment({ value, gd, pkd: scalarMul(gd, ivk), rcm: w.inRcm[i] as bigint });
    check(nullifier(cm, Number(pos), nkFold) === w.nf[i], `in${i}: nullifier`);
    const path = w.inPathElements[i] as readonly bigint[];
    check(path.length === LEVELS, `in${i}: path length`);
    if (value !== 0n) check(rootFromPath(cm, Number(pos), path) === w.root, `in${i}: root`);
  }
  for (let j = 0; j < 2; j++) {
    const gd = w.outGd[j] as Point;
    const pkd = w.outPkd[j] as Point;
    const value = w.outValue[j] as bigint;
    check(onCurve(gd) && onCurve(pkd), `out${j}: on curve`);
    check(value >= 0n && value <= MAX_VALUE, `out${j}: 64-bit value`);
    if (value >= 0n && value <= MAX_VALUE) {
      const cm = noteCommitment({ value, gd, pkd, rcm: w.outRcm[j] as bigint });
      check(cm === w.cmOut[j], `out${j}: commitment`);
    }
  }
  check(w.nf[0] !== w.nf[1], "distinct nullifiers");
  const sumIn = (w.inValue[0] as bigint) + (w.inValue[1] as bigint);
  const sumOut = (w.outValue[0] as bigint) + (w.outValue[1] as bigint);
  check(mod(sumIn + w.publicAmount) === mod(sumOut), "balance");
  for (const [name, x] of [
    ["root", w.root],
    ["publicAmount", w.publicAmount],
    ["extDataHash", w.extDataHash],
    ["domain", w.domain],
  ] as const) {
    check(x >= 0n && x < P, `${name}: field element`);
  }
  return out;
}
