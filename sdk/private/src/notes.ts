import { L, type Point } from "./babyjub.ts";
import { bytesToBigIntBE, randomBytes } from "./bytes.ts";
import { P } from "./field.ts";
import { TAG, fold } from "./keys.ts";
import { hash } from "./poseidon2.ts";

export const MAX_VALUE = (1n << 64n) - 1n;

export interface NoteCore {
  readonly value: bigint;
  readonly gd: Point;
  readonly pkd: Point;
  readonly rcm: bigint;
}

function isValue(value: bigint): boolean {
  return value >= 0n && value <= MAX_VALUE;
}

export function addressFold(gd: Point, pkd: Point): bigint {
  return hash([fold(gd, TAG.gd), fold(pkd, TAG.pkd)], TAG.address);
}

export function noteCommitment({ value, gd, pkd, rcm }: NoteCore): bigint {
  if (!isValue(value)) throw new RangeError("a note value is a 64-bit unsigned integer");
  return hash([value, addressFold(gd, pkd), rcm], TAG.commitment);
}

export function nullifier(cm: bigint, pos: number, nkFold: bigint): bigint {
  return hash([cm, BigInt(pos), nkFold], TAG.nullifier);
}

// 512 random bits reduced mod the modulus: the bias is below 2^-250.
export function randomFieldElement(): bigint {
  return bytesToBigIntBE(randomBytes(64)) % P;
}

export function randomScalar(): bigint {
  for (;;) {
    const s = bytesToBigIntBE(randomBytes(64)) % L;
    if (s !== 0n) return s;
  }
}
