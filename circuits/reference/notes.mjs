import { compress, hash } from "./poseidon2.mjs";
import { TAG, fold } from "./keys.mjs";

export const LEVELS = 20;

export function addressFold(gd, pkd) {
  return hash([fold(gd, TAG.gd), fold(pkd, TAG.pkd)], TAG.address);
}

export function noteCommitment({ value, gd, pkd, rcm }) {
  return hash([value, addressFold(gd, pkd), rcm], TAG.commitment);
}

export function nullifier(cm, pos, nkFold) {
  return hash([cm, BigInt(pos), nkFold], TAG.nullifier);
}

// ZEROS[i] is the root of an empty subtree of height i.
export const ZEROS = [0n];
for (let i = 1; i <= LEVELS; i++) ZEROS.push(compress(ZEROS[i - 1], ZEROS[i - 1]));

// Sparse, so tests can place leaves anywhere, including the last index.
export class MerkleTree {
  constructor(levels = LEVELS) {
    this.levels = levels;
    this.nodes = new Map();
  }

  node(level, index) {
    return this.nodes.get(`${level}:${index}`) ?? ZEROS[level];
  }

  set(pos, leaf) {
    let index = BigInt(pos);
    let current = leaf;
    this.nodes.set(`0:${index}`, current);
    for (let level = 0; level < this.levels; level++) {
      const sibling = this.node(level, index ^ 1n);
      current = index & 1n ? compress(sibling, current) : compress(current, sibling);
      index >>= 1n;
      this.nodes.set(`${level + 1}:${index}`, current);
    }
  }

  root() {
    return this.node(this.levels, 0n);
  }

  path(pos) {
    const elements = [];
    let index = BigInt(pos);
    for (let level = 0; level < this.levels; level++) {
      elements.push(this.node(level, index ^ 1n));
      index >>= 1n;
    }
    return elements;
  }
}
