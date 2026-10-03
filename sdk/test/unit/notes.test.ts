import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { mnemonicToSeedSync } from "@scure/bip39";
import { type Point } from "../../src/babyjub.ts";
import { toHex32 } from "../../src/bytes.ts";
import { computeDomain } from "../../src/domain.ts";
import { P } from "../../src/field.ts";
import { TAG, defaultAddressKey, deriveSpendingKeys, fold } from "../../src/keys.ts";
import {
  CommitmentTree,
  EMPTY_ROOT,
  LEVELS,
  PAGE_SIZE,
  ZEROS,
  pagePath,
  rootFromPath,
} from "../../src/merkle.ts";
import { MAX_VALUE, addressFold, noteCommitment, nullifier } from "../../src/notes.ts";
import { compress } from "../../src/poseidon2.ts";
import { MNEMONIC, circuitVectors, fixture, testScalar } from "../helpers.ts";

interface HexPoint {
  x: string;
  y: string;
}

interface NoteVectors {
  owner: {
    mnemonic: string;
    network: "mainnet";
    account: number;
    diversifier_index: number;
    nk_fold: string;
  };
  notes: {
    value: string;
    g_d: HexPoint;
    pk_d: HexPoint;
    rcm: string;
    g_d_fold: string;
    pk_d_fold: string;
    address_fold: string;
    cm: string;
    pos: number;
    nf: string;
  }[];
  merkle: { levels: number; zeros: string[]; leaves: string[]; roots_after_each_insert: string[] };
}

interface DomainVectors {
  domains: { network: "mainnet" | "testnet"; asset: string; preimage: string; domain: string }[];
}

const NOTES = circuitVectors<NoteVectors>("notes.json");
const point = (p: HexPoint): Point => [BigInt(p.x), BigInt(p.y)];

// Every level of the whole tree, computed directly from the leaves.
function fullLevels(leaves: readonly bigint[]): bigint[][] {
  const levels = [[...leaves]];
  for (let level = 1; level <= LEVELS; level++) {
    const below = levels[level - 1] as bigint[];
    const nodes: bigint[] = [];
    for (let i = 0; i < Math.max(1, below.length); i += 2) {
      const zero = ZEROS[level - 1] as bigint;
      nodes.push(compress(below[i] ?? zero, below[i + 1] ?? zero));
    }
    levels.push(nodes);
  }
  return levels;
}

function directPath(levels: bigint[][], pos: number): bigint[] {
  return Array.from(
    { length: LEVELS },
    (_, level) => levels[level]?.[Math.floor(pos / 2 ** level) ^ 1] ?? (ZEROS[level] as bigint),
  );
}

describe("notes", () => {
  const keys = deriveSpendingKeys(mnemonicToSeedSync(MNEMONIC), "mainnet", 0);
  const address = defaultAddressKey(keys);

  it("uses the vectors' owner", () => {
    assert.equal(NOTES.owner.mnemonic, MNEMONIC);
    assert.equal(address.index, NOTES.owner.diversifier_index);
    assert.equal(toHex32(keys.nkFold), NOTES.owner.nk_fold);
  });

  for (const v of NOTES.notes) {
    it(`reproduces the commitment and nullifier of value ${v.value} at ${v.pos}`, () => {
      const gd = point(v.g_d);
      const pkd = point(v.pk_d);
      assert.deepEqual([gd, pkd], [address.gd, address.pkd]);
      assert.equal(toHex32(fold(gd, TAG.gd)), v.g_d_fold);
      assert.equal(toHex32(fold(pkd, TAG.pkd)), v.pk_d_fold);
      assert.equal(toHex32(addressFold(gd, pkd)), v.address_fold);
      const cm = noteCommitment({ value: BigInt(v.value), gd, pkd, rcm: BigInt(v.rcm) });
      assert.equal(toHex32(cm), v.cm);
      assert.equal(toHex32(nullifier(cm, v.pos, keys.nkFold)), v.nf);
    });
  }

  it("refuses values outside 64 bits", () => {
    const note = { gd: address.gd, pkd: address.pkd, rcm: 1n };
    assert.doesNotThrow(() => noteCommitment({ ...note, value: MAX_VALUE }));
    assert.throws(() => noteCommitment({ ...note, value: MAX_VALUE + 1n }));
    assert.throws(() => noteCommitment({ ...note, value: -1n }));
  });
});

describe("commitment tree", () => {
  it("reproduces the zeros and roots of notes.json", () => {
    assert.equal(NOTES.merkle.levels, LEVELS);
    assert.deepEqual(ZEROS.map(toHex32), NOTES.merkle.zeros);
    assert.equal(EMPTY_ROOT, ZEROS[LEVELS]);
    const leaves = NOTES.merkle.leaves.map(BigInt);
    leaves.forEach((_, i) => {
      const tree = CommitmentTree.empty();
      tree.applyPage(leaves.slice(0, i + 1));
      assert.equal(toHex32(tree.root()), NOTES.merkle.roots_after_each_insert[i]);
    });
    assert.equal(CommitmentTree.empty().root(), EMPTY_ROOT);
  });

  it("matches a direct computation across complete and incomplete pages", () => {
    const leaves = Array.from({ length: 2 * PAGE_SIZE + 130 }, (_, i) => testScalar("tree", i, P));
    const tree = CommitmentTree.empty();
    const completed: (readonly bigint[] | undefined)[] = [];
    for (let page = 0; page * PAGE_SIZE < leaves.length; page++) {
      // a page is served growing, then complete
      const content = leaves.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
      assert.equal(tree.applyPage(content.slice(0, 64)), undefined);
      completed.push(tree.applyPage(content));
    }
    assert.equal(completed.filter((c) => c !== undefined).length, 2);
    assert.equal(tree.leafCount, leaves.length);
    const levels = fullLevels(leaves);
    assert.equal(tree.root(), levels[LEVELS]?.[0]);

    for (const pos of [0, 1, 777, PAGE_SIZE, 2 * PAGE_SIZE - 1, 2 * PAGE_SIZE, leaves.length - 1]) {
      const page = Math.floor(pos / PAGE_SIZE);
      const path =
        page === tree.currentPage
          ? tree.partialPath(pos)
          : [
              ...pagePath(leaves.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), pos % PAGE_SIZE),
              ...tree.upperPath(pos),
            ];
      assert.deepEqual(path, directPath(levels, pos));
      assert.equal(rootFromPath(leaves[pos] as bigint, pos, path), tree.root());
    }
  });

  it("survives a snapshot", () => {
    const leaves = Array.from({ length: PAGE_SIZE + 6 }, (_, i) => testScalar("snap", i, P));
    const tree = CommitmentTree.empty();
    tree.applyPage(leaves.slice(0, PAGE_SIZE));
    tree.applyPage(leaves.slice(PAGE_SIZE));
    const copy = CommitmentTree.fromSnapshot(tree.snapshot());
    assert.equal(copy.root(), tree.root());
    assert.equal(copy.leafCount, tree.leafCount);
    assert.throws(() =>
      CommitmentTree.fromSnapshot({ ...tree.snapshot(), leafCount: tree.leafCount + 2 }),
    );
  });

  it("refuses a page whose known leaves changed", () => {
    const tree = CommitmentTree.empty();
    tree.applyPage([1n, 2n, 3n, 4n]);
    assert.throws(() => tree.applyPage([1n, 2n, 9n, 4n, 5n, 6n]));
    assert.throws(() => tree.applyPage([1n, 2n]));
    assert.equal(tree.leafCount, 4);
  });
});

describe("domain", () => {
  const vectors = fixture<DomainVectors>("domains.json");
  for (const v of vectors.domains) {
    it(`reproduces ${v.network}/${v.asset.split(":")[0]}`, () => {
      assert.equal(toHex32(computeDomain(v.network, v.asset)), v.domain);
    });
  }
});
