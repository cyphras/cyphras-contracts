import { compress } from "./poseidon2.ts";

export const LEVELS = 32;
const PAGE_LEVELS = 10;
export const PAGE_SIZE = 1 << PAGE_LEVELS;
const CAPACITY = 2 ** LEVELS;

// ZEROS[i] is the root of an empty subtree of height i; the empty leaf is 0.
export const ZEROS: readonly bigint[] = (() => {
  const zeros = [0n];
  for (let i = 1; i <= LEVELS; i++) {
    const below = zeros[i - 1] as bigint;
    zeros.push(compress(below, below));
  }
  return zeros;
})();

export const EMPTY_ROOT = ZEROS[LEVELS] as bigint;

// Every level of a subtree of the given height whose leftmost leaves are `leaves`; absent nodes
// are left out and read as ZEROS.
function subtreeLevels(leaves: readonly bigint[], height: number): bigint[][] {
  const levels: bigint[][] = [[...leaves]];
  for (let level = 1; level <= height; level++) {
    const below = levels[level - 1] as bigint[];
    const nodes: bigint[] = [];
    for (let i = 0; i < below.length; i += 2) {
      nodes.push(compress(below[i] as bigint, below[i + 1] ?? (ZEROS[level - 1] as bigint)));
    }
    levels.push(nodes);
  }
  return levels;
}

function siblings(levels: readonly bigint[][], offset: number, height: number): bigint[] {
  const path: bigint[] = [];
  for (let level = 0; level < height; level++) {
    const sibling = (offset >> level) ^ 1;
    path.push(levels[level]?.[sibling] ?? (ZEROS[level] as bigint));
  }
  return path;
}

// The authentication path of `offset` inside one page, from the leaf level up to the page root.
export function pagePath(pageLeaves: readonly bigint[], offset: number): bigint[] {
  return siblings(subtreeLevels(pageLeaves, PAGE_LEVELS), offset, PAGE_LEVELS);
}

function pageRoot(pageLeaves: readonly bigint[]): bigint {
  return subtreeLevels(pageLeaves, PAGE_LEVELS)[PAGE_LEVELS]?.[0] ?? (ZEROS[PAGE_LEVELS] as bigint);
}

export interface TreeSnapshot {
  readonly leafCount: number;
  // upper[k] holds the complete nodes of level PAGE_LEVELS + k, left to right.
  readonly upper: readonly (readonly bigint[])[];
  // The commitments of the last, incomplete page.
  readonly partial: readonly bigint[];
}

// The local copy of the vault's commitment tree. Complete pages are kept only as their roots and
// the complete nodes above them, so the tree grows by about 64 bytes per page; the leaves of the
// incomplete last page are kept in full. Paths of owned notes in complete pages are captured when
// their page completes.
export class CommitmentTree {
  #leafCount: number;
  #upper: bigint[][];
  #partial: bigint[];
  #partialRoot: bigint | undefined;

  private constructor(snapshot: TreeSnapshot) {
    this.#leafCount = snapshot.leafCount;
    this.#upper = Array.from({ length: LEVELS - PAGE_LEVELS + 1 }, (_, k) => [
      ...(snapshot.upper[k] ?? []),
    ]);
    this.#partial = [...snapshot.partial];
  }

  static empty(): CommitmentTree {
    return new CommitmentTree({ leafCount: 0, upper: [], partial: [] });
  }

  static fromSnapshot(snapshot: TreeSnapshot): CommitmentTree {
    const tree = new CommitmentTree(snapshot);
    const pages = Math.floor(snapshot.leafCount / PAGE_SIZE);
    const consistent =
      Number.isSafeInteger(snapshot.leafCount) &&
      snapshot.leafCount >= 0 &&
      snapshot.leafCount <= CAPACITY &&
      snapshot.partial.length === snapshot.leafCount % PAGE_SIZE &&
      snapshot.upper.length <= LEVELS - PAGE_LEVELS + 1 &&
      tree.#upper.every((nodes, k) => nodes.length === Math.floor(pages / 2 ** k));
    if (!consistent) throw new RangeError("inconsistent tree snapshot");
    return tree;
  }

  snapshot(): TreeSnapshot {
    return {
      leafCount: this.#leafCount,
      upper: this.#upper.map((nodes) => [...nodes]),
      partial: [...this.#partial],
    };
  }

  get leafCount(): number {
    return this.#leafCount;
  }

  // The page the next leaf goes into, which is the one a sync fetches next.
  get currentPage(): number {
    return Math.floor(this.#leafCount / PAGE_SIZE);
  }

  get partialLeaves(): readonly bigint[] {
    return this.#partial;
  }

  // Applies the content of the current page as served. Its first leaves must be the ones already
  // applied. Returns the page's commitments when the page is now complete.
  applyPage(commitments: readonly bigint[]): readonly bigint[] | undefined {
    if (commitments.length > PAGE_SIZE) throw new RangeError("a page holds at most 1024 leaves");
    if (commitments.length < this.#partial.length) throw new RangeError("a page cannot shrink");
    this.#partial.forEach((cm, i) => {
      if (commitments[i] !== cm) throw new RangeError(`leaf ${i} of the page changed`);
    });
    const start = this.currentPage * PAGE_SIZE;
    if (start + commitments.length > CAPACITY) throw new RangeError("the tree is full");
    this.#partialRoot = undefined;
    this.#leafCount = start + commitments.length;
    if (commitments.length < PAGE_SIZE) {
      this.#partial = [...commitments];
      return undefined;
    }
    this.#partial = [];
    this.#pushComplete(0, pageRoot(commitments));
    return commitments;
  }

  // Appends leaves after the last one, across page boundaries. Returns every page this
  // completes, with its commitments, so paths inside it can be captured.
  append(leaves: readonly bigint[]): { page: number; leaves: readonly bigint[] }[] {
    const completed: { page: number; leaves: readonly bigint[] }[] = [];
    let rest = leaves;
    while (rest.length > 0) {
      const page = this.currentPage;
      const room = PAGE_SIZE - this.#partial.length;
      const done = this.applyPage([...this.#partial, ...rest.slice(0, room)]);
      if (done !== undefined) completed.push({ page, leaves: done });
      rest = rest.slice(room);
    }
    return completed;
  }

  // The full path of the leaf at `pos`, given its siblings inside a complete page.
  path(pos: number, pagePathOfLeaf: readonly bigint[] | undefined): bigint[] {
    if (pos >= this.#leafCount) throw new RangeError("the leaf is not in the tree");
    if (pos >= this.currentPage * PAGE_SIZE) return this.partialPath(pos);
    if (pagePathOfLeaf === undefined || pagePathOfLeaf.length !== PAGE_LEVELS) {
      throw new RangeError("the path inside a complete page is missing");
    }
    return [...pagePathOfLeaf, ...this.upperPath(pos)];
  }

  #pushComplete(k: number, node: bigint): void {
    const nodes = this.#upper[k] as bigint[];
    nodes.push(node);
    const index = nodes.length - 1;
    if (index % 2 === 1 && k < LEVELS - PAGE_LEVELS) {
      this.#pushComplete(k + 1, compress(nodes[index - 1] as bigint, node));
    }
  }

  #pageRootOfPartial(): bigint {
    this.#partialRoot ??= pageRoot(this.#partial);
    return this.#partialRoot;
  }

  // A node at level PAGE_LEVELS or above.
  node(level: number, index: number): bigint {
    const k = level - PAGE_LEVELS;
    const stored = this.#upper[k]?.[index];
    if (stored !== undefined) return stored;
    if (index * 2 ** level >= this.#leafCount) return ZEROS[level] as bigint;
    if (level === PAGE_LEVELS) return this.#pageRootOfPartial();
    return compress(this.node(level - 1, 2 * index), this.node(level - 1, 2 * index + 1));
  }

  root(): bigint {
    return this.node(LEVELS, 0);
  }

  // The siblings from level PAGE_LEVELS up to the root, for the leaf at `pos`.
  upperPath(pos: number): bigint[] {
    const path: bigint[] = [];
    for (let level = PAGE_LEVELS; level < LEVELS; level++) {
      path.push(this.node(level, Math.floor(pos / 2 ** level) ^ 1));
    }
    return path;
  }

  // The full path of a leaf in the incomplete page.
  partialPath(pos: number): bigint[] {
    if (pos < this.currentPage * PAGE_SIZE || pos >= this.#leafCount) {
      throw new RangeError("the leaf is not in the incomplete page");
    }
    return [...pagePath(this.#partial, pos % PAGE_SIZE), ...this.upperPath(pos)];
  }
}

// The root reached from a leaf and its path, as the circuit's MerkleProof computes it.
export function rootFromPath(leaf: bigint, pos: number, path: readonly bigint[]): bigint {
  let node = leaf;
  path.forEach((sibling, level) => {
    node =
      Math.floor(pos / 2 ** level) % 2 === 1 ? compress(sibling, node) : compress(node, sibling);
  });
  return node;
}
