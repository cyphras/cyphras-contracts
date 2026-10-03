//! The incremental Merkle tree of commitments. Leaves exist only in events; the vault keeps the
//! frontier, the empty-subtree roots and the root history.

use poseidon2::Compressor;
use soroban_sdk::{Env, Vec, U256};

use crate::storage::{self, DataKey, RootRing};

/// The tree depth, which must match the circuit's `Transaction(levels, 2, 2)`.
pub const DEPTH: u32 = 32;
pub const ROOT_HISTORY: u32 = 256;
const CAPACITY: u64 = 1 << DEPTH;

/// Stores an empty tree. `Zeros[i]` is the root of an empty subtree of height `i`, up to
/// `Zeros[DEPTH]`, the root of the empty tree, which also fills the first slot of the ring.
pub fn init(env: &Env) {
    let hasher = Compressor::new(env);
    let mut zeros = Vec::new(env);
    let mut node = U256::from_u32(env, 0);
    zeros.push_back(node.clone());
    for _ in 0..DEPTH {
        node = hasher.compress(&node, &node);
        zeros.push_back(node.clone());
    }
    let mut roots = Vec::new(env);
    roots.push_back(node);
    for _ in 1..ROOT_HISTORY {
        roots.push_back(U256::from_u32(env, 0));
    }
    storage::set(env, &DataKey::Zeros, &zeros);
    storage::set(env, &DataKey::Frontier, &zeros.slice(0..DEPTH));
    storage::set(env, &DataKey::Roots, &RootRing { roots, newest: 0 });
    storage::set(env, &DataKey::NextLeaf, &0u64);
}

/// The root of the empty tree, the only root a shield may prove against.
pub fn empty_root(env: &Env) -> U256 {
    storage::get::<Vec<U256>>(env, &DataKey::Zeros)
        .unwrap()
        .get_unchecked(DEPTH)
}

pub fn next_leaf(env: &Env) -> u64 {
    storage::get(env, &DataKey::NextLeaf).unwrap()
}

pub fn has_room(next_leaf: u64) -> bool {
    next_leaf + 2 <= CAPACITY
}

/// The part of the tree a transaction is checked against.
pub struct Tree {
    pub roots: RootRing,
    pub next_leaf: u64,
}

impl Tree {
    pub fn load(env: &Env) -> Self {
        Tree {
            roots: storage::get(env, &DataKey::Roots).unwrap(),
            next_leaf: next_leaf(env),
        }
    }

    pub fn knows_root(&self, root: &U256) -> bool {
        *root != U256::from_u32(root.env(), 0) && self.roots.roots.contains(root)
    }

    pub fn current_root(&self) -> U256 {
        self.roots.roots.get_unchecked(self.roots.newest)
    }
}

/// Appends leaf pairs, keeping the frontier in memory so a batch of pairs reads and writes the
/// tree entries once.
pub struct Appender {
    env: Env,
    tree: Tree,
    zeros: Vec<U256>,
    frontier: Vec<U256>,
    hasher: Compressor,
}

impl Appender {
    pub fn new(env: &Env, tree: Tree) -> Self {
        Appender {
            env: env.clone(),
            tree,
            zeros: storage::get(env, &DataKey::Zeros).unwrap(),
            frontier: storage::get(env, &DataKey::Frontier).unwrap(),
            hasher: Compressor::new(env),
        }
    }

    pub fn has_room(&self) -> bool {
        has_room(self.tree.next_leaf)
    }

    /// Inserts `left` and `right` at the next two leaf indices, which start at an even index, and
    /// pushes the one new root. Returns the index of `left`. The caller checks `has_room`.
    pub fn append(&mut self, left: &U256, right: &U256) -> u64 {
        let index = self.tree.next_leaf;
        self.frontier.set(0, left.clone());
        let mut node = self.hasher.compress(left, right);
        let mut position = index >> 1;
        for level in 1..DEPTH {
            if position & 1 == 0 {
                self.frontier.set(level, node.clone());
                node = self
                    .hasher
                    .compress(&node, &self.zeros.get_unchecked(level));
            } else {
                node = self
                    .hasher
                    .compress(&self.frontier.get_unchecked(level), &node);
            }
            position >>= 1;
        }
        let ring = &mut self.tree.roots;
        ring.newest = (ring.newest + 1) % ROOT_HISTORY;
        ring.roots.set(ring.newest, node);
        self.tree.next_leaf = index + 2;
        index
    }

    pub fn save(self) {
        storage::set(&self.env, &DataKey::Frontier, &self.frontier);
        storage::set(&self.env, &DataKey::Roots, &self.tree.roots);
        storage::set(&self.env, &DataKey::NextLeaf, &self.tree.next_leaf);
    }
}
