//! The incremental Merkle tree of commitments. Leaves exist only in events; the vault keeps the
//! frontier and the root history.

use poseidon2::Compressor;
use soroban_sdk::{Env, Vec, U256};

use crate::storage::{self, DataKey, RootRing};

/// The tree depth, which must match the circuit's `Transaction(levels, 2, 2)`.
pub const DEPTH: u32 = 32;
pub const ROOT_HISTORY: u32 = 256;
const CAPACITY: u64 = 1 << DEPTH;

// ZEROS[i] is the root of an empty subtree of height i, as big-endian 64-bit limbs: ZEROS[0] is
// the empty leaf 0 and ZEROS[i] = compress(ZEROS[i - 1], ZEROS[i - 1]). ZEROS[DEPTH] is the root of
// the empty tree.
const ZEROS: [[u64; 4]; DEPTH as usize + 1] = [
    [
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0x228981b886e5effb,
        0x2c05a6be7ab4a05f,
        0xde6bf702a2d039e4,
        0x6c87057dd729ef97,
    ],
    [
        0x218fbf2e2f12f047,
        0x5d3dcf2e0ab1bd4b,
        0x9ab528e954738c18,
        0xc4b7c9b5f4b84964,
    ],
    [
        0x2e16a8d602271ea5,
        0x0b5a1bd35b854610,
        0xef0bddf8f385bdeb,
        0x0bb31c4562fa0cd6,
    ],
    [
        0x2b44a101801fa0b8,
        0x10feb3d82c25e71b,
        0x88bc6f4aeecd9fcd,
        0xc2152b1f3c38d044,
    ],
    [
        0x19f2fcaf65567ab8,
        0x803e4fb84e678548,
        0x15d83a4e1b7be24c,
        0x6814ba2ba9bdc5ca,
    ],
    [
        0x1a3bd772e2782ad0,
        0x18b9c451bf66c3b0,
        0xad223a0e68347fae,
        0x11c78681bf6478df,
    ],
    [
        0x034d4539eb246822,
        0x72ab024133ca575c,
        0x1cade051f9fdce59,
        0x48b6b806767e225b,
    ],
    [
        0x2971eb2b9cd60a12,
        0x70db7ab8aada485f,
        0x64fae5a5e85bed73,
        0x6c67329c410fffee,
    ],
    [
        0x2ef220cf75c94a6b,
        0xc8f4900fe8153ce5,
        0x3132c2de05163d55,
        0xecd0fd13519104b4,
    ],
    [
        0x2075381e03f1e1f6,
        0x0029fc3079d49b91,
        0x8c967b58e2655b17,
        0x70c86ca3984ab65c,
    ],
    [
        0x1d4789eb40dffb09,
        0x091a0690d88df7ff,
        0x993c23d172e866a9,
        0x3631f6792909118c,
    ],
    [
        0x2b082d0afac14544,
        0xd746c924d6fc882f,
        0x6931b7b6aacd796c,
        0x82d7fe81ce33ce4c,
    ],
    [
        0x175c16bc97822dba,
        0x5fdf5580638d4983,
        0x831dab655f5095bd,
        0xe23b6685f61981cd,
    ],
    [
        0x0c4b05c87053bf23,
        0x6ef505872eac4304,
        0x546d3c4f989b1d19,
        0xb93ef9115e883f66,
    ],
    [
        0x2d7e044c16807771,
        0x000769efac4e9147,
        0xa90359c5f58da398,
        0x80697de3afdd6d56,
    ],
    [
        0x18b029a33a590d74,
        0x8323e8d6cb8ac763,
        0x6cdff4a154ddb7e1,
        0x9ac9cb6845adff69,
    ],
    [
        0x1e45bd2b39d74ef5,
        0x0d211fc7303d55a0,
        0x6478517cd4488730,
        0x8ba40cb6d4d44216,
    ],
    [
        0x189b2c3495c37308,
        0x649a0c3e9fe3dd06,
        0xe83612e9cb152883,
        0x3acf358bc9b43271,
    ],
    [
        0x0ec11644818dab9d,
        0x62fdacacda9fdc5d,
        0x2fb6f4627a332e3b,
        0x25bbbc7dfb0672e7,
    ],
    [
        0x119827e780a1850d,
        0x7b7e34646edc1ce9,
        0x18211c26dda4e13b,
        0xcd1611f6f81c3680,
    ],
    [
        0x084449b11bad2bd2,
        0x6ab39b799cccb940,
        0x8c4f3bcdbef4210f,
        0x5cd6544d821c85c6,
    ],
    [
        0x02f313f5eaf87dd5,
        0xe81f34e8ef6b98c2,
        0x928272ba35b80821,
        0x267b95176775a5dd,
    ],
    [
        0x2d01ab8332efd3bc,
        0xd5d4fe99cdb66d80,
        0x9fbf6a1a84c93194,
        0x2ea40fb5cf4ebdaa,
    ],
    [
        0x2adfa5bb110a9201,
        0x58ca367f5cfa6f63,
        0x2aeb78a9a7b1f2d9,
        0xc0d29f2a197c244b,
    ],
    [
        0x1045e59b73045e7b,
        0xb07ad0bd51e8b5ec,
        0x08c2b71abc64eaec,
        0x485ad91a2a528ea8,
    ],
    [
        0x1549ebd6196d7d30,
        0x3bf4791a3b33c088,
        0x09f19e5ebf9a5ef5,
        0xba438d3ec4d9a324,
    ],
    [
        0x305e08a953165f5d,
        0x8e4560d619ca03d0,
        0x5c06e7514dfb7f7a,
        0x2a25dfaf558907dc,
    ],
    [
        0x0fb5add1601d2850,
        0x978d2c5b2de15426,
        0xa50b7c766c593984,
        0x3637f759a34ab617,
    ],
    [
        0x232052690c527bf3,
        0x5f76a2fd8db54c96,
        0xf1dd28d009e19c6d,
        0x00af6d389188fac5,
    ],
    [
        0x228ffdf6570d757e,
        0x6ebc79516241b636,
        0xbdceed0996036242,
        0xd00fdd61050975a2,
    ],
    [
        0x05933a091621546e,
        0xd0b08a34233c40bf,
        0xfd7de08aac23eda0,
        0x986afc620f1ebe84,
    ],
    [
        0x2dab419ddd63b813,
        0xb7a156068546ace4,
        0x06b72a8a6207dbf3,
        0x88e6fe1c8174246c,
    ],
];

pub fn zero(env: &Env, height: u32) -> U256 {
    let limbs = &ZEROS[height as usize];
    U256::from_parts(env, limbs[0], limbs[1], limbs[2], limbs[3])
}

/// Stores an empty tree, whose root fills the first slot of the ring.
pub fn init(env: &Env) {
    let mut frontier = Vec::new(env);
    for height in 0..DEPTH {
        frontier.push_back(zero(env, height));
    }
    let mut roots = Vec::new(env);
    roots.push_back(empty_root(env));
    for _ in 1..ROOT_HISTORY {
        roots.push_back(U256::from_u32(env, 0));
    }
    storage::set(env, &DataKey::Frontier, &frontier);
    storage::set(env, &DataKey::Roots, &RootRing { roots, newest: 0 });
    storage::set(env, &DataKey::NextLeaf, &0u64);
}

/// The root of the empty tree, the only root a shield may prove against.
pub fn empty_root(env: &Env) -> U256 {
    zero(env, DEPTH)
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
    frontier: Vec<U256>,
    hasher: Compressor,
}

impl Appender {
    pub fn new(env: &Env, tree: Tree) -> Self {
        Appender {
            env: env.clone(),
            tree,
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
                node = self.hasher.compress(&node, &zero(&self.env, level));
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
