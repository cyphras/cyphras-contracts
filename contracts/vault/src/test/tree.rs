use poseidon2::Compressor;
use soroban_sdk::{Env, Vec, U256};

use super::{
    fixtures,
    setup::{Setup, DELAY_SMALL, XLM},
};
use crate::{
    storage::{self, DataKey},
    tree::{Appender, Tree, DEPTH, ROOT_HISTORY},
    Error, RootRing,
};

/// The root of a tree holding `leaves` from index 0, recomputed level by level.
pub fn reference_root(env: &Env, leaves: &[U256]) -> U256 {
    env.cost_estimate().budget().reset_unlimited();
    let hasher = Compressor::new(env);
    let mut level = leaves.to_vec();
    let mut zero = U256::from_u32(env, 0);
    for _ in 0..DEPTH {
        if level.len() % 2 == 1 {
            level.push(zero.clone());
        }
        level = level
            .chunks(2)
            .map(|pair| hasher.compress(&pair[0], &pair[1]))
            .collect();
        zero = hasher.compress(&zero, &zero);
    }
    level.first().cloned().unwrap_or(zero)
}

/// Inserts pairs straight into the tree, without the proofs a transaction needs, in batches that
/// fit the per-invocation limits.
pub fn append(s: &Setup, pairs: &[(U256, U256)]) {
    for batch in pairs.chunks(25) {
        s.env.cost_estimate().budget().reset_unlimited();
        s.env.as_contract(&s.vault.address, || {
            let mut appender = Appender::new(&s.env, Tree::load(&s.env));
            for (left, right) in batch {
                appender.append(left, right);
            }
            appender.save();
        });
    }
}

#[test]
fn an_empty_tree_matches_the_reference_zeros() {
    let s = Setup::new();
    let env = &s.env;
    let notes = fixtures::notes();
    assert_eq!(notes["merkle"]["levels"].as_u64(), Some(DEPTH as u64));
    let zeros = notes["merkle"]["zeros"].as_array().unwrap();
    assert_eq!(
        s.vault.current_root(),
        fixtures::field(env, &zeros[DEPTH as usize])
    );
    assert_eq!(s.vault.current_root(), reference_root(env, &[]));
    assert_eq!(s.vault.current_root(), s.empty_root);
    let stored: Vec<U256> = s.env.as_contract(&s.vault.address, || {
        storage::get(env, &DataKey::Zeros).unwrap()
    });
    assert_eq!(stored.len(), DEPTH + 1);
    for (i, zero) in stored.iter().enumerate() {
        assert_eq!(zero, fixtures::field(env, &zeros[i]));
    }
    assert!(!s.vault.is_known_root(&U256::from_u32(env, 0)));
    assert_eq!(s.vault.next_leaf_index(), 0);
}

#[test]
fn pair_insertion_matches_the_reference_vectors() {
    let s = Setup::new();
    let env = &s.env;
    let merkle = &fixtures::notes()["merkle"];
    let leaf = |i: usize| fixtures::field(env, &merkle["leaves"][i]);
    let root = |i: usize| fixtures::field(env, &merkle["roots_after_each_insert"][i]);
    append(&s, &[(leaf(0), leaf(1))]);
    assert_eq!(s.vault.current_root(), root(1));
    append(&s, &[(leaf(2), leaf(3))]);
    assert_eq!(s.vault.current_root(), root(3));
    assert_eq!(s.vault.next_leaf_index(), 4);
}

#[test]
fn incremental_roots_match_a_full_recomputation() {
    let s = Setup::new();
    let mut leaves = std::vec::Vec::new();
    // 70 pairs cross every power-of-two boundary up to 128 leaves.
    for _ in 0..70 {
        let pair = (s.field(), s.field());
        leaves.push(pair.0.clone());
        leaves.push(pair.1.clone());
        append(&s, &[pair]);
        assert_eq!(s.vault.current_root(), reference_root(&s.env, &leaves));
    }
}

#[test]
fn every_inserted_pair_pushes_exactly_one_root() {
    let s = Setup::new();
    s.fund_pool("funder", 100 * XLM);
    let relayer = s.account("relayer", 0);
    let ring_before: RootRing = s.env.as_contract(&s.vault.address, || {
        storage::get(&s.env, &DataKey::Roots).unwrap()
    });
    let ext = s.ext(-XLM, 0, &relayer, &relayer);
    s.transact(&relayer, &ext).unwrap();
    let ring: RootRing = s.env.as_contract(&s.vault.address, || {
        storage::get(&s.env, &DataKey::Roots).unwrap()
    });
    assert_eq!(ring.newest, ring_before.newest + 1);
    assert_eq!(ring.roots.len(), ROOT_HISTORY);
    for i in 0..ROOT_HISTORY {
        if i != ring.newest {
            assert_eq!(
                ring.roots.get_unchecked(i),
                ring_before.roots.get_unchecked(i)
            );
        }
    }
}

#[test]
fn a_root_stays_valid_for_255_later_insertions() {
    let s = Setup::new();
    s.fund_pool("funder", 1_000 * XLM);
    let relayer = s.account("relayer", 0);
    let oldest = s.vault.current_root();

    // 255 more pairs: the oldest root is still in the ring.
    let pairs: std::vec::Vec<_> = (0..255).map(|_| (s.field(), s.field())).collect();
    append(&s, &pairs);
    assert!(s.vault.is_known_root(&oldest));
    let ext = s.ext(-XLM, 0, &relayer, &relayer);
    let proof = s.prove_with(
        &ext,
        oldest.clone(),
        [s.field(), s.field()],
        [s.field(), s.field()],
    );
    // Settling it is the 256th insertion since `oldest`, which pushes it out of the ring.
    s.vault.transact(&proof, &ext, &relayer);
    assert!(!s.vault.is_known_root(&oldest));

    let ext = s.ext(-XLM, 0, &relayer, &relayer);
    let proof = s.prove_with(&ext, oldest, [s.field(), s.field()], [s.field(), s.field()]);
    let result = super::setup::outcome(s.vault.try_transact(&proof, &ext, &relayer));
    assert_eq!(result, Err(Error::UnknownRoot));

    // The ring has wrapped around: its newest slot index went past 255 back to the start.
    let ring: RootRing = s.env.as_contract(&s.vault.address, || {
        storage::get(&s.env, &DataKey::Roots).unwrap()
    });
    assert_eq!(ring.roots.len(), ROOT_HISTORY);
    assert_eq!(ring.newest, 1);
    for root in ring.roots.iter() {
        assert!(s.vault.is_known_root(&root));
    }
}

#[test]
fn a_full_tree_refuses_new_leaves() {
    let s = Setup::new();
    let depositor = s.account("depositor", 1_000 * XLM);
    let relayer = s.account("relayer", 0);
    s.fund_pool("funder", 100 * XLM);
    s.shield(&depositor, XLM).unwrap();
    s.shield(&depositor, XLM).unwrap();
    let (first, second) = (
        s.vault.status().next_deposit_id - 2,
        s.vault.status().next_deposit_id - 1,
    );
    s.vault.attest(&second);
    s.advance(DELAY_SMALL);

    // Two leaves of room left: one pair.
    s.env.as_contract(&s.vault.address, || {
        storage::set(&s.env, &DataKey::NextLeaf, &((1u64 << DEPTH) - 2));
    });
    let both = Vec::from_slice(&s.env, &[first, second]);
    assert_eq!(
        super::setup::outcome(s.vault.try_admit(&both)),
        Err(Error::TreeFull)
    );
    assert_eq!(
        s.vault.admit(&Vec::from_slice(&s.env, &[first])),
        Vec::from_slice(&s.env, &[first])
    );
    assert_eq!(s.vault.next_leaf_index(), 1u64 << DEPTH);

    assert_eq!(s.shield(&depositor, XLM), Err(Error::TreeFull));
    let ext = s.ext(-XLM, 0, &relayer, &relayer);
    assert_eq!(s.transact(&relayer, &ext), Err(Error::TreeFull));
    let one = Vec::from_slice(&s.env, &[second]);
    assert_eq!(
        super::setup::outcome(s.vault.try_admit(&one)),
        Err(Error::TreeFull)
    );
    // The deposit that no longer fits can still leave.
    s.vault.cancel(&second);
}
