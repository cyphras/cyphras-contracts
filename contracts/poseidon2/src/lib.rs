#![no_std]

//! Poseidon2 over the BN254 scalar field, computed with the CAP-0075 `poseidon2_permutation`
//! host function: the keyed hash `P2_n(x1..xn; tag)` and the Merkle compression.

mod constants;

use constants::{Params, T2, T3, T4};
use soroban_sdk::{symbol_short, vec, Env, Vec, U256};

/// Returns the BN254 scalar field order `p`.
pub fn modulus(env: &Env) -> U256 {
    U256::from_parts(
        env,
        0x30644e72e131a029,
        0xb85045b68181585d,
        0x2833e84879b97091,
        0x43e1f593f0000001,
    )
}

/// The Poseidon2 permutation for one state width: 8 full rounds, 56 partial rounds and the S-box
/// `x^5`. Building it once lets every use in an invocation share the parameter objects.
struct Permutation {
    env: Env,
    width: u32,
    mat_internal_diag_m_1: Vec<U256>,
    round_constants: Vec<Vec<U256>>,
}

impl Permutation {
    fn new(env: &Env, params: &Params) -> Self {
        let width = params.mat_internal_diag_m_1.len();
        let element =
            |limbs: &[u64; 4]| U256::from_parts(env, limbs[0], limbs[1], limbs[2], limbs[3]);
        let full_round = |round: usize| {
            let mut row = Vec::new(env);
            for limbs in &params.full[round * width..(round + 1) * width] {
                row.push_back(element(limbs));
            }
            row
        };

        // The host takes one row of `width` constants per round; a partial round only uses the
        // first.
        let mut round_constants = Vec::new(env);
        for round in 0..4 {
            round_constants.push_back(full_round(round));
        }
        for limbs in params.partial {
            let mut row = vec![env, element(limbs)];
            for _ in 1..width {
                row.push_back(U256::from_u32(env, 0));
            }
            round_constants.push_back(row);
        }
        for round in 4..8 {
            round_constants.push_back(full_round(round));
        }

        let mut mat_internal_diag_m_1 = Vec::new(env);
        for limbs in params.mat_internal_diag_m_1 {
            mat_internal_diag_m_1.push_back(element(limbs));
        }
        Permutation {
            env: env.clone(),
            width: width as u32,
            mat_internal_diag_m_1,
            round_constants,
        }
    }

    /// Every element of `state` must be canonical, below `p`: the host reduces larger values
    /// silently.
    fn permute(&self, state: &Vec<U256>) -> Vec<U256> {
        self.env.crypto_hazmat().poseidon2_permutation(
            state,
            symbol_short!("BN254"),
            self.width,
            5,
            8,
            56,
            &self.mat_internal_diag_m_1,
            &self.round_constants,
        )
    }
}

/// `P2_n(inputs; tag)` in hash mode for `n` in {1, 2, 3}: the state is `[x1, ..., xn, tag]` and
/// the output is `state[0]` after the permutation.
pub fn hash(env: &Env, inputs: &[U256], tag: u32) -> U256 {
    let params = match inputs.len() {
        1 => &T2,
        2 => &T3,
        3 => &T4,
        _ => panic!("Poseidon2 hashes one to three inputs"),
    };
    let mut state = Vec::new(env);
    for x in inputs {
        state.push_back(x.clone());
    }
    state.push_back(U256::from_u32(env, tag));
    Permutation::new(env, params)
        .permute(&state)
        .get_unchecked(0)
}

/// The `t = 2` compression `compress(l, r) = (P(l, r) + (l, r))[0]`, used only for Merkle nodes.
pub struct Compressor {
    permutation: Permutation,
    modulus: U256,
}

impl Compressor {
    pub fn new(env: &Env) -> Self {
        Compressor {
            permutation: Permutation::new(env, &T2),
            modulus: modulus(env),
        }
    }

    /// Both inputs must be canonical.
    pub fn compress(&self, left: &U256, right: &U256) -> U256 {
        let state = vec![&self.permutation.env, left.clone(), right.clone()];
        let sum = self.permutation.permute(&state).get_unchecked(0).add(left);
        if sum >= self.modulus {
            sum.sub(&self.modulus)
        } else {
            sum
        }
    }
}

#[cfg(test)]
mod test;
