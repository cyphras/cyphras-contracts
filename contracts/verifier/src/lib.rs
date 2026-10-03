#![no_std]

//! Groth16 verification over BN254 against a verifying key compiled in at build time.

use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, BytesN, Env, Vec,
};
use types::Groth16Proof;

mod key {
    include!(concat!(env!("OUT_DIR"), "/vk.rs"));
}

pub const PUBLIC_INPUTS: u32 = 8;

/// A Groth16 verifying key in the host's encoding. `ic0` is the constant term of `vk_x` and `ic`
/// holds one point per public input.
pub struct VerifyingKey {
    pub alpha: Bn254G1Affine,
    pub beta: Bn254G2Affine,
    pub gamma: Bn254G2Affine,
    pub delta: Bn254G2Affine,
    pub ic0: Bn254G1Affine,
    pub ic: Vec<Bn254G1Affine>,
}

impl VerifyingKey {
    /// The key compiled in from `keys/`: the testnet-forgeable dev key, or the ceremony key when
    /// built with the `mainnet` feature.
    pub fn embedded(env: &Env) -> Self {
        let g1 = |b: &[u8; 64]| Bn254G1Affine::from_bytes(BytesN::from_array(env, b));
        let g2 = |b: &[u8; 128]| Bn254G2Affine::from_bytes(BytesN::from_array(env, b));
        let mut ic = Vec::new(env);
        for point in &key::IC[1..] {
            ic.push_back(g1(point));
        }
        VerifyingKey {
            alpha: g1(&key::ALPHA),
            beta: g2(&key::BETA),
            gamma: g2(&key::GAMMA),
            delta: g2(&key::DELTA),
            ic0: g1(&key::IC[0]),
            ic,
        }
    }
}

/// Returns true only for a valid proof of `inputs` under `vk`.
///
/// The pairing host function checks that `b` is on the curve and in G2 before it pairs anything,
/// and traps otherwise; the SDK has no separate G2 membership check.
pub fn verify(env: &Env, vk: &VerifyingKey, proof: &Groth16Proof, inputs: Vec<Bn254Fr>) -> bool {
    if inputs.len() != PUBLIC_INPUTS || vk.ic.len() != PUBLIC_INPUTS {
        return false;
    }
    let bn254 = env.crypto().bn254();

    // The pairing would also refuse a point off the curve, but by trapping; checking first turns a
    // malformed proof into a plain rejection. An honest proof never holds the identity, and
    // refusing it removes the trivial pairings it would create.
    let g1_zero = BytesN::from_array(env, &[0; 64]);
    let g2_zero = BytesN::from_array(env, &[0; 128]);
    if !bn254.g1_is_on_curve(&proof.a)
        || !bn254.g1_is_on_curve(&proof.c)
        || proof.a.to_bytes() == g1_zero
        || proof.c.to_bytes() == g1_zero
        || proof.b.to_bytes() == g2_zero
    {
        return false;
    }

    let vk_x = bn254.g1_add(&vk.ic0, &bn254.g1_msm(vk.ic.clone(), inputs));
    bn254.pairing_check(
        vec![env, -&proof.a, vk.alpha.clone(), vk_x, proof.c.clone()],
        vec![
            env,
            proof.b.clone(),
            vk.beta.clone(),
            vk.gamma.clone(),
            vk.delta.clone(),
        ],
    )
}
