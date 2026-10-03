//! A verifying key built from known scalars. Knowing them, a test forges a valid Groth16 proof for
//! any public inputs, so the vault's own checks and the real pairing run on arbitrary scenarios
//! without a prover. The real-proof tests use the embedded key instead.

use std::cell::Cell;

use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    BytesN, Env, Vec, U256,
};
use types::Groth16Proof;
use verifier::VerifyingKey;

const ALPHA: u64 = 3;
const BETA: u64 = 5;
const GAMMA: u64 = 7;
const DELTA: u64 = 11;
const IC: [u64; 9] = [13, 17, 19, 23, 29, 31, 37, 41, 43];

std::thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// While alive, the vault verifies against the trapdoor key on this thread.
pub struct Guard;

pub fn enable() -> Guard {
    ACTIVE.with(|active| active.set(true));
    Guard
}

impl Drop for Guard {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(false));
    }
}

pub fn active_key(env: &Env) -> Option<VerifyingKey> {
    ACTIVE.with(|active| active.get()).then(|| key(env))
}

fn be(f: &Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn g1(env: &Env, scalar: Fr) -> Bn254G1Affine {
    let p = (G1Affine::generator() * scalar).into_affine();
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&be(&p.x));
    out[32..].copy_from_slice(&be(&p.y));
    Bn254G1Affine::from_bytes(BytesN::from_array(env, &out))
}

fn g2(env: &Env, scalar: Fr) -> Bn254G2Affine {
    let p = (G2Affine::generator() * scalar).into_affine();
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&be(&p.x.c1));
    out[32..64].copy_from_slice(&be(&p.x.c0));
    out[64..96].copy_from_slice(&be(&p.y.c1));
    out[96..].copy_from_slice(&be(&p.y.c0));
    Bn254G2Affine::from_bytes(BytesN::from_array(env, &out))
}

pub fn key(env: &Env) -> VerifyingKey {
    let mut ic = Vec::new(env);
    for s in &IC[1..] {
        ic.push_back(g1(env, Fr::from(*s)));
    }
    VerifyingKey {
        alpha: g1(env, Fr::from(ALPHA)),
        beta: g2(env, Fr::from(BETA)),
        gamma: g2(env, Fr::from(GAMMA)),
        delta: g2(env, Fr::from(DELTA)),
        ic0: g1(env, Fr::from(IC[0])),
        ic,
    }
}

fn scalar(x: &U256) -> Fr {
    let bytes = x.to_be_bytes();
    let mut buf = [0u8; 32];
    bytes.copy_into_slice(&mut buf);
    Fr::from_be_bytes_mod_order(&buf)
}

/// With A = alpha and B = beta the pairing equation reduces to
/// `e(vk_x, gamma) * e(C, delta) = 1`, which `C = -(gamma / delta) * vk_x` satisfies.
pub fn forge(env: &Env, inputs: &[U256; 8]) -> Groth16Proof {
    let mut vk_x = Fr::from(IC[0]);
    for (x, s) in inputs.iter().zip(&IC[1..]) {
        vk_x += scalar(x) * Fr::from(*s);
    }
    let c = -(Fr::from(GAMMA) * vk_x) * Fr::from(DELTA).inverse().unwrap();
    Groth16Proof {
        a: g1(env, Fr::from(ALPHA)),
        b: g2(env, Fr::from(BETA)),
        c: g1(env, c),
    }
}
