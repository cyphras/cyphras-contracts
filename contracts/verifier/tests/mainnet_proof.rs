//! A proof made with the mainnet ceremony key, from circuits/scripts/mainnet-proof-fixture.mjs,
//! checked against the key the mainnet build embeds.
#![cfg(feature = "mainnet")]

use serde_json::Value;
use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    Bytes, BytesN, Env, Vec, U256,
};
use types::Groth16Proof;
use verifier::{verify, VerifyingKey, FORGEABLE};

const PROOF: &str = include_str!("mainnet_proof.json");

fn bytes<const N: usize>(hex: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn fixture(env: &Env) -> (Groth16Proof, Vec<Bn254Fr>) {
    let p: Value = serde_json::from_str(PROOF).unwrap();
    let proof = Groth16Proof {
        a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &bytes(p["a"].as_str().unwrap()))),
        b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &bytes(p["b"].as_str().unwrap()))),
        c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &bytes(p["c"].as_str().unwrap()))),
    };
    let mut inputs = Vec::new(env);
    for input in p["inputs"].as_array().unwrap() {
        let hex = input.as_str().unwrap().trim_start_matches("0x");
        let value = U256::from_be_bytes(env, &Bytes::from_array(env, &bytes::<32>(hex)));
        inputs.push_back(Bn254Fr::from_u256(value));
    }
    (proof, inputs)
}

#[test]
fn the_mainnet_build_embeds_the_ceremony_key() {
    assert!(!FORGEABLE);
}

#[test]
fn a_proof_made_with_the_ceremony_key_verifies() {
    let env = Env::default();
    let (proof, inputs) = fixture(&env);
    assert!(verify(&env, &VerifyingKey::embedded(&env), &proof, inputs));
}

#[test]
fn the_same_proof_of_other_inputs_does_not_verify() {
    let env = Env::default();
    let (proof, inputs) = fixture(&env);
    let mut changed = inputs.clone();
    changed.set(1, Bn254Fr::from_u256(U256::from_u32(&env, 1)));
    assert!(!verify(
        &env,
        &VerifyingKey::embedded(&env),
        &proof,
        changed
    ));
}
