#![cfg(test)]
extern crate std;

use super::{VerifierContract, VerifierContractClient};
use soroban_sdk::{Bytes, BytesN, Env, Vec};

const FIXTURE: &str = include_str!("../tests/proof_fixture.json");
// The actual deployment artifact produced by circuits/scripts/parse-vk.mjs.
const VK_PARSED: &str = include_str!("../../../circuits/build/testnet/vk_parsed.json");

fn decode<const N: usize>(env: &Env, hex_str: &str) -> BytesN<N> {
    let raw = hex::decode(hex_str).unwrap();
    let arr: [u8; N] = raw.try_into().unwrap();
    BytesN::from_array(env, &arr)
}

fn decode_bytes(env: &Env, hex_str: &str) -> Bytes {
    let raw = hex::decode(hex_str).unwrap();
    Bytes::from_slice(env, &raw)
}

fn deploy_from_vk<'a>(env: &Env, vk: &serde_json::Value) -> VerifierContractClient<'a> {
    let mut ic = Vec::new(env);
    for item in vk["ic"].as_array().unwrap() {
        ic.push_back(decode::<64>(env, item.as_str().unwrap()));
    }
    let id = env.register(
        VerifierContract,
        (
            decode::<64>(env, vk["alpha_g1"].as_str().unwrap()),
            decode::<128>(env, vk["beta_g2"].as_str().unwrap()),
            decode::<128>(env, vk["gamma_g2"].as_str().unwrap()),
            decode::<128>(env, vk["delta_g2"].as_str().unwrap()),
            ic,
        ),
    );
    VerifierContractClient::new(env, &id)
}

#[test]
fn verifies_real_proof_and_rejects_tampered() {
    let env = Env::default();

    let f: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let client = deploy_from_vk(&env, &f["vk"]);

    let proof = decode_bytes(&env, f["proof"].as_str().unwrap());
    let ps = f["publicSignals"].as_array().unwrap();
    let sig = |i: usize| decode::<32>(&env, ps[i].as_str().unwrap());

    let ok = client.verify(
        &proof,
        &sig(0),
        &sig(1),
        &sig(2),
        &sig(3),
        &sig(4),
        &sig(5),
        &sig(6),
    );
    assert!(ok, "valid proof must verify");

    let tampered = decode::<32>(
        &env,
        "0000000000000000000000000000000000000000000000000000000000000001",
    );
    let ok_tampered = client.verify(
        &proof,
        &sig(0),
        &sig(1),
        &tampered,
        &sig(3),
        &sig(4),
        &sig(5),
        &sig(6),
    );
    assert!(!ok_tampered, "tampered public input must not verify");

    // non-canonical input: r itself (the Fr modulus) is >= r and must be rejected
    let non_canonical = decode::<32>(
        &env,
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    );
    let ok_nc = client.verify(
        &proof,
        &sig(0),
        &sig(1),
        &non_canonical,
        &sig(3),
        &sig(4),
        &sig(5),
        &sig(6),
    );
    assert!(!ok_nc, "non-canonical public input must not verify");
}

#[test]
fn verifies_with_production_vk_from_parse_vk() {
    // Proves the deployment path: the VK bytes emitted by parse-vk.mjs feed the constructor and
    // verify a real proof. Guards against a serialization mismatch between the parser and
    // the contract.
    let env = Env::default();

    let vk: serde_json::Value = serde_json::from_str(VK_PARSED).unwrap();
    let client = deploy_from_vk(&env, &vk);

    let f: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let proof = decode_bytes(&env, f["proof"].as_str().unwrap());
    let ps = f["publicSignals"].as_array().unwrap();
    let sig = |i: usize| decode::<32>(&env, ps[i].as_str().unwrap());

    let ok = client.verify(
        &proof,
        &sig(0),
        &sig(1),
        &sig(2),
        &sig(3),
        &sig(4),
        &sig(5),
        &sig(6),
    );
    assert!(
        ok,
        "production VK from parse-vk.mjs must verify a real proof"
    );
}
