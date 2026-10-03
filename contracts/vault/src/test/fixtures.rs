//! Real proofs from circuits/scripts/contract-fixtures.mjs, and the reference test vectors.

use serde_json::Value;
use soroban_sdk::{
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    vec, Address, Bytes, BytesN, Env, MuxedAddress, U256,
};
use types::{ExtData, Groth16Proof, TxProof};

const PROOFS: &str = include_str!("../../fixtures/proofs.json");
const DOMAINS: &str = include_str!("../../../../circuits/test/vectors/domains.json");
const NOTES: &str = include_str!("../../../../circuits/test/vectors/notes.json");

pub fn proofs() -> Value {
    serde_json::from_str(PROOFS).unwrap()
}

pub fn domains() -> Value {
    serde_json::from_str(DOMAINS).unwrap()
}

pub fn notes() -> Value {
    serde_json::from_str(NOTES).unwrap()
}

pub fn step(name: &str) -> Value {
    proofs()["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no fixture step {name}"))
        .clone()
}

pub fn vault_address(env: &Env) -> Address {
    Address::from_str(env, proofs()["vault"].as_str().unwrap())
}

pub fn account(env: &Env, name: &str) -> Address {
    Address::from_str(env, proofs()["accounts"][name].as_str().unwrap())
}

pub fn raw(hex: &str) -> std::vec::Vec<u8> {
    let hex = hex.trim_start_matches("0x");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

pub fn array<const N: usize>(hex: &str) -> [u8; N] {
    raw(hex).try_into().unwrap()
}

pub fn field(env: &Env, v: &Value) -> U256 {
    U256::from_be_bytes(
        env,
        &Bytes::from_array(env, &array::<32>(v.as_str().unwrap())),
    )
}

fn bytes(env: &Env, v: &Value) -> Bytes {
    Bytes::from_slice(env, &raw(v.as_str().unwrap()))
}

fn amount(v: &Value) -> i128 {
    v.as_str().unwrap().parse().unwrap()
}

pub fn ext(env: &Env, step: &Value) -> ExtData {
    let e = &step["ext"];
    ExtData {
        vault: Address::from_str(env, e["vault"].as_str().unwrap()),
        network_id: BytesN::from_array(env, &array(e["network_id"].as_str().unwrap())),
        deadline: e["deadline"].as_u64().unwrap() as u32,
        ext_amount: amount(&e["ext_amount"]),
        fee: amount(&e["fee"]),
        recipient: MuxedAddress::from_str(env, e["recipient"].as_str().unwrap()),
        relayer: Address::from_str(env, e["relayer"].as_str().unwrap()),
        encrypted_output0: bytes(env, &e["encrypted_output0"]),
        encrypted_output1: bytes(env, &e["encrypted_output1"]),
    }
}

pub fn proof(env: &Env, step: &Value) -> TxProof {
    let p = &step["proof"];
    let pair = |v: &Value| vec![env, field(env, &v[0]), field(env, &v[1])];
    TxProof {
        proof: Groth16Proof {
            a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &array(p["a"].as_str().unwrap()))),
            b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &array(p["b"].as_str().unwrap()))),
            c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &array(p["c"].as_str().unwrap()))),
        },
        root: field(env, &p["root"]),
        public_amount: field(env, &p["public_amount"]),
        ext_data_hash: field(env, &p["ext_data_hash"]),
        input_nullifiers: pair(&p["input_nullifiers"]),
        output_commitments: pair(&p["output_commitments"]),
    }
}
