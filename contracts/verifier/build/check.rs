// Checks a snarkjs `verification_key.json` before the build compiles it in, and encodes it the
// way the host expects. Shared by build.rs and the tests in tests/key_check.rs.

use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PUBLIC_INPUTS: usize = 8;

// SHA-256 of keys/testnet-forgeable/verification_key.json, the dev key from the circuit's
// `setup:testnet-forgeable` script. Whoever ran that setup can forge proofs for it.
pub const FORGEABLE_SHA256: &str =
    "526f5befc2ff836621cc6f2f181fa50de3318a6865d6eca2121c678a225e2b9c";

// SHA-256 of keys/mainnet/verification_key.json, set from the multi-party ceremony output. Until
// then a mainnet build fails.
pub const MAINNET_SHA256: Option<&str> = None;

pub struct Key {
    pub alpha: [u8; 64],
    pub beta: [u8; 128],
    pub gamma: [u8; 128],
    pub delta: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn testnet_forgeable(json: &[u8]) -> Result<Key, String> {
    pinned(json, FORGEABLE_SHA256)?;
    parse(json)
}

/// Refuses the forgeable dev key by file hash and by its phase-2 `delta`, whether or not the
/// mainnet pin was set to it, before it checks the pin.
pub fn mainnet(json: &[u8], forgeable_json: &[u8], pin: Option<&str>) -> Result<Key, String> {
    let key = parse(json)?;
    if sha256_hex(json) == FORGEABLE_SHA256 || key.delta == parse(forgeable_json)?.delta {
        return Err("the testnet-forgeable key cannot back a mainnet build".into());
    }
    let pin = pin.ok_or("no mainnet verifying key is pinned yet")?;
    pinned(json, pin)?;
    Ok(key)
}

fn pinned(json: &[u8], expected: &str) -> Result<(), String> {
    let actual = sha256_hex(json);
    if actual != expected {
        return Err(format!(
            "verifying key sha256 {actual} does not match the pinned {expected}"
        ));
    }
    Ok(())
}

pub fn parse(json: &[u8]) -> Result<Key, String> {
    let v: Value = serde_json::from_slice(json).map_err(|e| format!("not JSON: {e}"))?;
    if v["protocol"] != "groth16" || v["curve"] != "bn128" {
        return Err("the key must be Groth16 over BN254".into());
    }
    if v["nPublic"].as_u64() != Some(PUBLIC_INPUTS as u64) {
        return Err(format!("the key must have {PUBLIC_INPUTS} public inputs"));
    }
    let ic = v["IC"].as_array().ok_or("IC is missing")?;
    if ic.len() != PUBLIC_INPUTS + 1 {
        return Err(format!("the key must have {} IC points", PUBLIC_INPUTS + 1));
    }

    let gamma = g2(&v["vk_gamma_2"])?;
    let delta = g2(&v["vk_delta_2"])?;
    // snarkjs fixes gamma to the generator and the setup starts delta there too, so a key whose
    // delta is still the generator, or equal to gamma, never received a phase-2 contribution.
    if delta == gamma || delta == G2Affine::generator() {
        return Err("delta was never changed by a phase-2 contribution".into());
    }

    Ok(Key {
        alpha: encode_g1(&g1(&v["vk_alpha_1"])?),
        beta: encode_g2(&g2(&v["vk_beta_2"])?),
        gamma: encode_g2(&gamma),
        delta: encode_g2(&delta),
        ic: ic
            .iter()
            .map(|p| g1(p).map(|p| encode_g1(&p)))
            .collect::<Result<_, _>>()?,
    })
}

fn fq(v: &Value) -> Result<Fq, String> {
    let n: BigUint = v
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or("a coordinate is not a decimal string")?;
    if n >= BigUint::from(Fq::MODULUS) {
        return Err("a coordinate is not below the field modulus".into());
    }
    Ok(Fq::from(n))
}

// snarkjs writes affine points with a third coordinate of 1; its point at infinity has 0 there.
fn affine_marker(v: &Value, one: &Value) -> Result<(), String> {
    if v != one {
        return Err("a key point is not an affine point".into());
    }
    Ok(())
}

fn g1(v: &Value) -> Result<G1Affine, String> {
    let c = v
        .as_array()
        .filter(|c| c.len() == 3)
        .ok_or("bad G1 point")?;
    affine_marker(&c[2], &Value::from("1"))?;
    let p = G1Affine::new_unchecked(fq(&c[0])?, fq(&c[1])?);
    if !p.is_on_curve() {
        return Err("a G1 point is not on the curve".into());
    }
    Ok(p)
}

fn g2(v: &Value) -> Result<G2Affine, String> {
    let c = v
        .as_array()
        .filter(|c| c.len() == 3)
        .ok_or("bad G2 point")?;
    affine_marker(&c[2], &serde_json::json!(["1", "0"]))?;
    let coordinate = |v: &Value| -> Result<Fq2, String> {
        let pair = v
            .as_array()
            .filter(|p| p.len() == 2)
            .ok_or("bad Fq2 element")?;
        Ok(Fq2::new(fq(&pair[0])?, fq(&pair[1])?))
    };
    let p = G2Affine::new_unchecked(coordinate(&c[0])?, coordinate(&c[1])?);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err("a G2 point is not in G2".into());
    }
    Ok(p)
}

fn be(f: &Fq) -> [u8; 32] {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn encode_g1(p: &G1Affine) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&be(&p.x));
    out[32..].copy_from_slice(&be(&p.y));
    out
}

// The host orders each Fq2 coordinate as c1 || c0.
fn encode_g2(p: &G2Affine) -> [u8; 128] {
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&be(&p.x.c1));
    out[32..64].copy_from_slice(&be(&p.x.c0));
    out[64..96].copy_from_slice(&be(&p.y.c1));
    out[96..].copy_from_slice(&be(&p.y.c0));
    out
}
