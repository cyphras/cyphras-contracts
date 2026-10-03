// The checks build.rs applies before it compiles a verifying key in.

#[allow(dead_code)]
#[path = "../build/check.rs"]
mod check;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use serde_json::{json, Value};

const FORGEABLE: &[u8] = include_bytes!("../keys/testnet-forgeable/verification_key.json");

fn decimal(f: Fq) -> String {
    BigUint::from(f.into_bigint()).to_string()
}

fn g1_json(p: G1Affine) -> Value {
    json!([decimal(p.x), decimal(p.y), "1"])
}

fn g2_json(p: G2Affine) -> Value {
    json!([
        [decimal(p.x.c0), decimal(p.x.c1)],
        [decimal(p.y.c0), decimal(p.y.c1)],
        ["1", "0"]
    ])
}

// A well-formed key with independent random-looking points, shaped like snarkjs output.
fn synthetic_key(delta_scalar: u64) -> Value {
    let g1 = |s: u64| (G1Affine::generator() * Fr::from(s)).into_affine();
    let g2 = |s: u64| (G2Affine::generator() * Fr::from(s)).into_affine();
    json!({
        "protocol": "groth16",
        "curve": "bn128",
        "nPublic": 8,
        "vk_alpha_1": g1_json(g1(11)),
        "vk_beta_2": g2_json(g2(13)),
        "vk_gamma_2": g2_json(G2Affine::generator()),
        "vk_delta_2": g2_json(g2(delta_scalar)),
        "IC": (0..9).map(|i| g1_json(g1(100 + i))).collect::<Vec<_>>(),
    })
}

fn bytes(v: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(v).unwrap()
}

fn rejects(v: &Value, expected: &str) {
    match check::parse(&bytes(v)) {
        Ok(_) => panic!("accepted a key that should fail with: {expected}"),
        Err(e) => assert!(e.contains(expected), "{e}"),
    }
}

#[test]
fn the_default_build_accepts_the_pinned_forgeable_key() {
    let key = check::testnet_forgeable(FORGEABLE).unwrap();
    assert_eq!(key.ic.len(), check::PUBLIC_INPUTS + 1);
    assert_eq!(check::sha256_hex(FORGEABLE), check::FORGEABLE_SHA256);
}

#[test]
fn the_default_build_rejects_any_other_key() {
    let other = bytes(&synthetic_key(17));
    assert!(check::testnet_forgeable(&other)
        .err()
        .unwrap()
        .contains("does not match the pinned"));
}

#[test]
fn the_mainnet_build_refuses_the_forgeable_key_even_when_pinned_to_it() {
    for pin in [None, Some(check::FORGEABLE_SHA256)] {
        let err = check::mainnet(FORGEABLE, FORGEABLE, pin).err().unwrap();
        assert!(err.contains("testnet-forgeable"), "{err}");
    }

    // Reformatting the file changes its hash but not its delta.
    let reformatted = bytes(&serde_json::from_slice::<Value>(FORGEABLE).unwrap());
    assert_ne!(check::sha256_hex(&reformatted), check::FORGEABLE_SHA256);
    let pin = check::sha256_hex(&reformatted);
    let err = check::mainnet(&reformatted, FORGEABLE, Some(&pin))
        .err()
        .unwrap();
    assert!(err.contains("testnet-forgeable"), "{err}");
}

#[test]
fn the_mainnet_build_needs_a_pin_and_a_matching_key() {
    let key = bytes(&synthetic_key(17));
    let err = check::mainnet(&key, FORGEABLE, check::MAINNET_SHA256)
        .err()
        .unwrap();
    assert!(err.contains("no mainnet verifying key is pinned"), "{err}");

    let other = check::sha256_hex(&bytes(&synthetic_key(19)));
    let err = check::mainnet(&key, FORGEABLE, Some(&other)).err().unwrap();
    assert!(err.contains("does not match the pinned"), "{err}");

    let pin = check::sha256_hex(&key);
    assert!(check::mainnet(&key, FORGEABLE, Some(&pin)).is_ok());
}

#[test]
fn a_key_without_a_phase_2_contribution_is_refused() {
    let mut v = synthetic_key(17);
    v["vk_delta_2"] = v["vk_gamma_2"].clone();
    rejects(&v, "never changed by a phase-2 contribution");

    let mut v = synthetic_key(17);
    v["vk_gamma_2"] = synthetic_key(23)["vk_delta_2"].clone();
    v["vk_delta_2"] = g2_json(G2Affine::generator());
    rejects(&v, "never changed by a phase-2 contribution");
}

#[test]
fn a_key_of_the_wrong_shape_is_refused() {
    let mut v = synthetic_key(17);
    v["protocol"] = json!("plonk");
    rejects(&v, "Groth16 over BN254");

    let mut v = synthetic_key(17);
    v["curve"] = json!("bls12381");
    rejects(&v, "Groth16 over BN254");

    let mut v = synthetic_key(17);
    v["nPublic"] = json!(7);
    rejects(&v, "8 public inputs");

    let mut v = synthetic_key(17);
    v["IC"].as_array_mut().unwrap().pop();
    rejects(&v, "9 IC points");
}

#[test]
fn a_key_with_an_invalid_point_is_refused() {
    let mut v = synthetic_key(17);
    v["vk_alpha_1"][1] = json!("5");
    rejects(&v, "G1 point is not on the curve");

    let mut v = synthetic_key(17);
    v["IC"][3] = json!(["0", "1", "0"]);
    rejects(&v, "not an affine point");

    let mut v = synthetic_key(17);
    v["vk_beta_2"][0][0] = json!("1");
    rejects(&v, "G2 point is not in G2");

    // p itself is one past the largest canonical coordinate.
    let mut v = synthetic_key(17);
    v["vk_alpha_1"][0] =
        json!("21888242871839275222246405745257275088696311157297823662689037894645226208583");
    rejects(&v, "not below the field modulus");
}

#[test]
fn a_g2_point_outside_the_subgroup_is_refused() {
    // On the twist but not in G2: search x = c0 + 0i for a point whose cofactor part survives.
    let mut v = synthetic_key(17);
    let point = (1u64..)
        .find_map(|x| {
            let x = Fq2::new(Fq::from(x), Fq::from(0u64));
            G2Affine::get_point_from_x_unchecked(x, false)
                .filter(|p| !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap();
    v["vk_beta_2"] = g2_json(point);
    rejects(&v, "G2 point is not in G2");
}

#[test]
fn every_coordinate_must_be_a_canonical_decimal() {
    let valid = synthetic_key(17);
    let x = valid["vk_alpha_1"][0].as_str().unwrap().to_string();
    for spelling in [
        format!("+{x}"),
        format!("0{x}"),
        format!("00{x}"),
        format!("{}_{}", &x[..3], &x[3..]),
        format!(" {x}"),
        format!("{x} "),
        format!("-{x}"),
        format!("0x{x}"),
        "00".to_string(),
        "-0".to_string(),
        String::new(),
    ] {
        let mut v = valid.clone();
        v["vk_alpha_1"][0] = json!(spelling);
        rejects(&v, "not a canonical decimal string");
    }
    // The same holds inside G2 points and the IC list.
    let mut v = valid.clone();
    let c = v["vk_beta_2"][1][0].as_str().unwrap().to_string();
    v["vk_beta_2"][1][0] = json!(format!("0{c}"));
    rejects(&v, "not a canonical decimal string");
    let mut v = valid.clone();
    v["IC"][8][1] = json!(1);
    rejects(&v, "not a canonical decimal string");
}

#[test]
fn a_canonical_decimal_has_no_sign_no_leading_zero_and_no_separator() {
    for s in ["0", "1", "10", "9", "1234567890"] {
        assert!(check::canonical_decimal(s), "{s}");
    }
    for s in [
        "", "00", "01", "007", "+1", "-1", "-0", "+0", "1_0", "_1", "1_", " 1", "1 ", "0x1", "1e3",
        "1.0",
    ] {
        assert!(!check::canonical_decimal(s), "{s}");
    }
}
