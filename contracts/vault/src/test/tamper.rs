//! Real proofs with one public input, ExtData field or proof point changed.

use ark_bn254::{Fq, Fq2, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    testutils::{Address as _, Ledger, MuxedAddress as _},
    vec, Address, Bytes, BytesN, Env, MuxedAddress, U256,
};
use types::{ExtData, TxProof};
use verifier::VerifyingKey;

use super::{
    e2e::Flow,
    fixtures,
    setup::{
        asset_contract, env, host_aborted, limits, outcome, sha256, DELAY_LARGE, DELAY_SMALL,
        MAINNET, TESTNET,
    },
};
use crate::{proof, Error, Vault, VaultClient};

const STEP: &str = "unshield_muxed";

fn attempt(
    flow: &Flow,
    name: &str,
    change: impl FnOnce(&Env, &mut TxProof, &mut ExtData),
) -> Result<(), Error> {
    let env = &flow.s.env;
    let step = fixtures::step(name);
    let mut proof = fixtures::proof(env, &step);
    let mut ext = fixtures::ext(env, &step);
    change(env, &mut proof, &mut ext);
    let caller = flow.caller(&step);
    if step["call"] == "shield" {
        outcome(flow.s.vault.try_shield(&proof, &ext, &caller)).map(|_| ())
    } else {
        outcome(flow.s.vault.try_transact(&proof, &ext, &caller))
    }
}

fn plus(x: &U256, n: u32) -> U256 {
    x.add(&U256::from_u32(x.env(), n))
}

fn plus_p(x: &U256) -> U256 {
    x.add(&poseidon2::modulus(x.env()))
}

fn flip_last_byte(b: &Bytes) -> Bytes {
    let mut b = b.clone();
    let last = b.len() - 1;
    b.set(last, b.get_unchecked(last) ^ 1);
    b
}

/// The changes to ExtData that keep it valid, each paired with its name.
fn ext_changes(env: &Env, flow: &Flow) -> std::vec::Vec<(&'static str, ExtData)> {
    let base = fixtures::ext(env, &fixtures::step(STEP));
    let with = |f: &dyn Fn(&mut ExtData)| {
        let mut e = base.clone();
        f(&mut e);
        e
    };
    let exchange = flow.exchange.clone();
    let alice = flow.alice.clone();
    std::vec![
        ("deadline", with(&|e| e.deadline -= 1)),
        ("ext_amount", with(&|e| e.ext_amount += 1)),
        ("fee", with(&|e| e.fee -= 1)),
        (
            "recipient muxed id",
            with(&|e| e.recipient = MuxedAddress::new(exchange.clone(), 7))
        ),
        (
            "recipient without muxed id",
            with(&|e| e.recipient = exchange.clone().into())
        ),
        (
            "recipient account",
            with(&|e| e.recipient = alice.clone().into())
        ),
        ("relayer", with(&|e| e.relayer = alice.clone())),
        (
            "encrypted_output0",
            with(&|e| e.encrypted_output0 = flip_last_byte(&e.encrypted_output0))
        ),
        (
            "encrypted_output1",
            with(&|e| e.encrypted_output1 = flip_last_byte(&e.encrypted_output1))
        ),
    ]
}

#[test]
fn every_ext_data_field_is_bound_by_the_proof() {
    let flow = Flow::at(STEP);
    let env = &flow.s.env;
    for (field, changed) in ext_changes(env, &flow) {
        // Against the proof's own extDataHash the change is caught before verification.
        let result = attempt(&flow, STEP, |_, _, ext| *ext = changed.clone());
        assert_eq!(result, Err(Error::ExtDataHashMismatch), "{field}");

        // With the hash and public amount recomputed to match, only the proof can catch it.
        let result = attempt(&flow, STEP, |env, proof, ext| {
            *ext = changed.clone();
            proof.ext_data_hash = proof::ext_data_hash(env, ext);
            proof.public_amount = proof::public_amount(env, ext.ext_amount, ext.fee).unwrap();
        });
        assert_eq!(result, Err(Error::InvalidProof), "{field}");
    }
    // The untouched proof still goes through afterwards.
    assert_eq!(attempt(&flow, STEP, |_, _, _| {}), Ok(()));
}

#[test]
fn a_changed_amount_is_caught_by_the_public_amount_too() {
    let flow = Flow::at(STEP);
    let result = attempt(&flow, STEP, |env, proof, ext| {
        ext.fee += 1;
        proof.ext_data_hash = proof::ext_data_hash(env, ext);
    });
    assert_eq!(result, Err(Error::PublicAmountMismatch));
}

#[test]
fn a_proof_for_another_vault_or_network_is_refused() {
    let flow = Flow::at(STEP);
    let other = fixtures::account(&flow.s.env, "merchant");
    assert_eq!(
        attempt(&flow, STEP, |_, _, ext| ext.vault = other),
        Err(Error::WrongVault)
    );
    assert_eq!(
        attempt(&flow, STEP, |env, _, ext| ext.network_id =
            BytesN::from_array(env, &[7; 32])),
        Err(Error::WrongNetwork)
    );

    // The same vault seen from mainnet: every testnet proof names the testnet network.
    let flow = Flow::new();
    let mainnet = sha256(MAINNET.as_bytes());
    flow.s.env.ledger().with_mut(|l| l.network_id = mainnet);
    assert_eq!(
        flow.run(&fixtures::step("shield_alice")),
        Err(Error::WrongNetwork)
    );
}

#[test]
fn a_proof_is_bound_to_the_vault_domain() {
    // Same address and network, but a vault for another asset derives another domain.
    let env = env(TESTNET);
    let issuer = xdr_issuer();
    let token = asset_contract(&env, issued_asset(issuer));
    let vault = vault_at_fixture_address(&env, token);
    let step = fixtures::step("shield_alice");
    let alice = fixtures::account(&env, "alice");
    assert_ne!(
        vault.config().domain,
        fixtures::field(&env, &fixtures::proofs()["domain"])
    );
    let result = vault.try_shield(
        &fixtures::proof(&env, &step),
        &fixtures::ext(&env, &step),
        &alice,
    );
    assert_eq!(outcome(result), Err(Error::InvalidProof));
}

fn vault_at_fixture_address(env: &Env, token: Address) -> VaultClient<'static> {
    let id = env.register_at(
        &fixtures::vault_address(env),
        Vault,
        (
            token,
            Address::generate(env),
            Address::generate(env),
            DELAY_SMALL,
            DELAY_LARGE,
            limits(),
        ),
    );
    VaultClient::new(env, &id)
}

fn xdr_issuer() -> soroban_sdk::xdr::AccountId {
    use soroban_sdk::xdr::{AccountId, PublicKey, Uint256};
    AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([9; 32])))
}

fn issued_asset(issuer: soroban_sdk::xdr::AccountId) -> soroban_sdk::xdr::Asset {
    use soroban_sdk::xdr::{AlphaNum4, Asset, AssetCode4};
    Asset::CreditAlphanum4(AlphaNum4 {
        asset_code: AssetCode4(*b"USDC"),
        issuer,
    })
}

#[test]
fn every_public_input_is_bound_by_the_proof() {
    let flow = Flow::at(STEP);
    let env = &flow.s.env;
    let empty_root = fixtures::field(env, &fixtures::proofs()["empty_root"]);
    let fresh = U256::from_u32(env, 12_345);
    let swap = |v: &mut soroban_sdk::Vec<U256>| {
        let (a, b) = (v.get_unchecked(0), v.get_unchecked(1));
        *v = vec![v.env(), b, a];
    };
    let cases = [
        "an older known root",
        "nullifier 0",
        "nullifier 1",
        "commitment 0",
        "commitment 1",
        "swapped nullifiers",
        "swapped commitments",
    ];
    for (case, name) in cases.into_iter().enumerate() {
        let result = attempt(&flow, STEP, |_, p, _| match case {
            0 => p.root = empty_root.clone(),
            1 => p.input_nullifiers.set(0, fresh.clone()),
            2 => p.input_nullifiers.set(1, fresh.clone()),
            3 => p.output_commitments.set(0, fresh.clone()),
            4 => p.output_commitments.set(1, fresh.clone()),
            5 => swap(&mut p.input_nullifiers),
            _ => swap(&mut p.output_commitments),
        });
        assert_eq!(result, Err(Error::InvalidProof), "{name}");
    }
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.public_amount =
            plus(&p.public_amount, 1)),
        Err(Error::PublicAmountMismatch)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.ext_data_hash =
            plus(&p.ext_data_hash, 1)),
        Err(Error::ExtDataHashMismatch)
    );
    assert_eq!(attempt(&flow, STEP, |_, _, _| {}), Ok(()));
}

#[test]
fn a_root_outside_the_history_is_refused() {
    let flow = Flow::at(STEP);
    assert_eq!(
        attempt(&flow, STEP, |env, p, _| p.root = U256::from_u32(env, 0)),
        Err(Error::UnknownRoot)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.root = plus(&p.root, 1)),
        Err(Error::UnknownRoot)
    );
}

#[test]
fn non_canonical_public_inputs_are_refused_although_they_would_verify() {
    let flow = Flow::at(STEP);
    let env = &flow.s.env;
    let step = fixtures::step(STEP);
    let original = fixtures::proof(env, &step);

    // x + p is the same field element as x, so the pairing alone accepts it.
    let inputs = |p: &TxProof| {
        let mut v = vec![env, Bn254Fr::from_u256(p.root.clone())];
        for x in [
            &p.public_amount,
            &p.ext_data_hash,
            &flow.s.vault.config().domain,
        ] {
            v.push_back(Bn254Fr::from_u256(x.clone()));
        }
        for i in 0..2 {
            v.push_back(Bn254Fr::from_u256(p.input_nullifiers.get_unchecked(i)));
        }
        for i in 0..2 {
            v.push_back(Bn254Fr::from_u256(p.output_commitments.get_unchecked(i)));
        }
        v
    };
    let mut shifted = original.clone();
    shifted
        .input_nullifiers
        .set(0, plus_p(&original.input_nullifiers.get_unchecked(0)));
    assert!(verifier::verify(
        env,
        &VerifyingKey::embedded(env),
        &shifted.proof,
        inputs(&shifted)
    ));

    type Shift = fn(&mut TxProof);
    let shifts: [(&str, Shift); 7] = [
        ("root", |p| p.root = plus_p(&p.root)),
        ("public amount", |p| {
            p.public_amount = plus_p(&p.public_amount)
        }),
        ("ext data hash", |p| {
            p.ext_data_hash = plus_p(&p.ext_data_hash)
        }),
        ("nullifier 0", |p| {
            p.input_nullifiers
                .set(0, plus_p(&p.input_nullifiers.get_unchecked(0)))
        }),
        ("nullifier 1", |p| {
            p.input_nullifiers
                .set(1, plus_p(&p.input_nullifiers.get_unchecked(1)))
        }),
        ("commitment 0", |p| {
            p.output_commitments
                .set(0, plus_p(&p.output_commitments.get_unchecked(0)))
        }),
        ("commitment 1", |p| {
            p.output_commitments
                .set(1, plus_p(&p.output_commitments.get_unchecked(1)))
        }),
    ];
    for (name, shift) in shifts {
        assert_eq!(
            attempt(&flow, STEP, |_, p, _| shift(p)),
            Err(Error::NonCanonical),
            "{name}"
        );
    }
}

#[test]
fn degenerate_nullifiers_and_commitments_are_refused() {
    let flow = Flow::at(STEP);
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p
            .input_nullifiers
            .set(1, p.input_nullifiers.get_unchecked(0))),
        Err(Error::DuplicateNullifier)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p
            .output_commitments
            .set(1, p.output_commitments.get_unchecked(0))),
        Err(Error::DuplicateCommitment)
    );
    for (nullifiers, commitments) in [(1, 2), (3, 2), (2, 1), (2, 3), (0, 0)] {
        let result = attempt(&flow, STEP, |env, p, _| {
            let resize = |v: &mut soroban_sdk::Vec<U256>, n: u32| {
                while v.len() > n {
                    v.pop_back();
                }
                while v.len() < n {
                    v.push_back(U256::from_u32(env, 99 + v.len()));
                }
            };
            resize(&mut p.input_nullifiers, nullifiers);
            resize(&mut p.output_commitments, commitments);
        });
        assert_eq!(
            result,
            Err(Error::BadArity),
            "{nullifiers} nullifiers, {commitments} commitments"
        );
    }

    // A nullifier that an earlier transaction spent.
    let spent = fixtures::proof(&flow.s.env, &fixtures::step("transfer"))
        .input_nullifiers
        .get_unchecked(0);
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p
            .input_nullifiers
            .set(0, spent.clone())),
        Err(Error::NullifierSpent)
    );

    // The same transaction twice.
    assert_eq!(attempt(&flow, STEP, |_, _, _| {}), Ok(()));
    assert_eq!(
        attempt(&flow, STEP, |_, _, _| {}),
        Err(Error::NullifierSpent)
    );
}

#[test]
fn malformed_proof_points_are_refused() {
    let flow = Flow::at(STEP);
    let other = fixtures::proof(&flow.s.env, &fixtures::step("transfer")).proof;
    let off_curve = |env: &Env| Bn254G1Affine::from_bytes(BytesN::from_array(env, &[1; 64]));
    let g1_zero = |env: &Env| Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0; 64]));
    assert_eq!(
        attempt(&flow, STEP, |env, p, _| p.proof.a = off_curve(env)),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |env, p, _| p.proof.c = off_curve(env)),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |env, p, _| p.proof.a = g1_zero(env)),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |env, p, _| p.proof.c = g1_zero(env)),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |env, p, _| p.proof.b =
            Bn254G2Affine::from_bytes(BytesN::from_array(env, &[0; 128]))),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.proof.a = other.a.clone()),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.proof.b = other.b.clone()),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.proof.c = other.c.clone()),
        Err(Error::InvalidProof)
    );
    assert_eq!(
        attempt(&flow, STEP, |_, p, _| p.proof = other.clone()),
        Err(Error::InvalidProof)
    );

    // B off the curve: the pairing host function refuses it by aborting the call.
    let step = fixtures::step(STEP);
    let env = &flow.s.env;
    let mut proof = fixtures::proof(env, &step);
    proof.proof.b = Bn254G2Affine::from_bytes(BytesN::from_array(env, &[1; 128]));
    let result = flow
        .s
        .vault
        .try_transact(&proof, &fixtures::ext(env, &step), &flow.caller(&step));
    assert!(host_aborted(result));
    assert_eq!(attempt(&flow, STEP, |_, _, _| {}), Ok(()));
}

/// The host encoding of a G2 point: each Fq2 coordinate as c1 || c0.
fn host_g2(p: &G2Affine) -> [u8; 128] {
    let be = |f: &Fq| {
        let bytes = f.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    };
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&be(&p.x.c1));
    out[32..64].copy_from_slice(&be(&p.x.c0));
    out[64..96].copy_from_slice(&be(&p.y.c1));
    out[96..].copy_from_slice(&be(&p.y.c0));
    out
}

#[test]
fn a_b_on_the_curve_but_outside_g2_is_refused() {
    // The G2 curve has points outside the prime-order subgroup: search x = c0 + 0i for one.
    let outside = (1u64..)
        .find_map(|x| {
            G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(x), Fq::from(0u64)), false)
                .filter(|p| p.is_on_curve() && !p.is_in_correct_subgroup_assuming_on_curve())
        })
        .unwrap();
    assert!(!outside.is_zero());

    let flow = Flow::at(STEP);
    let env = &flow.s.env;
    let step = fixtures::step(STEP);
    let mut proof = fixtures::proof(env, &step);
    proof.proof.b = Bn254G2Affine::from_bytes(BytesN::from_array(env, &host_g2(&outside)));
    let result = flow
        .s
        .vault
        .try_transact(&proof, &fixtures::ext(env, &step), &flow.caller(&step));
    assert!(host_aborted(result));
    // The genuine proof still settles afterwards.
    flow.run(&step).unwrap();
}

#[test]
fn a_withheld_proof_expires_at_its_deadline() {
    let flow = Flow::at(STEP);
    let deadline = fixtures::ext(&flow.s.env, &fixtures::step(STEP)).deadline;
    flow.s.env.ledger().set_sequence_number(deadline + 1);
    assert_eq!(attempt(&flow, STEP, |_, _, _| {}), Err(Error::Expired));
    flow.s.env.ledger().set_sequence_number(deadline);
    assert_eq!(attempt(&flow, STEP, |_, _, _| {}), Ok(()));
}

#[test]
fn a_shield_proof_only_works_as_a_shield_by_its_depositor() {
    let flow = Flow::at("shield_alice");
    let env = &flow.s.env;
    let step = fixtures::step("shield_alice");
    let proof = fixtures::proof(env, &step);
    let ext = fixtures::ext(env, &step);
    assert_eq!(
        outcome(flow.s.vault.try_transact(&proof, &ext, &flow.alice)),
        Err(Error::BadAmount)
    );
    assert_eq!(
        outcome(flow.s.vault.try_shield(&proof, &ext, &flow.bob)),
        Err(Error::BadParties)
    );
    assert_eq!(
        outcome(flow.s.vault.try_shield(&proof, &ext, &flow.alice)),
        Ok(1)
    );

    let flow = Flow::at("transfer");
    let step = fixtures::step("transfer");
    let env = &flow.s.env;
    let result = flow.s.vault.try_shield(
        &fixtures::proof(env, &step),
        &fixtures::ext(env, &step),
        &flow.relayer,
    );
    assert_eq!(outcome(result), Err(Error::NonEmptyRoot));
}
