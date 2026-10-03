//! The proof checks `shield` and `transact` share.

use soroban_sdk::{crypto::bn254::Bn254Fr, vec, xdr::ToXdr, Bytes, Env, U256};
use types::{ExtData, TxProof};
use verifier::VerifyingKey;

use crate::{
    error::Error,
    storage::{self, Config},
};

pub const CIPHERTEXT_LEN: u32 = 181;

/// `keccak256(XDR(ScVal(ext))) mod p`.
pub fn ext_data_hash(env: &Env, ext: &ExtData) -> U256 {
    let digest = env.crypto().keccak256(&ext.clone().to_xdr(env));
    U256::from_be_bytes(env, &Bytes::from(digest.to_bytes())).rem_euclid(&poseidon2::modulus(env))
}

/// `(ext_amount - fee) mod p`.
pub fn public_amount(env: &Env, ext_amount: i128, fee: i128) -> Result<U256, Error> {
    let net = ext_amount.checked_sub(fee).ok_or(Error::Overflow)?;
    let magnitude = U256::from_u128(env, net.unsigned_abs());
    Ok(if net < 0 {
        poseidon2::modulus(env).sub(&magnitude)
    } else {
        magnitude
    })
}

/// The ExtData checks both entry points make: the proof is for this vault on this network, and
/// both outputs are full-size ciphertexts.
pub fn check_binding(env: &Env, ext: &ExtData) -> Result<(), Error> {
    if ext.vault != env.current_contract_address() {
        return Err(Error::WrongVault);
    }
    if ext.network_id != env.ledger().network_id() {
        return Err(Error::WrongNetwork);
    }
    if ext.encrypted_output0.len() != CIPHERTEXT_LEN
        || ext.encrypted_output1.len() != CIPHERTEXT_LEN
    {
        return Err(Error::BadCiphertext);
    }
    Ok(())
}

/// The first of the proof checks both entry points share: two nullifiers and two commitments,
/// all public inputs canonical, no duplicates, and the deadline not passed.
pub fn check_shape(env: &Env, proof: &TxProof, ext: &ExtData) -> Result<(), Error> {
    if proof.input_nullifiers.len() != 2 || proof.output_commitments.len() != 2 {
        return Err(Error::BadArity);
    }
    let nf0 = proof.input_nullifiers.get_unchecked(0);
    let nf1 = proof.input_nullifiers.get_unchecked(1);
    let cm0 = proof.output_commitments.get_unchecked(0);
    let cm1 = proof.output_commitments.get_unchecked(1);

    // x and x + p are the same field element, so a non-canonical value would let one proof stand
    // for two different nullifiers or commitments on chain.
    let p = poseidon2::modulus(env);
    for x in [
        &proof.root,
        &proof.public_amount,
        &proof.ext_data_hash,
        &nf0,
        &nf1,
        &cm0,
        &cm1,
    ] {
        if *x >= p {
            return Err(Error::NonCanonical);
        }
    }
    if nf0 == nf1 {
        return Err(Error::DuplicateNullifier);
    }
    // Equal outputs would let one transaction poison indexers that key leaves by commitment.
    if cm0 == cm1 {
        return Err(Error::DuplicateCommitment);
    }
    if ext.deadline < env.ledger().sequence() {
        return Err(Error::Expired);
    }
    Ok(())
}

/// The proof checks that follow the root check: unspent nullifiers, `extDataHash` and
/// `publicAmount` recomputed from `ext`, and Groth16 verification with the vault's `domain` as
/// public input 4.
pub fn check_spend(
    env: &Env,
    config: &Config,
    proof: &TxProof,
    ext: &ExtData,
) -> Result<(), Error> {
    let nf0 = proof.input_nullifiers.get_unchecked(0);
    let nf1 = proof.input_nullifiers.get_unchecked(1);
    // An archived nullifier entry is restored when it is in the footprint, so it still reads as
    // spent here.
    if storage::is_spent(env, &nf0) || storage::is_spent(env, &nf1) {
        return Err(Error::NullifierSpent);
    }

    if ext_data_hash(env, ext) != proof.ext_data_hash {
        return Err(Error::ExtDataHashMismatch);
    }
    if public_amount(env, ext.ext_amount, ext.fee)? != proof.public_amount {
        return Err(Error::PublicAmountMismatch);
    }

    let inputs = vec![
        env,
        Bn254Fr::from_u256(proof.root.clone()),
        Bn254Fr::from_u256(proof.public_amount.clone()),
        Bn254Fr::from_u256(proof.ext_data_hash.clone()),
        Bn254Fr::from_u256(config.domain.clone()),
        Bn254Fr::from_u256(nf0),
        Bn254Fr::from_u256(nf1),
        Bn254Fr::from_u256(proof.output_commitments.get_unchecked(0)),
        Bn254Fr::from_u256(proof.output_commitments.get_unchecked(1)),
    ];
    if !verifier::verify(env, &verifying_key(env), &proof.proof, inputs) {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

fn verifying_key(env: &Env) -> VerifyingKey {
    // Unit tests can swap in a key whose trapdoor they know, to forge proofs for arbitrary
    // inputs; cfg(test) code is never part of a contract build.
    #[cfg(test)]
    if let Some(key) = crate::test::trapdoor::active_key(env) {
        return key;
    }
    VerifyingKey::embedded(env)
}
