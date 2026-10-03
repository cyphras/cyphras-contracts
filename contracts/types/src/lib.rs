#![no_std]

//! Types that clients encode when they call the vault.

use soroban_sdk::{
    contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    Address, Bytes, BytesN, MuxedAddress, Vec, U256,
};

/// A Groth16 proof in the host's uncompressed big-endian encoding.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

/// A transaction proof and the public inputs the client supplies. The vault injects
/// `domain` itself, so it is not part of this type.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxProof {
    pub proof: Groth16Proof,
    pub root: U256,
    pub public_amount: U256,
    pub ext_data_hash: U256,
    pub input_nullifiers: Vec<U256>,
    pub output_commitments: Vec<U256>,
}

/// The external data a proof binds through `ext_data_hash`, which is
/// `keccak256(XDR(ScVal(ExtData))) mod p`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtData {
    pub vault: Address,
    pub network_id: BytesN<32>,
    pub deadline: u32,
    pub ext_amount: i128,
    pub fee: i128,
    pub recipient: MuxedAddress,
    pub relayer: Address,
    pub encrypted_output0: Bytes,
    pub encrypted_output1: Bytes,
}
