#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine, Fr},
    vec, Address, Bytes, BytesN, Env, Vec,
};

// Groth16 verifier over BN254 for the Cyphras withdraw circuit.
//
// Public input order (hard contract with the circuit and client):
//   [root, nullifierHash, recipient, relayer, relayerFee, amountHash, assetId]
//
// Byte layout (matches circuits/scripts/parse-vk.mjs and gen-proof-fixture.mjs):
//   G1 point  = x || y                              (64 bytes)
//   G2 point  = x_c1 || x_c0 || y_c1 || y_c0        (128 bytes, EIP-197 order)
//   proof     = pi_a (G1) || pi_b (G2) || pi_c (G1) (256 bytes)
//
// Verification equation (alpha is stored un-negated; pi_a is negated here):
//   e(-pi_a, pi_b) * e(alpha, beta) * e(vk_x, gamma) * e(pi_c, delta) == 1
//   where vk_x = ic[0] + sum_i ic[i+1] * input[i]
//
// TTL: the VK lives in instance storage and is subject to Soroban archival. An off-chain
// keeper extends the instance TTL periodically so the stored VK is never archived.

const NUM_PUBLIC_INPUTS: u32 = 7;

// BN254 scalar field modulus r, big-endian. Public inputs must be canonical (< r);
// otherwise x and x + r would satisfy the same proof, letting the pool see two distinct
// 32-byte values (e.g. nullifiers) for one valid proof.
const FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[contracttype]
enum DataKey {
    VkAlphaG1,
    VkBetaG2,
    VkGammaG2,
    VkDeltaG2,
    VkIc,
    Admin,
}

fn is_canonical(x: &BytesN<32>) -> bool {
    x.to_array() < FR_MODULUS
}

#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    pub fn init_vk(
        env: Env,
        admin: Address,
        alpha_g1: BytesN<64>,
        beta_g2: BytesN<128>,
        gamma_g2: BytesN<128>,
        delta_g2: BytesN<128>,
        ic: Vec<BytesN<64>>,
    ) {
        admin.require_auth();

        if env.storage().instance().has(&DataKey::VkAlphaG1) {
            panic!("vk already initialized");
        }

        if ic.len() != NUM_PUBLIC_INPUTS + 1 {
            panic!("ic must have NUM_PUBLIC_INPUTS + 1 points");
        }

        // Validate every VK point is a well-formed, on-curve, in-subgroup point now, so a
        // malformed VK fails at deploy rather than on the first user verify (the VK is
        // immutable after this call).
        Bn254G1Affine::from_bytes(alpha_g1.clone());
        Bn254G2Affine::from_bytes(beta_g2.clone());
        Bn254G2Affine::from_bytes(gamma_g2.clone());
        Bn254G2Affine::from_bytes(delta_g2.clone());
        for i in 0..ic.len() {
            Bn254G1Affine::from_bytes(ic.get(i).unwrap());
        }

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::VkAlphaG1, &alpha_g1);
        env.storage().instance().set(&DataKey::VkBetaG2, &beta_g2);
        env.storage().instance().set(&DataKey::VkGammaG2, &gamma_g2);
        env.storage().instance().set(&DataKey::VkDeltaG2, &delta_g2);
        env.storage().instance().set(&DataKey::VkIc, &ic);
    }

    pub fn is_initialized(env: Env) -> bool {
        env.storage().instance().has(&DataKey::VkAlphaG1)
    }

    pub fn verify(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier_hash: BytesN<32>,
        recipient: BytesN<32>,
        relayer: BytesN<32>,
        relayer_fee: BytesN<32>,
        amount_hash: BytesN<32>,
        asset_id: BytesN<32>,
    ) -> bool {
        if !env.storage().instance().has(&DataKey::VkAlphaG1) {
            panic!("vk not initialized");
        }

        if proof.len() != 256 {
            panic!("proof must be 256 bytes");
        }

        // Reject non-canonical public inputs (see FR_MODULUS note).
        if !is_canonical(&root)
            || !is_canonical(&nullifier_hash)
            || !is_canonical(&recipient)
            || !is_canonical(&relayer)
            || !is_canonical(&relayer_fee)
            || !is_canonical(&amount_hash)
            || !is_canonical(&asset_id)
        {
            return false;
        }

        let pi_a_bytes: BytesN<64> = proof.slice(0..64).try_into().unwrap();
        let pi_b_bytes: BytesN<128> = proof.slice(64..192).try_into().unwrap();
        let pi_c_bytes: BytesN<64> = proof.slice(192..256).try_into().unwrap();

        let pi_a = Bn254G1Affine::from_bytes(pi_a_bytes);
        let pi_b = Bn254G2Affine::from_bytes(pi_b_bytes);
        let pi_c = Bn254G1Affine::from_bytes(pi_c_bytes);
        let pi_a_neg = -pi_a;

        let alpha_g1 = Self::g1(&env, &DataKey::VkAlphaG1);
        let beta_g2 = Self::g2(&env, &DataKey::VkBetaG2);
        let gamma_g2 = Self::g2(&env, &DataKey::VkGammaG2);
        let delta_g2 = Self::g2(&env, &DataKey::VkDeltaG2);
        let ic = Self::ic(&env);

        let bn254 = env.crypto().bn254();

        let inputs = vec![
            &env,
            Fr::from_bytes(root),
            Fr::from_bytes(nullifier_hash),
            Fr::from_bytes(recipient),
            Fr::from_bytes(relayer),
            Fr::from_bytes(relayer_fee),
            Fr::from_bytes(amount_hash),
            Fr::from_bytes(asset_id),
        ];

        let mut vk_x = ic.get(0).unwrap();
        for i in 0..inputs.len() {
            let term = bn254.g1_mul(&ic.get(i + 1).unwrap(), &inputs.get(i).unwrap());
            vk_x = bn254.g1_add(&vk_x, &term);
        }

        let g1_points = vec![&env, pi_a_neg, alpha_g1, vk_x, pi_c];
        let g2_points = vec![&env, pi_b, beta_g2, gamma_g2, delta_g2];

        bn254.pairing_check(g1_points, g2_points)
    }

    fn g1(env: &Env, key: &DataKey) -> Bn254G1Affine {
        let bytes: BytesN<64> = env.storage().instance().get(key).unwrap();
        Bn254G1Affine::from_bytes(bytes)
    }

    fn g2(env: &Env, key: &DataKey) -> Bn254G2Affine {
        let bytes: BytesN<128> = env.storage().instance().get(key).unwrap();
        Bn254G2Affine::from_bytes(bytes)
    }

    fn ic(env: &Env) -> Vec<Bn254G1Affine> {
        let raw: Vec<BytesN<64>> = env.storage().instance().get(&DataKey::VkIc).unwrap();
        let mut out = Vec::new(env);
        for i in 0..raw.len() {
            out.push_back(Bn254G1Affine::from_bytes(raw.get(i).unwrap()));
        }
        out
    }
}

mod test;
