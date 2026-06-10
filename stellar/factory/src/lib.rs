#![no_std]

use soroban_sdk::{
    contract, contractevent, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Vec,
};

const MERKLE_LEVELS: u32 = 20;
const MAX_LEAVES: u32 = 1 << MERKLE_LEVELS;
const TTL_THRESHOLD: u32 = 100_000;
const TTL_BUMP: u32 = 518_400;

#[contracttype]
enum DataKey {
    Admin,
    Verifier,
    XlmToken,
    PoolWasmHash,
    // (token, denomination) -> the active (latest generation) pool address
    ActivePool(Address, i128),
    // (token, denomination) -> current generation number
    Generation(Address, i128),
    // all deployed pools across every generation, for enumeration
    PoolList,
}

#[contracttype]
#[derive(Clone)]
pub struct PoolInfo {
    pub token: Address,
    pub denomination: i128,
    pub generation: u32,
    pub pool: Address,
}

#[contractevent]
pub struct PoolCreated {
    #[topic]
    pub token: Address,
    pub denomination: i128,
    pub generation: u32,
    pub pool: Address,
}

#[contractevent]
pub struct WasmUpdated {
    pub pool_wasm_hash: BytesN<32>,
}

#[contract]
pub struct FactoryContract;

#[contractimpl]
impl FactoryContract {
    // Runs once at deploy. The deployer chooses the admin, verifier, XLM token, and the pool
    // WASM hash used for every pool this factory creates.
    pub fn __constructor(
        env: Env,
        admin: Address,
        verifier: Address,
        xlm_token: Address,
        pool_wasm_hash: BytesN<32>,
    ) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        env.storage().instance().set(&DataKey::XlmToken, &xlm_token);
        env.storage()
            .instance()
            .set(&DataKey::PoolWasmHash, &pool_wasm_hash);
    }

    // Deploy the first generation of a pool for a (token, denomination) pair. The pool is
    // constructed atomically at deploy, so it can never exist uninitialized.
    pub fn create_pool(env: Env, token: Address, denomination: i128) -> Address {
        Self::admin(&env).require_auth();
        if denomination <= 0 {
            panic!("invalid denomination");
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::ActivePool(token.clone(), denomination))
        {
            panic!("pool already exists");
        }
        let pool = Self::deploy_pool(&env, &token, denomination, 0);
        Self::register(&env, &token, denomination, 0, &pool);
        pool
    }

    // Deploy the next generation once the active pool's Merkle tree is full. New commits route
    // to the new generation; the old pool keeps serving reveals against its existing notes.
    pub fn rotate_pool(env: Env, token: Address, denomination: i128) -> Address {
        Self::admin(&env).require_auth();
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ActivePool(token.clone(), denomination))
            .expect("pool does not exist");
        if pool::PoolClient::new(&env, &current).next_index() < MAX_LEAVES {
            panic!("current pool not full");
        }
        let next_gen = env
            .storage()
            .persistent()
            .get(&DataKey::Generation(token.clone(), denomination))
            .unwrap_or(0)
            + 1;
        let pool = Self::deploy_pool(&env, &token, denomination, next_gen);
        Self::register(&env, &token, denomination, next_gen, &pool);
        pool
    }

    pub fn get_pool(env: Env, token: Address, denomination: i128) -> Option<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::ActivePool(token, denomination))
    }

    pub fn get_generation(env: Env, token: Address, denomination: i128) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Generation(token, denomination))
            .unwrap_or(0)
    }

    pub fn get_pools(env: Env) -> Vec<PoolInfo> {
        env.storage()
            .persistent()
            .get(&DataKey::PoolList)
            .unwrap_or(Vec::new(&env))
    }

    pub fn get_verifier(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Verifier).unwrap()
    }

    pub fn get_xlm_token(env: Env) -> Address {
        env.storage().instance().get(&DataKey::XlmToken).unwrap()
    }

    // Update the pool WASM used for FUTURE deployments. Existing pools are unaffected.
    pub fn set_pool_wasm(env: Env, pool_wasm_hash: BytesN<32>) {
        Self::admin(&env).require_auth();
        env.storage()
            .instance()
            .set(&DataKey::PoolWasmHash, &pool_wasm_hash);
        WasmUpdated { pool_wasm_hash }.publish(&env);
    }

    fn admin(env: &Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }

    fn deploy_pool(env: &Env, token: &Address, denomination: i128, generation: u32) -> Address {
        let verifier: Address = env.storage().instance().get(&DataKey::Verifier).unwrap();
        let xlm_token: Address = env.storage().instance().get(&DataKey::XlmToken).unwrap();
        let wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::PoolWasmHash)
            .unwrap();

        // deterministic salt per (token, denomination, generation)
        let mut input = Bytes::new(env);
        input.append(&token.to_xdr(env));
        input.extend_from_slice(&denomination.to_be_bytes());
        input.extend_from_slice(&generation.to_be_bytes());
        let salt = env.crypto().sha256(&input);

        env.deployer().with_current_contract(salt).deploy_v2(
            wasm_hash,
            (token.clone(), xlm_token, verifier, denomination),
        )
    }

    fn register(env: &Env, token: &Address, denomination: i128, generation: u32, pool: &Address) {
        let active_key = DataKey::ActivePool(token.clone(), denomination);
        let gen_key = DataKey::Generation(token.clone(), denomination);

        env.storage().persistent().set(&active_key, pool);
        env.storage().persistent().set(&gen_key, &generation);

        let mut list: Vec<PoolInfo> = env
            .storage()
            .persistent()
            .get(&DataKey::PoolList)
            .unwrap_or(Vec::new(env));
        list.push_back(PoolInfo {
            token: token.clone(),
            denomination,
            generation,
            pool: pool.clone(),
        });
        env.storage().persistent().set(&DataKey::PoolList, &list);

        // Registry must outlive long-dormant pools. Bump here; an off-chain keeper re-bumps
        // periodically so entries never archive and pools stay findable and rotatable.
        env.storage()
            .persistent()
            .extend_ttl(&active_key, TTL_THRESHOLD, TTL_BUMP);
        env.storage()
            .persistent()
            .extend_ttl(&gen_key, TTL_THRESHOLD, TTL_BUMP);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::PoolList, TTL_THRESHOLD, TTL_BUMP);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);

        PoolCreated {
            token: token.clone(),
            denomination,
            generation,
            pool: pool.clone(),
        }
        .publish(env);
    }
}

mod pool {
    use soroban_sdk::{contractclient, Env};

    #[allow(dead_code)]
    #[contractclient(name = "PoolClient")]
    pub trait Pool {
        fn next_index(env: Env) -> u32;
    }
}

mod test;
