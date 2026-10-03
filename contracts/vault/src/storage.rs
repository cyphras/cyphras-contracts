use soroban_sdk::{contracttype, Address, Bytes, Env, IntoVal, TryFromVal, Val, Vec, U256};

// Ledgers per day at the nominal five-second close time.
const DAY_IN_LEDGERS: u32 = 17_280;

// A write keeps the entry alive for at least this long, so live state survives a stalled keeper.
// Extending only a little past the threshold keeps the rent a user transaction pays small.
const TTL_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const TTL_EXTEND_TO: u32 = TTL_THRESHOLD + DAY_IN_LEDGERS / 24;

// A day total must outlive its UTC day, or the per-depositor cap would reset early. This many
// ledgers last a day even at one ledger a second, five times the nominal rate.
const DAY_TOTAL_TTL: u32 = 86_400;

/// Every storage key of the vault. Clients read state with `getLedgerEntries` on these keys.
#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Config,
    Limits,
    QueuedLimits,
    Status,
    Roots,
    Frontier,
    Zeros,
    NextLeaf,
    Nullifier(U256),
    Pending(u64),
    DepositorDay(Address, u64),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub token: Address,
    pub domain: U256,
    pub guardian: Address,
    pub asp: Address,
    pub delay_small: u64,
    pub delay_large: u64,
}

/// Amounts in the asset's smallest unit.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_deposit: i128,
    pub max_daily_per_depositor: i128,
    pub tvl_cap: i128,
    pub max_daily_outflow: i128,
    pub max_fee: i128,
    pub large_deposit_threshold: i128,
}

/// A loosening of the limits that applies once `ready_at` has passed.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedLimits {
    pub limits: Limits,
    pub ready_at: u64,
}

/// `outflow` is the total paid out on day `outflow_day`; a later day starts from zero.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub deposits_paused: bool,
    pub transfers_paused: bool,
    pub halted_until: u64,
    pub next_halt_at: u64,
    pub next_deposit_id: u64,
    pub attested_up_to: u64,
    pub tvl: i128,
    pub outflow_day: u64,
    pub outflow: i128,
}

impl Status {
    pub fn halted(&self, now: u64) -> bool {
        now < self.halted_until
    }
}

/// A deposit waiting in the entry queue. `flag` holds the reason code of a refusal.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDeposit {
    pub depositor: Address,
    pub amount: i128,
    pub commitment0: U256,
    pub commitment1: U256,
    pub encrypted_output0: Bytes,
    pub encrypted_output1: Bytes,
    pub created_at: u64,
    pub flag: Option<u32>,
}

/// The last 256 roots, one per inserted leaf pair. `newest` indexes the current root; slots not
/// yet written hold 0, which is never accepted as a root.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootRing {
    pub roots: Vec<U256>,
    pub newest: u32,
}

fn instance<V: TryFromVal<Env, Val>>(env: &Env, key: &DataKey) -> V {
    env.storage().instance().get(key).unwrap()
}

fn set_instance<V: IntoVal<Env, Val>>(env: &Env, key: &DataKey, value: &V) {
    let storage = env.storage().instance();
    storage.set(key, value);
    storage.extend_ttl(TTL_THRESHOLD, TTL_EXTEND_TO);
}

pub fn get<V: TryFromVal<Env, Val>>(env: &Env, key: &DataKey) -> Option<V> {
    env.storage().persistent().get(key)
}

pub fn set<V: IntoVal<Env, Val>>(env: &Env, key: &DataKey, value: &V) {
    let storage = env.storage().persistent();
    storage.set(key, value);
    storage.extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

pub fn config(env: &Env) -> Config {
    instance(env, &DataKey::Config)
}

pub fn set_config(env: &Env, config: &Config) {
    set_instance(env, &DataKey::Config, config);
}

pub fn limits(env: &Env) -> Limits {
    instance(env, &DataKey::Limits)
}

pub fn set_limits(env: &Env, limits: &Limits) {
    set_instance(env, &DataKey::Limits, limits);
}

pub fn queued_limits(env: &Env) -> Option<QueuedLimits> {
    env.storage().instance().get(&DataKey::QueuedLimits)
}

pub fn set_queued_limits(env: &Env, queued: &QueuedLimits) {
    set_instance(env, &DataKey::QueuedLimits, queued);
}

pub fn remove_queued_limits(env: &Env) {
    env.storage().instance().remove(&DataKey::QueuedLimits);
}

pub fn status(env: &Env) -> Status {
    instance(env, &DataKey::Status)
}

pub fn set_status(env: &Env, status: &Status) {
    set_instance(env, &DataKey::Status, status);
}

pub fn is_spent(env: &Env, nullifier: &U256) -> bool {
    env.storage()
        .persistent()
        .has(&DataKey::Nullifier(nullifier.clone()))
}

pub fn spend(env: &Env, nullifier: &U256) {
    set(env, &DataKey::Nullifier(nullifier.clone()), &());
}

pub fn pending(env: &Env, id: u64) -> Option<PendingDeposit> {
    get(env, &DataKey::Pending(id))
}

pub fn set_pending(env: &Env, id: u64, deposit: &PendingDeposit) {
    set(env, &DataKey::Pending(id), deposit);
}

pub fn remove_pending(env: &Env, id: u64) {
    env.storage().persistent().remove(&DataKey::Pending(id));
}

pub fn day_total(env: &Env, depositor: &Address, day: u64) -> i128 {
    env.storage()
        .temporary()
        .get(&DataKey::DepositorDay(depositor.clone(), day))
        .unwrap_or(0)
}

pub fn set_day_total(env: &Env, depositor: &Address, day: u64, total: i128) {
    let key = DataKey::DepositorDay(depositor.clone(), day);
    let storage = env.storage().temporary();
    storage.set(&key, &total);
    let ttl = DAY_TOTAL_TTL.min(env.storage().max_ttl());
    storage.extend_ttl(&key, ttl, ttl);
}

/// Extends the instance and the tree entries to the network's maximum TTL, and every listed
/// pending deposit that still exists.
pub fn bump(env: &Env, pending_ids: &Vec<u64>) {
    let max = env.storage().max_ttl();
    env.storage().instance().extend_ttl(max, max);
    let storage = env.storage().persistent();
    for key in [
        DataKey::Roots,
        DataKey::Frontier,
        DataKey::Zeros,
        DataKey::NextLeaf,
    ] {
        storage.extend_ttl(&key, max, max);
    }
    for id in pending_ids.iter() {
        let key = DataKey::Pending(id);
        if storage.has(&key) {
            storage.extend_ttl(&key, max, max);
        }
    }
}
