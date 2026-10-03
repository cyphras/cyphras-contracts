#![no_std]

//! The shielded pool vault for one asset on one network. It holds the asset through its Stellar
//! Asset Contract, keeps the commitment tree and the nullifier set, verifies proofs, screens
//! deposits through an entry queue and enforces limits. It has no upgrade path and no way to move
//! funds other than its entry points.

mod error;
mod events;
mod proof;
mod storage;
mod tree;

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod test;

use soroban_sdk::{
    contract, contractimpl, token::TokenClient, Address, Bytes, BytesN, Env, MuxedAddress, Vec,
    U256,
};
use types::{ExtData, TxProof};

pub use error::Error;
pub use storage::{Config, DataKey, Limits, PendingDeposit, QueuedLimits, RootRing, Status};

const DAY: u64 = 86_400;
const HALT_DURATION: u64 = 72 * 3_600;
const HALT_COOLDOWN: u64 = 7 * DAY;
const LOOSENING_DELAY: u64 = 7 * DAY;

// sha256("Public Global Stellar Network ; September 2015")
const MAINNET_NETWORK_ID: [u8; 32] = [
    0x7a, 0xc3, 0x39, 0x97, 0x54, 0x4e, 0x31, 0x75, 0xd2, 0x66, 0xbd, 0x02, 0x24, 0x39, 0xb2, 0x2c,
    0xdb, 0x16, 0x50, 0x8c, 0x01, 0x16, 0x3f, 0x26, 0xe5, 0xcb, 0x2a, 0x3e, 0x10, 0x45, 0xa9, 0x79,
];

#[contract]
pub struct Vault;

#[contractimpl]
impl Vault {
    /// Runs with the deployment, so the vault never exists unconfigured. `domain` is derived from
    /// the network and the asset contract's name rather than taken as an argument. A build with
    /// the testnet-forgeable key refuses to deploy on mainnet.
    pub fn __constructor(
        env: Env,
        token: Address,
        guardian: Address,
        asp: Address,
        delay_small: u64,
        delay_large: u64,
        limits: Limits,
    ) -> Result<(), Error> {
        if verifier::FORGEABLE && on_mainnet(&env) {
            return Err(Error::ForgeableKey);
        }
        if delay_small > delay_large {
            return Err(Error::BadConfig);
        }
        check_limits(&limits)?;
        let domain = domain(&env, &token);
        if domain == U256::from_u32(&env, 0) {
            return Err(Error::BadConfig);
        }
        storage::set_config(
            &env,
            &Config {
                token,
                domain,
                guardian,
                asp,
                delay_small,
                delay_large,
            },
        );
        storage::set_limits(&env, &limits);
        storage::set_status(
            &env,
            &Status {
                deposits_paused: false,
                transfers_paused: false,
                halted_until: 0,
                next_halt_at: 0,
                next_deposit_id: 1,
                attested_up_to: 0,
                tvl: 0,
                outflow_day: 0,
                outflow: 0,
            },
        );
        tree::init(&env);
        Ok(())
    }

    /// Queues a deposit of `ext.ext_amount` from `depositor` and returns its ID. The commitments
    /// enter the tree only when the deposit is admitted.
    pub fn shield(
        env: Env,
        proof: TxProof,
        ext: ExtData,
        depositor: Address,
    ) -> Result<u64, Error> {
        depositor.require_auth();
        let config = storage::config(&env);
        let limits = storage::limits(&env);
        let mut status = storage::status(&env);
        let now = env.ledger().timestamp();
        if status.halted(now) {
            return Err(Error::Halted);
        }
        if status.deposits_paused {
            return Err(Error::DepositsPaused);
        }
        // Only dummy inputs skip the in-circuit root check, and no real note is in the empty
        // tree, so a deposit can never spend, and on refund burn, a real note.
        if proof.root != tree::empty_root(&env) {
            return Err(Error::NonEmptyRoot);
        }

        if ext.ext_amount <= 0 {
            return Err(Error::BadAmount);
        }
        if ext.fee != 0 {
            return Err(Error::BadFee);
        }
        if ext.recipient != MuxedAddress::from(&depositor) || ext.relayer != depositor {
            return Err(Error::BadParties);
        }
        proof::check_binding(&env, &ext)?;

        let amount = ext.ext_amount;
        if amount > limits.max_deposit {
            return Err(Error::DepositTooLarge);
        }
        let day = now / DAY;
        let day_total = storage::day_total(&env, &depositor, day)
            .checked_add(amount)
            .ok_or(Error::Overflow)?;
        if day_total > limits.max_daily_per_depositor {
            return Err(Error::DepositorDailyLimit);
        }
        let tvl = status.tvl.checked_add(amount).ok_or(Error::Overflow)?;
        if tvl > limits.tvl_cap {
            return Err(Error::TvlCapExceeded);
        }

        proof::check_shape(&env, &proof, &ext)?;
        if !tree::has_room(tree::next_leaf(&env)) {
            return Err(Error::TreeFull);
        }
        proof::check_spend(&env, &config, &proof, &ext)?;

        spend_nullifiers(&env, &proof);
        let id = status.next_deposit_id;
        status.next_deposit_id = id.checked_add(1).ok_or(Error::Overflow)?;
        status.tvl = tvl;
        let commitment0 = proof.output_commitments.get_unchecked(0);
        let commitment1 = proof.output_commitments.get_unchecked(1);
        storage::set_pending(
            &env,
            id,
            &PendingDeposit {
                depositor: depositor.clone(),
                amount,
                commitment0: commitment0.clone(),
                commitment1: commitment1.clone(),
                encrypted_output0: ext.encrypted_output0,
                encrypted_output1: ext.encrypted_output1,
                created_at: now,
                flag: None,
            },
        );
        storage::set_status(&env, &status);
        storage::set_day_total(&env, &depositor, day, day_total);
        events::DepositPending {
            id,
            depositor: depositor.clone(),
            amount,
            commitment0,
            commitment1,
            created_at: now,
        }
        .publish(&env);

        TokenClient::new(&env, &config.token).transfer(
            &depositor,
            env.current_contract_address(),
            &amount,
        );
        Ok(id)
    }

    /// Settles a transfer (`ext_amount == 0`) or an unshield (`ext_amount < 0`). `submitter` is
    /// the relayer, or the user when self-relaying.
    pub fn transact(
        env: Env,
        proof: TxProof,
        ext: ExtData,
        submitter: Address,
    ) -> Result<(), Error> {
        submitter.require_auth();
        let config = storage::config(&env);
        let limits = storage::limits(&env);
        let mut status = storage::status(&env);
        let now = env.ledger().timestamp();
        if status.halted(now) {
            return Err(Error::Halted);
        }

        if ext.ext_amount > 0 {
            return Err(Error::BadAmount);
        }
        // Unshields stay open while transfers are paused.
        if ext.ext_amount == 0 && status.transfers_paused {
            return Err(Error::TransfersPaused);
        }
        if ext.fee < 0 || ext.fee > limits.max_fee {
            return Err(Error::BadFee);
        }
        proof::check_binding(&env, &ext)?;

        let payout = ext.ext_amount.checked_neg().ok_or(Error::Overflow)?;
        let outflow = payout.checked_add(ext.fee).ok_or(Error::Overflow)?;
        let day = now / DAY;
        let outflow_today = if status.outflow_day == day {
            status.outflow
        } else {
            0
        }
        .checked_add(outflow)
        .ok_or(Error::Overflow)?;
        if outflow_today > limits.max_daily_outflow {
            return Err(Error::OutflowLimit);
        }

        proof::check_shape(&env, &proof, &ext)?;
        let tree = tree::Tree::load(&env);
        if !tree.knows_root(&proof.root) {
            return Err(Error::UnknownRoot);
        }
        if !tree::has_room(tree.next_leaf) {
            return Err(Error::TreeFull);
        }
        proof::check_spend(&env, &config, &proof, &ext)?;

        spend_nullifiers(&env, &proof);
        let mut appender = tree::Appender::new(&env, tree);
        insert_pair(
            &env,
            &mut appender,
            proof.output_commitments.get_unchecked(0),
            proof.output_commitments.get_unchecked(1),
            ext.encrypted_output0,
            ext.encrypted_output1,
        );
        appender.save();
        // More can only leave than entered if a proof was forged.
        status.tvl = status
            .tvl
            .checked_sub(outflow)
            .filter(|tvl| *tvl >= 0)
            .ok_or(Error::Overflow)?;
        status.outflow_day = day;
        status.outflow = outflow_today;
        storage::set_status(&env, &status);
        events::Settled {
            ext_amount: ext.ext_amount,
            fee: ext.fee,
            recipient: ext.recipient.clone(),
            relayer: ext.relayer.clone(),
        }
        .publish(&env);

        let token = TokenClient::new(&env, &config.token);
        let vault = env.current_contract_address();
        if payout > 0 {
            token.transfer(&vault, &ext.recipient, &payout);
        }
        if ext.fee > 0 {
            token.transfer(&vault, &ext.relayer, &ext.fee);
        }
        Ok(())
    }

    /// The ASP asserts that every unflagged deposit with an ID up to `up_to` passed screening.
    /// Attestations only move forward and never past the last deposit.
    pub fn attest(env: Env, up_to: u64) -> Result<(), Error> {
        storage::config(&env).asp.require_auth();
        let mut status = storage::status(&env);
        if status.halted(env.ledger().timestamp()) {
            return Err(Error::Halted);
        }
        if up_to <= status.attested_up_to || up_to >= status.next_deposit_id {
            return Err(Error::BadAttestation);
        }
        status.attested_up_to = up_to;
        storage::set_status(&env, &status);
        events::Attested { up_to }.publish(&env);
        Ok(())
    }

    /// The ASP refuses a pending deposit with a public reason code, replacing any earlier flag.
    /// Code 0 is reserved for a depositor's cancellation.
    pub fn flag(env: Env, id: u64, reason: u32) -> Result<(), Error> {
        storage::config(&env).asp.require_auth();
        if reason == 0 {
            return Err(Error::BadReason);
        }
        let mut deposit = storage::pending(&env, id).ok_or(Error::UnknownDeposit)?;
        deposit.flag = Some(reason);
        storage::set_pending(&env, id, &deposit);
        events::DepositFlagged { id, reason }.publish(&env);
        Ok(())
    }

    /// The ASP clears a flag set by mistake, while the deposit is still pending.
    pub fn unflag(env: Env, id: u64) -> Result<(), Error> {
        storage::config(&env).asp.require_auth();
        let mut deposit = storage::pending(&env, id).ok_or(Error::UnknownDeposit)?;
        let reason = deposit.flag.ok_or(Error::NotFlagged)?;
        deposit.flag = None;
        storage::set_pending(&env, id, &deposit);
        events::DepositUnflagged { id, reason }.publish(&env);
        Ok(())
    }

    /// Inserts the commitments of every listed deposit that is eligible: pending, not flagged,
    /// attested, and past its delay. Others are skipped. IDs must be strictly ascending. Returns
    /// the admitted IDs.
    pub fn admit(env: Env, ids: Vec<u64>) -> Result<Vec<u64>, Error> {
        let status = storage::status(&env);
        let now = env.ledger().timestamp();
        if status.halted(now) {
            return Err(Error::Halted);
        }
        let config = storage::config(&env);
        let limits = storage::limits(&env);

        let mut admitted = Vec::new(&env);
        let mut appender: Option<tree::Appender> = None;
        let mut previous: Option<u64> = None;
        for id in ids.iter() {
            if previous.is_some_and(|p| id <= p) {
                return Err(Error::BadIds);
            }
            previous = Some(id);
            let Some(deposit) = storage::pending(&env, id) else {
                continue;
            };
            let delay = if deposit.amount >= limits.large_deposit_threshold {
                config.delay_large
            } else {
                config.delay_small
            };
            if deposit.flag.is_some()
                || id > status.attested_up_to
                || now < deposit.created_at.saturating_add(delay)
            {
                continue;
            }
            let appender =
                appender.get_or_insert_with(|| tree::Appender::new(&env, tree::Tree::load(&env)));
            if !appender.has_room() {
                return Err(Error::TreeFull);
            }
            let index = insert_pair(
                &env,
                appender,
                deposit.commitment0,
                deposit.commitment1,
                deposit.encrypted_output0,
                deposit.encrypted_output1,
            );
            events::DepositAdmitted {
                id,
                leaf_index0: index,
                leaf_index1: index + 1,
            }
            .publish(&env);
            storage::remove_pending(&env, id);
            admitted.push_back(id);
        }
        if let Some(appender) = appender {
            appender.save();
        }
        Ok(admitted)
    }

    /// The depositor takes back a deposit that is not yet admitted, flagged or not. Works while
    /// halted.
    pub fn cancel(env: Env, id: u64) -> Result<(), Error> {
        let deposit = storage::pending(&env, id).ok_or(Error::UnknownDeposit)?;
        deposit.depositor.require_auth();
        release(&env, id, deposit, 0);
        Ok(())
    }

    /// Anyone returns a flagged deposit to its depositor. Works while halted.
    pub fn refund(env: Env, id: u64) -> Result<(), Error> {
        let deposit = storage::pending(&env, id).ok_or(Error::UnknownDeposit)?;
        let reason = deposit.flag.ok_or(Error::NotFlagged)?;
        release(&env, id, deposit, reason);
        Ok(())
    }

    /// The guardian stops or resumes deposits and transfers. Unshields, cancellations and refunds
    /// are never paused.
    pub fn set_pause(env: Env, deposits: bool, transfers: bool) -> Result<(), Error> {
        storage::config(&env).guardian.require_auth();
        let mut status = storage::status(&env);
        status.deposits_paused = deposits;
        status.transfers_paused = transfers;
        storage::set_status(&env, &status);
        events::Paused {
            deposits,
            transfers,
        }
        .publish(&env);
        Ok(())
    }

    /// The guardian stops `shield`, `transact` and `admit` for 72 hours. The next halt is allowed
    /// 7 days after this one ends, so users always get a week to exit between halts.
    pub fn halt(env: Env) -> Result<(), Error> {
        storage::config(&env).guardian.require_auth();
        let mut status = storage::status(&env);
        let now = env.ledger().timestamp();
        if now < status.next_halt_at {
            return Err(Error::HaltCooldown);
        }
        status.halted_until = now + HALT_DURATION;
        status.next_halt_at = status.halted_until + HALT_COOLDOWN;
        storage::set_status(&env, &status);
        events::Halted {
            until: status.halted_until,
        }
        .publish(&env);
        Ok(())
    }

    /// The guardian ends a halt early. The cooldown then runs from now.
    pub fn resume(env: Env) -> Result<(), Error> {
        storage::config(&env).guardian.require_auth();
        let mut status = storage::status(&env);
        let now = env.ledger().timestamp();
        if !status.halted(now) {
            return Err(Error::NotHalted);
        }
        status.halted_until = now;
        status.next_halt_at = now + HALT_COOLDOWN;
        storage::set_status(&env, &status);
        events::Resumed {
            next_halt_at: status.next_halt_at,
        }
        .publish(&env);
        Ok(())
    }

    /// The guardian changes the limits. A tightening, where no field rises, applies at once; any
    /// loosening replaces the queued one and applies 7 days later through `apply_limits`.
    /// `max_daily_outflow` never decreases, so a full pool can always exit within a week.
    pub fn set_limits(env: Env, limits: Limits) -> Result<(), Error> {
        storage::config(&env).guardian.require_auth();
        let current = storage::limits(&env);
        check_change(&current, &limits)?;
        let now = env.ledger().timestamp();
        let tightening = limits.max_deposit <= current.max_deposit
            && limits.max_daily_per_depositor <= current.max_daily_per_depositor
            && limits.tvl_cap <= current.tvl_cap
            && limits.max_daily_outflow <= current.max_daily_outflow
            && limits.max_fee <= current.max_fee
            && limits.large_deposit_threshold <= current.large_deposit_threshold;
        if tightening {
            storage::set_limits(&env, &limits);
            events::LimitsApplied {
                limits,
                ready_at: now,
            }
            .publish(&env);
        } else {
            let ready_at = now + LOOSENING_DELAY;
            storage::set_queued_limits(
                &env,
                &QueuedLimits {
                    limits: limits.clone(),
                    ready_at,
                },
            );
            events::LimitsQueued { limits, ready_at }.publish(&env);
        }
        Ok(())
    }

    /// Anyone applies the queued loosening once it is due.
    pub fn apply_limits(env: Env) -> Result<(), Error> {
        let queued = storage::queued_limits(&env).ok_or(Error::NoQueuedLimits)?;
        if env.ledger().timestamp() < queued.ready_at {
            return Err(Error::LimitsNotReady);
        }
        check_change(&storage::limits(&env), &queued.limits)?;
        storage::set_limits(&env, &queued.limits);
        storage::remove_queued_limits(&env);
        events::LimitsApplied {
            limits: queued.limits,
            ready_at: queued.ready_at,
        }
        .publish(&env);
        Ok(())
    }

    /// The guardian drops the queued loosening.
    pub fn cancel_limits(env: Env) -> Result<(), Error> {
        storage::config(&env).guardian.require_auth();
        let queued = storage::queued_limits(&env).ok_or(Error::NoQueuedLimits)?;
        storage::remove_queued_limits(&env);
        events::LimitsCancelled {
            limits: queued.limits,
            ready_at: queued.ready_at,
        }
        .publish(&env);
        Ok(())
    }

    /// Anyone extends the instance, the tree entries and the listed pending deposits to the
    /// network's maximum TTL. IDs that are no longer pending are skipped.
    pub fn bump_ttl(env: Env, pending_ids: Vec<u64>) {
        storage::bump(&env, &pending_ids);
    }

    pub fn config(env: Env) -> Config {
        storage::config(&env)
    }

    pub fn limits(env: Env) -> Limits {
        storage::limits(&env)
    }

    pub fn queued_limits(env: Env) -> Option<QueuedLimits> {
        storage::queued_limits(&env)
    }

    pub fn status(env: Env) -> Status {
        storage::status(&env)
    }

    pub fn current_root(env: Env) -> U256 {
        tree::Tree::load(&env).current_root()
    }

    pub fn is_known_root(env: Env, root: U256) -> bool {
        tree::Tree::load(&env).knows_root(&root)
    }

    pub fn next_leaf_index(env: Env) -> u64 {
        tree::next_leaf(&env)
    }

    pub fn is_spent(env: Env, nullifier: U256) -> bool {
        storage::is_spent(&env, &nullifier)
    }

    pub fn pending(env: Env, id: u64) -> Option<PendingDeposit> {
        storage::pending(&env, id)
    }
}

fn on_mainnet(env: &Env) -> bool {
    env.ledger().network_id() == BytesN::from_array(env, &MAINNET_NETWORK_ID)
}

/// `OS2IP(sha256("cyphras/v2/domain/" || network || "/" || asset)) mod p`, where `network` is
/// `mainnet` on the public network and `testnet` on any other, and `asset` is the asset
/// contract's name: `native`, or `CODE:ISSUER`.
fn domain(env: &Env, token: &Address) -> U256 {
    let network: &[u8; 7] = if on_mainnet(env) {
        b"mainnet"
    } else {
        b"testnet"
    };
    let mut preimage = Bytes::from_slice(env, b"cyphras/v2/domain/");
    preimage.extend_from_slice(network);
    preimage.push_back(b'/');
    preimage.append(&TokenClient::new(env, token).name().to_bytes());
    let digest = env.crypto().sha256(&preimage);
    U256::from_be_bytes(env, &Bytes::from(digest.to_bytes())).rem_euclid(&poseidon2::modulus(env))
}

fn check_limits(limits: &Limits) -> Result<(), Error> {
    let amounts = [
        limits.max_deposit,
        limits.max_daily_per_depositor,
        limits.tvl_cap,
        limits.max_daily_outflow,
        limits.max_fee,
        limits.large_deposit_threshold,
    ];
    // At this outflow a full pool can always leave within a week.
    if amounts.iter().any(|a| *a < 0) || limits.tvl_cap > limits.max_daily_outflow.saturating_mul(7)
    {
        return Err(Error::BadLimits);
    }
    Ok(())
}

fn check_change(current: &Limits, next: &Limits) -> Result<(), Error> {
    check_limits(next)?;
    if next.max_daily_outflow < current.max_daily_outflow {
        return Err(Error::OutflowDecrease);
    }
    Ok(())
}

fn spend_nullifiers(env: &Env, proof: &TxProof) {
    for nullifier in proof.input_nullifiers.iter() {
        storage::spend(env, &nullifier);
        events::NewNullifier { nullifier }.publish(env);
    }
}

fn insert_pair(
    env: &Env,
    appender: &mut tree::Appender,
    commitment0: U256,
    commitment1: U256,
    encrypted_output0: Bytes,
    encrypted_output1: Bytes,
) -> u64 {
    let index = appender.append(&commitment0, &commitment1);
    events::NewCommitment {
        index,
        commitment: commitment0,
        encrypted_output: encrypted_output0,
    }
    .publish(env);
    events::NewCommitment {
        index: index + 1,
        commitment: commitment1,
        encrypted_output: encrypted_output1,
    }
    .publish(env);
    index
}

/// Returns a pending deposit to the depositor recorded at `shield`, never anywhere else.
fn release(env: &Env, id: u64, deposit: PendingDeposit, reason: u32) {
    storage::remove_pending(env, id);
    let mut status = storage::status(env);
    status.tvl -= deposit.amount;
    storage::set_status(env, &status);
    events::DepositRefunded { id, reason }.publish(env);
    TokenClient::new(env, &storage::config(env).token).transfer(
        &env.current_contract_address(),
        &deposit.depositor,
        &deposit.amount,
    );
}
