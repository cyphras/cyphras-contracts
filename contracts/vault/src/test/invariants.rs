//! A random sequence of calls against a model of the spec. After every call the vault's result
//! must match the model's, its whole state must match, and the invariants of vault.md must hold.

use std::collections::{BTreeMap, BTreeSet};

use soroban_sdk::{Address, Vec, U256};

use super::setup::{outcome, Setup, DAY, DELAY_LARGE, DELAY_SMALL, XLM};
use crate::{Error, Limits, QueuedLimits, Status};

const HALT: u64 = 72 * 3_600;
const WEEK: u64 = 7 * DAY;

#[derive(Clone)]
struct Deposit {
    depositor: usize,
    amount: i128,
    created_at: u64,
    delay: u64,
    flag: Option<u32>,
    flagged_at: u64,
}

#[derive(Debug)]
enum Op {
    Shield(usize, i128),
    Transact {
        payout: i128,
        fee: i128,
        reuse: Option<u32>,
    },
    Attest(u64),
    Flag(u64, u32),
    Unflag(u64),
    Admit(std::vec::Vec<u64>),
    Cancel(u64),
    Refund(u64),
    SetPause(bool, bool),
    Halt,
    Resume,
    SetLimits(Limits),
    ApplyLimits,
    CancelLimits,
    BumpTtl,
    Advance(u64),
}

#[derive(Debug, PartialEq)]
enum Done {
    Unit,
    Id(u64),
    Ids(std::vec::Vec<u64>),
}

#[derive(Clone)]
struct Model {
    limits: Limits,
    queued: Option<QueuedLimits>,
    status: Status,
    pending: BTreeMap<u64, Deposit>,
    resolved: BTreeSet<u64>,
    day_totals: BTreeMap<(usize, u64), i128>,
    notes: i128,
    next_leaf: u64,
    highest_outflow_cap: i128,
}

fn valid(l: &Limits) -> bool {
    let fields = [
        l.max_deposit,
        l.max_daily_per_depositor,
        l.tvl_cap,
        l.max_daily_outflow,
        l.max_fee,
        l.large_deposit_threshold,
    ];
    l.min_deposit >= 1
        && fields.iter().all(|f| *f >= 0)
        && l.tvl_cap <= l.max_daily_outflow.saturating_mul(7)
}

impl Model {
    fn halted(&self, now: u64) -> bool {
        now < self.status.halted_until
    }

    fn delay(&self, amount: i128) -> u64 {
        if amount >= self.limits.large_deposit_threshold {
            DELAY_LARGE
        } else {
            DELAY_SMALL
        }
    }

    fn eligible(&self, id: u64, now: u64) -> bool {
        self.pending.get(&id).is_some_and(|d| {
            let delay = d.delay.max(self.delay(d.amount));
            d.flag.is_none() && id <= self.status.attested_up_to && now >= d.created_at + delay
        })
    }

    fn resolve(&mut self, id: u64) {
        self.pending.remove(&id);
        assert!(self.resolved.insert(id), "deposit {id} resolved twice");
    }

    fn check_change(&self, next: &Limits) -> Result<(), Error> {
        if !valid(next) {
            return Err(Error::BadLimits);
        }
        if next.max_daily_outflow < self.limits.max_daily_outflow {
            return Err(Error::OutflowDecrease);
        }
        Ok(())
    }

    /// The result the spec gives for `op`; the model changes only when it succeeds.
    fn expect(&mut self, op: &Op, now: u64) -> Result<Done, Error> {
        let day = now / DAY;
        match op {
            Op::Shield(depositor, amount) => {
                if self.halted(now) {
                    return Err(Error::Halted);
                }
                if self.status.deposits_paused {
                    return Err(Error::DepositsPaused);
                }
                if *amount <= 0 {
                    return Err(Error::BadAmount);
                }
                if *amount < self.limits.min_deposit {
                    return Err(Error::DepositTooSmall);
                }
                if *amount > self.limits.max_deposit {
                    return Err(Error::DepositTooLarge);
                }
                let total = self.day_totals.get(&(*depositor, day)).unwrap_or(&0) + amount;
                if total > self.limits.max_daily_per_depositor {
                    return Err(Error::DepositorDailyLimit);
                }
                if self.status.tvl + amount > self.limits.tvl_cap {
                    return Err(Error::TvlCapExceeded);
                }
                let id = self.status.next_deposit_id;
                self.status.next_deposit_id += 1;
                self.status.tvl += amount;
                self.status.pending_total += amount;
                self.day_totals.insert((*depositor, day), total);
                let deposit = Deposit {
                    depositor: *depositor,
                    amount: *amount,
                    created_at: now,
                    delay: self.delay(*amount),
                    flag: None,
                    flagged_at: 0,
                };
                self.pending.insert(id, deposit);
                Ok(Done::Id(id))
            }
            Op::Transact { payout, fee, reuse } => {
                if self.halted(now) {
                    return Err(Error::Halted);
                }
                if *payout == 0 && self.status.transfers_paused {
                    return Err(Error::TransfersPaused);
                }
                if *fee < 0 || *fee > self.limits.max_fee {
                    return Err(Error::BadFee);
                }
                let outflow = payout + fee;
                let today = if self.status.outflow_day == day {
                    self.status.outflow
                } else {
                    0
                } + outflow;
                if today > self.limits.max_daily_outflow {
                    return Err(Error::OutflowLimit);
                }
                if outflow > self.status.tvl - self.status.pending_total {
                    return Err(Error::ExceedsAdmittedValue);
                }
                if reuse.is_some() {
                    return Err(Error::NullifierSpent);
                }
                self.notes -= outflow;
                self.status.tvl -= outflow;
                self.status.outflow_day = day;
                self.status.outflow = today;
                self.next_leaf += 2;
                Ok(Done::Unit)
            }
            Op::Attest(up_to) => {
                if self.halted(now) {
                    return Err(Error::Halted);
                }
                if *up_to <= self.status.attested_up_to || *up_to >= self.status.next_deposit_id {
                    return Err(Error::BadAttestation);
                }
                self.status.attested_up_to = *up_to;
                Ok(Done::Unit)
            }
            Op::Flag(id, reason) => {
                if *reason == 0 {
                    return Err(Error::BadReason);
                }
                let deposit = self.pending.get_mut(id).ok_or(Error::UnknownDeposit)?;
                if deposit.flag.is_none() {
                    deposit.flagged_at = now;
                }
                deposit.flag = Some(*reason);
                Ok(Done::Unit)
            }
            Op::Unflag(id) => {
                let deposit = self.pending.get_mut(id).ok_or(Error::UnknownDeposit)?;
                deposit.flag.take().ok_or(Error::NotFlagged)?;
                deposit.flagged_at = 0;
                Ok(Done::Unit)
            }
            Op::Admit(ids) => {
                if self.halted(now) {
                    return Err(Error::Halted);
                }
                if ids.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(Error::BadIds);
                }
                let admitted: std::vec::Vec<u64> = ids
                    .iter()
                    .copied()
                    .filter(|id| self.eligible(*id, now))
                    .collect();
                for id in &admitted {
                    self.notes += self.pending[id].amount;
                    self.status.pending_total -= self.pending[id].amount;
                    self.next_leaf += 2;
                    self.resolve(*id);
                }
                Ok(Done::Ids(admitted))
            }
            Op::Cancel(id) | Op::Refund(id) => {
                let deposit = self.pending.get(id).ok_or(Error::UnknownDeposit)?;
                if matches!(op, Op::Refund(_)) {
                    deposit.flag.ok_or(Error::NotFlagged)?;
                    if now < deposit.flagged_at + DAY {
                        return Err(Error::RefundTooEarly);
                    }
                }
                self.status.tvl -= deposit.amount;
                self.status.pending_total -= deposit.amount;
                self.resolve(*id);
                Ok(Done::Unit)
            }
            Op::SetPause(deposits, transfers) => {
                self.status.deposits_paused = *deposits;
                self.status.transfers_paused = *transfers;
                Ok(Done::Unit)
            }
            Op::Halt => {
                if now < self.status.next_halt_at {
                    return Err(Error::HaltCooldown);
                }
                self.status.halted_until = now + HALT;
                self.status.next_halt_at = now + HALT + WEEK;
                Ok(Done::Unit)
            }
            Op::Resume => {
                if !self.halted(now) {
                    return Err(Error::NotHalted);
                }
                self.status.halted_until = now;
                self.status.next_halt_at = now + WEEK;
                Ok(Done::Unit)
            }
            Op::SetLimits(next) => {
                self.check_change(next)?;
                let l = &self.limits;
                let tightening = next.min_deposit >= l.min_deposit
                    && next.max_deposit <= l.max_deposit
                    && next.max_daily_per_depositor <= l.max_daily_per_depositor
                    && next.tvl_cap <= l.tvl_cap
                    && next.max_daily_outflow <= l.max_daily_outflow
                    && next.max_fee <= l.max_fee
                    && next.large_deposit_threshold <= l.large_deposit_threshold;
                if tightening {
                    self.limits = next.clone();
                    self.queued = None;
                } else {
                    self.queued = Some(QueuedLimits {
                        limits: next.clone(),
                        ready_at: now + WEEK,
                    });
                }
                Ok(Done::Unit)
            }
            Op::ApplyLimits => {
                let queued = self.queued.clone().ok_or(Error::NoQueuedLimits)?;
                if now < queued.ready_at {
                    return Err(Error::LimitsNotReady);
                }
                self.check_change(&queued.limits)?;
                self.limits = queued.limits;
                self.queued = None;
                Ok(Done::Unit)
            }
            Op::CancelLimits => {
                self.queued.take().ok_or(Error::NoQueuedLimits)?;
                Ok(Done::Unit)
            }
            Op::BumpTtl | Op::Advance(_) => Ok(Done::Unit),
        }
    }
}

struct Run {
    s: Setup,
    model: Model,
    depositors: std::vec::Vec<Address>,
    relayer: Address,
    spent: std::vec::Vec<U256>,
}

impl Run {
    fn new(seed: u64) -> Self {
        let limits = Limits {
            min_deposit: XLM / 10,
            max_deposit: 100 * XLM,
            max_daily_per_depositor: 250 * XLM,
            tvl_cap: 1_000 * XLM,
            max_daily_outflow: 200 * XLM,
            max_fee: 2 * XLM,
            large_deposit_threshold: 50 * XLM,
        };
        let s = Setup::with_limits(limits.clone());
        for _ in 0..seed {
            s.next_u64();
        }
        let depositors = (0..3)
            .map(|i| s.account(&std::format!("depositor {i}"), 1_000_000 * XLM))
            .collect();
        let relayer = s.account("relayer", 0);
        let model = Model {
            highest_outflow_cap: limits.max_daily_outflow,
            limits,
            queued: None,
            status: s.vault.status(),
            pending: BTreeMap::new(),
            resolved: BTreeSet::new(),
            day_totals: BTreeMap::new(),
            notes: 0,
            next_leaf: 0,
        };
        Run {
            s,
            model,
            depositors,
            relayer,
            spent: std::vec::Vec::new(),
        }
    }

    fn pick<T: Copy>(&self, options: &[T]) -> T {
        options[self.s.below(options.len() as u64) as usize]
    }

    fn some_id(&self) -> u64 {
        self.s.below(self.model.status.next_deposit_id + 2)
    }

    /// Half of the time a pending deposit for which `wanted` holds, if there is one; otherwise
    /// any ID, pending or not.
    fn id_where(&self, wanted: impl Fn(&Deposit) -> bool) -> u64 {
        let ids: std::vec::Vec<u64> = self
            .model
            .pending
            .iter()
            .filter(|(_, d)| wanted(d))
            .map(|(id, _)| *id)
            .collect();
        if ids.is_empty() || self.s.below(2) == 0 {
            return self.some_id();
        }
        ids[self.s.below(ids.len() as u64) as usize]
    }

    fn scaled(&self, value: i128) -> i128 {
        let percent = self.pick(&[50, 80, 100, 100, 120, 150]);
        value * percent / 100
    }

    fn random_op(&self) -> Op {
        let s = &self.s;
        let m = &self.model;
        let now = s.now();
        // Some calls can only succeed in a state that random calls rarely leave the vault in.
        if m.halted(now) && s.below(4) == 0 {
            return Op::Resume;
        }
        if let Some(queued) = &m.queued {
            if s.below(4) == 0 {
                return if now >= queued.ready_at {
                    Op::ApplyLimits
                } else {
                    Op::Advance(queued.ready_at - now)
                };
            }
        }
        match s.below(100) {
            0..=21 => {
                let amount = self.pick(&[
                    1,
                    m.limits.min_deposit,
                    10 * XLM,
                    m.limits.large_deposit_threshold - 1,
                    m.limits.large_deposit_threshold,
                    m.limits.max_deposit,
                    m.limits.max_deposit + 1,
                    0,
                    1 + s.below(120 * XLM as u64) as i128,
                ]);
                Op::Shield(s.below(3) as usize, amount)
            }
            22..=39 => {
                // A third of the attempts also spend a nullifier already in the set, in a random
                // slot, with a payout and fee small enough to pass every earlier check.
                let reuse = (s.below(3) == 0 && !self.spent.is_empty()).then(|| s.below(2) as u32);
                if reuse.is_some() {
                    let payout = if m.status.transfers_paused {
                        m.notes.min(1)
                    } else {
                        0
                    };
                    return Op::Transact {
                        payout,
                        fee: 0,
                        reuse,
                    };
                }
                let fee = self.pick(&[0, 1, XLM, m.limits.max_fee, m.limits.max_fee + 1]);
                let payout = match s.below(10) {
                    0 => m.status.tvl + 1,
                    1 => 0,
                    _ => (m.notes - fee).max(0) * (1 + s.below(100) as i128) / 100,
                };
                Op::Transact { payout, fee, reuse }
            }
            40..=46 => Op::Attest(self.some_id()),
            47..=51 => Op::Flag(self.id_where(|_| true), self.pick(&[0, 1, 2, 3, 4, 5, 99])),
            52..=54 => Op::Unflag(self.id_where(|d| d.flag.is_some())),
            55..=63 => {
                let mut ids: std::vec::Vec<u64> =
                    (0..1 + s.below(4)).map(|_| self.some_id()).collect();
                if s.below(8) != 0 {
                    ids.sort_unstable();
                    ids.dedup();
                }
                Op::Admit(ids)
            }
            64..=67 => Op::Cancel(self.id_where(|_| true)),
            68..=71 => Op::Refund(self.id_where(|d| d.flag.is_some() && now >= d.flagged_at + DAY)),
            72..=73 => Op::SetPause(s.below(4) == 0, s.below(4) == 0),
            74..=76 => Op::Halt,
            77..=78 => Op::Resume,
            79..=82 => {
                let l = &m.limits;
                let max_daily_outflow = self.scaled(l.max_daily_outflow);
                Op::SetLimits(Limits {
                    min_deposit: self.scaled(l.min_deposit),
                    max_deposit: self.scaled(l.max_deposit),
                    max_daily_per_depositor: self.scaled(l.max_daily_per_depositor),
                    tvl_cap: self
                        .scaled(l.tvl_cap)
                        .min(7 * max_daily_outflow + self.pick(&[0, 0, 1])),
                    max_daily_outflow,
                    max_fee: self.scaled(l.max_fee),
                    large_deposit_threshold: self.scaled(l.large_deposit_threshold),
                })
            }
            83..=85 => Op::ApplyLimits,
            86 => Op::CancelLimits,
            87 => Op::BumpTtl,
            _ => {
                Op::Advance(self.pick(&[1, 59, 3_599, 3_600, 6 * 3_600, DAY - 1, DAY, HALT, WEEK]))
            }
        }
    }

    fn execute(&mut self, op: &Op) -> Result<Done, Error> {
        let s = &self.s;
        let v = &s.vault;
        let ids = |list: &[u64]| Vec::from_slice(&s.env, list);
        match op {
            Op::Shield(d, amount) => {
                let depositor = &self.depositors[*d];
                let ext = s.ext(*amount, 0, depositor, depositor);
                let proof = s.prove_with(
                    &ext,
                    s.empty_root.clone(),
                    [s.field(), s.field()],
                    [s.field(), s.field()],
                );
                let result = outcome(v.try_shield(&proof, &ext, depositor)).map(Done::Id);
                if result.is_ok() {
                    self.spent.extend(proof.input_nullifiers.iter());
                }
                result
            }
            Op::Transact { payout, fee, reuse } => {
                let ext = s.ext(-payout, *fee, &self.relayer, &self.relayer);
                let mut proof = s.prove(&ext);
                if let Some(slot) = reuse {
                    let spent = self.spent[s.below(self.spent.len() as u64) as usize].clone();
                    let nullifiers = if *slot == 0 {
                        [spent, s.field()]
                    } else {
                        [s.field(), spent]
                    };
                    proof = s.prove_with(&ext, proof.root, nullifiers, [s.field(), s.field()]);
                }
                let result =
                    outcome(v.try_transact(&proof, &ext, &self.relayer)).map(|_| Done::Unit);
                if result.is_ok() {
                    self.spent.extend(proof.input_nullifiers.iter());
                }
                result
            }
            Op::Attest(up_to) => outcome(v.try_attest(up_to)).map(|_| Done::Unit),
            Op::Flag(id, reason) => outcome(v.try_flag(id, reason)).map(|_| Done::Unit),
            Op::Unflag(id) => outcome(v.try_unflag(id)).map(|_| Done::Unit),
            Op::Admit(list) => {
                outcome(v.try_admit(&ids(list))).map(|a| Done::Ids(a.iter().collect()))
            }
            Op::Cancel(id) => outcome(v.try_cancel(id)).map(|_| Done::Unit),
            Op::Refund(id) => outcome(v.try_refund(id)).map(|_| Done::Unit),
            Op::SetPause(d, t) => outcome(v.try_set_pause(d, t)).map(|_| Done::Unit),
            Op::Halt => outcome(v.try_halt()).map(|_| Done::Unit),
            Op::Resume => outcome(v.try_resume()).map(|_| Done::Unit),
            Op::SetLimits(l) => outcome(v.try_set_limits(l)).map(|_| Done::Unit),
            Op::ApplyLimits => outcome(v.try_apply_limits()).map(|_| Done::Unit),
            Op::CancelLimits => outcome(v.try_cancel_limits()).map(|_| Done::Unit),
            Op::BumpTtl => {
                v.bump_ttl(&ids(&self
                    .model
                    .pending
                    .keys()
                    .copied()
                    .collect::<std::vec::Vec<_>>()));
                Ok(Done::Unit)
            }
            Op::Advance(seconds) => {
                s.advance(*seconds);
                Ok(Done::Unit)
            }
        }
    }

    /// The vault matches the model, and the invariants of vault.md hold.
    fn check(&mut self, previous_leaf: u64) {
        let s = &self.s;
        let m = &self.model;
        let status = s.vault.status();
        assert_eq!(status, m.status);
        assert_eq!(s.vault.limits(), m.limits);
        assert_eq!(s.vault.queued_limits(), m.queued);
        for (id, d) in &m.pending {
            let actual = s.vault.pending(id).unwrap();
            assert_eq!(actual.depositor, self.depositors[d.depositor]);
            assert_eq!(
                (
                    actual.amount,
                    actual.created_at,
                    actual.flag,
                    actual.flagged_at
                ),
                (d.amount, d.created_at, d.flag, d.flagged_at)
            );
        }

        // 1. The token balance covers the TVL, which is pending deposits plus unspent notes.
        let pending: i128 = m.pending.values().map(|d| d.amount).sum();
        assert_eq!(status.pending_total, pending);
        assert_eq!(status.tvl, pending + m.notes);
        assert!(s.balance(&s.vault.address) >= status.tvl);
        // 2. The next leaf index only grows, by two per inserted pair.
        let leaf = s.vault.next_leaf_index();
        assert_eq!(leaf, m.next_leaf);
        assert!(leaf >= previous_leaf && (leaf - previous_leaf).is_multiple_of(2));
        // 3. A spent nullifier stays spent.
        for nullifier in &self.spent {
            assert!(s.vault.is_spent(nullifier));
        }
        // 4. A deposit ID is resolved at most once, and never pending again.
        for id in &m.resolved {
            assert!(s.vault.pending(id).is_none());
        }
        // 5. Today's outflow never exceeds the cap.
        assert!(status.outflow <= m.limits.max_daily_outflow);
        // 6. The cap never decreases and always lets a full pool leave within a week.
        let limits = s.vault.limits();
        assert!(limits.max_daily_outflow >= m.highest_outflow_cap);
        assert!(7 * limits.max_daily_outflow >= limits.tvl_cap);
        self.model.highest_outflow_cap = limits.max_daily_outflow;
    }
}

/// Runs `steps` random calls and counts each entry point's outcomes, with the refusals of a spent
/// nullifier counted per slot.
fn run(seed: u64, steps: usize) -> BTreeMap<std::string::String, usize> {
    let mut run = Run::new(seed);
    let mut seen = BTreeMap::new();
    for _ in 0..steps {
        let op = run.random_op();
        let now = run.s.now();
        let previous_leaf = run.model.next_leaf;
        let mut predicted = run.model.clone();
        let expected = predicted.expect(&op, now);
        let actual = run.execute(&op);
        assert_eq!(actual, expected, "seed {seed}: {op:?}");
        if actual.is_ok() {
            run.model = predicted;
        }
        run.check(previous_leaf);
        let name =
            std::string::String::from(std::format!("{op:?}").split(['(', ' ']).next().unwrap());
        let key = std::format!("{name} {}", if actual.is_ok() { "ok" } else { "refused" });
        *seen.entry(key).or_insert(0) += 1;
        if let (
            Op::Transact {
                reuse: Some(slot), ..
            },
            Err(Error::NullifierSpent),
        ) = (&op, &actual)
        {
            *seen
                .entry(std::format!("spent nullifier in slot {slot}"))
                .or_insert(0) += 1;
        }
    }
    seen
}

#[test]
fn random_sequences_keep_the_vault_equal_to_the_spec_model() {
    let mut seen = BTreeMap::new();
    for seed in 0..4 {
        for (k, n) in run(seed, 300) {
            *seen.entry(k).or_insert(0) += n;
        }
    }
    // Every entry point both succeeded and was refused somewhere in the runs.
    for op in [
        "Shield",
        "Transact",
        "Attest",
        "Flag",
        "Unflag",
        "Admit",
        "Cancel",
        "Refund",
        "Halt",
        "Resume",
        "SetLimits",
        "ApplyLimits",
        "CancelLimits",
    ] {
        assert!(
            seen.contains_key(&std::format!("{op} ok")),
            "{op} never succeeded: {seen:?}"
        );
        assert!(
            seen.contains_key(&std::format!("{op} refused")),
            "{op} never refused: {seen:?}"
        );
    }
    // A transaction spending an already spent nullifier reached the check in both slots.
    for slot in 0..2 {
        assert!(
            seen.contains_key(&std::format!("spent nullifier in slot {slot}")),
            "no spent nullifier refused in slot {slot}: {seen:?}"
        );
    }
}
