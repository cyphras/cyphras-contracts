//! A random sequence of calls against a model of the spec. After every call the vault's result
//! must match the model's, its whole state must match, and the invariants of vault.md must hold.
//! The vault holds a classic asset whose issuer revokes and restores the authorization of the
//! parties exits pay, so that payments are refused and exits strand.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use soroban_sdk::{
    testutils::MuxedAddress as _, token::StellarAssetClient, Address, MuxedAddress, Vec, U256,
};

use super::setup::{outcome, Classic, Setup, DAY, DELAY_LARGE, DELAY_SMALL, XLM};
use crate::{Error, Exit, Limits, QueuedLimits, Status};

const HALT: u64 = 72 * 3_600;
const WEEK: u64 = 7 * DAY;
// The accounts exits pay, as recipients and as relayers.
const PARTIES: usize = 3;
const MUXED_ID: u64 = 77;

#[derive(Clone)]
struct Deposit {
    depositor: usize,
    amount: i128,
    created_at: u64,
    delay: u64,
    flag: Option<u32>,
    flagged_at: u64,
}

/// A queued exit, or the unpaid parts of a stranded one.
#[derive(Clone, Debug)]
struct Owed {
    id: u64,
    recipient: usize,
    muxed: bool,
    payout: i128,
    relayer: usize,
    fee: i128,
    queued_at: u64,
}

#[derive(Debug)]
enum Op {
    Shield(usize, i128),
    Transact {
        payout: i128,
        fee: i128,
        recipient: usize,
        muxed: bool,
        relayer: usize,
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
    Release(u32),
    Claim(u64),
    // The issuer authorizes a party to hold the asset, or revokes it.
    Authorize(usize, bool),
    BumpTtl,
    Advance(u64),
}

#[derive(Debug, PartialEq)]
enum Done {
    Unit,
    Id(u64),
    Ids(std::vec::Vec<u64>),
    Count(u32),
}

/// Which calls a run draws: every entry point, or mostly those around the exit queue, with the
/// parties' right to hold the asset revoked as often as restored.
#[derive(Clone, Copy, PartialEq)]
enum Mix {
    Everything,
    Exits,
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
    exits: VecDeque<Owed>,
    stranded: BTreeMap<u64, Owed>,
    can_receive: [bool; PARTIES],
    received: [i128; PARTIES],
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

    fn outflow_today(&self, day: u64) -> i128 {
        if self.status.outflow_day == day {
            self.status.outflow
        } else {
            0
        }
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

    /// Records `amount` of outflow paid today.
    fn pay(&mut self, day: u64, amount: i128) {
        self.status.tvl -= amount;
        self.status.outflow = self.outflow_today(day) + amount;
        self.status.outflow_day = day;
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
            Op::Transact {
                payout,
                fee,
                recipient,
                muxed,
                relayer,
                reuse,
            } => {
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
                if outflow > self.limits.max_daily_outflow {
                    return Err(Error::ExceedsDailyOutflow);
                }
                if outflow > self.notes {
                    return Err(Error::ExceedsAdmittedValue);
                }
                if (*payout > 0 && !self.can_receive[*recipient])
                    || (*fee > 0 && !self.can_receive[*relayer])
                {
                    return Err(Error::CannotReceive);
                }
                if reuse.is_some() {
                    return Err(Error::NullifierSpent);
                }
                self.notes -= outflow;
                self.next_leaf += 2;
                let owed = Owed {
                    id: self.status.exit_tail,
                    recipient: *recipient,
                    muxed: *muxed,
                    payout: *payout,
                    relayer: *relayer,
                    fee: *fee,
                    queued_at: now,
                };
                let today = self.outflow_today(day) + outflow;
                if outflow > 0 && (!self.exits.is_empty() || today > self.limits.max_daily_outflow)
                {
                    self.exits.push_back(owed);
                    self.status.exit_tail += 1;
                    self.status.queued_total += outflow;
                    return Ok(Done::Unit);
                }
                self.received[*recipient] += payout;
                self.received[*relayer] += fee;
                self.pay(day, outflow);
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
            Op::Release(max) => {
                if self.halted(now) {
                    return Err(Error::Halted);
                }
                let mut count = 0;
                while count < *max {
                    let room = self.limits.max_daily_outflow - self.outflow_today(day);
                    if room == 0 || self.exits.is_empty() {
                        break;
                    }
                    let mut exit = self.exits.pop_front().unwrap();
                    count += 1;
                    // Payout first, then the fee, as far as the window reaches.
                    let payout = exit.payout.min(room);
                    let fee = exit.fee.min(room - payout);
                    let payout_paid = if self.can_receive[exit.recipient] {
                        payout
                    } else {
                        0
                    };
                    let fee_paid = if self.can_receive[exit.relayer] {
                        fee
                    } else {
                        0
                    };
                    self.received[exit.recipient] += payout_paid;
                    self.received[exit.relayer] += fee_paid;
                    exit.payout -= payout_paid;
                    exit.fee -= fee_paid;
                    self.status.queued_total -= payout_paid + fee_paid;
                    self.pay(day, payout_paid + fee_paid);
                    if payout_paid < payout || fee_paid < fee {
                        self.status.exit_head += 1;
                        self.stranded.insert(exit.id, exit);
                    } else if exit.payout + exit.fee == 0 {
                        self.status.exit_head += 1;
                    } else {
                        self.exits.push_front(exit);
                    }
                }
                Ok(Done::Count(count))
            }
            Op::Claim(id) => {
                if self.halted(now) {
                    return Err(Error::Halted);
                }
                let mut owed = self.stranded.get(id).ok_or(Error::NotStranded)?.clone();
                // The parts whose party can receive now move to the tail of the queue; the value
                // stays owed and nothing is paid.
                let payout = if self.can_receive[owed.recipient] {
                    owed.payout
                } else {
                    0
                };
                let fee = if self.can_receive[owed.relayer] {
                    owed.fee
                } else {
                    0
                };
                if payout + fee == 0 {
                    return Err(Error::NothingClaimable);
                }
                let new_id = self.status.exit_tail;
                self.exits.push_back(Owed {
                    id: new_id,
                    payout,
                    fee,
                    queued_at: now,
                    ..owed.clone()
                });
                self.status.exit_tail += 1;
                owed.payout -= payout;
                owed.fee -= fee;
                if owed.payout + owed.fee == 0 {
                    self.stranded.remove(id);
                } else {
                    self.stranded.insert(*id, owed);
                }
                Ok(Done::Id(new_id))
            }
            Op::Authorize(party, authorized) => {
                self.can_receive[*party] = *authorized;
                Ok(Done::Unit)
            }
            Op::BumpTtl | Op::Advance(_) => Ok(Done::Unit),
        }
    }
}

struct Run {
    s: Setup,
    asset: StellarAssetClient<'static>,
    mix: Mix,
    model: Model,
    depositors: std::vec::Vec<Address>,
    parties: std::vec::Vec<Address>,
    spent: std::vec::Vec<U256>,
    // The outflow the parties actually received on each day.
    received_on: BTreeMap<u64, i128>,
}

impl Run {
    fn new(seed: u64, mix: Mix) -> Self {
        let limits = Limits {
            min_deposit: XLM / 10,
            max_deposit: 100 * XLM,
            max_daily_per_depositor: 250 * XLM,
            tvl_cap: 700 * XLM,
            // Small next to the pool, so that exits often wait in the exit queue.
            max_daily_outflow: 100 * XLM,
            max_fee: 2 * XLM,
            large_deposit_threshold: 50 * XLM,
        };
        let classic = Classic::new(limits.clone());
        for _ in 0..seed {
            classic.s.next_u64();
        }
        let depositors = (0..3)
            .map(|i| classic.holder(&std::format!("depositor {i}"), 1_000_000 * XLM))
            .collect();
        let parties = (0..PARTIES)
            .map(|i| classic.holder(&std::format!("party {i}"), 0))
            .collect();
        // The pool starts with four days of outflow in spendable notes.
        classic.fund(4, 100 * XLM);
        let Classic { s, asset } = classic;
        let model = Model {
            highest_outflow_cap: limits.max_daily_outflow,
            limits,
            queued: None,
            status: s.vault.status(),
            pending: BTreeMap::new(),
            resolved: (1..=4).collect(),
            day_totals: BTreeMap::new(),
            notes: 400 * XLM,
            exits: VecDeque::new(),
            stranded: BTreeMap::new(),
            can_receive: [true; PARTIES],
            received: [0; PARTIES],
            next_leaf: 8,
        };
        Run {
            s,
            asset,
            mix,
            model,
            depositors,
            parties,
            spent: std::vec::Vec::new(),
            received_on: BTreeMap::new(),
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

    /// Most of the time a stranded exit, if there is one; otherwise any exit ID.
    fn some_stranded(&self) -> u64 {
        let ids: std::vec::Vec<u64> = self.model.stranded.keys().copied().collect();
        if ids.is_empty() || self.s.below(4) == 0 {
            return self.s.below(self.model.status.exit_tail + 1);
        }
        ids[self.s.below(ids.len() as u64) as usize]
    }

    fn scaled(&self, value: i128) -> i128 {
        let percent = self.pick(&[50, 80, 100, 100, 120, 150]);
        value * percent / 100
    }

    /// Mostly a party that can receive, so that most payments go through.
    fn party(&self) -> usize {
        let able: std::vec::Vec<usize> = (0..PARTIES)
            .filter(|p| self.model.can_receive[*p])
            .collect();
        if able.is_empty() || self.s.below(5) == 0 {
            return self.s.below(PARTIES as u64) as usize;
        }
        able[self.s.below(able.len() as u64) as usize]
    }

    fn transact(&self) -> Op {
        let s = &self.s;
        let m = &self.model;
        let relayer = self.party();
        // A fifth of the attempts also spend a nullifier already in the set, in a random slot,
        // with a payout and fee small enough to pass every earlier check.
        let reuse = (s.below(5) == 0 && !self.spent.is_empty()).then(|| s.below(2) as u32);
        let (payout, fee) = if reuse.is_some() {
            let payout = if m.status.transfers_paused {
                m.notes.min(1)
            } else {
                0
            };
            (payout, 0)
        } else {
            let fee = self.pick(&[0, 1, XLM, m.limits.max_fee, m.limits.max_fee + 1]);
            let window = m.limits.max_daily_outflow;
            let room = window - m.outflow_today(s.now() / DAY);
            let payout = match s.below(10) {
                0 => m.status.tvl + 1,
                1 => 0,
                2 => (window - fee + self.pick(&[0, 1])).max(0),
                3 | 4 => (room - fee + self.pick(&[0, 1])).max(0),
                _ => (m.notes - fee).clamp(0, window) * (1 + s.below(50) as i128) / 100,
            };
            (payout, fee)
        };
        // A transfer names its relayer as the recipient.
        let (recipient, muxed) = if payout == 0 {
            (relayer, false)
        } else {
            (self.party(), s.below(4) == 0)
        };
        Op::Transact {
            payout,
            fee,
            recipient,
            muxed,
            relayer,
            reuse,
        }
    }

    /// Exits, releases, claims, the issuer revoking and restoring the parties, and time passing,
    /// with deposits now and then so that there are notes to spend.
    fn exit_op(&self) -> Op {
        let s = &self.s;
        let m = &self.model;
        let now = s.now();
        // With the queue empty an exit may be paid at once.
        if m.exits.is_empty() && s.below(3) == 0 {
            return self.transact();
        }
        // Now and then a party of the head loses the right to hold the asset, so that the head
        // strands, often with both of its parts.
        if let Some(head) = m.exits.front() {
            let party = self.pick(&[head.recipient, head.relayer]);
            if m.can_receive[party] && s.below(4) == 0 {
                return Op::Authorize(party, false);
            }
        }
        if let Some(&last) = m.pending.keys().last() {
            if s.below(4) == 0 {
                return if last > m.status.attested_up_to {
                    Op::Attest(last)
                } else {
                    Op::Admit(m.pending.keys().copied().take(4).collect())
                };
            }
        }
        match s.below(20) {
            0..=6 => self.transact(),
            7..=9 => Op::Release(self.pick(&[1, 2, 50])),
            10..=12 => Op::Claim(self.some_stranded()),
            13..=15 => Op::Authorize(s.below(PARTIES as u64) as usize, s.below(2) == 0),
            16 => Op::Shield(s.below(3) as usize, self.pick(&[10 * XLM, 49 * XLM])),
            _ => Op::Advance(self.pick(&[3_600, 6 * 3_600, DAY - now % DAY])),
        }
    }

    fn random_op(&self) -> Op {
        if self.mix == Mix::Exits {
            return self.exit_op();
        }
        let s = &self.s;
        let m = &self.model;
        let now = s.now();
        // Some calls can only succeed in a state that random calls rarely leave the vault in.
        if m.halted(now) && s.below(4) == 0 {
            return if s.below(2) == 0 {
                Op::Resume
            } else {
                Op::Release(1)
            };
        }
        let room = m.limits.max_daily_outflow - m.outflow_today(now / DAY);
        // The queue is released while the window has room, and now and then the head's recipient
        // loses the right to hold the asset first, so that the head strands.
        if let Some(head) = m.exits.front() {
            if s.below(4) == 0 {
                return if s.below(4) == 0 && m.can_receive[head.recipient] {
                    Op::Authorize(head.recipient, false)
                } else if room > 0 {
                    Op::Release(self.pick(&[1, 2, 50]))
                } else {
                    Op::Advance(DAY - now % DAY)
                };
            }
        }
        // A stranded exit is claimed once its parties can receive again.
        if let Some(exit) = m.stranded.values().next() {
            if s.below(5) == 0 {
                return if exit.payout > 0 && !m.can_receive[exit.recipient] {
                    Op::Authorize(exit.recipient, true)
                } else if exit.fee > 0 && !m.can_receive[exit.relayer] {
                    Op::Authorize(exit.relayer, true)
                } else {
                    Op::Claim(exit.id)
                };
            }
        }
        // Pending deposits are flagged now and then, and a flagged one unflagged or, once a day
        // has passed, refunded.
        if let Some(&first) = m.pending.keys().next() {
            if s.below(8) == 0 {
                return match m.pending.iter().find(|(_, d)| d.flag.is_some()) {
                    Some((&id, d)) if s.below(2) == 0 => {
                        if now >= d.flagged_at + DAY && s.below(2) == 0 {
                            Op::Refund(id)
                        } else {
                            Op::Unflag(id)
                        }
                    }
                    _ => Op::Flag(first, self.pick(&[1, 2, 5])),
                };
            }
        }
        // Deposits become spendable notes only once attested and admitted.
        if let Some(&last) = m.pending.keys().last() {
            if s.below(8) == 0 {
                return if last > m.status.attested_up_to {
                    Op::Attest(last)
                } else {
                    Op::Admit(m.pending.keys().copied().take(4).collect())
                };
            }
        }
        if let Some(queued) = &m.queued {
            if s.below(4) == 0 {
                return if s.below(4) == 0 {
                    Op::CancelLimits
                } else if now >= queued.ready_at {
                    Op::ApplyLimits
                } else {
                    Op::Advance(queued.ready_at - now)
                };
            }
        }
        match s.below(120) {
            0..=19 => {
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
            20..=44 => self.transact(),
            45..=51 => Op::Attest(self.some_id()),
            52..=56 => Op::Flag(self.id_where(|_| true), self.pick(&[0, 1, 2, 3, 4, 5, 99])),
            57..=59 => Op::Unflag(self.id_where(|d| d.flag.is_some())),
            60..=68 => {
                let mut ids: std::vec::Vec<u64> =
                    (0..1 + s.below(4)).map(|_| self.some_id()).collect();
                if s.below(8) != 0 {
                    ids.sort_unstable();
                    ids.dedup();
                }
                Op::Admit(ids)
            }
            69..=72 => Op::Cancel(self.id_where(|_| true)),
            73..=76 => Op::Refund(self.id_where(|d| d.flag.is_some() && now >= d.flagged_at + DAY)),
            77..=78 => Op::SetPause(s.below(4) == 0, s.below(4) == 0),
            79..=81 => Op::Halt,
            82..=83 => Op::Resume,
            84..=87 => {
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
            88..=90 => Op::ApplyLimits,
            91 => Op::CancelLimits,
            92 => Op::BumpTtl,
            93..=98 => Op::Release(self.pick(&[0, 1, 2, 5, 50])),
            99..=102 => Op::Claim(self.some_stranded()),
            103..=107 => Op::Authorize(s.below(PARTIES as u64) as usize, s.below(4) != 0),
            _ => {
                Op::Advance(self.pick(&[1, 59, 3_599, 3_600, 6 * 3_600, DAY - 1, DAY, HALT, WEEK]))
            }
        }
    }

    fn recipient(&self, party: usize, muxed: bool) -> MuxedAddress {
        let base = self.parties[party].clone();
        if muxed {
            MuxedAddress::new(base, MUXED_ID)
        } else {
            base.into()
        }
    }

    /// The vault's entry for `owed`.
    fn stored(&self, owed: &Owed) -> Exit {
        Exit {
            recipient: self.recipient(owed.recipient, owed.muxed),
            payout: owed.payout,
            relayer: self.parties[owed.relayer].clone(),
            fee: owed.fee,
            queued_at: owed.queued_at,
        }
    }

    fn received(&self) -> i128 {
        self.parties.iter().map(|p| self.s.balance(p)).sum()
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
            Op::Transact {
                payout,
                fee,
                recipient,
                muxed,
                relayer,
                reuse,
            } => {
                let relayer = &self.parties[*relayer];
                let ext = s.ext(-payout, *fee, self.recipient(*recipient, *muxed), relayer);
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
                let result = outcome(v.try_transact(&proof, &ext, relayer)).map(|_| Done::Unit);
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
            Op::Release(max) => outcome(v.try_release(max)).map(Done::Count),
            Op::Claim(id) => outcome(v.try_claim(id)).map(Done::Id),
            Op::Authorize(party, authorized) => {
                self.asset.set_authorized(&self.parties[*party], authorized);
                Ok(Done::Unit)
            }
            Op::BumpTtl => {
                let m = &self.model;
                let pending: std::vec::Vec<u64> = m.pending.keys().copied().collect();
                let exits: std::vec::Vec<u64> = m
                    .exits
                    .iter()
                    .map(|e| e.id)
                    .chain(m.stranded.keys().copied())
                    .collect();
                v.bump_ttl(&ids(&pending), &ids(&exits));
                Ok(Done::Unit)
            }
            Op::Advance(seconds) => {
                s.advance(*seconds);
                Ok(Done::Unit)
            }
        }
    }

    /// The vault matches the model, and the invariants of vault.md hold.
    fn check(&mut self, before: &Model, day: u64) {
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

        // 1. The TVL is the unspent notes, the pending deposits and the exits still owed, and
        // nothing else moves the asset here, so the vault's balance equals it.
        let pending: i128 = m.pending.values().map(|d| d.amount).sum();
        let owed: i128 = m
            .exits
            .iter()
            .chain(m.stranded.values())
            .map(|e| e.payout + e.fee)
            .sum();
        assert_eq!(status.pending_total, pending);
        assert_eq!(status.queued_total, owed);
        assert_eq!(status.tvl, m.notes + pending + owed);
        assert_eq!(s.balance(&s.vault.address), status.tvl);
        // 2. The next leaf index only grows, by two per inserted pair.
        let leaf = s.vault.next_leaf_index();
        assert_eq!(leaf, m.next_leaf);
        assert!(leaf >= before.next_leaf && (leaf - before.next_leaf).is_multiple_of(2));
        // 3. A spent nullifier stays spent.
        for nullifier in &self.spent {
            assert!(s.vault.is_spent(nullifier));
        }
        // 4. A deposit ID is resolved at most once, and never pending again.
        for id in &m.resolved {
            assert!(s.vault.pending(id).is_none());
        }
        // 5. No day pays out more than the cap, and the window counts exactly what was paid.
        let received = self.received_on.get(&day).copied().unwrap_or(0);
        assert!(received <= m.limits.max_daily_outflow);
        if status.outflow_day == day {
            assert_eq!(status.outflow, received);
        }
        // 6. The cap never decreases and always lets a full pool leave within a week.
        let limits = s.vault.limits();
        assert!(limits.max_daily_outflow >= m.highest_outflow_cap);
        assert!(7 * limits.max_daily_outflow >= limits.tvl_cap);
        // 7. Exits are paid or stranded in ID order and none is paid twice: the queue holds
        // exactly the exits from its head on, a stranded exit holds exactly its unpaid parts,
        // an exit paid in full is gone, and each party holds exactly what it was paid.
        let ids: std::vec::Vec<u64> = m.exits.iter().map(|e| e.id).collect();
        let expected: std::vec::Vec<u64> = (status.exit_head..status.exit_tail).collect();
        assert_eq!(ids, expected);
        for exit in &m.exits {
            assert_eq!(s.vault.exit(&exit.id), Some(self.stored(exit)));
            assert_eq!(s.vault.stranded(&exit.id), None);
        }
        for exit in m.stranded.values() {
            assert!(exit.id < status.exit_head);
            assert_eq!(s.vault.exit(&exit.id), None);
            assert_eq!(s.vault.stranded(&exit.id), Some(self.stored(exit)));
        }
        let owed_before = before.exits.iter().chain(before.stranded.values());
        for exit in owed_before {
            if !m.stranded.contains_key(&exit.id) && exit.id < status.exit_head {
                assert_eq!(s.vault.exit(&exit.id), None);
                assert_eq!(s.vault.stranded(&exit.id), None);
            }
        }
        for (party, received) in self.parties.iter().zip(m.received) {
            assert_eq!(s.balance(party), received);
        }
        self.model.highest_outflow_cap = limits.max_daily_outflow;
    }
}

/// Runs `steps` random calls and counts each entry point's outcomes, with the refusals of a spent
/// nullifier counted per slot.
fn run(seed: u64, steps: usize, mix: Mix) -> BTreeMap<std::string::String, usize> {
    let mut run = Run::new(seed, mix);
    let mut seen = BTreeMap::new();
    for _ in 0..steps {
        let op = run.random_op();
        let now = run.s.now();
        let before = run.model.clone();
        let received = run.received();
        let mut predicted = run.model.clone();
        let expected = predicted.expect(&op, now);
        let actual = run.execute(&op);
        assert_eq!(actual, expected, "seed {seed}: {op:?}");
        if actual.is_ok() {
            run.model = predicted;
        }
        let paid = run.received() - received;
        *run.received_on.entry(now / DAY).or_insert(0) += paid;
        run.check(&before, now / DAY);

        let name =
            std::string::String::from(std::format!("{op:?}").split(['(', ' ']).next().unwrap());
        let result = if actual.is_ok() { "ok" } else { "refused" };
        *seen.entry(std::format!("{name} {result}")).or_insert(0) += 1;
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
        if run.model.status.exit_tail > before.status.exit_tail {
            *seen.entry("Transact queued".into()).or_insert(0) += 1;
        }
        if matches!(op, Op::Transact { .. }) && actual == Err(Error::CannotReceive) {
            *seen.entry("Transact cannot receive".into()).or_insert(0) += 1;
        }
        if run.model.stranded.len() > before.stranded.len() {
            *seen.entry("Release stranded".into()).or_insert(0) += 1;
        }
        if let (Some(old), Some(new)) = (before.exits.front(), run.model.exits.front()) {
            if old.id == new.id && old.payout + old.fee > new.payout + new.fee {
                *seen.entry("Release paid in part".into()).or_insert(0) += 1;
            }
        }
        if let Op::Claim(id) = &op {
            if actual.is_ok() && run.model.stranded.contains_key(id) {
                *seen.entry("Claim moved one part".into()).or_insert(0) += 1;
            }
            if actual == Err(Error::NothingClaimable) {
                *seen.entry("Claim moved nothing".into()).or_insert(0) += 1;
            }
        }
    }
    seen
}

#[test]
fn random_sequences_keep_the_vault_equal_to_the_spec_model() {
    let mut seen = BTreeMap::new();
    for seed in 0..4 {
        for (k, n) in run(seed, 300, Mix::Everything) {
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
        "Release",
        "Claim",
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
    // Exits queued, paid in part and stranded.
    for case in [
        "Transact queued",
        "Release paid in part",
        "Release stranded",
    ] {
        assert!(seen.contains_key(case), "never {case}: {seen:?}");
    }
    // A transaction spending an already spent nullifier reached the check in both slots.
    for slot in 0..2 {
        assert!(
            seen.contains_key(&std::format!("spent nullifier in slot {slot}")),
            "no spent nullifier refused in slot {slot}: {seen:?}"
        );
    }
}

#[test]
fn random_exit_sequences_keep_the_vault_equal_to_the_spec_model() {
    let mut seen = BTreeMap::new();
    for seed in 0..4 {
        for (k, n) in run(seed, 150, Mix::Exits) {
            *seen.entry(k).or_insert(0) += n;
        }
    }
    // Exits queued, paid in part and stranded, claims that moved both parts, one or nothing back
    // into the queue, and exits refused because a party cannot receive.
    for case in [
        "Transact queued",
        "Release paid in part",
        "Release stranded",
        "Claim ok",
        "Claim moved one part",
        "Claim moved nothing",
        "Transact cannot receive",
    ] {
        assert!(seen.contains_key(case), "never {case}: {seen:?}");
    }
}
