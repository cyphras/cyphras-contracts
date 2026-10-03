//! A random sequence of calls against a model of the spec. After every call the vault's result
//! must match the model's, its whole state must match, and the invariants of vault.md must hold.
//! Most runs hold a classic asset whose issuer revokes and restores the authorization of the
//! parties exits pay, so that payments are refused and exits strand. The others hold XLM and pay
//! accounts that do not exist yet while the base reserve rises and falls.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
};

use soroban_sdk::{
    testutils::{Ledger, MuxedAddress as _},
    token::StellarAssetClient,
    xdr::{self, ScAddress},
    Address, Env, InvokeError, MuxedAddress, Vec, U256,
};

use super::setup::{
    account_address, create_account, outcome, Classic, Setup, DAY, DELAY_LARGE, DELAY_SMALL, XLM,
};
use crate::{Error, Exit, Limits, QueuedLimits, Status};

const HALT: u64 = 72 * 3_600;
const WEEK: u64 = 7 * DAY;
// The accounts exits pay, as recipients and as relayers.
const PARTIES: usize = 3;
// In a run of XLM, further parties whose accounts exist only once a payment or someone else
// creates them.
const FRESH: usize = 24;
const MUXED_ID: u64 = 77;
// The least XLM payout that may go to an account that does not exist yet.
const ACCOUNT_MIN: i128 = XLM;
// What each party that exists from the start holds in a run of XLM, far more than any reserve.
const HELD: i128 = 1_000 * XLM;
// The base reserve of the live networks, in stroops.
const RESERVE: u32 = 5_000_000;
// The asset contract's own codes for the payments it refuses.
const BALANCE_ERROR: u32 = 10;
const BALANCE_DEAUTHORIZED: u32 = 11;
const INSUFFICIENT_ACCOUNT_RESERVE: u32 = 14;

#[derive(Clone)]
struct Deposit {
    depositor: usize,
    amount: i128,
    created_at: u64,
    delay: u64,
    flag: Option<u32>,
    flagged_at: u64,
}

#[derive(Clone)]
struct Party {
    // The issuer lets the party hold the asset, as it always does for XLM.
    authorized: bool,
    exists: bool,
    // What the party holds. An account of XLM must hold two base reserves after any payment it
    // takes, and a missing one is created by a payment of two.
    balance: i128,
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
    // The network's base reserve changes.
    Reserve(u32),
    // Someone else creates the account of a party that does not exist yet, holding this much.
    Create(usize, i128),
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

/// Why a call failed: the vault refused it, or the asset contract refused a payment the vault
/// made at once, which fails the whole call with that contract's own error code.
#[derive(Debug, PartialEq)]
enum Refusal {
    Vault(Error),
    Asset(u32),
}

impl From<Error> for Refusal {
    fn from(error: Error) -> Self {
        Refusal::Vault(error)
    }
}

/// Which calls a run draws: every entry point; mostly those around the exit queue, with the
/// parties' right to hold the asset revoked as often as restored; or those around the exit queue
/// of XLM, with exits to accounts that do not exist yet.
#[derive(Clone, Copy, PartialEq)]
enum Mix {
    Everything,
    Exits,
    Fresh,
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
    // Whether the asset is XLM, and the network's base reserve.
    native: bool,
    reserve: i128,
    parties: std::vec::Vec<Party>,
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

    /// Whether `party` can receive `amount` now, as the vault judges it from reads alone.
    fn can_receive(&self, party: usize, amount: i128) -> bool {
        let p = &self.parties[party];
        p.authorized && (p.exists || (self.native && amount >= ACCOUNT_MIN))
    }

    /// Pays `amount` to `party` if the asset contract takes it, or returns the code with which it
    /// refuses.
    fn take(&mut self, party: usize, amount: i128) -> Result<(), u32> {
        let (native, minimum) = (self.native, 2 * self.reserve);
        let p = &mut self.parties[party];
        if !p.authorized {
            return Err(BALANCE_DEAUTHORIZED);
        }
        if native {
            if p.exists && p.balance + amount < minimum {
                return Err(BALANCE_ERROR);
            }
            if !p.exists && amount < minimum {
                return Err(INSUFFICIENT_ACCOUNT_RESERVE);
            }
        }
        p.exists = true;
        p.balance += amount;
        Ok(())
    }

    /// Records `amount` of outflow paid today.
    fn pay(&mut self, day: u64, amount: i128) {
        self.status.tvl -= amount;
        self.status.outflow = self.outflow_today(day) + amount;
        self.status.outflow_day = day;
    }

    /// The result the spec gives for `op`; the model changes only when it succeeds.
    fn expect(&mut self, op: &Op, now: u64) -> Result<Done, Refusal> {
        let day = now / DAY;
        match op {
            Op::Shield(depositor, amount) => {
                if self.halted(now) {
                    return Err(Error::Halted.into());
                }
                if self.status.deposits_paused {
                    return Err(Error::DepositsPaused.into());
                }
                if *amount <= 0 {
                    return Err(Error::BadAmount.into());
                }
                if *amount < self.limits.min_deposit {
                    return Err(Error::DepositTooSmall.into());
                }
                if *amount > self.limits.max_deposit {
                    return Err(Error::DepositTooLarge.into());
                }
                let total = self.day_totals.get(&(*depositor, day)).unwrap_or(&0) + amount;
                if total > self.limits.max_daily_per_depositor {
                    return Err(Error::DepositorDailyLimit.into());
                }
                if self.status.tvl + amount > self.limits.tvl_cap {
                    return Err(Error::TvlCapExceeded.into());
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
                    return Err(Error::Halted.into());
                }
                if *payout == 0 && self.status.transfers_paused {
                    return Err(Error::TransfersPaused.into());
                }
                if *fee < 0 || *fee > self.limits.max_fee {
                    return Err(Error::BadFee.into());
                }
                let outflow = payout + fee;
                if outflow > self.limits.max_daily_outflow {
                    return Err(Error::ExceedsDailyOutflow.into());
                }
                if outflow > self.notes {
                    return Err(Error::ExceedsAdmittedValue.into());
                }
                if (*payout > 0 && !self.can_receive(*recipient, *payout))
                    || (*fee > 0 && !self.can_receive(*relayer, 0))
                {
                    return Err(Error::CannotReceive.into());
                }
                if reuse.is_some() {
                    return Err(Error::NullifierSpent.into());
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
                // Paid at once, a payment the asset contract refuses fails the whole call.
                for (party, amount) in [(*recipient, *payout), (*relayer, *fee)] {
                    if amount > 0 {
                        self.take(party, amount).map_err(Refusal::Asset)?;
                    }
                }
                self.pay(day, outflow);
                Ok(Done::Unit)
            }
            Op::Attest(up_to) => {
                if self.halted(now) {
                    return Err(Error::Halted.into());
                }
                if *up_to <= self.status.attested_up_to || *up_to >= self.status.next_deposit_id {
                    return Err(Error::BadAttestation.into());
                }
                self.status.attested_up_to = *up_to;
                Ok(Done::Unit)
            }
            Op::Flag(id, reason) => {
                if *reason == 0 {
                    return Err(Error::BadReason.into());
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
                    return Err(Error::Halted.into());
                }
                if ids.windows(2).any(|w| w[0] >= w[1]) {
                    return Err(Error::BadIds.into());
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
                        return Err(Error::RefundTooEarly.into());
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
                    return Err(Error::HaltCooldown.into());
                }
                self.status.halted_until = now + HALT;
                self.status.next_halt_at = now + HALT + WEEK;
                Ok(Done::Unit)
            }
            Op::Resume => {
                if !self.halted(now) {
                    return Err(Error::NotHalted.into());
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
                    return Err(Error::LimitsNotReady.into());
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
                    return Err(Error::Halted.into());
                }
                let mut count = 0;
                while count < *max {
                    let room = self.limits.max_daily_outflow - self.outflow_today(day);
                    let Some(head) = self.exits.front() else {
                        break;
                    };
                    if room == 0 {
                        break;
                    }
                    // Payout first, then the fee, as far as the window reaches.
                    let payout = head.payout.min(room);
                    let fee = head.fee.min(room - payout);
                    // A payout that would create its account is never paid in a part too small to
                    // do so; the exit waits at the head for the next window.
                    if self.native
                        && payout < ACCOUNT_MIN
                        && head.payout >= ACCOUNT_MIN
                        && !self.parties[head.recipient].exists
                    {
                        break;
                    }
                    let mut exit = self.exits.pop_front().unwrap();
                    count += 1;
                    let payout_paid = if payout > 0 && self.take(exit.recipient, payout).is_ok() {
                        payout
                    } else {
                        0
                    };
                    let fee_paid = if fee > 0 && self.take(exit.relayer, fee).is_ok() {
                        fee
                    } else {
                        0
                    };
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
                    return Err(Error::Halted.into());
                }
                let mut owed = self.stranded.get(id).ok_or(Error::NotStranded)?.clone();
                // The parts whose party can receive now move to the tail of the queue; the value
                // stays owed and nothing is paid.
                let payout = if self.can_receive(owed.recipient, owed.payout) {
                    owed.payout
                } else {
                    0
                };
                let fee = if self.can_receive(owed.relayer, 0) {
                    owed.fee
                } else {
                    0
                };
                if payout + fee == 0 {
                    return Err(Error::NothingClaimable.into());
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
                self.parties[*party].authorized = *authorized;
                Ok(Done::Unit)
            }
            Op::Reserve(reserve) => {
                self.reserve = *reserve as i128;
                Ok(Done::Unit)
            }
            Op::Create(party, balance) => {
                let p = &mut self.parties[*party];
                if !p.exists {
                    p.exists = true;
                    p.balance = *balance;
                }
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
    // What the parties' accounts got from anyone but the vault.
    outside: i128,
    spent: std::vec::Vec<U256>,
    // The outflow the parties actually received on each day.
    received_on: BTreeMap<u64, i128>,
}

/// The XLM an account holds, or None if it does not exist, read from the ledger, as the asset
/// contract does not report a balance below the account's reserve.
fn account_balance(env: &Env, address: &Address) -> Option<i128> {
    let ScAddress::Account(account_id) = ScAddress::from(address) else {
        panic!("not an account address");
    };
    let key = Rc::new(xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
        account_id,
    }));
    let (entry, _) = env.host().get_ledger_entry(&key).unwrap()?;
    let xdr::LedgerEntryData::Account(account) = &entry.data else {
        panic!("not an account entry");
    };
    Some(account.balance.into())
}

impl Run {
    fn new(seed: u64, mix: Mix) -> Self {
        let native = mix == Mix::Fresh;
        // Exits of XLM run in a window a few times the least payout that may create an account,
        // so that what is left of a window is often less than that.
        let window = if native { 10 * XLM } else { 100 * XLM };
        let limits = Limits {
            min_deposit: XLM / 10,
            max_deposit: window,
            max_daily_per_depositor: 5 * window / 2,
            tvl_cap: 7 * window,
            // Small next to the pool, so that exits often wait in the exit queue.
            max_daily_outflow: window,
            max_fee: 2 * XLM,
            large_deposit_threshold: window / 2,
        };
        // The pool starts with four days of outflow in spendable notes.
        let (s, asset, depositors, parties, outside) = if native {
            let s = Setup::with_limits(limits.clone());
            for _ in 0..seed {
                s.next_u64();
            }
            let depositors = (0..3)
                .map(|i| s.account(&std::format!("depositor {i}"), 1_000_000 * XLM))
                .collect();
            let parties: std::vec::Vec<Address> = (0..PARTIES + FRESH)
                .map(|i| {
                    let tag = std::format!("party {i}");
                    if i < PARTIES {
                        s.account(&tag, HELD)
                    } else {
                        account_address(&s.env, &tag)
                    }
                })
                .collect();
            for i in 0..4 {
                s.fund_pool(&std::format!("funder {i}"), window);
            }
            s.env.ledger().with_mut(|l| l.base_reserve = RESERVE);
            let asset = StellarAssetClient::new(&s.env, &s.token.address);
            (s, asset, depositors, parties, PARTIES as i128 * HELD)
        } else {
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
            classic.fund(4, window);
            let Classic { s, asset } = classic;
            (s, asset, depositors, parties, 0)
        };
        let model = Model {
            highest_outflow_cap: limits.max_daily_outflow,
            limits,
            queued: None,
            status: s.vault.status(),
            pending: BTreeMap::new(),
            resolved: (1..=4).collect(),
            day_totals: BTreeMap::new(),
            notes: 4 * window,
            exits: VecDeque::new(),
            stranded: BTreeMap::new(),
            native,
            reserve: if native { RESERVE.into() } else { 0 },
            parties: (0..parties.len())
                .map(|i| Party {
                    authorized: true,
                    exists: !native || i < PARTIES,
                    balance: if native && i < PARTIES { HELD } else { 0 },
                })
                .collect(),
            next_leaf: 8,
        };
        Run {
            s,
            asset,
            mix,
            model,
            depositors,
            parties,
            outside,
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
            .filter(|p| self.model.parties[*p].authorized)
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
            if m.parties[party].authorized && s.below(4) == 0 {
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

    /// Of the parties for which `wanted` holds, one at random, or None if there is none.
    fn party_where(&self, wanted: impl Fn(&Party) -> bool) -> Option<usize> {
        let parties: std::vec::Vec<usize> = (0..self.model.parties.len())
            .filter(|p| wanted(&self.model.parties[*p]))
            .collect();
        (!parties.is_empty()).then(|| parties[self.s.below(parties.len() as u64) as usize])
    }

    /// An exit of XLM to an existing account or, half of the time, to one that does not exist
    /// yet, of a size around the least payout that may create it or, unless `small`, one that
    /// leaves less than that of today's window. Now and then the relayer does not exist either.
    fn fresh_transact(&self, small: bool) -> Op {
        let s = &self.s;
        let m = &self.model;
        // One time in `odds` a party that does not exist yet, if there is one, else one that does.
        let party = |odds: u64| match self.party_where(|p| !p.exists) {
            Some(missing) if s.below(odds) == 0 => missing,
            _ => self.party_where(|p| p.exists).unwrap(),
        };
        let relayer = party(8);
        let fee = self
            .pick(&[0, 0, XLM / 10, XLM, m.limits.max_fee])
            .min(m.notes);
        let window = m.limits.max_daily_outflow;
        let room = window - m.outflow_today(s.now() / DAY);
        let payout = match if small { 0 } else { s.below(6) } {
            0..=2 => self.pick(&[
                ACCOUNT_MIN - 1,
                ACCOUNT_MIN,
                ACCOUNT_MIN + 1,
                3 * ACCOUNT_MIN / 2,
                2 * ACCOUNT_MIN,
                3 * ACCOUNT_MIN,
            ]),
            3 | 4 => room - fee - self.pick(&[0, XLM / 2, ACCOUNT_MIN - 1]),
            _ => window - fee - self.pick(&[0, XLM / 2]),
        }
        .clamp(0, m.notes - fee);
        // A transfer names its relayer as the recipient.
        let (recipient, muxed) = if payout == 0 {
            (relayer, false)
        } else {
            (party(2), s.below(4) == 0)
        };
        Op::Transact {
            payout,
            fee,
            recipient,
            muxed,
            relayer,
            reuse: None,
        }
    }

    /// Exits of XLM to accounts that may not exist yet, releases and claims, the base reserve
    /// rising and falling, accounts created by others, and time passing, with deposits now and
    /// then so that there are notes to spend.
    fn fresh_op(&self) -> Op {
        let s = &self.s;
        let m = &self.model;
        let now = s.now();
        let room = m.limits.max_daily_outflow - m.outflow_today(now / DAY);
        // With the queue empty an exit may be paid at once. While the base reserve is raised, such
        // an exit is small, so that it often falls short of creating its recipient's account.
        if m.exits.is_empty() && s.below(3) == 0 {
            return self.fresh_transact(m.reserve > i128::from(RESERVE));
        }
        // While less than 1 XLM of the window is left, which an exit that would create its
        // account waits out, the queue is released now and then.
        if !m.exits.is_empty() && room > 0 && room < ACCOUNT_MIN && s.below(2) == 0 {
            return Op::Release(self.pick(&[1, 50]));
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
            0..=4 => self.fresh_transact(false),
            5..=8 => Op::Release(self.pick(&[1, 2, 50])),
            9 | 10 => Op::Claim(self.some_stranded()),
            11 | 12 => Op::Reserve(self.pick(&[RESERVE, 2 * RESERVE, 3 * RESERVE])),
            13 => Op::Create(
                self.party_where(|p| !p.exists).unwrap_or(0),
                self.pick(&[XLM, 5 * XLM]),
            ),
            14 | 15 => Op::Shield(s.below(3) as usize, self.pick(&[2 * XLM, 9 * XLM])),
            _ => Op::Advance(self.pick(&[3_600, 6 * 3_600, DAY - now % DAY])),
        }
    }

    fn random_op(&self) -> Op {
        match self.mix {
            Mix::Exits => return self.exit_op(),
            Mix::Fresh => return self.fresh_op(),
            Mix::Everything => {}
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
                return if s.below(4) == 0 && m.parties[head.recipient].authorized {
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
                return if exit.payout > 0 && !m.parties[exit.recipient].authorized {
                    Op::Authorize(exit.recipient, true)
                } else if exit.fee > 0 && !m.parties[exit.relayer].authorized {
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

    /// What `party` holds, or None if its account does not exist.
    fn balance(&self, party: &Address) -> Option<i128> {
        if self.model.native {
            account_balance(&self.s.env, party)
        } else {
            Some(self.s.balance(party))
        }
    }

    /// What the vault has paid the parties.
    fn received(&self) -> i128 {
        let held: i128 = self
            .parties
            .iter()
            .map(|p| self.balance(p).unwrap_or(0))
            .sum();
        held - self.outside
    }

    fn execute(&mut self, op: &Op) -> Result<Done, Refusal> {
        let s = &self.s;
        let v = &s.vault;
        let ids = |list: &[u64]| Vec::from_slice(&s.env, list);
        let result = match op {
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
                let result = match v.try_transact(&proof, &ext, relayer) {
                    Err(Err(InvokeError::Contract(code))) => return Err(Refusal::Asset(code)),
                    result => outcome(result).map(|_| Done::Unit),
                };
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
            Op::Reserve(reserve) => {
                s.env.ledger().with_mut(|l| l.base_reserve = *reserve);
                Ok(Done::Unit)
            }
            Op::Create(party, balance) => {
                let address = &self.parties[*party];
                if !address.exists() {
                    create_account(&s.env, address, *balance);
                    self.outside += balance;
                }
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
        };
        result.map_err(Refusal::Vault)
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
        for (address, party) in self.parties.iter().zip(&m.parties) {
            assert_eq!(self.balance(address), party.exists.then_some(party.balance));
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
            Err(Refusal::Vault(Error::NullifierSpent)),
        ) = (&op, &actual)
        {
            *seen
                .entry(std::format!("spent nullifier in slot {slot}"))
                .or_insert(0) += 1;
        }
        if run.model.status.exit_tail > before.status.exit_tail {
            *seen.entry("Transact queued".into()).or_insert(0) += 1;
        }
        if matches!(op, Op::Transact { .. }) && actual == Err(Error::CannotReceive.into()) {
            *seen.entry("Transact cannot receive".into()).or_insert(0) += 1;
        }
        if matches!(actual, Err(Refusal::Asset(_))) {
            *seen
                .entry("Transact refused by the asset".into())
                .or_insert(0) += 1;
        }
        let created = (0..run.model.parties.len())
            .any(|p| run.model.parties[p].exists && !before.parties[p].exists);
        if created && matches!(op, Op::Transact { .. } | Op::Release(_)) {
            *seen
                .entry(std::format!("{name} created an account"))
                .or_insert(0) += 1;
        }
        if let (Op::Release(max), Ok(Done::Count(count))) = (&op, &actual) {
            let room = run.model.limits.max_daily_outflow - run.model.outflow_today(now / DAY);
            if count < max && room > 0 && !run.model.exits.is_empty() {
                *seen.entry("Release waited for room".into()).or_insert(0) += 1;
            }
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
            if actual == Err(Error::NothingClaimable.into()) {
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

#[test]
fn random_fresh_account_sequences_keep_the_vault_equal_to_the_spec_model() {
    let mut seen = BTreeMap::new();
    for seed in 0..4 {
        for (k, n) in run(seed, 150, Mix::Fresh) {
            *seen.entry(k).or_insert(0) += n;
        }
    }
    // Payouts that created accounts at once and from the queue, a release that stopped to wait
    // for room to create one, payments below two raised reserves that failed a call or stranded
    // an exit and were claimed, and exits refused because a party cannot receive.
    for case in [
        "Transact created an account",
        "Release created an account",
        "Release waited for room",
        "Transact refused by the asset",
        "Release stranded",
        "Claim ok",
        "Transact cannot receive",
    ] {
        assert!(seen.contains_key(case), "never {case}: {seen:?}");
    }
}
