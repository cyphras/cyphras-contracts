// Package chainstate rebuilds the vault's state from its events and checks every transaction
// against the rules the vault enforces, so an event stream that breaks an invariant is caught
// before anything is served from it.
package chainstate

import (
	"errors"
	"fmt"
	"maps"
	"math/big"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// ErrInconsistent reports events that contradict the vault's own rules.
var ErrInconsistent = errors.New("chainstate: events contradict the vault")

func inconsistent(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInconsistent, fmt.Sprintf(format, args...))
}

const (
	day          = 86_400
	haltCooldown = 7 * day
	refundDelay  = day
)

// Deposit is a deposit still in the entry queue.
type Deposit struct {
	ID            uint64
	Depositor     string
	Amount        *big.Int
	Commitment0   fr.Element
	Commitment1   fr.Element
	CreatedAt     uint64
	CreatedLedger uint32
	CreatedTx     string
	Flag          *uint32
	FlaggedAt     uint64
}

func (d *Deposit) clone() *Deposit {
	c := *d
	if d.Flag != nil {
		f := *d.Flag
		c.Flag = &f
	}
	return &c
}

// Exit is a payment the vault owes: one waiting in the exit queue, or, among the stranded exits,
// the parts a release could not pay. Payout and Fee are what is still owed, less any part
// payment.
type Exit struct {
	ID        uint64
	Payout    *big.Int
	Fee       *big.Int
	Recipient string
	Relayer   string
	QueuedAt  uint64
	Ledger    uint32
	TxHash    string
	// StrandedLedger, StrandedAt and StrandedTx are set on a stranded exit: the release that
	// stranded it.
	StrandedLedger uint32
	StrandedAt     int64
	StrandedTx     string
}

// Outflow is what the exit takes from a day's window.
func (e Exit) Outflow() *big.Int {
	return new(big.Int).Add(e.Payout, e.Fee)
}

// State is what the vault's events determine. Spent nullifiers are not kept here; the store
// enforces that each appears once.
type State struct {
	Tree           tree.Tree
	NextDepositID  uint64
	AttestedUpTo   uint64
	Pending        map[uint64]*Deposit
	NullifierCount uint64
	// Tvl is everything the vault holds for users: pending deposits, queued exits and notes.
	Tvl          *big.Int
	PendingTotal *big.Int
	QueuedTotal  *big.Int
	ExitHead     uint64
	ExitTail     uint64
	Exits        map[uint64]*Exit
	// Stranded holds the unpaid parts of released exits until claim pays them.
	Stranded   map[uint64]*Exit
	OutflowDay uint64
	Outflow    *big.Int

	DepositsPaused  bool
	TransfersPaused bool
	HaltedUntil     uint64
	NextHaltAt      uint64
	// Limits is nil until the first limits event, since the constructor emits none.
	Limits *vault.Limits
	Queued *vault.QueuedLimits
}

// New returns the state of a freshly deployed vault.
func New() *State {
	return &State{
		NextDepositID: 1, Pending: map[uint64]*Deposit{}, Tvl: new(big.Int), PendingTotal: new(big.Int),
		QueuedTotal: new(big.Int), ExitHead: 1, ExitTail: 1, Exits: map[uint64]*Exit{}, Stranded: map[uint64]*Exit{},
		Outflow: new(big.Int),
	}
}

func (e *Exit) clone() *Exit {
	c := *e
	c.Payout, c.Fee = new(big.Int).Set(e.Payout), new(big.Int).Set(e.Fee)
	return &c
}

// Clone returns a deep copy, so a window can be applied and discarded on failure.
func (s *State) Clone() *State {
	c := *s
	c.Pending = make(map[uint64]*Deposit, len(s.Pending))
	for id, d := range maps.All(s.Pending) {
		c.Pending[id] = d.clone()
	}
	c.Exits = make(map[uint64]*Exit, len(s.Exits))
	for id, e := range maps.All(s.Exits) {
		c.Exits[id] = e.clone()
	}
	c.Stranded = make(map[uint64]*Exit, len(s.Stranded))
	for id, e := range maps.All(s.Stranded) {
		c.Stranded[id] = e.clone()
	}
	for _, n := range []**big.Int{&c.Tvl, &c.PendingTotal, &c.QueuedTotal, &c.Outflow} {
		*n = new(big.Int).Set(*n)
	}
	if s.Limits != nil {
		l := *s.Limits
		c.Limits = &l
	}
	if s.Queued != nil {
		q := *s.Queued
		c.Queued = &q
	}
	return &c
}

// OutflowOn is what the window of the given day has paid.
func (s *State) OutflowOn(d uint64) *big.Int {
	if s.OutflowDay == d {
		return new(big.Int).Set(s.Outflow)
	}
	return new(big.Int)
}

// Leaf is an inserted commitment.
type Leaf struct {
	Index      uint64
	Commitment fr.Element
	Ciphertext []byte
	Ledger     uint32
	TxHash     string
}

// Nullifier is a spent nullifier; Seq is its position in chain order.
type Nullifier struct {
	Seq       uint64
	Nullifier fr.Element
	Ledger    uint32
	TxHash    string
}

// Outcome is how a deposit left the queue.
type Outcome string

// The outcomes of a deposit.
const (
	Admitted  Outcome = "admitted"
	Cancelled Outcome = "cancelled"
	Refunded  Outcome = "refunded"
)

// Resolution records a deposit leaving the queue.
type Resolution struct {
	Deposit    Deposit
	Outcome    Outcome
	Reason     uint32
	Ledger     uint32
	ClosedAt   int64
	TxHash     string
	LeafIndex0 uint64
	LeafIndex1 uint64
}

// Settlement records one payment out of the vault: a transact paid at once, a queued exit paid by
// release, what a release paid of an exit it stranded, or a claim. Only the stranded case has no
// settled event of its own.
type Settlement struct {
	vault.Settled
	Ledger   uint32
	ClosedAt int64
	TxHash   string
}

// Released is a queued exit that release took off the queue. UnpaidPayout and UnpaidFee are the
// parts the asset contract refused, both zero when the exit was paid in full.
type Released struct {
	Exit
	UnpaidPayout *big.Int
	UnpaidFee    *big.Int
	PaidLedger   uint32
	PaidAt       int64
	PaidTx       string
}

// PartPaid is the exit at the head of the queue after a release paid part of it.
type PartPaid struct {
	ID         uint64
	PayoutLeft *big.Int
	FeeLeft    *big.Int
}

// Claimed is a stranded exit that claim paid.
type Claimed struct {
	ID       uint64
	Ledger   uint32
	ClosedAt int64
	TxHash   string
}

// RootAt is the tree's root once it holds LeafCount leaves. The vault keeps the same roots in its
// root ring, so a root read from the chain is compared with the one at the same leaf count.
type RootAt struct {
	LeafCount uint64
	Root      fr.Element
}

// Notice is a governance, queue or exit event, kept for the services that report them.
type Notice struct {
	Name     string
	Body     any
	Ledger   uint32
	ClosedAt int64
	TxHash   string
}

// Delta is what one window of transactions changed.
type Delta struct {
	Leaves      []Leaf
	Roots       []RootAt
	Nullifiers  []Nullifier
	Created     []Deposit
	Updated     []Deposit
	Resolved    []Resolution
	Settlements []Settlement
	Queued      []Exit
	PartPaid    []PartPaid
	Released    []Released
	Claimed     []Claimed
	Notices     []Notice
}

// Apply applies the transactions in chain order and returns what changed. On error the state is
// left partly applied, so callers apply to a Clone.
func (s *State) Apply(txs []vault.Tx) (Delta, error) {
	var d Delta
	spent := map[fr.Element]bool{}
	for _, tx := range txs {
		for _, call := range tx.Calls {
			if err := s.apply(tx, call, &d, spent); err != nil {
				return Delta{}, fmt.Errorf("transaction %s in ledger %d: %w", tx.Hash, tx.Ledger, err)
			}
		}
	}
	return d, nil
}

func (s *State) halted(now uint64) bool {
	return now < s.HaltedUntil
}

func (s *State) apply(tx vault.Tx, call any, d *Delta, spent map[fr.Element]bool) error {
	now := uint64(tx.ClosedAt)
	switch c := call.(type) {
	case vault.Shield:
		if s.halted(now) || s.DepositsPaused {
			return inconsistent("a deposit while halted or while deposits are paused")
		}
		if err := s.spend(tx, c.Nullifiers, d, spent); err != nil {
			return err
		}
		p := c.Deposit
		if p.ID != s.NextDepositID {
			return inconsistent("deposit %d where %d was next", p.ID, s.NextDepositID)
		}
		if p.Commitment0 == p.Commitment1 {
			return inconsistent("deposit %d has two equal outputs", p.ID)
		}
		dep := &Deposit{
			ID: p.ID, Depositor: p.Depositor, Amount: new(big.Int).Set(p.Amount),
			Commitment0: p.Commitment0, Commitment1: p.Commitment1,
			CreatedAt: p.CreatedAt, CreatedLedger: tx.Ledger, CreatedTx: tx.Hash,
		}
		s.Pending[p.ID] = dep
		s.NextDepositID++
		s.Tvl.Add(s.Tvl, p.Amount)
		s.PendingTotal.Add(s.PendingTotal, p.Amount)
		d.Created = append(d.Created, *dep.clone())
	case vault.Transact:
		return s.transact(tx, c, d, spent)
	case vault.ExitSettled:
		if _, ok := s.Stranded[*c.Settled.ExitID]; ok {
			return s.claim(tx, c.Settled, d)
		}
		return s.release(tx, c.Settled, d)
	case vault.ExitPaid:
		return s.payPart(tx, c, d)
	case vault.ExitStranded:
		return s.strand(tx, c, d)
	case vault.Admission:
		id := c.Admitted.ID
		dep, ok := s.Pending[id]
		if !ok {
			return inconsistent("deposit %d admitted while not pending", id)
		}
		if dep.Flag != nil || id > s.AttestedUpTo {
			return inconsistent("deposit %d admitted while flagged or not attested", id)
		}
		if s.halted(now) {
			return inconsistent("deposit %d admitted while halted", id)
		}
		if c.Outputs[0].Commitment != dep.Commitment0 || c.Outputs[1].Commitment != dep.Commitment1 {
			return inconsistent("deposit %d admitted with other commitments", id)
		}
		if err := s.insert(tx, c.Outputs, d); err != nil {
			return err
		}
		delete(s.Pending, id)
		s.PendingTotal.Sub(s.PendingTotal, dep.Amount)
		d.Resolved = append(d.Resolved, Resolution{
			Deposit: *dep, Outcome: Admitted, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash,
			LeafIndex0: c.Admitted.LeafIndex0, LeafIndex1: c.Admitted.LeafIndex1,
		})
	case vault.DepositFlagged:
		dep, ok := s.Pending[c.ID]
		if !ok {
			return inconsistent("deposit %d flagged while not pending", c.ID)
		}
		if dep.Flag == nil {
			dep.FlaggedAt = now
		}
		reason := c.Reason
		dep.Flag = &reason
		d.Updated = append(d.Updated, *dep.clone())
		s.notice(tx, "deposit_flagged", c, d)
	case vault.DepositUnflagged:
		dep, ok := s.Pending[c.ID]
		if !ok || dep.Flag == nil || *dep.Flag != c.Reason {
			return inconsistent("deposit %d unflagged without that flag", c.ID)
		}
		dep.Flag = nil
		dep.FlaggedAt = 0
		d.Updated = append(d.Updated, *dep.clone())
		s.notice(tx, "deposit_unflagged", c, d)
	case vault.Attested:
		if s.halted(now) {
			return inconsistent("an attestation while halted")
		}
		if c.UpTo <= s.AttestedUpTo || c.UpTo >= s.NextDepositID {
			return inconsistent("attestation up to %d after %d with %d next", c.UpTo, s.AttestedUpTo, s.NextDepositID)
		}
		s.AttestedUpTo = c.UpTo
		s.notice(tx, "attested", c, d)
	case vault.DepositRefunded:
		dep, ok := s.Pending[c.ID]
		if !ok {
			return inconsistent("deposit %d refunded while not pending", c.ID)
		}
		outcome := Cancelled
		if c.Reason != 0 {
			if dep.Flag == nil || *dep.Flag != c.Reason {
				return inconsistent("deposit %d refunded for reason %d it was not flagged with", c.ID, c.Reason)
			}
			if now < dep.FlaggedAt+refundDelay {
				return inconsistent("deposit %d refunded within a day of its flag", c.ID)
			}
			outcome = Refunded
		}
		delete(s.Pending, c.ID)
		s.Tvl.Sub(s.Tvl, dep.Amount)
		s.PendingTotal.Sub(s.PendingTotal, dep.Amount)
		if s.Tvl.Sign() < 0 || s.PendingTotal.Sign() < 0 {
			return inconsistent("refund of deposit %d exceeds the value held", c.ID)
		}
		d.Resolved = append(d.Resolved, Resolution{Deposit: *dep, Outcome: outcome, Reason: c.Reason, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	case vault.Paused:
		s.DepositsPaused, s.TransfersPaused = c.Deposits, c.Transfers
		s.notice(tx, "paused", c, d)
	case vault.Halted:
		s.HaltedUntil = c.Until
		s.NextHaltAt = c.Until + haltCooldown
		s.notice(tx, "halted", c, d)
	case vault.Resumed:
		s.HaltedUntil = now
		s.NextHaltAt = c.NextHaltAt
		s.notice(tx, "resumed", c, d)
	case vault.LimitsQueued:
		q := vault.QueuedLimits{Limits: c.Limits, ReadyAt: c.ReadyAt}
		s.Queued = &q
		s.notice(tx, "limits_queued", c, d)
	case vault.LimitsApplied:
		l := c.Limits
		s.Limits = &l
		if s.Queued != nil && s.Queued.ReadyAt == c.ReadyAt {
			s.Queued = nil
		}
		s.notice(tx, "limits_applied", c, d)
	case vault.LimitsCancelled:
		s.Queued = nil
		s.notice(tx, "limits_cancelled", c, d)
	default:
		return inconsistent("unexpected call %T", call)
	}
	return nil
}

func (s *State) transact(tx vault.Tx, c vault.Transact, d *Delta, spent map[fr.Element]bool) error {
	now := uint64(tx.ClosedAt)
	if s.halted(now) {
		return inconsistent("a transact while halted")
	}
	var extAmount, fee *big.Int
	var recipient, relayer string
	if c.Queued != nil {
		extAmount, fee, recipient, relayer = c.Queued.ExtAmount, c.Queued.Fee, c.Queued.Recipient, c.Queued.Relayer
	} else {
		extAmount, fee, recipient, relayer = c.Settled.ExtAmount, c.Settled.Fee, c.Settled.Recipient, c.Settled.Relayer
	}
	if extAmount.Sign() == 0 && (s.TransfersPaused || recipient != relayer) {
		return inconsistent("a transfer while transfers are paused or to a recipient other than its relayer")
	}
	if c.Outputs[0].Commitment == c.Outputs[1].Commitment {
		return inconsistent("a transaction with two equal outputs")
	}
	outflow := new(big.Int).Sub(fee, extAmount)
	notes := new(big.Int).Sub(s.Tvl, s.PendingTotal)
	notes.Sub(notes, s.QueuedTotal)
	if outflow.Cmp(notes) > 0 {
		return inconsistent("an exit larger than the value of the admitted notes")
	}
	if s.Limits != nil && (fee.Cmp(s.Limits.MaxFee) > 0 || outflow.Cmp(s.Limits.MaxDailyOutflow) > 0) {
		return inconsistent("a fee above max_fee or an exit above max_daily_outflow")
	}
	if err := s.spend(tx, c.Nullifiers, d, spent); err != nil {
		return err
	}
	if err := s.insert(tx, c.Outputs, d); err != nil {
		return err
	}
	fits := s.ExitHead == s.ExitTail && s.fits(now, outflow)
	if c.Queued != nil {
		q := c.Queued
		if q.ID != s.ExitTail {
			return inconsistent("exit %d queued where %d was next", q.ID, s.ExitTail)
		}
		if fits && s.Limits != nil {
			return inconsistent("exit %d queued while it could be paid at once", q.ID)
		}
		e := &Exit{ID: q.ID, Payout: new(big.Int).Neg(q.ExtAmount), Fee: new(big.Int).Set(q.Fee), Recipient: q.Recipient, Relayer: q.Relayer, QueuedAt: now, Ledger: tx.Ledger, TxHash: tx.Hash}
		s.Exits[q.ID] = e
		s.ExitTail++
		s.QueuedTotal.Add(s.QueuedTotal, outflow)
		d.Queued = append(d.Queued, *e)
		s.notice(tx, "exit_queued", *q, d)
		return nil
	}
	if outflow.Sign() > 0 && !fits {
		return inconsistent("an exit paid at once past a queued one or beyond today's window")
	}
	s.pay(now, outflow)
	d.Settlements = append(d.Settlements, Settlement{Settled: *c.Settled, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	return nil
}

// head returns the exit at the head of the queue, which a release must handle next.
func (s *State) head(now uint64, id uint64) (*Exit, error) {
	if s.halted(now) {
		return nil, inconsistent("a release while halted")
	}
	e, ok := s.Exits[id]
	if !ok || id != s.ExitHead {
		return nil, inconsistent("exit %d released out of turn; the head is %d", id, s.ExitHead)
	}
	return e, nil
}

// release pays what the exit at the head of the queue still owes and completes it.
func (s *State) release(tx vault.Tx, settled vault.Settled, d *Delta) error {
	now := uint64(tx.ClosedAt)
	id := *settled.ExitID
	e, err := s.head(now, id)
	if err != nil {
		return err
	}
	if new(big.Int).Neg(settled.ExtAmount).Cmp(e.Payout) != 0 || settled.Fee.Cmp(e.Fee) != 0 || settled.Recipient != e.Recipient || settled.Relayer != e.Relayer {
		return inconsistent("exit %d paid differently from what it owes", id)
	}
	if !s.fits(now, e.Outflow()) {
		return inconsistent("exit %d paid beyond today's window", id)
	}
	if err := s.takeOff(now, id, e.Outflow()); err != nil {
		return err
	}
	d.Released = append(d.Released, Released{Exit: *e, UnpaidPayout: new(big.Int), UnpaidFee: new(big.Int), PaidLedger: tx.Ledger, PaidAt: tx.ClosedAt, PaidTx: tx.Hash})
	d.Settlements = append(d.Settlements, Settlement{Settled: settled, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	s.notice(tx, "exit_released", settled, d)
	return nil
}

// payPart pays part of the exit at the head of the queue and leaves the rest there, as release
// does when the day's window cannot pay all of it: the window is full afterwards.
func (s *State) payPart(tx vault.Tx, c vault.ExitPaid, d *Delta) error {
	now := uint64(tx.ClosedAt)
	e, err := s.head(now, c.ID)
	if err != nil {
		return err
	}
	if new(big.Int).Add(c.PayoutPaid, c.PayoutLeft).Cmp(e.Payout) != 0 || new(big.Int).Add(c.FeePaid, c.FeeLeft).Cmp(e.Fee) != 0 {
		return inconsistent("exit %d part paid differently from what it owes", c.ID)
	}
	if p, f, known := s.step(now, e); known && (c.PayoutPaid.Cmp(p) != 0 || c.FeePaid.Cmp(f) != 0) {
		return inconsistent("exit %d part paid other than what today's window allows", c.ID)
	}
	paid := new(big.Int).Add(c.PayoutPaid, c.FeePaid)
	e.Payout, e.Fee = new(big.Int).Set(c.PayoutLeft), new(big.Int).Set(c.FeeLeft)
	s.QueuedTotal.Sub(s.QueuedTotal, paid)
	s.pay(now, paid)
	if s.Tvl.Sign() < 0 || s.QueuedTotal.Sign() < 0 {
		return inconsistent("exit %d pays more than the vault holds", c.ID)
	}
	id := c.ID
	part := vault.Settled{ExtAmount: new(big.Int).Neg(c.PayoutPaid), Fee: new(big.Int).Set(c.FeePaid), Recipient: e.Recipient, Relayer: e.Relayer, ExitID: &id}
	d.PartPaid = append(d.PartPaid, PartPaid{ID: c.ID, PayoutLeft: e.Payout, FeeLeft: e.Fee})
	d.Settlements = append(d.Settlements, Settlement{Settled: part, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	s.notice(tx, "exit_paid", c, d)
	return nil
}

// strand releases the exit at the head of the queue with the parts the asset contract refused
// left owed.
func (s *State) strand(tx vault.Tx, c vault.ExitStranded, d *Delta) error {
	now := uint64(tx.ClosedAt)
	e, err := s.head(now, c.ID)
	if err != nil {
		return err
	}
	if c.Payout.Cmp(e.Payout) > 0 || c.Fee.Cmp(e.Fee) > 0 {
		return inconsistent("exit %d stranded with more than it owes", c.ID)
	}
	paidPayout := new(big.Int).Sub(e.Payout, c.Payout)
	paidFee := new(big.Int).Sub(e.Fee, c.Fee)
	paid := new(big.Int).Add(paidPayout, paidFee)
	if !s.fits(now, paid) {
		return inconsistent("exit %d released beyond today's window", c.ID)
	}
	// Each transfer of the step is taken in full or refused in full, and at least one was refused.
	if p, f, known := s.step(now, e); known {
		whole := func(paid, part *big.Int) bool { return paid.Sign() == 0 || paid.Cmp(part) == 0 }
		if !whole(paidPayout, p) || !whole(paidFee, f) || (paidPayout.Cmp(p) == 0 && paidFee.Cmp(f) == 0) {
			return inconsistent("exit %d stranded with parts its release could not have left", c.ID)
		}
	}
	if err := s.takeOff(now, c.ID, paid); err != nil {
		return err
	}
	left := e.clone()
	left.Payout, left.Fee = new(big.Int).Set(c.Payout), new(big.Int).Set(c.Fee)
	left.StrandedLedger, left.StrandedAt, left.StrandedTx = tx.Ledger, tx.ClosedAt, tx.Hash
	s.Stranded[c.ID] = left
	d.Released = append(d.Released, Released{Exit: *e, UnpaidPayout: left.Payout, UnpaidFee: left.Fee, PaidLedger: tx.Ledger, PaidAt: tx.ClosedAt, PaidTx: tx.Hash})
	if paid.Sign() > 0 {
		id := c.ID
		part := vault.Settled{ExtAmount: new(big.Int).Neg(paidPayout), Fee: paidFee, Recipient: e.Recipient, Relayer: e.Relayer, ExitID: &id}
		d.Settlements = append(d.Settlements, Settlement{Settled: part, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	}
	s.notice(tx, "exit_stranded", c, d)
	return nil
}

// takeOff removes the head exit from the queue and pays what was paid of it.
func (s *State) takeOff(now uint64, id uint64, paid *big.Int) error {
	delete(s.Exits, id)
	s.ExitHead++
	s.QueuedTotal.Sub(s.QueuedTotal, paid)
	s.pay(now, paid)
	if s.Tvl.Sign() < 0 || s.QueuedTotal.Sign() < 0 {
		return inconsistent("exit %d pays more than the vault holds", id)
	}
	return nil
}

// claim pays the unpaid parts of a stranded exit.
func (s *State) claim(tx vault.Tx, settled vault.Settled, d *Delta) error {
	now := uint64(tx.ClosedAt)
	if s.halted(now) {
		return inconsistent("a claim while halted")
	}
	id := *settled.ExitID
	e := s.Stranded[id]
	if new(big.Int).Neg(settled.ExtAmount).Cmp(e.Payout) != 0 || settled.Fee.Cmp(e.Fee) != 0 || settled.Recipient != e.Recipient || settled.Relayer != e.Relayer {
		return inconsistent("stranded exit %d claimed differently from what it owes", id)
	}
	outflow := e.Outflow()
	if !s.fits(now, outflow) {
		return inconsistent("stranded exit %d claimed beyond today's window", id)
	}
	delete(s.Stranded, id)
	s.QueuedTotal.Sub(s.QueuedTotal, outflow)
	s.pay(now, outflow)
	if s.Tvl.Sign() < 0 || s.QueuedTotal.Sign() < 0 {
		return inconsistent("stranded exit %d pays more than the vault holds", id)
	}
	d.Claimed = append(d.Claimed, Claimed{ID: id, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	d.Settlements = append(d.Settlements, Settlement{Settled: settled, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	s.notice(tx, "exit_claimed", settled, d)
	return nil
}

// step is what a release tries to pay of an exit today: the payout first, then the fee, each cut
// to what is left of the window. It is unknown before the first limits event.
func (s *State) step(now uint64, e *Exit) (payout, fee *big.Int, known bool) {
	if s.Limits == nil {
		return nil, nil, false
	}
	room := new(big.Int).Sub(s.Limits.MaxDailyOutflow, s.OutflowOn(now/day))
	if room.Sign() < 0 {
		room.SetInt64(0)
	}
	payout = minInt(e.Payout, room)
	fee = minInt(e.Fee, new(big.Int).Sub(room, payout))
	return payout, fee, true
}

func minInt(a, b *big.Int) *big.Int {
	if a.Cmp(b) < 0 {
		return new(big.Int).Set(a)
	}
	return new(big.Int).Set(b)
}

// fits reports whether an outflow fits what is left of today's window. Before the first limits
// event the window is unknown and every outflow fits.
func (s *State) fits(now uint64, outflow *big.Int) bool {
	if s.Limits == nil {
		return true
	}
	return new(big.Int).Add(s.OutflowOn(now/day), outflow).Cmp(s.Limits.MaxDailyOutflow) <= 0
}

// pay takes an outflow out of the vault and today's window.
func (s *State) pay(now uint64, outflow *big.Int) {
	s.Tvl.Sub(s.Tvl, outflow)
	if today := now / day; today != s.OutflowDay {
		s.OutflowDay = today
		s.Outflow.SetInt64(0)
	}
	s.Outflow.Add(s.Outflow, outflow)
}

func (s *State) notice(tx vault.Tx, name string, body any, d *Delta) {
	d.Notices = append(d.Notices, Notice{Name: name, Body: body, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
}

func (s *State) spend(tx vault.Tx, nfs [2]vault.NewNullifier, d *Delta, spent map[fr.Element]bool) error {
	if nfs[0].Nullifier == nfs[1].Nullifier {
		return inconsistent("one transaction spends a nullifier twice")
	}
	for _, nf := range nfs {
		if spent[nf.Nullifier] {
			return inconsistent("nullifier %s spent twice", nf.Nullifier.Hex())
		}
		spent[nf.Nullifier] = true
		d.Nullifiers = append(d.Nullifiers, Nullifier{Seq: s.NullifierCount, Nullifier: nf.Nullifier, Ledger: tx.Ledger, TxHash: tx.Hash})
		s.NullifierCount++
	}
	return nil
}

func (s *State) insert(tx vault.Tx, outputs [2]vault.NewCommitment, d *Delta) error {
	if outputs[0].Index != s.Tree.Len() {
		return inconsistent("leaf %d inserted where %d was next", outputs[0].Index, s.Tree.Len())
	}
	if _, err := s.Tree.AppendPair(outputs[0].Commitment, outputs[1].Commitment); err != nil {
		return inconsistent("insertion: %v", err)
	}
	d.Roots = append(d.Roots, RootAt{LeafCount: s.Tree.Len(), Root: s.Tree.Root()})
	for _, o := range outputs {
		d.Leaves = append(d.Leaves, Leaf{Index: o.Index, Commitment: o.Commitment, Ciphertext: o.Ciphertext, Ledger: tx.Ledger, TxHash: tx.Hash})
	}
	return nil
}
