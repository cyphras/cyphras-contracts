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

const day = 86_400

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

// State is what the vault's events determine. Spent nullifiers are not kept here; the store
// enforces that each appears once.
type State struct {
	Tree           tree.Tree
	NextDepositID  uint64
	AttestedUpTo   uint64
	Pending        map[uint64]*Deposit
	NullifierCount uint64
	Tvl            *big.Int
	OutflowDay     uint64
	Outflow        *big.Int

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
	return &State{NextDepositID: 1, Pending: map[uint64]*Deposit{}, Tvl: new(big.Int), Outflow: new(big.Int)}
}

// Clone returns a deep copy, so a window can be applied and discarded on failure.
func (s *State) Clone() *State {
	c := *s
	c.Pending = make(map[uint64]*Deposit, len(s.Pending))
	for id, d := range maps.All(s.Pending) {
		c.Pending[id] = d.clone()
	}
	c.Tvl = new(big.Int).Set(s.Tvl)
	c.Outflow = new(big.Int).Set(s.Outflow)
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

// Settlement records one transact.
type Settlement struct {
	vault.Settled
	Ledger   uint32
	ClosedAt int64
	TxHash   string
}

// Notice is a governance or queue event, kept for the services that report them.
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
	Nullifiers  []Nullifier
	Created     []Deposit
	Updated     []Deposit
	Resolved    []Resolution
	Settlements []Settlement
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

func (s *State) apply(tx vault.Tx, call any, d *Delta, spent map[fr.Element]bool) error {
	now := uint64(tx.ClosedAt)
	switch c := call.(type) {
	case vault.Shield:
		if err := s.spend(tx, c.Nullifiers, d, spent); err != nil {
			return err
		}
		p := c.Deposit
		if p.ID != s.NextDepositID {
			return inconsistent("deposit %d where %d was next", p.ID, s.NextDepositID)
		}
		dep := &Deposit{
			ID: p.ID, Depositor: p.Depositor, Amount: new(big.Int).Set(p.Amount),
			Commitment0: p.Commitment0, Commitment1: p.Commitment1,
			CreatedAt: p.CreatedAt, CreatedLedger: tx.Ledger, CreatedTx: tx.Hash,
		}
		s.Pending[p.ID] = dep
		s.NextDepositID++
		s.Tvl.Add(s.Tvl, p.Amount)
		d.Created = append(d.Created, *dep.clone())
	case vault.Transact:
		if err := s.spend(tx, c.Nullifiers, d, spent); err != nil {
			return err
		}
		if err := s.insert(tx, c.Outputs, d); err != nil {
			return err
		}
		outflow := new(big.Int).Sub(c.Settled.Fee, c.Settled.ExtAmount)
		s.Tvl.Sub(s.Tvl, outflow)
		if s.Tvl.Sign() < 0 {
			return inconsistent("more left the vault than entered it")
		}
		if today := now / day; today != s.OutflowDay {
			s.OutflowDay = today
			s.Outflow.SetInt64(0)
		}
		s.Outflow.Add(s.Outflow, outflow)
		d.Settlements = append(d.Settlements, Settlement{Settled: c.Settled, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	case vault.Admission:
		id := c.Admitted.ID
		dep, ok := s.Pending[id]
		if !ok {
			return inconsistent("deposit %d admitted while not pending", id)
		}
		if dep.Flag != nil || id > s.AttestedUpTo {
			return inconsistent("deposit %d admitted while flagged or not attested", id)
		}
		if now < s.HaltedUntil {
			return inconsistent("deposit %d admitted while halted", id)
		}
		if c.Outputs[0].Commitment != dep.Commitment0 || c.Outputs[1].Commitment != dep.Commitment1 {
			return inconsistent("deposit %d admitted with other commitments", id)
		}
		if err := s.insert(tx, c.Outputs, d); err != nil {
			return err
		}
		delete(s.Pending, id)
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
			outcome = Refunded
		}
		delete(s.Pending, c.ID)
		s.Tvl.Sub(s.Tvl, dep.Amount)
		if s.Tvl.Sign() < 0 {
			return inconsistent("refund of deposit %d exceeds the value held", c.ID)
		}
		d.Resolved = append(d.Resolved, Resolution{Deposit: *dep, Outcome: outcome, Reason: c.Reason, Ledger: tx.Ledger, ClosedAt: tx.ClosedAt, TxHash: tx.Hash})
	case vault.Paused:
		s.DepositsPaused, s.TransfersPaused = c.Deposits, c.Transfers
		s.notice(tx, "paused", c, d)
	case vault.Halted:
		s.HaltedUntil = c.Until
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
	for _, o := range outputs {
		d.Leaves = append(d.Leaves, Leaf{Index: o.Index, Commitment: o.Commitment, Ciphertext: o.Ciphertext, Ledger: tx.Ledger, TxHash: tx.Hash})
	}
	return nil
}
