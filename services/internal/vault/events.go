package vault

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// RawEvent is a vault event as it appears on chain, with its position in the ledger. It is the
// unit of the event archive, so its encoding must stay stable.
type RawEvent struct {
	Ledger   uint32 `json:"ledger"`
	ClosedAt int64  `json:"closed_at"`
	TxHash   string `json:"tx_hash"`
	// Tx is the 1-based application order of the transaction in its ledger.
	Tx       uint32   `json:"tx"`
	Op       uint32   `json:"op"`
	Index    uint32   `json:"index"`
	Contract string   `json:"contract"`
	Topics   []string `json:"topics"`
	Value    string   `json:"value"`
}

// Position orders events in chain order.
type Position struct {
	Ledger, Tx, Op, Index uint32
}

// Pos returns the event's position.
func (r RawEvent) Pos() Position {
	return Position{r.Ledger, r.Tx, r.Op, r.Index}
}

// Less reports whether p comes before o.
func (p Position) Less(o Position) bool {
	if p.Ledger != o.Ledger {
		return p.Ledger < o.Ledger
	}
	if p.Tx != o.Tx {
		return p.Tx < o.Tx
	}
	if p.Op != o.Op {
		return p.Op < o.Op
	}
	return p.Index < o.Index
}

// ErrUnknownTopic reports an event the vault never emits.
var ErrUnknownTopic = errors.New("vault: unknown event topic")

// DepositPending is emitted by shield.
type DepositPending struct {
	ID          uint64
	Depositor   string
	Amount      *big.Int
	Commitment0 fr.Element
	Commitment1 fr.Element
	CreatedAt   uint64
}

// DepositFlagged is emitted by flag.
type DepositFlagged struct {
	ID     uint64
	Reason uint32
}

// DepositUnflagged is emitted by unflag; Reason is the code of the cleared flag.
type DepositUnflagged struct {
	ID     uint64
	Reason uint32
}

// Attested is emitted by attest.
type Attested struct {
	UpTo uint64
}

// DepositAdmitted is emitted by admit for each admitted deposit.
type DepositAdmitted struct {
	ID         uint64
	LeafIndex0 uint64
	LeafIndex1 uint64
}

// DepositRefunded is emitted by cancel, with reason 0, and by refund.
type DepositRefunded struct {
	ID     uint64
	Reason uint32
}

// NewCommitment is emitted for every leaf inserted into the tree.
type NewCommitment struct {
	Index      uint64
	Commitment fr.Element
	Ciphertext []byte
}

// NewNullifier is emitted for every spent nullifier.
type NewNullifier struct {
	Nullifier fr.Element
}

// Settled is emitted by transact when it pays at once. With the exit's ID it is emitted by release
// for the step that completes a queued exit, and by claim for the unpaid parts of a stranded exit;
// it then carries only what that step paid.
type Settled struct {
	ExtAmount *big.Int
	Fee       *big.Int
	Recipient string
	Relayer   string
	ExitID    *uint64
}

// ExitQueued is emitted by transact when its payment joins the exit queue.
type ExitQueued struct {
	ID        uint64
	ExtAmount *big.Int
	Fee       *big.Int
	Recipient string
	Relayer   string
}

// ExitPaid is emitted by release for a part payment of the exit at the head of the queue, when
// the day's window cannot pay all it owes; the rest stays at the head.
type ExitPaid struct {
	ID         uint64
	PayoutPaid *big.Int
	FeePaid    *big.Int
	PayoutLeft *big.Int
	FeeLeft    *big.Int
}

// ExitStranded is emitted by release for a queued exit with a part the asset contract refused.
// Payout and Fee are what it still owes, which claim pays.
type ExitStranded struct {
	ID     uint64
	Payout *big.Int
	Fee    *big.Int
}

// Paused is emitted by set_pause.
type Paused struct {
	Deposits  bool
	Transfers bool
}

// Halted is emitted by halt.
type Halted struct {
	Until uint64
}

// Resumed is emitted by resume.
type Resumed struct {
	NextHaltAt uint64
}

// LimitsChange is the data of limits_queued, limits_applied and limits_cancelled.
type LimitsChange struct {
	Limits  Limits
	ReadyAt uint64
}

// LimitsQueued is emitted when a loosening is queued.
type LimitsQueued struct{ LimitsChange }

// LimitsApplied is emitted when limits take effect.
type LimitsApplied struct{ LimitsChange }

// LimitsCancelled is emitted when a queued loosening is dropped.
type LimitsCancelled struct{ LimitsChange }

// Event is a decoded vault event.
type Event struct {
	Raw  RawEvent
	Name string
	// Body is one of the event types of this package.
	Body any
}

// RawFromXDR converts a contract event from transaction metadata. The position fields are the
// caller's to fill.
func RawFromXDR(e xdr.ContractEvent) (RawEvent, error) {
	body, ok := e.Body.GetV0()
	if !ok || e.ContractId == nil {
		return RawEvent{}, malformed("event body version %d", e.Body.V)
	}
	topics := make([]string, len(body.Topics))
	for i, t := range body.Topics {
		s, err := xdr.MarshalBase64(t)
		if err != nil {
			return RawEvent{}, err
		}
		topics[i] = s
	}
	value, err := xdr.MarshalBase64(body.Data)
	if err != nil {
		return RawEvent{}, err
	}
	contract, err := strkey.Encode(strkey.VersionByteContract, e.ContractId[:])
	if err != nil {
		return RawEvent{}, err
	}
	return RawEvent{Contract: contract, Topics: topics, Value: value}, nil
}

// Decode dispatches on the topic before it reads the data, so an unknown event never reaches a
// data decoder.
func Decode(raw RawEvent) (Event, error) {
	if len(raw.Topics) != 1 {
		return Event{}, malformed("event with %d topics", len(raw.Topics))
	}
	var topic xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(raw.Topics[0], &topic); err != nil {
		return Event{}, malformed("topic: %v", err)
	}
	name, ok := symbolOf(topic)
	if !ok {
		return Event{}, malformed("topic is not a symbol")
	}
	decode, ok := decoders[name]
	if !ok {
		return Event{}, fmt.Errorf("%w: %q", ErrUnknownTopic, name)
	}
	var value xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(raw.Value, &value); err != nil {
		return Event{}, malformed("%s data: %v", name, err)
	}
	body, err := decode(value)
	if err != nil {
		return Event{}, fmt.Errorf("%s: %w", name, err)
	}
	return Event{Raw: raw, Name: name, Body: body}, nil
}

var decoders = map[string]func(xdr.ScVal) (any, error){
	"deposit_pending": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "depositor", "amount", "commitment0", "commitment1", "created_at"})
		if d.err != nil {
			return nil, d.err
		}
		e := DepositPending{
			ID:          d.u64("id"),
			Depositor:   d.address("depositor"),
			Amount:      d.i128("amount"),
			Commitment0: d.field("commitment0"),
			Commitment1: d.field("commitment1"),
			CreatedAt:   d.u64("created_at"),
		}
		if d.err == nil && e.Amount.Sign() <= 0 {
			return nil, malformed("deposit of %v", e.Amount)
		}
		return e, d.err
	},
	"deposit_flagged": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "reason"})
		if d.err != nil {
			return nil, d.err
		}
		e := DepositFlagged{ID: d.u64("id"), Reason: d.u32("reason")}
		if d.err == nil && e.Reason == 0 {
			return nil, malformed("flag with reason 0")
		}
		return e, d.err
	},
	"deposit_unflagged": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "reason"})
		if d.err != nil {
			return nil, d.err
		}
		return DepositUnflagged{ID: d.u64("id"), Reason: d.u32("reason")}, d.err
	},
	"attested": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"up_to"})
		if d.err != nil {
			return nil, d.err
		}
		return Attested{UpTo: d.u64("up_to")}, d.err
	},
	"deposit_admitted": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "leaf_index0", "leaf_index1"})
		if d.err != nil {
			return nil, d.err
		}
		return DepositAdmitted{ID: d.u64("id"), LeafIndex0: d.u64("leaf_index0"), LeafIndex1: d.u64("leaf_index1")}, d.err
	},
	"deposit_refunded": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "reason"})
		if d.err != nil {
			return nil, d.err
		}
		return DepositRefunded{ID: d.u64("id"), Reason: d.u32("reason")}, d.err
	},
	"new_commitment": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"index", "commitment", "encrypted_output"})
		if d.err != nil {
			return nil, d.err
		}
		e := NewCommitment{Index: d.u64("index"), Commitment: d.field("commitment"), Ciphertext: d.bytes("encrypted_output")}
		if d.err == nil && len(e.Ciphertext) != CiphertextLen {
			return nil, malformed("ciphertext of %d bytes", len(e.Ciphertext))
		}
		return e, d.err
	},
	"new_nullifier": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"nullifier"})
		if d.err != nil {
			return nil, d.err
		}
		return NewNullifier{Nullifier: d.field("nullifier")}, d.err
	},
	"settled": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"ext_amount", "fee", "recipient", "relayer", "exit_id"})
		if d.err != nil {
			return nil, d.err
		}
		exit, err := optionU64Of(d.fields["exit_id"])
		d.keep(err)
		e := Settled{ExtAmount: d.i128("ext_amount"), Fee: d.i128("fee"), Recipient: d.address("recipient"), Relayer: d.address("relayer"), ExitID: exit}
		if d.err == nil && (e.ExtAmount.Sign() > 0 || e.Fee.Sign() < 0) {
			return nil, malformed("settled with ext_amount %v and fee %v", e.ExtAmount, e.Fee)
		}
		return e, d.err
	},
	"exit_queued": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "ext_amount", "fee", "recipient", "relayer"})
		if d.err != nil {
			return nil, d.err
		}
		e := ExitQueued{ID: d.u64("id"), ExtAmount: d.i128("ext_amount"), Fee: d.i128("fee"), Recipient: d.address("recipient"), Relayer: d.address("relayer")}
		if d.err == nil && (e.ExtAmount.Sign() > 0 || e.Fee.Sign() < 0 || new(big.Int).Sub(e.Fee, e.ExtAmount).Sign() <= 0) {
			return nil, malformed("queued exit with ext_amount %v and fee %v", e.ExtAmount, e.Fee)
		}
		return e, d.err
	},
	"exit_paid": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "payout_paid", "fee_paid", "payout_left", "fee_left"})
		if d.err != nil {
			return nil, d.err
		}
		e := ExitPaid{ID: d.u64("id"), PayoutPaid: d.i128("payout_paid"), FeePaid: d.i128("fee_paid"), PayoutLeft: d.i128("payout_left"), FeeLeft: d.i128("fee_left")}
		if d.err != nil {
			return nil, d.err
		}
		for _, n := range []*big.Int{e.PayoutPaid, e.FeePaid, e.PayoutLeft, e.FeeLeft} {
			if n.Sign() < 0 {
				return nil, malformed("exit part payment with a negative part")
			}
		}
		if e.PayoutPaid.Sign()+e.FeePaid.Sign() == 0 || e.PayoutLeft.Sign()+e.FeeLeft.Sign() == 0 {
			return nil, malformed("exit part payment that pays nothing or leaves nothing")
		}
		return e, nil
	},
	"exit_stranded": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"id", "payout", "fee"})
		if d.err != nil {
			return nil, d.err
		}
		e := ExitStranded{ID: d.u64("id"), Payout: d.i128("payout"), Fee: d.i128("fee")}
		if d.err == nil && (e.Payout.Sign() < 0 || e.Fee.Sign() < 0 || e.Payout.Sign()+e.Fee.Sign() == 0) {
			return nil, malformed("stranded exit with payout %v and fee %v", e.Payout, e.Fee)
		}
		return e, d.err
	},
	"paused": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"deposits", "transfers"})
		if d.err != nil {
			return nil, d.err
		}
		return Paused{Deposits: d.bool("deposits"), Transfers: d.bool("transfers")}, d.err
	},
	"halted": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"until"})
		if d.err != nil {
			return nil, d.err
		}
		return Halted{Until: d.u64("until")}, d.err
	},
	"resumed": func(v xdr.ScVal) (any, error) {
		d := newDecoder(v, []string{"next_halt_at"})
		if d.err != nil {
			return nil, d.err
		}
		return Resumed{NextHaltAt: d.u64("next_halt_at")}, d.err
	},
	"limits_queued": func(v xdr.ScVal) (any, error) {
		c, err := decodeLimitsChange(v)
		return LimitsQueued{c}, err
	},
	"limits_applied": func(v xdr.ScVal) (any, error) {
		c, err := decodeLimitsChange(v)
		return LimitsApplied{c}, err
	},
	"limits_cancelled": func(v xdr.ScVal) (any, error) {
		c, err := decodeLimitsChange(v)
		return LimitsCancelled{c}, err
	},
}

func decodeLimitsChange(v xdr.ScVal) (LimitsChange, error) {
	d := newDecoder(v, []string{"limits", "ready_at"})
	if d.err != nil {
		return LimitsChange{}, d.err
	}
	limits, err := DecodeLimits(d.fields["limits"])
	if err != nil {
		return LimitsChange{}, err
	}
	return LimitsChange{Limits: limits, ReadyAt: d.u64("ready_at")}, d.err
}
