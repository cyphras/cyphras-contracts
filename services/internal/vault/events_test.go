package vault

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

const (
	testDepositor = "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH"
	testRelayer   = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
)

func b64(t *testing.T, v xdr.ScVal) string {
	t.Helper()
	s, err := xdr.MarshalBase64(v)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func addr(t *testing.T, s string) xdr.ScVal {
	t.Helper()
	v, err := Address(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func i128(t *testing.T, n int64) xdr.ScVal {
	t.Helper()
	v, err := I128(big.NewInt(n))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func fieldScVal(n uint64) xdr.ScVal {
	return U256(fr.SetUint64(n).Bytes())
}

// builder emits events the way #[contractevent] encodes them: one symbol topic, map data.
type builder struct {
	t      *testing.T
	ledger uint32
	tx     uint32
	hash   string
	index  uint32
	events []Event
}

func newBuilder(t *testing.T) *builder {
	return &builder{t: t, ledger: 100}
}

func (b *builder) nextTx(hash string) *builder {
	b.tx++
	b.hash = hash
	b.index = 0
	return b
}

func (b *builder) raw(name string, data xdr.ScVal) RawEvent {
	r := RawEvent{
		Ledger: b.ledger, ClosedAt: 1_700_000_000, TxHash: b.hash, Tx: b.tx, Op: 0, Index: b.index,
		Contract: "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5",
		Topics:   []string{b64(b.t, Symbol(name))}, Value: b64(b.t, data),
	}
	b.index++
	return r
}

func (b *builder) emit(name string, fields ...Field) *builder {
	b.t.Helper()
	ev, err := Decode(b.raw(name, Struct(fields...)))
	if err != nil {
		b.t.Fatalf("%s: %v", name, err)
	}
	b.events = append(b.events, ev)
	return b
}

func (b *builder) nullifier(n uint64) *builder {
	return b.emit("new_nullifier", Field{"nullifier", fieldScVal(n)})
}

func (b *builder) commitment(index, value uint64) *builder {
	return b.emit("new_commitment",
		Field{"index", U64(index)}, Field{"commitment", fieldScVal(value)},
		Field{"encrypted_output", Bytes(make([]byte, CiphertextLen))})
}

func (b *builder) pending(id uint64, amount int64) *builder {
	return b.emit("deposit_pending",
		Field{"id", U64(id)}, Field{"depositor", addr(b.t, testDepositor)}, Field{"amount", i128(b.t, amount)},
		Field{"commitment0", fieldScVal(1000 + 2*id)}, Field{"commitment1", fieldScVal(1001 + 2*id)},
		Field{"created_at", U64(1_700_000_000)})
}

func (b *builder) settled(extAmount, fee int64) *builder {
	return b.emit("settled",
		Field{"ext_amount", i128(b.t, extAmount)}, Field{"fee", i128(b.t, fee)},
		Field{"recipient", addr(b.t, testRelayer)}, Field{"relayer", addr(b.t, testRelayer)})
}

func (b *builder) admitted(id, leaf uint64) *builder {
	return b.emit("deposit_admitted", Field{"id", U64(id)}, Field{"leaf_index0", U64(leaf)}, Field{"leaf_index1", U64(leaf + 1)})
}

func testLimits(t *testing.T) xdr.ScVal {
	return Struct(
		Field{"min_deposit", i128(t, 1)},
		Field{"max_deposit", i128(t, 25_000_000_000)},
		Field{"max_daily_per_depositor", i128(t, 50_000_000_000)},
		Field{"tvl_cap", i128(t, 250_000_000_000)},
		Field{"max_daily_outflow", i128(t, 50_000_000_000)},
		Field{"max_fee", i128(t, 50_000_000)},
		Field{"large_deposit_threshold", i128(t, 5_000_000_000)},
	)
}

func TestEveryEventDecodes(t *testing.T) {
	b := newBuilder(t).nextTx("aa")
	b.pending(1, 10_000_000).
		emit("deposit_flagged", Field{"id", U64(1)}, Field{"reason", U32(3)}).
		emit("deposit_unflagged", Field{"id", U64(1)}, Field{"reason", U32(3)}).
		emit("attested", Field{"up_to", U64(1)}).
		admitted(1, 0).
		emit("deposit_refunded", Field{"id", U64(2)}, Field{"reason", U32(0)}).
		commitment(0, 7).
		nullifier(9).
		settled(-5, 1).
		emit("paused", Field{"deposits", Bool(true)}, Field{"transfers", Bool(false)}).
		emit("halted", Field{"until", U64(99)}).
		emit("resumed", Field{"next_halt_at", U64(100)}).
		emit("limits_queued", Field{"limits", testLimits(t)}, Field{"ready_at", U64(5)}).
		emit("limits_applied", Field{"limits", testLimits(t)}, Field{"ready_at", U64(5)}).
		emit("limits_cancelled", Field{"limits", testLimits(t)}, Field{"ready_at", U64(5)})
	if len(b.events) != 15 {
		t.Fatalf("decoded %d events", len(b.events))
	}
	p := b.events[0].Body.(DepositPending)
	if p.ID != 1 || p.Depositor != testDepositor || p.Amount.Int64() != 10_000_000 || p.Commitment0 != fr.SetUint64(1002) {
		t.Fatalf("deposit_pending decoded as %+v", p)
	}
	s := b.events[8].Body.(Settled)
	if s.ExtAmount.Int64() != -5 || s.Fee.Int64() != 1 || s.Recipient != testRelayer {
		t.Fatalf("settled decoded as %+v", s)
	}
	q := b.events[12].Body.(LimitsQueued)
	if q.ReadyAt != 5 || q.Limits.MaxFee.Int64() != 50_000_000 {
		t.Fatalf("limits_queued decoded as %+v", q)
	}
}

func TestUnknownTopicsAndMalformedEventsAreRefused(t *testing.T) {
	b := newBuilder(t).nextTx("aa")
	if _, err := Decode(b.raw("transfer", Struct())); !errors.Is(err, ErrUnknownTopic) {
		t.Fatalf("unknown topic: %v", err)
	}
	// The topic is checked before the data, so an unknown topic with odd data is still unknown.
	if _, err := Decode(b.raw("mint", U32(1))); !errors.Is(err, ErrUnknownTopic) {
		t.Fatalf("unknown topic with non-map data: %v", err)
	}
	nonCanonical := [32]byte{}
	for i := range nonCanonical {
		nonCanonical[i] = 0xff
	}
	bad := map[string]xdr.ScVal{
		"not a map":          U32(1),
		"missing field":      Struct(Field{"index", U64(0)}, Field{"commitment", fieldScVal(1)}),
		"extra field":        Struct(Field{"index", U64(0)}, Field{"commitment", fieldScVal(1)}, Field{"encrypted_output", Bytes(make([]byte, CiphertextLen))}, Field{"x", U32(0)}),
		"wrong type":         Struct(Field{"index", U32(0)}, Field{"commitment", fieldScVal(1)}, Field{"encrypted_output", Bytes(make([]byte, CiphertextLen))}),
		"short ciphertext":   Struct(Field{"index", U64(0)}, Field{"commitment", fieldScVal(1)}, Field{"encrypted_output", Bytes(make([]byte, CiphertextLen-1))}),
		"oversized output":   Struct(Field{"index", U64(0)}, Field{"commitment", fieldScVal(1)}, Field{"encrypted_output", Bytes(make([]byte, 4096))}),
		"non-canonical leaf": Struct(Field{"index", U64(0)}, Field{"commitment", U256(nonCanonical)}, Field{"encrypted_output", Bytes(make([]byte, CiphertextLen))}),
	}
	for name, v := range bad {
		if _, err := Decode(b.raw("new_commitment", v)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	two := b.raw("attested", Struct(Field{"up_to", U64(1)}))
	two.Topics = append(two.Topics, two.Topics[0])
	if _, err := Decode(two); !errors.Is(err, ErrMalformed) {
		t.Fatalf("two topics: %v", err)
	}
	if _, err := Decode(b.raw("deposit_flagged", Struct(Field{"id", U64(1)}, Field{"reason", U32(0)}))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("flag reason 0: %v", err)
	}
	if _, err := Decode(b.raw("settled", Struct(
		Field{"ext_amount", i128(t, 1)}, Field{"fee", i128(t, 0)},
		Field{"recipient", addr(t, testRelayer)}, Field{"relayer", addr(t, testRelayer)}))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("positive settlement: %v", err)
	}
}

func TestTransactionsParseIntoTheShapesTheVaultEmits(t *testing.T) {
	b := newBuilder(t)
	b.nextTx("01").nullifier(1).nullifier(2).pending(1, 5)
	b.nextTx("02").nullifier(3).nullifier(4).pending(2, 5)
	b.nextTx("03").commitment(0, 11).commitment(1, 12).admitted(1, 0).commitment(2, 13).commitment(3, 14).admitted(2, 2)
	b.nextTx("04").nullifier(5).nullifier(6).commitment(4, 15).commitment(5, 16).settled(-10, 1)
	// A contract that calls the vault twice in one transaction.
	b.nextTx("05").nullifier(7).nullifier(8).commitment(6, 17).commitment(7, 18).settled(0, 0).
		nullifier(9).nullifier(10).commitment(8, 19).commitment(9, 20).settled(0, 0).
		emit("attested", Field{"up_to", U64(2)})
	txs, err := ParseTxs(b.events)
	if err != nil {
		t.Fatal(err)
	}
	if len(txs) != 5 {
		t.Fatalf("%d transactions", len(txs))
	}
	if _, ok := txs[0].Calls[0].(Shield); !ok || len(txs[0].Calls) != 1 {
		t.Fatalf("shield parsed as %+v", txs[0].Calls)
	}
	if len(txs[2].Calls) != 2 {
		t.Fatalf("admission of two deposits parsed as %d calls", len(txs[2].Calls))
	}
	a := txs[2].Calls[1].(Admission)
	if a.Admitted.ID != 2 || a.Outputs[0].Index != 2 {
		t.Fatalf("second admission %+v", a)
	}
	if tr := txs[3].Calls[0].(Transact); tr.Settled.ExtAmount.Int64() != -10 || tr.Outputs[1].Index != 5 {
		t.Fatalf("transact %+v", tr)
	}
	if len(txs[4].Calls) != 3 {
		t.Fatalf("multi-call transaction parsed as %d calls", len(txs[4].Calls))
	}
}

func TestBrokenShapesAreRefused(t *testing.T) {
	cases := map[string]func(*builder){
		"lone nullifier":         func(b *builder) { b.nullifier(1) },
		"three nullifiers":       func(b *builder) { b.nullifier(1).nullifier(2).nullifier(3) },
		"pending alone":          func(b *builder) { b.pending(1, 5) },
		"settled alone":          func(b *builder) { b.settled(0, 0) },
		"admitted alone":         func(b *builder) { b.admitted(1, 0) },
		"transact without end":   func(b *builder) { b.nullifier(1).nullifier(2).commitment(0, 1).commitment(1, 2) },
		"odd first leaf":         func(b *builder) { b.commitment(1, 1).commitment(2, 2).admitted(1, 1) },
		"non-adjacent leaves":    func(b *builder) { b.commitment(0, 1).commitment(2, 2).admitted(1, 0) },
		"admitted at other leaf": func(b *builder) { b.commitment(0, 1).commitment(1, 2).admitted(1, 2) },
		"outputs then settled":   func(b *builder) { b.commitment(0, 1).commitment(1, 2).settled(0, 0) },
	}
	for name, build := range cases {
		b := newBuilder(t).nextTx("aa")
		build(b)
		if _, err := ParseTxs(b.events); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	b := newBuilder(t)
	b.nextTx("aa").emit("attested", Field{"up_to", U64(1)})
	b.nextTx("bb").emit("attested", Field{"up_to", U64(2)})
	b.events[1].Raw.Tx = 1
	b.events[1].Raw.Index = 0
	if _, err := ParseTxs(b.events); !errors.Is(err, ErrMalformed) {
		t.Fatalf("transactions out of order: %v", err)
	}
	b = newBuilder(t)
	b.nextTx("aa").emit("attested", Field{"up_to", U64(1)})
	b.nextTx("bb").emit("attested", Field{"up_to", U64(2)})
	b.nextTx("aa").emit("attested", Field{"up_to", U64(3)})
	if _, err := ParseTxs(b.events); !errors.Is(err, ErrMalformed) {
		t.Fatalf("split transaction: %v", err)
	}
}
