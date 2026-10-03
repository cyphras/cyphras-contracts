package follow

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const passphrase = "Test SDF Network ; September 2015"

// activity builds a chain with deposits, admissions and transfers spread over ledgers 10 to 60.
func activity() *vaulttest.Chain {
	c := vaulttest.New(10, 1_728_000_000)
	for range 12 {
		c.Shield(vaulttest.Depositor, 10_000_000)
		c.NextLedger(5)
		c.Shield(vaulttest.Depositor, 20_000_000)
		c.NextLedger(5)
	}
	c.Attest(24)
	c.NextLedger(5)
	ids := make([]uint64, 24)
	for i := range ids {
		ids[i] = uint64(i + 1)
	}
	c.Admit(ids[:12]...)
	c.Admit(ids[12:]...)
	for range 10 {
		c.NextLedger(5)
		c.Transact(-1_000_000, 100_000, vaulttest.Relayer)
		c.Transact(0, 100_000, vaulttest.Relayer)
	}
	return c
}

func load(f *rpctest.Fake, events []vault.RawEvent) {
	for _, e := range events {
		f.AddEvent(rpctest.EventInfo(e))
	}
}

func between(events []vault.RawEvent, from, to uint32) []vault.RawEvent {
	var out []vault.RawEvent
	for _, e := range events {
		if e.Ledger >= from && e.Ledger <= to {
			out = append(out, e)
		}
	}
	return out
}

func TestTheRPCSourceFollowsTheCursorThroughFullPages(t *testing.T) {
	c := activity()
	f := rpctest.New(passphrase, 100)
	load(f, c.Events)
	src := RPCSource{Client: f, Contract: vaulttest.Vault, PageLimit: 7}
	got, err := src.Events(context.Background(), 10, 40)
	if err != nil {
		t.Fatal(err)
	}
	want := between(c.Events, 10, 40)
	if len(got) != len(want) || len(want) < 70 {
		t.Fatalf("read %d events, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Pos() != want[i].Pos() || got[i].Value != want[i].Value || got[i].ClosedAt != want[i].ClosedAt {
			t.Fatalf("event %d differs", i)
		}
	}
	if f.CallCount("getEvents") < 10 {
		t.Fatalf("only %d pages for %d events", f.CallCount("getEvents"), len(got))
	}
}

func TestARangeTheRPCNoLongerKeepsIsPastItsRetention(t *testing.T) {
	c := activity()
	f := rpctest.New(passphrase, 100)
	load(f, c.Events)
	f.Oldest = 50
	src := RPCSource{Client: f, Contract: vaulttest.Vault, PageLimit: 7}
	if _, err := src.Events(context.Background(), 10, 40); !errors.Is(err, ErrRetention) {
		t.Fatalf("a range before the oldest ledger: %v", err)
	}
	// Any other refusal stays a failure.
	f.Fail["getEvents"] = errors.New("rpc down")
	if _, err := src.Events(context.Background(), 60, 70); err == nil || errors.Is(err, ErrRetention) {
		t.Fatalf("a failure in range: %v", err)
	}
}

type memSink struct {
	cursor  uint32
	batches []Batch
	fail    error
}

func (m *memSink) Cursor() uint32 { return m.cursor }

func (m *memSink) Apply(_ context.Context, b Batch) error {
	if m.fail != nil {
		return m.fail
	}
	if b.From != m.cursor+1 {
		return errors.New("window out of order")
	}
	m.batches = append(m.batches, b)
	m.cursor = b.To
	return nil
}

func drain(t *testing.T, fl *Follower) {
	t.Helper()
	for range 1000 {
		progressed, err := fl.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !progressed {
			return
		}
	}
	t.Fatal("follower never caught up")
}

func TestTheFollowerAppliesEveryLedgerOnceInOrder(t *testing.T) {
	c := activity()
	f := rpctest.New(passphrase, 0)
	load(f, c.Events)
	f.SetLatest(75)
	sink := &memSink{cursor: 9}
	fl := &Follower{RPC: f, Live: RPCSource{Client: f, Contract: vaulttest.Vault, PageLimit: 5}, Window: 7, Sink: sink}
	drain(t, fl)
	if sink.cursor != 75 {
		t.Fatalf("cursor %d", sink.cursor)
	}
	var calls, txs int
	for _, b := range sink.batches {
		txs += len(b.Txs)
		for _, tx := range b.Txs {
			calls += len(tx.Calls)
		}
	}
	// 24 shields, one attestation, 24 admissions and 20 transacts.
	if calls != 69 || txs != 24+1+2+20 {
		t.Fatalf("%d calls in %d transactions", calls, txs)
	}
}

func TestAnUnknownTopicIsAFaultAndNothingIsApplied(t *testing.T) {
	c := vaulttest.New(10, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 5)
	c.NextLedger(5).Tx().Emit("mint", vault.Field{Name: "amount", Value: vault.U32(1)})
	f := rpctest.New(passphrase, 0)
	load(f, c.Events)
	sink := &memSink{cursor: 9}
	fl := &Follower{RPC: f, Live: RPCSource{Client: f, Contract: vaulttest.Vault}, Window: 10, Sink: sink}
	if _, err := fl.Step(context.Background()); !errors.Is(err, ErrFault) || !errors.Is(err, vault.ErrUnknownTopic) {
		t.Fatalf("unknown topic: %v", err)
	}
	if sink.cursor != 9 {
		t.Fatal("a faulty window was applied")
	}
}

func TestMalformedEventsFromTheRPCAreAFault(t *testing.T) {
	c := vaulttest.New(10, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 5)
	f := rpctest.New(passphrase, 0)
	for _, e := range c.Events {
		info := rpctest.EventInfo(e)
		info.EventType = protocol.EventTypeSystem
		f.AddEvent(info)
	}
	sink := &memSink{cursor: 9}
	fl := &Follower{RPC: f, Live: RPCSource{Client: f, Contract: vaulttest.Vault}, Window: 10, Sink: sink}
	if _, err := fl.Step(context.Background()); !errors.Is(err, ErrFault) || !errors.Is(err, vault.ErrMalformed) {
		t.Fatalf("a system event: %v", err)
	}
	if sink.cursor != 9 {
		t.Fatal("a malformed window was applied")
	}
}

func TestOlderLedgersComeFromHistoryThenRPCTakesOver(t *testing.T) {
	c := activity()
	f := rpctest.New(passphrase, 0)
	load(f, c.Events)
	f.Oldest = 40
	dir := t.TempDir()
	if err := (archive.Writer{Dir: dir}).Append(between(c.Events, 10, 45), 10, 45); err != nil {
		t.Fatal(err)
	}
	sink := &memSink{cursor: 9}
	fl := &Follower{
		RPC: f, Live: RPCSource{Client: f, Contract: vaulttest.Vault, PageLimit: 50},
		History: []Source{archive.Reader{Dir: dir, Vault: vaulttest.Vault}}, Window: 8, Sink: sink,
	}
	drain(t, fl)
	if sink.cursor != f.Latest {
		t.Fatalf("cursor %d of %d", sink.cursor, f.Latest)
	}
	var n int
	for _, b := range sink.batches {
		n += len(b.Raw)
		if b.From < 40 && b.To >= 40 {
			t.Fatal("a window mixed history and RPC")
		}
	}
	if n != len(c.Events) {
		t.Fatalf("applied %d of %d events", n, len(c.Events))
	}

	fl.History = nil
	sink.cursor = 9
	if _, err := fl.Step(context.Background()); !errors.Is(err, ErrRetention) {
		t.Fatalf("no history beyond retention: %v", err)
	}
}

// The naming examples of the SEP-54 reference implementation.
func TestObjectKeysFollowSEP54(t *testing.T) {
	cases := []struct {
		perPartition, ledger, perFile uint32
		key                           string
	}{
		{0, 5, 1, "FFFFFFFA--5.xdr.zst"},
		{0, 5, 10, "FFFFFFFF--0-9.xdr.zst"},
		{2, 10, 100, "FFFFFFFF--0-199/FFFFFFFF--0-99.xdr.zst"},
		{2, 150, 50, "FFFFFF9B--100-199/FFFFFF69--150-199.xdr.zst"},
		{2, 300, 200, "FFFFFFFF--0-399/FFFFFF37--200-399.xdr.zst"},
		{2, 1, 1, "FFFFFFFF--0-1/FFFFFFFE--1.xdr.zst"},
		{4, 250, 50, "FFFFFF37--200-399/FFFFFF05--250-299.xdr.zst"},
		{1, 300, 200, "FFFFFF37--200-399.xdr.zst"},
		{64000, 63000123, 1, "FC3F0FFF--62976000-63039999/FC3EB1C4--63000123.xdr.zst"},
	}
	for _, c := range cases {
		s := archiveSchema{LedgersPerBatch: c.perFile, BatchesPerPartition: c.perPartition}
		if got := s.objectKey(c.ledger); got != c.key {
			t.Fatalf("%+v: %s", c, got)
		}
	}
}

func lcmWithEvents(t *testing.T, seq uint32, closeTime uint64, vaultID string) xdr.LedgerCloseMeta {
	t.Helper()
	raw, err := strkey.Decode(strkey.VersionByteContract, vaultID)
	if err != nil {
		t.Fatal(err)
	}
	var mine, other xdr.ContractId
	copy(mine[:], raw)
	other[0] = 9
	event := func(id xdr.ContractId, name string) xdr.ContractEvent {
		sym := xdr.ScSymbol(name)
		data := vault.Struct(vault.Field{Name: "up_to", Value: vault.U64(1)})
		return xdr.ContractEvent{ContractId: &id, Type: xdr.ContractEventTypeContract, Body: xdr.ContractEventBody{
			V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{{Type: xdr.ScValTypeScvSymbol, Sym: &sym}}, Data: data},
		}}
	}
	result := func(hash byte, code xdr.TransactionResultCode, events []xdr.ContractEvent) xdr.TransactionResultMetaV1 {
		return xdr.TransactionResultMetaV1{
			Result: xdr.TransactionResultPair{
				TransactionHash: xdr.Hash{hash},
				Result:          xdr.TransactionResult{Result: xdr.TransactionResultResult{Code: code, Results: &[]xdr.OperationResult{}}},
			},
			TxApplyProcessing: xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{Operations: []xdr.OperationMetaV2{{Events: events}}}},
		}
	}
	return xdr.LedgerCloseMeta{V: 2, V2: &xdr.LedgerCloseMetaV2{
		LedgerHeader: xdr.LedgerHeaderHistoryEntry{Header: xdr.LedgerHeader{
			LedgerSeq: xdr.Uint32(seq),
			ScpValue:  xdr.StellarValue{CloseTime: xdr.TimePoint(closeTime), Ext: xdr.StellarValueExt{V: xdr.StellarValueTypeStellarValueBasic}},
		}},
		TxSet: xdr.GeneralizedTransactionSet{V: 1, V1TxSet: &xdr.TransactionSetV1{}},
		TxProcessing: []xdr.TransactionResultMetaV1{
			result(1, xdr.TransactionResultCodeTxSuccess, []xdr.ContractEvent{event(other, "transfer"), event(mine, "attested"), event(mine, "attested")}),
			result(2, xdr.TransactionResultCodeTxFailed, []xdr.ContractEvent{event(mine, "attested")}),
		},
	}}
}

func TestTheLedgerArchiveExtractsTheVaultsEventsWithRPCPositions(t *testing.T) {
	const ledger = 63_000_123
	batch := xdr.LedgerCloseMetaBatch{StartSequence: ledger, EndSequence: ledger, LedgerCloseMetas: []xdr.LedgerCloseMeta{lcmWithEvents(t, ledger, 1_750_000_000, vaulttest.Vault)}}
	raw, err := batch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	enc, _ := zstd.NewWriter(&compressed)
	_, _ = enc.Write(raw)
	_ = enc.Close()
	schema := archiveSchema{LedgersPerBatch: 1, BatchesPerPartition: 64000}
	key := schema.objectKey(ledger)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pubnet/.config.json":
			_, _ = w.Write([]byte(`{"networkPassphrase":"` + passphrase + `","version":"1.0","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":64000}`))
		case "/pubnet/" + key:
			_, _ = w.Write(compressed.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a := &LedgerArchive{BaseURL: srv.URL + "/pubnet", Passphrase: passphrase, Vault: vaulttest.Vault, Workers: 4}
	got, err := a.Events(context.Background(), ledger, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d events", len(got))
	}
	hash := hex.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	if got[0].Tx != 1 || got[0].Op != 0 || got[0].Index != 1 || got[1].Index != 2 || got[0].TxHash != hash || got[0].ClosedAt != 1_750_000_000 {
		t.Fatalf("positions %+v", got)
	}
	if e, err := vault.Decode(got[0]); err != nil || e.Body.(vault.Attested).UpTo != 1 {
		t.Fatalf("decoded %+v, %v", e, err)
	}
	if _, err := a.Events(context.Background(), ledger+1, ledger+1); !errors.Is(err, ErrRetention) {
		t.Fatalf("missing ledger file: %v", err)
	}
	wrong := &LedgerArchive{BaseURL: srv.URL + "/pubnet", Passphrase: "Public Global Stellar Network ; September 2015", Vault: vaulttest.Vault}
	if _, err := wrong.Events(context.Background(), ledger, ledger); err == nil {
		t.Fatal("archive of another network accepted")
	}
}

func TestTheLedgerArchiveRefusesGapsAndRetriesItsLayout(t *testing.T) {
	const ledger = 63_000_200
	compress := func(seq uint32) []byte {
		batch := xdr.LedgerCloseMetaBatch{StartSequence: xdr.Uint32(seq), EndSequence: xdr.Uint32(seq), LedgerCloseMetas: []xdr.LedgerCloseMeta{lcmWithEvents(t, seq, 1_750_000_000, vaulttest.Vault)}}
		raw, err := batch.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		enc, _ := zstd.NewWriter(&out)
		_, _ = enc.Write(raw)
		_ = enc.Close()
		return out.Bytes()
	}
	schema := archiveSchema{LedgersPerBatch: 1, BatchesPerPartition: 64000}
	failures := 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pubnet/.config.json":
			if failures > 0 {
				failures--
				http.Error(w, "busy", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"networkPassphrase":"` + passphrase + `","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":64000}`))
		case "/pubnet/" + schema.objectKey(ledger):
			// The file of one ledger that holds the next one instead.
			_, _ = w.Write(compress(ledger + 1))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a := &LedgerArchive{BaseURL: srv.URL + "/pubnet", Passphrase: passphrase, Vault: vaulttest.Vault}
	if _, err := a.Events(context.Background(), ledger, ledger); err == nil {
		t.Fatal("an unreadable layout was accepted")
	}
	if _, err := a.Events(context.Background(), ledger, ledger); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("a batch without its ledger: %v", err)
	}
}

func TestAnUnknownMetaVersionIsAnError(t *testing.T) {
	lcm := lcmWithEvents(t, 7, 1, vaulttest.Vault)
	lcm.V2.TxProcessing[0].TxApplyProcessing = xdr.TransactionMeta{V: 9}
	raw, err := strkey.Decode(strkey.VersionByteContract, vaulttest.Vault)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledgerEvents(lcm, xdr.ContractId(raw)); !errors.Is(err, vault.ErrMalformed) {
		t.Fatalf("unknown meta version: %v", err)
	}
}

func TestARangeThatEndsBeforeItStartsIsRefused(t *testing.T) {
	ctx := context.Background()
	f := rpctest.New(passphrase, 0)
	if _, err := (RPCSource{Client: f, Contract: vaulttest.Vault}).Events(ctx, 11, 10); !errors.Is(err, ErrRange) {
		t.Fatalf("rpc: %v", err)
	}
	if _, err := (&LedgerArchive{BaseURL: "http://127.0.0.1:1", Passphrase: passphrase, Vault: vaulttest.Vault}).Events(ctx, 11, 10); !errors.Is(err, ErrRange) {
		t.Fatalf("ledger archive: %v", err)
	}
	// An RPC that says it keeps ledgers past its latest one is not followed.
	f.SetLatest(20)
	f.Oldest = 25
	fol := &Follower{RPC: f, Live: RPCSource{Client: f, Contract: vaulttest.Vault}, Window: 5, Sink: &memSink{cursor: 9}}
	if _, err := fol.Step(ctx); !errors.Is(err, ErrRange) {
		t.Fatalf("step: %v", err)
	}
}
