package relayer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const (
	passphrase = "Test SDF Network ; September 2015"
	feeAddress = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
)

// fixture returns the request body of one of the vault's real-proof fixture steps.
func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../vault/testdata/proofs.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Steps []struct {
			Name  string         `json:"name"`
			Ext   map[string]any `json:"ext"`
			Proof map[string]any `json:"proof"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, s := range f.Steps {
		if s.Name != name {
			continue
		}
		strip := func(v any) any {
			switch x := v.(type) {
			case string:
				return strings.TrimPrefix(x, "0x")
			case []any:
				out := make([]any, len(x))
				for i, item := range x {
					out[i] = strings.TrimPrefix(item.(string), "0x")
				}
				return out
			}
			return v
		}
		proof := map[string]any{}
		for k, v := range s.Proof {
			if k != "domain" {
				proof[k] = strip(v)
			}
		}
		return map[string]any{"proof": proof, "ext": s.Ext}
	}
	t.Fatalf("no step %s", name)
	return nil
}

type screenStub struct {
	allow  bool
	reason uint32
	err    error
	asked  []string
}

func (s *screenStub) Screen(_ context.Context, address string) (bool, uint32, error) {
	s.asked = append(s.asked, address)
	return s.allow, s.reason, s.err
}

type harness struct {
	t      *testing.T
	fake   *rpctest.Fake
	r      *Relayer
	screen *screenStub
	now    time.Time
	mu     sync.Mutex
	sent   int
	status protocol.GetTransactionResponse
	simErr string
}

func success(resource int64) protocol.GetTransactionResponse {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: xdr.Int64(resource + 100), Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}})
	meta, _ := xdr.MarshalBase64(xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{SorobanMeta: &xdr.SorobanTransactionMetaV2{
		Ext: xdr.SorobanTransactionMetaExt{V: 1, V1: &xdr.SorobanTransactionMetaExtV1{TotalNonRefundableResourceFeeCharged: xdr.Int64(resource)}},
	}}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusSuccess, ResultXDR: r, ResultMetaXDR: meta, Ledger: 1001}}
}

func newHarness(t *testing.T, status vault.Status) *harness {
	t.Helper()
	h := &harness{t: t, fake: rpctest.New(passphrase, 1000), screen: &screenStub{allow: true}, now: time.Unix(1_728_000_000, 0), status: success(900_000)}
	h.fake.CloseTime = h.now.Unix()
	h.fake.FeeStats.SorobanInclusionFee.P90 = 100
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000, Status: status,
	}), 10, nil)
	var channels []*submit.Account
	for range 2 {
		kp := keypair.MustRandom()
		key, _ := vault.AccountKey(kp.Address())
		h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, SeqNum: 7}}, 1, nil)
		channels = append(channels, submit.NewAccount(kp.Address(), kp))
	}
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		if h.simErr != "" {
			return protocol.SimulateTransactionResponse{Error: h.simErr}, nil
		}
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 800_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	h.fake.Send = func(protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		h.mu.Lock()
		h.sent++
		h.mu.Unlock()
		return protocol.SendTransactionResponse{Status: "PENDING"}, nil
	}
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.status, nil
	}
	pool, err := chainstate.Open(context.Background(), testdb.URL(t), Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	engine := &submit.Engine{RPC: h.fake, Passphrase: passphrase, Validity: time.Minute, Poll: time.Millisecond, Now: h.clock}
	r, err := New(ctx, Config{
		Vault: vaulttest.Vault, NetworkID: rpc.NetworkID(passphrase), Asset: "native", FeeAddress: feeAddress,
		Pricing: Pricing{Native: true, MarginBps: 500, Tier: big.NewInt(100_000)}, LedgerSeconds: 5, MaxHeld: 10,
	}, h.fake, engine, channels, h.screen, NewStore(pool), 1_000_000, &alert.Alerter{Service: "relayer"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.now = h.clock
	h.r = r
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// clock is the harness's time, which held requests read from their own goroutines.
func (h *harness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func mustKey[T any](k T, err error) T {
	if err != nil {
		panic(err)
	}
	return k
}

func (h *harness) post(body map[string]any) (int, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/submit", bytes.NewReader(raw)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *harness) get(path string) (int, map[string]any) {
	rec := httptest.NewRecorder()
	h.r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *harness) waitIdle() {
	h.t.Helper()
	for range 500 {
		if h.r.channels.ready() == h.r.channels.total {
			h.r.mu.Lock()
			idle := len(h.r.inflight) == 0
			h.r.mu.Unlock()
			if idle {
				return
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	h.t.Fatal("submissions never finished")
}

func TestTheQuoteCoversTheCostWithAPublishedMargin(t *testing.T) {
	p := Pricing{Native: true, MarginBps: 500, Tier: big.NewInt(100_000)}
	if got := p.Quote(1_000_100); got.Int64() != 1_100_000 {
		t.Fatalf("quote %v", got)
	}
	usdc := Pricing{PerStroopNum: big.NewInt(1), PerStroopDen: big.NewInt(3), MarginBps: 0, Tier: big.NewInt(10)}
	if got := usdc.Quote(31); got.Int64() != 20 {
		t.Fatalf("converted quote %v", got)
	}
	if (Pricing{Native: true, MarginBps: 1001, Tier: big.NewInt(1)}).Validate() == nil {
		t.Fatal("a margin above 10 percent accepted")
	}
	if (Pricing{MarginBps: 0, Tier: big.NewInt(1)}).Validate() == nil {
		t.Fatal("an unpriced asset accepted")
	}
	c := NewCosts(777, nil)
	for i := range Samples - 1 {
		c.Add(int64(i))
	}
	if c.ResourceFee() != 777 {
		t.Fatal("bootstrap value not used before 50 samples")
	}
	for i := range Samples {
		c.Add(int64(1000 + i))
	}
	if got := c.ResourceFee(); got != 1044 {
		t.Fatalf("p90 %d", got)
	}
	var q quotes
	now := time.Unix(0, 0)
	q.publish(now, big.NewInt(300))
	q.publish(now.Add(time.Minute), big.NewInt(200))
	q.publish(now.Add(4*time.Minute), big.NewInt(400))
	if q.lowest(now.Add(5*time.Minute)).Int64() != 200 || q.lowest(now.Add(7*time.Minute)).Int64() != 400 {
		t.Fatal("lowest quote of the last five minutes")
	}
}

func TestATransferIsRelayedTrackedAndRecorded(t *testing.T) {
	h := newHarness(t, vault.Status{})
	code, body := h.post(fixture(t, "transfer"))
	if code != http.StatusAccepted || body["hash"] == nil {
		t.Fatalf("submit answered %d %v", code, body)
	}
	hash := body["hash"].(string)
	h.waitIdle()
	if _, st := h.get("/v1/tx/" + hash); st["status"] != "success" {
		t.Fatalf("status %v", st)
	}
	var n int
	var kind string
	_ = h.r.db.pool.QueryRow(context.Background(), `SELECT count(*), max(kind) FROM relays WHERE tx_hash = $1 AND fee = 5000000 AND resource_fee = 900000`, hash).Scan(&n, &kind)
	if n != 1 || kind != "transfer" {
		t.Fatal("relay record missing")
	}
	if len(h.screen.asked) != 0 {
		t.Fatal("a transfer was screened")
	}
	if code, _ := h.get("/v1/tx/" + strings.Repeat("ab", 32)); code != http.StatusNotFound {
		t.Fatal("an unknown hash answered")
	}
}

func TestUnshieldsAreScreenedAndTheRelayerFailsClosed(t *testing.T) {
	h := newHarness(t, vault.Status{})
	body := fixture(t, "unshield_muxed")
	h.screen.allow, h.screen.reason = false, 1
	if code, out := h.post(body); code != http.StatusForbidden || out["error"] != CodeRefused || out["reason"].(float64) != 1 {
		t.Fatalf("refused destination: %d %v", code, out)
	}
	h.screen.err = errors.New("timeout")
	if code, out := h.post(body); code != http.StatusServiceUnavailable || out["error"] != CodeUnavailable {
		t.Fatalf("screening down: %d %v", code, out)
	}
	h.screen.allow, h.screen.err = true, nil
	if code, _ := h.post(body); code != http.StatusAccepted {
		t.Fatalf("allowed destination answered %d", code)
	}
	if h.screen.asked[0] != "MA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QKAAAAEPXD6YEZNZKQ" {
		t.Fatal("the destination was not screened")
	}
	h.waitIdle()
	var dest string
	_ = h.r.db.pool.QueryRow(context.Background(), `SELECT destination FROM relays WHERE kind = 'unshield'`).Scan(&dest)
	if dest == "" {
		t.Fatal("unshield record lacks its destination")
	}
}

func TestTheSameNotesCannotBeInFlightTwice(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.mu.Lock()
	h.status = protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}
	h.mu.Unlock()
	if code, _ := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("first submission answered %d", code)
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusConflict || out["error"] != CodeDuplicate {
		t.Fatalf("second submission answered %d %v", code, out)
	}
	h.mu.Lock()
	h.status = success(900_000)
	h.mu.Unlock()
	h.waitIdle()
}

func TestSubmissionsAreCheckedBeforeAnySimulation(t *testing.T) {
	h := newHarness(t, vault.Status{})
	cases := map[string]func(map[string]any){
		CodeWrongVault: func(b map[string]any) { b["ext"].(map[string]any)["vault"] = vaulttest.Token },
		CodeFeeTooLow:  func(b map[string]any) { b["ext"].(map[string]any)["fee"] = "1" },
		CodeBadRequest: func(b map[string]any) { b["ext"].(map[string]any)["ext_amount"] = "5" },
		"relayer":      func(b map[string]any) { b["ext"].(map[string]any)["relayer"] = vaulttest.Depositor },
		"uppercase": func(b map[string]any) {
			b["proof"].(map[string]any)["a"] = strings.ToUpper(b["proof"].(map[string]any)["a"].(string))
		},
		"zero padded":  func(b map[string]any) { b["ext"].(map[string]any)["fee"] = "05000000" },
		"short output": func(b map[string]any) { b["ext"].(map[string]any)["encrypted_output0"] = "00" },
		"recipient":    func(b map[string]any) { b["ext"].(map[string]any)["recipient"] = vaulttest.Depositor },
		CodeRejected:   func(b map[string]any) { b["ext"].(map[string]any)["deadline"] = 1001 },
		"bound fee":    func(b map[string]any) { b["ext"].(map[string]any)["fee"] = "6000000" },
		"unknown":      func(b map[string]any) { b["extra"] = 1 },
	}
	want := map[string]string{"relayer": CodeBadRequest, "uppercase": CodeBadRequest, "zero padded": CodeBadRequest, "short output": CodeBadRequest, "recipient": CodeBadRequest, "bound fee": CodeRejected, "unknown": CodeBadRequest}
	for name, mutate := range cases {
		body := fixture(t, "transfer")
		mutate(body)
		_, out := h.post(body)
		expected := want[name]
		if expected == "" {
			expected = name
		}
		if out["error"] != expected {
			t.Fatalf("%s: answered %v", name, out)
		}
	}
	if h.fake.CallCount("simulateTransaction") != 0 {
		t.Fatal("a refused request was simulated")
	}
	h.simErr = "HostError: Error(WasmVm, InvalidAction)"
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected || strings.Contains(out["error"].(string), "Host") {
		t.Fatalf("failed simulation: %d %v", code, out)
	}
	if len(h.r.inflight) != 0 {
		t.Fatal("a refused request kept its nullifiers in flight")
	}
}

func TestTheVaultStateGatesRelaying(t *testing.T) {
	h := newHarness(t, vault.Status{TransfersPaused: true})
	if _, out := h.post(fixture(t, "transfer")); out["error"] != CodePaused {
		t.Fatalf("paused transfer: %v", out)
	}
	if code, _ := h.post(fixture(t, "unshield_muxed")); code != http.StatusAccepted {
		t.Fatal("an unshield while transfers are paused")
	}
	h.waitIdle()
	halted := newHarness(t, vault.Status{HaltedUntil: 1_728_100_000})
	if _, out := halted.post(fixture(t, "unshield_muxed")); out["error"] != CodeUnavailable {
		t.Fatalf("halted vault: %v", out)
	}
}

func TestAnExitNoWindowCanPayIsRefused(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 700_000_000, Large: 5_000_000_000,
	}), 10, nil)
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, out := h.post(fixture(t, "unshield_muxed")); out["error"] != CodeRejected {
		t.Fatalf("exit above the daily outflow: %v", out)
	}
}

func TestAnExitThatWaitsInTheQueueReportsItsID(t *testing.T) {
	h := newHarness(t, vault.Status{})
	raw, err := strkey.Decode(strkey.VersionByteContract, vaulttest.Vault)
	if err != nil {
		t.Fatal(err)
	}
	id := xdr.ContractId(raw)
	sym := xdr.ScSymbol("exit_queued")
	recipient, _ := vault.Address("MA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QKAAAAEPXD6YEZNZKQ")
	relayer, _ := vault.Address(feeAddress)
	amount := func(n int64) xdr.ScVal { v, _ := vault.I128(big.NewInt(n)); return v }
	queued := xdr.ContractEvent{ContractId: &id, Type: xdr.ContractEventTypeContract, Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{
		Topics: []xdr.ScVal{{Type: xdr.ScValTypeScvSymbol, Sym: &sym}},
		Data: vault.Struct(vault.Field{Name: "id", Value: vault.U64(7)}, vault.Field{Name: "ext_amount", Value: amount(-10)},
			vault.Field{Name: "fee", Value: amount(5)}, vault.Field{Name: "recipient", Value: recipient}, vault.Field{Name: "relayer", Value: relayer}),
	}}}
	st := success(900_000)
	var meta xdr.TransactionMeta
	_ = xdr.SafeUnmarshalBase64(st.ResultMetaXDR, &meta)
	meta.V4.Operations = []xdr.OperationMetaV2{{Events: []xdr.ContractEvent{queued}}}
	st.ResultMetaXDR, _ = xdr.MarshalBase64(meta)
	h.status = st
	code, body := h.post(fixture(t, "unshield_muxed"))
	if code != http.StatusAccepted {
		t.Fatalf("submit answered %d %v", code, body)
	}
	h.waitIdle()
	hash := body["hash"].(string)
	if _, out := h.get("/v1/tx/" + hash); out["status"] != "success" || out["exit_id"].(float64) != 7 {
		t.Fatalf("status %v", out)
	}
	// The record keeps the exit ID after the in-memory status is gone.
	h.r.mu.Lock()
	delete(h.r.statuses, hash)
	h.r.mu.Unlock()
	if _, out := h.get("/v1/tx/" + hash); out["exit_id"].(float64) != 7 {
		t.Fatalf("status from the record %v", out)
	}
}

func TestADelayedRequestIsHeldThenSent(t *testing.T) {
	h := newHarness(t, vault.Status{})
	body := fixture(t, "transfer")
	notBefore := h.now.Unix() + 2
	body["not_before"] = notBefore
	code, out := h.post(body)
	if code != http.StatusAccepted || out["held"] != true || out["hash"] != nil {
		t.Fatalf("held request: %d %v", code, out)
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusConflict {
		t.Fatalf("its notes stay in flight: %d %v", code, out)
	}
	nf := body["proof"].(map[string]any)["input_nullifiers"].([]any)[0].(string)
	if _, st := h.get("/v1/held/" + nf); st["status"] != "held" || st["hash"] != nil {
		t.Fatalf("held status %v", st)
	}
	if code, _ := h.get("/v1/held/" + strings.Repeat("0", 63) + "1"); code != http.StatusNotFound {
		t.Fatalf("an unknown nullifier answered %d", code)
	}
	h.mu.Lock()
	h.now = h.now.Add(2 * time.Second)
	h.mu.Unlock()
	for range 1000 {
		h.mu.Lock()
		sent := h.sent
		h.mu.Unlock()
		if sent == 1 {
			h.waitIdle()
			if _, st := h.get("/v1/held/" + nf); st["status"] != "success" || st["hash"] == nil {
				t.Fatalf("status once sent %v", st)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the held request was never sent")
}

func TestHealthAndQuoteReportIdentity(t *testing.T) {
	h := newHarness(t, vault.Status{})
	_, health := h.get("/v1/health")
	if health["ready"] != true || health["fee_address"] != feeAddress || health["ready_channels"].(float64) != 2 || health["network_id"] != "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472" || health["max_daily_outflow"] != "1000000000000" {
		t.Fatalf("health %v", health)
	}
	before := h.fake.CallCount("getFeeStats")
	_, quote := h.get("/v1/quote")
	if quote["fee"] != "1100000" || quote["tier"] != "100000" || quote["margin_bps"].(float64) != 500 || quote["vault"] != vaulttest.Vault {
		t.Fatalf("quote %v", quote)
	}
	h.get("/v1/quote")
	if h.fake.CallCount("getFeeStats") != before {
		t.Fatal("a client's quote request reached the RPC")
	}
}
