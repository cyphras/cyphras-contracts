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
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/groth16"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const (
	proofFixtures = "../../../contracts/vault/fixtures/proofs.json"
	// The fixtures are proved against the testnet verifier's key.
	verifyingKey = "../../../contracts/verifier/keys/testnet-forgeable/verification_key.json"
)

const (
	passphrase = "Test SDF Network ; September 2015"
	feeAddress = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
)

// fund creates the account behind an address, so the vault would pay it.
func (h *harness) fund(address string) {
	account, err := vault.AccountOf(address)
	if err != nil {
		h.t.Fatal(err)
	}
	if account[0] == 'C' {
		return
	}
	key := mustKey(vault.AccountKey(account))
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, Balance: 10_000_000}}, 1, nil)
}

// fixtureRecipients lists the recipients the fixture proofs pay.
func fixtureRecipients(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(proofFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Steps []struct {
			Ext struct {
				Recipient string `json:"recipient"`
			} `json:"ext"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range f.Steps {
		if s.Ext.Recipient != "" {
			out = append(out, s.Ext.Recipient)
		}
	}
	return out
}

// fixtureChain returns the domain the fixture proofs are bound to and every root they prove
// against, which the test vault then knows.
func fixtureChain(t *testing.T) (fr.Element, []fr.Element) {
	t.Helper()
	raw, err := os.ReadFile(proofFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Domain string `json:"domain"`
		Steps  []struct {
			Proof struct {
				Root string `json:"root"`
			} `json:"proof"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	domain, err := fr.SetHex(strings.TrimPrefix(f.Domain, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	var roots []fr.Element
	for _, s := range f.Steps {
		if s.Proof.Root == "" {
			continue
		}
		root, err := fr.SetHex(strings.TrimPrefix(s.Proof.Root, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		roots = append(roots, root)
	}
	return domain, roots
}

// fixture returns the request body of one of the vault's real-proof fixtures: a step, or a proof
// the vault refuses.
func fixture(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(proofFixtures)
	if err != nil {
		t.Fatal(err)
	}
	type step struct {
		Name  string         `json:"name"`
		Ext   map[string]any `json:"ext"`
		Proof map[string]any `json:"proof"`
	}
	var f struct {
		Steps   []step `json:"steps"`
		Refused []step `json:"refused"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	for _, s := range append(f.Steps, f.Refused...) {
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
	domain fr.Element
}

func success(resource int64) protocol.GetTransactionResponse {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: xdr.Int64(resource + 100), Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}})
	meta, _ := xdr.MarshalBase64(xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{SorobanMeta: &xdr.SorobanTransactionMetaV2{
		Ext: xdr.SorobanTransactionMetaExt{V: 1, V1: &xdr.SorobanTransactionMetaExtV1{TotalNonRefundableResourceFeeCharged: xdr.Int64(resource)}},
	}}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusSuccess, ResultXDR: r, ResultMetaXDR: meta, Ledger: 1001}}
}

func newHarness(t *testing.T, status vault.Status, mutate ...func(*Config)) *harness {
	t.Helper()
	h := &harness{t: t, fake: rpctest.New(passphrase, 1000), screen: &screenStub{allow: true}, now: time.Unix(1_728_000_000, 0), status: success(900_000)}
	h.fake.CloseTime = h.now.Unix()
	h.fake.FeeStats.SorobanInclusionFee.P90 = 100
	h.fake.SetSettings(rpctest.Mainnet)
	domain, roots := fixtureChain(t)
	h.domain = domain
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000, Status: status, Domain: domain,
	}), 10, nil)
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.Roots(roots...), 10, nil)
	for _, recipient := range fixtureRecipients(t) {
		h.fund(recipient)
	}
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
	rawKey, err := os.ReadFile(verifyingKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := groth16.ParseKey(rawKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Vault: vaulttest.Vault, NetworkID: rpc.NetworkID(passphrase), Asset: "native", FeeAddress: feeAddress,
		Pricing: Pricing{Native: true, MarginBps: 500, Tier: big.NewInt(100_000)}, LedgerSeconds: 5, MaxHeld: 10, Key: key,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	r, err := New(ctx, cfg, h.fake, engine, channels, h.screen, NewStore(pool), 1_000_000, &alert.Alerter{Service: "relayer"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
				h.r.Wait()
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
	// The same proof sent again soon is answered from memory, without asking screening again.
	if code, out := h.post(body); code != http.StatusForbidden || out["reason"].(float64) != 1 || len(h.screen.asked) != 1 {
		t.Fatalf("the same proof again: %d %v, screening asked %d times", code, out, len(h.screen.asked))
	}
	h.mu.Lock()
	h.now = h.now.Add(verdictLifetime)
	h.mu.Unlock()
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
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
	reads := h.fake.CallCount("getLedgerEntries")
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
		// Refused means untouched: nothing claimed, screened, simulated, sent or recorded, and no
		// part of the costly budget spent.
		var records int
		_ = h.r.db.pool.QueryRow(context.Background(), `SELECT count(*) FROM relays`).Scan(&records)
		if len(h.r.inflight) != 0 || len(h.screen.asked) != 0 || h.sent != 0 || records != 0 || h.fake.CallCount("getLedgerEntries") != reads {
			t.Fatalf("%s: a refused request left a trace", name)
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
	id, _ := out["id"].(string)
	if code != http.StatusAccepted || out["held"] != true || out["hash"] != nil || len(id) != 32 {
		t.Fatalf("held request: %d %v", code, out)
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusConflict {
		t.Fatalf("its notes stay in flight: %d %v", code, out)
	}
	if _, st := h.get("/v1/held/" + id); st["status"] != "held" || st["hash"] != nil {
		t.Fatalf("held status %v", st)
	}
	nf := body["proof"].(map[string]any)["input_nullifiers"].([]any)[0].(string)
	if code, _ := h.get("/v1/held/" + nf); code != http.StatusBadRequest {
		t.Fatalf("a lookup by nullifier answered %d", code)
	}
	if code, _ := h.get("/v1/held/" + strings.Repeat("0", 31) + "1"); code != http.StatusNotFound {
		t.Fatalf("an unknown ID answered %d", code)
	}
	if len(h.screen.asked) != 0 {
		t.Fatal("a held request was screened before it was due")
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
			if _, st := h.get("/v1/held/" + id); st["status"] != "success" || st["hash"] == nil {
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

func TestARelaySentBeforeARestartIsFollowedToItsOutcome(t *testing.T) {
	h := newHarness(t, vault.Status{})
	hash := strings.Repeat("cd", 32)
	if err := h.r.db.sent(context.Background(), Record{Hash: hash, Kind: "transfer", Fee: "5000000"}); err != nil {
		t.Fatal(err)
	}
	if err := h.r.Resume(); err != nil {
		t.Fatal(err)
	}
	for range 500 {
		if outcome, _, _, _ := h.r.db.lookup(context.Background(), hash); outcome == outcomeSuccess {
			if _, st := h.get("/v1/tx/" + hash); st["status"] != "success" {
				t.Fatalf("status %v", st)
			}
			var fee int64
			_ = h.r.db.pool.QueryRow(context.Background(), `SELECT resource_fee FROM relays WHERE tx_hash = $1`, hash).Scan(&fee)
			if fee != 900_000 {
				t.Fatalf("resource fee %d", fee)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the pending relay was never completed")
}

func TestForgedOrSpentProofsAreRefusedBeforeAnything(t *testing.T) {
	h := newHarness(t, vault.Status{})
	forged := fixture(t, "unshield_muxed")
	proof := forged["proof"].(map[string]any)
	a := []byte(proof["a"].(string))
	a[10] ^= 1
	proof["a"] = string(a)
	if code, out := h.post(forged); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("forged proof: %d %v", code, out)
	}
	// A valid proof whose notes are already spent.
	body := fixture(t, "unshield_muxed")
	nf, err := fr.SetHex(body["proof"].(map[string]any)["input_nullifiers"].([]any)[0].(string))
	if err != nil {
		t.Fatal(err)
	}
	h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, nf.Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, nil)
	if code, out := h.post(body); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("spent notes: %d %v", code, out)
	}
	if len(h.screen.asked) != 0 || h.fake.CallCount("simulateTransaction") != 0 {
		t.Fatal("a refused proof reached screening or simulation")
	}
	// A valid proof that spends a nullifier already spent, in either input slot, passes every
	// other check and is refused for that alone.
	for slot, name := range []string{"double_spend_slot0", "double_spend_slot1"} {
		body := fixture(t, name)
		var sb SubmitBody
		raw, _ := json.Marshal(body)
		if err := json.Unmarshal(raw, &sb); err != nil {
			t.Fatal(err)
		}
		req, err := sb.Parse()
		if err != nil {
			t.Fatal(err)
		}
		h.fund(req.Ext.Recipient)
		for _, nf := range req.Proof.Nullifiers {
			h.fake.DeleteEntry(mustKey(vault.NullifierKey(vaulttest.Vault, nf.Bytes())))
		}
		if f := h.r.fresh(context.Background(), req); f != nil {
			t.Fatalf("%s refused while unspent: %s", name, f.code)
		}
		h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, req.Proof.Nullifiers[slot].Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, nil)
		if f := h.r.fresh(context.Background(), req); f == nil || f.code != CodeRejected {
			t.Fatalf("%s accepted with a spent nullifier", name)
		}
	}
}

func TestAnUnshieldToAnAccountThatCannotReceiveIsRefusedFirst(t *testing.T) {
	// The fixture pays 70 XLM, enough to create a missing account, so here the vault holds an issued
	// asset the recipient has no trustline for.
	issuer := keypair.MustRandom().Address()
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Asset = "USDC:" + issuer })
	if code, out := h.post(fixture(t, "unshield_muxed")); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("unshield to an account without a trustline: %d %v", code, out)
	}
	if len(h.screen.asked) != 0 || h.fake.CallCount("simulateTransaction") != 0 {
		t.Fatal("an unpayable unshield reached screening or simulation")
	}
	// Of the native asset, the same payout creates the account, so it goes on.
	h = newHarness(t, vault.Status{})
	body := fixture(t, "unshield_muxed")
	recipient, err := vault.AccountOf(body["ext"].(map[string]any)["recipient"].(string))
	if err != nil {
		t.Fatal(err)
	}
	h.fake.DeleteEntry(mustKey(vault.AccountKey(recipient)))
	if code, out := h.post(body); code != http.StatusAccepted {
		t.Fatalf("unshield that creates its account: %d %v", code, out)
	}
}

func TestAMissingAccountIsPaidOnlyTheNativeAssetAndEnoughToCreateIt(t *testing.T) {
	fake := rpctest.New(passphrase, 1000)
	r := &Relayer{cfg: Config{Asset: "native"}, rpc: fake}
	missing := keypair.MustRandom().Address()
	for payout, want := range map[int64]bool{0: false, vault.MinNewAccountPayout - 1: false, vault.MinNewAccountPayout: true} {
		if got, err := r.CanReceive(context.Background(), missing, big.NewInt(payout)); err != nil || got != want {
			t.Fatalf("a payout of %d: %t, %v", payout, got, err)
		}
	}
	r.cfg.Asset = "USDC:" + keypair.MustRandom().Address()
	if got, err := r.CanReceive(context.Background(), missing, big.NewInt(vault.MinNewAccountPayout)); err != nil || got {
		t.Fatalf("an issued asset to a missing account: %t, %v", got, err)
	}
}

func TestAnIssuedAssetNeedsAnAuthorizedTrustlineExceptForItsIssuer(t *testing.T) {
	fake := rpctest.New(passphrase, 1000)
	issuer, holder := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	r := &Relayer{cfg: Config{Asset: "USDC:" + issuer}, rpc: fake}
	for _, a := range []string{issuer, holder} {
		key := mustKey(vault.AccountKey(a))
		fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId}}, 1, nil)
	}
	check := func(address string, want bool) {
		t.Helper()
		if got, err := r.CanReceive(context.Background(), address, big.NewInt(vault.MinNewAccountPayout)); err != nil || got != want {
			t.Fatalf("can receive %t, %v; want %t", got, err, want)
		}
	}
	check(holder, false)
	check(issuer, true)
	key := mustKey(vault.TrustlineKey(holder, r.cfg.Asset))
	asset, err := xdr.NewCreditAsset("USDC", issuer)
	if err != nil {
		t.Fatal(err)
	}
	for flags, want := range map[xdr.TrustLineFlags]bool{0: false, xdr.TrustLineFlagsAuthorizedToMaintainLiabilitiesFlag: false, xdr.TrustLineFlagsAuthorizedFlag: true} {
		fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeTrustline, TrustLine: &xdr.TrustLineEntry{
			AccountId: key.MustTrustLine().AccountId, Asset: asset.ToTrustLineAsset(), Limit: 1_000_000, Flags: xdr.Uint32(flags),
		}}, 1, nil)
		check(holder, want)
	}
}
