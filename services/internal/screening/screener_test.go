package screening

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const passphrase = "Test SDF Network ; September 2015"

func sep53Digest(msg string) []byte {
	d := sha256.Sum256([]byte("Stellar Signed Message:\n" + msg))
	return d[:]
}

// call is a vault invocation the screener sent.
type call struct {
	fn   string
	args []xdr.ScVal
}

type harness struct {
	t       *testing.T
	fake    *rpctest.Fake
	chain   *vaulttest.Chain
	s       *Screener
	f       *follow.Follower
	sources *staticSource
	funders funderMap
	now     time.Time
	mu      sync.Mutex
	calls   []call
	effects []call
	pages   []alert.Alert
	attest  uint64
}

func (h *harness) Send(_ context.Context, a alert.Alert) error {
	h.pages = append(h.pages, a)
	return nil
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, fake: rpctest.New(passphrase, 9), chain: vaulttest.New(10, 1_728_000_000), now: time.Unix(1_728_000_000, 0), funders: funderMap{}}
	pool, err := chainstate.Open(context.Background(), testdb.URL(t), Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	hot := keypair.MustRandom()
	key, _ := vault.AccountKey(vaulttest.Asp)
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, SeqNum: 100}}, 1, nil)
	h.fake.FeeStats.SorobanInclusionFee.P90 = 100
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 1000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	h.fake.Send = func(req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		var env xdr.TransactionEnvelope
		if err := xdr.SafeUnmarshalBase64(req.Transaction, &env); err != nil {
			return protocol.SendTransactionResponse{}, err
		}
		inv := env.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.HostFunction.InvokeContract
		h.mu.Lock()
		h.calls = append(h.calls, call{string(inv.FunctionName), inv.Args})
		h.effects = append(h.effects, call{string(inv.FunctionName), inv.Args})
		h.mu.Unlock()
		return protocol.SendTransactionResponse{Status: "PENDING"}, nil
	}
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		r, _ := xdr.MarshalBase64(xdr.TransactionResult{Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}})
		return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusSuccess, ResultXDR: r}}, nil
	}
	engine := &submit.Engine{RPC: h.fake, Passphrase: passphrase, Validity: time.Minute, Poll: time.Millisecond, Now: func() time.Time { return h.now }}
	h.sources = static("exploits", h.now, map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}})
	check := &Checker{Sources: []Source{h.sources}, Funders: h.funders, MaxFunders: 25, Now: func() time.Time { return h.now }}
	alerts := &alert.Alerter{Service: "screening", Channels: []alert.Channel{h}, Cooldown: time.Hour, Now: func() time.Time { return h.now }}
	s, err := New(context.Background(), Config{
		Vault: vaulttest.Vault, DeployLedger: 10, Network: "testnet", PolicyVersion: "1",
		RecheckWindow: 10 * time.Minute, Cutoff: 2 * time.Minute, FirstCheckWithin: 10 * time.Minute,
	}, h.fake, &chainstate.Store{Pool: pool}, check, engine, submit.NewAccount(vaulttest.Asp, hot), alerts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return h.now }
	h.s = s
	h.f = &follow.Follower{RPC: h.fake, Live: follow.RPCSource{Client: h.fake, Contract: vaulttest.Vault}, Window: 50, Sink: s}
	h.setVault(0)
	return h
}

func (h *harness) setVault(attested uint64) {
	h.attest = attested
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000,
		Status: vault.Status{AttestedUpTo: attested, NextDepositID: h.chain.NextID},
	}), 10, nil)
}

// land puts the calls the screener sent on chain, as the vault would.
func (h *harness) land() {
	h.mu.Lock()
	effects := h.effects
	h.effects = nil
	h.mu.Unlock()
	for _, c := range effects {
		switch c.fn {
		case "flag":
			h.chain.Flag(uint64(*c.args[0].U64), uint32(*c.args[1].U32))
		case "unflag":
			h.chain.Unflag(uint64(*c.args[0].U64), 0)
		case "attest":
			h.attest = uint64(*c.args[0].U64)
			h.chain.Attest(h.attest)
		}
	}
	h.chain.NextLedger(5)
}

func mustKey[T any](k T, err error) T {
	if err != nil {
		panic(err)
	}
	return k
}

// shield makes a deposit on chain, with the Pending entry the vault would store.
func (h *harness) shield(depositor string, amount int64) uint64 {
	id := h.chain.Shield(depositor, amount)
	delay := uint64(3600)
	if amount >= 5_000_000_000 {
		delay = 86400
	}
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, depositor, amount, uint64(h.chain.ClosedAt), delay, nil, 0), h.chain.Ledger, nil)
	h.chain.NextLedger(5)
	return id
}

// sync publishes the chain and lets the screener ingest it.
func (h *harness) sync() {
	h.t.Helper()
	h.fake.Events = nil
	for _, e := range h.chain.Events {
		h.fake.AddEvent(rpctest.EventInfo(e))
	}
	h.fake.SetLatest(h.chain.Ledger)
	for range 50 {
		progressed, err := h.f.Step(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		if !progressed {
			return
		}
	}
}

func (h *harness) tick() {
	h.t.Helper()
	h.setVault(h.attest)
	h.sync()
	h.s.RefreshSources(context.Background())
	if err := h.s.Tick(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	h.land()
}

func (h *harness) sent() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, c := range h.calls {
		parts := []string{c.fn}
		for _, a := range c.args {
			switch a.Type {
			case xdr.ScValTypeScvU64:
				parts = append(parts, itoa(int64(*a.U64)))
			case xdr.ScValTypeScvU32:
				parts = append(parts, itoa(int64(*a.U32)))
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	h.calls = nil
	return out
}

func (h *harness) decisions() []string {
	rows, err := h.s.db.pool.Query(context.Background(), `SELECT kind || ' ' || outcome || ' ' || COALESCE(reason::text, '-') FROM decisions ORDER BY id`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		out = append(out, s)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestACleanDepositIsAttestedInItsFinalWindowAndADirtyOneFlagged(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 10_000_000)
	h.shield(thief, 10_000_000)
	h.funders[clean] = []string{funder}
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 2 2"}) {
		t.Fatalf("first round sent %v", got)
	}
	// Nothing is attested before the final check.
	h.now = h.now.Add(40 * time.Minute)
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("early round sent %v", got)
	}
	h.now = h.now.Add(15 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"attest 1"}) {
		t.Fatalf("final window sent %v", got)
	}
	want := []string{"first_check pass -", "first_check refuse 2", "first_check flag 2", "recheck pass -", "attest attest -"}
	if got := h.decisions(); !equal(got, want) {
		t.Fatalf("decisions %v", got)
	}
}

func TestAttestationWaitsForEveryLowerDepositToBeDecided(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 10_000_000)
	h.shield(clean, 10_000_000)
	h.sources.set(map[string]Hit{}, "1", h.now.Add(-2*time.Hour))
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("stale sources sent %v", got)
	}
	if len(h.pages) == 0 {
		t.Fatal("no alert while screening is blind")
	}
	h.sources.set(map[string]Hit{}, "1", h.now.Add(55*time.Minute))
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"attest 2"}) {
		t.Fatalf("after the sources came back: %v", got)
	}
}

func TestALargeDepositNeedsAReview(t *testing.T) {
	h := newHarness(t)
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	reviews, err := h.s.Reviews(context.Background())
	if err != nil || len(reviews) != 1 || reviews[0].ID != big {
		t.Fatalf("reviews %v %v", reviews, err)
	}
	// Unreviewed when its final check comes, it is refused with reason 5.
	h.now = h.now.Add(24*time.Hour - 9*time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 5"}) {
		t.Fatalf("unreviewed deposit: %v", got)
	}

	h2 := newHarness(t)
	h2.shield(clean, 6_000_000_000)
	h2.tick()
	if err := h2.s.DecideReview(context.Background(), 1, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h2.now = h2.now.Add(24*time.Hour - 9*time.Minute)
	h2.sources.set(map[string]Hit{}, "2", h2.now)
	h2.tick()
	if got := h2.sent(); !equal(got, []string{"attest 1"}) {
		t.Fatalf("reviewed deposit: %v", got)
	}
}

func TestAnAttestedDepositThatCannotBeRecheckedIsRefused(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 10_000_000)
	h.tick()
	h.attest = 1
	h.funders["unreachable"] = nil
	h.s.check.Funders = funderMap{clean: nil}
	// The sources go stale inside the final window.
	h.now = h.now.Add(59 * time.Minute)
	h.sources.set(map[string]Hit{}, "1", h.now.Add(-2*time.Hour))
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 5"}) {
		t.Fatalf("blind final check: %v", got)
	}
}

func TestASelfReportBlocksTheAddress(t *testing.T) {
	h := newHarness(t)
	kp := keypair.MustRandom()
	h.shield(kp.Address(), 10_000_000)
	h.tick()
	h.sent()
	day := h.now.UTC().Format(time.DateOnly)
	sig, _ := kp.Sign(sep53Digest(SelfReportMessage("testnet", kp.Address(), day)))
	body, _ := json.Marshal(map[string]string{"address": kp.Address(), "date": day, "signature": base64.StdEncoding.EncodeToString(sig)})
	api := h.s.Public(httpapi.NewLimiter(60, 10), httpapi.NewLimiter(60, 10))
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/self-report", bytes.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("self-report answered %d %s", rec.Code, rec.Body.String())
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 4"}) {
		t.Fatalf("after the report: %v", got)
	}
	forged, _ := json.Marshal(map[string]string{"address": clean, "date": day, "signature": base64.StdEncoding.EncodeToString(sig)})
	rec = httptest.NewRecorder()
	api.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/self-report", bytes.NewReader(forged)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "bad_signature") {
		t.Fatalf("forged report answered %d", rec.Code)
	}
}

func TestTheRelayerScreenNeedsItsTokenAndFailsClosed(t *testing.T) {
	h := newHarness(t)
	token := "relayer-token"
	api := h.s.Internal(sha256.Sum256([]byte(token)))
	screen := func(auth, address string) (int, string) {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/screen", strings.NewReader(`{"address":"`+address+`"}`))
		req.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, _ := screen("Bearer wrong", clean); code != http.StatusUnauthorized {
		t.Fatalf("wrong token answered %d", code)
	}
	if code, body := screen("Bearer "+token, clean); code != http.StatusOK || !strings.Contains(body, `"allow"`) {
		t.Fatalf("clean destination: %d %s", code, body)
	}
	if code, body := screen("Bearer "+token, thief); code != http.StatusOK || !strings.Contains(body, `"refuse"`) || !strings.Contains(body, `"reason":2`) {
		t.Fatalf("dirty destination: %d %s", code, body)
	}
	h.sources.set(map[string]Hit{}, "1", h.now.Add(-2*time.Hour))
	if code, _ := screen("Bearer "+token, clean); code != http.StatusServiceUnavailable {
		t.Fatalf("stale sources answered %d", code)
	}
	st, err := h.s.db.stats(context.Background())
	if err != nil || st.UnshieldRefusals["2"] != 1 {
		t.Fatalf("refusal statistics %+v %v", st.UnshieldRefusals, err)
	}
	var at int64
	_ = h.s.db.pool.QueryRow(context.Background(), `SELECT at FROM decisions WHERE kind = 'unshield'`).Scan(&at)
	if at%86400 != 0 {
		t.Fatal("an unshield refusal kept its time of day")
	}
}

func TestTheCandidateNeverVouchesForAnUnflaggedRefusal(t *testing.T) {
	r := func(id uint64, first, recheck string) row { return row{id: id, firstCheck: first, recheck: recheck} }
	four := uint32(4)
	cases := []struct {
		rows []row
		want uint64
	}{
		{[]row{r(1, "pass", "pass"), r(2, "pass", ""), r(3, "pass", "pass")}, 3},
		{[]row{r(1, "pass", "pass"), r(2, "", ""), r(3, "pass", "pass")}, 1},
		{[]row{r(1, "refuse", ""), r(2, "pass", "pass")}, 0},
		{[]row{{id: 1, firstCheck: "refuse", flagSent: &four}, r(2, "pass", "pass")}, 2},
		{[]row{r(1, "pass", "refuse"), r(2, "pass", "pass")}, 0},
		{[]row{{id: 1, firstCheck: "refer", review: "needed"}, r(2, "pass", "pass")}, 2},
		{[]row{{id: 1, firstCheck: "pass", needsFlag: true}, r(2, "pass", "pass")}, 0},
	}
	for i, c := range cases {
		if got := attestCandidate(c.rows, 0); got != c.want {
			t.Fatalf("case %d: %d, want %d", i, got, c.want)
		}
	}
	if got := attestCandidate([]row{r(1, "", ""), r(2, "pass", "pass")}, 1); got != 2 {
		t.Fatal("attested deposits do not block")
	}
}
