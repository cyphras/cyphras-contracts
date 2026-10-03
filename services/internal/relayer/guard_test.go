package relayer

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// fixtureDeadline is the ExtData deadline every fixture proof is bound to.
const fixtureDeadline = 10_000_000

func failedOnChain() protocol.GetTransactionResponse {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: 900_100, Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxFailed, Results: &[]xdr.OperationResult{}}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusFailed, ResultXDR: r, Ledger: 1001}}
}

// sentEnvelopes records what the harness's RPC was asked to send.
func (h *harness) sentEnvelopes() *[]string {
	var out []string
	h.fake.Send = func(req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		h.mu.Lock()
		h.sent++
		out = append(out, req.Transaction)
		h.mu.Unlock()
		return protocol.SendTransactionResponse{Status: "PENDING"}, nil
	}
	return &out
}

func (h *harness) setTxStatus(st protocol.GetTransactionResponse) {
	h.mu.Lock()
	h.status = st
	h.mu.Unlock()
}

func (h *harness) setLatest(latest uint32, refresh bool) {
	h.t.Helper()
	h.fake.SetLatest(latest)
	if refresh {
		if err := h.r.Refresh(context.Background()); err != nil {
			h.t.Fatal(err)
		}
	}
}

func TestATightDeadlineIsRefusedAndASentTransactionStopsAtIt(t *testing.T) {
	h := newHarness(t, vault.Status{})
	sent := h.sentEnvelopes()
	// Only the distance to the deadline changes: one ledger short of the margin is refused.
	h.setLatest(fixtureDeadline-19, true)
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("a deadline 19 ledgers out: %d %v", code, out)
	}
	if h.fake.CallCount("simulateTransaction") != 0 || len(h.r.inflight) != 0 {
		t.Fatal("a request too close to its deadline was simulated or kept in flight")
	}
	// The cached tip is old, so the cheap check passes; the fresh read before sending refuses it.
	h.setLatest(1000, true)
	h.setLatest(fixtureDeadline-19, false)
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("a deadline only a fresh read catches: %d %v", code, out)
	}
	if h.fake.CallCount("simulateTransaction") != 0 {
		t.Fatal("simulated against a stale tip")
	}
	h.setLatest(fixtureDeadline-20, true)
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("a deadline 20 ledgers out: %d %v", code, out)
	}
	h.waitIdle()
	parsed, err := txnbuild.TransactionFromXDR((*sent)[0])
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := parsed.Transaction()
	pre := tx.ToXDR().Preconditions()
	if pre.V2 == nil || pre.V2.LedgerBounds == nil || pre.V2.LedgerBounds.MaxLedger != fixtureDeadline {
		t.Fatalf("preconditions %+v", pre)
	}
}

func TestAHeldRequestMustStayValidThroughItsWindow(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Jitter = 10 * time.Minute })
	// Ledgers have closed every 6 seconds, not the assumed 5.
	h.r.clock = &ledgerClock{fallback: 5}
	start := h.now.Unix() - 600
	for i := range uint32(101) {
		h.r.clock.observe(fixtureDeadline-5000+i, start+int64(i)*6)
	}
	if got := h.r.clock.secondsPerLedger(); got != 6 {
		t.Fatalf("pace %v", got)
	}
	latest := uint32(fixtureDeadline - 5000 + 100)
	h.fake.SetLatest(latest)
	h.fake.CloseTime = start + 600
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An hour plus the ten-minute window is 700 ledgers at 6 seconds: the deadline, 4900 ledgers
	// out, covers a hold of up to about seven hours, not eight.
	body := fixture(t, "transfer")
	body["not_before"] = h.now.Unix() + 8*3600
	if code, out := h.post(body); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("a hold past the deadline: %d %v", code, out)
	}
	body["not_before"] = h.now.Unix() + 7*3600
	if code, out := h.post(body); code != http.StatusAccepted || out["held"] != true {
		t.Fatalf("a hold within the deadline: %d %v", code, out)
	}
}

func TestAHeldRequestIsCheckedAndPricedOnlyWhenItIsSent(t *testing.T) {
	h := newHarness(t, vault.Status{})
	body := fixture(t, "unshield_muxed")
	body["not_before"] = h.now.Unix() + 1
	reads := h.fake.CallCount("getLedgerEntries")
	code, out := h.post(body)
	if code != http.StatusAccepted || out["held"] != true {
		t.Fatalf("held request: %d %v", code, out)
	}
	if h.fake.CallCount("getLedgerEntries") != reads || len(h.screen.asked) != 0 {
		t.Fatal("the notes or destination of a held request were read before it was due")
	}
	// By the time it is due, relaying costs more than the fee it offered.
	h.mu.Lock()
	h.now = h.now.Add(6 * time.Minute)
	h.mu.Unlock()
	h.fake.FeeStats.SorobanInclusionFee.P90 = 20_000_000
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	id := out["id"].(string)
	for range 500 {
		if _, st := h.get("/v1/held/" + id); st["status"] == "failed" {
			h.mu.Lock()
			sent := h.sent
			h.mu.Unlock()
			if st["code"] != CodeFeeTooLow || sent != 0 {
				t.Fatalf("held request priced at send time: %v, %d sent", st, sent)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the held request was never decided")
}

func TestAHeldRequestCanBeCancelledByItsID(t *testing.T) {
	h := newHarness(t, vault.Status{})
	body := fixture(t, "transfer")
	body["not_before"] = h.now.Unix() + 3600
	_, out := h.post(body)
	id := out["id"].(string)
	cancel := func() int {
		rec := httptest.NewRecorder()
		h.r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/v1/held/"+id, nil))
		return rec.Code
	}
	if code := cancel(); code != http.StatusOK {
		t.Fatalf("cancel answered %d", code)
	}
	if _, st := h.get("/v1/held/" + id); st["status"] != "cancelled" {
		t.Fatalf("status %v", st)
	}
	if code := cancel(); code != http.StatusNotFound {
		t.Fatalf("a second cancel answered %d", code)
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("its notes were not freed: %d %v", code, out)
	}
	h.waitIdle()
	if h.r.held != 0 {
		t.Fatalf("%d requests counted as held", h.r.held)
	}
}

func TestAFailureOnChainCoolsDownItsNotesAndDestination(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.setTxStatus(failedOnChain())
	if code, out := h.post(fixture(t, "unshield_muxed")); code != http.StatusAccepted {
		t.Fatalf("submit answered %d %v", code, out)
	}
	h.waitIdle()
	h.setTxStatus(success(900_000))
	if code, out := h.post(fixture(t, "unshield_muxed")); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
		t.Fatalf("the same notes again: %d %v", code, out)
	}
	if h.fake.CallCount("simulateTransaction") != 1 {
		t.Fatal("a cooling request was simulated")
	}
	var rows int
	_ = h.r.db.pool.QueryRow(context.Background(), `SELECT count(*) FROM relay_cooldowns`).Scan(&rows)
	if rows != 3 {
		t.Fatalf("%d cooldowns stored", rows)
	}
	// A restart remembers them.
	again, err := New(context.Background(), h.r.cfg, h.fake, h.r.engine, nil, h.screen, h.r.db, 1_000_000, &alert.Alerter{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	account, _ := vault.AccountOf("MA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QKAAAAEPXD6YEZNZKQ")
	if !again.cool.cooling(h.now.Unix(), destinationKey(account)) {
		t.Fatal("the destination's cooldown was forgotten")
	}
	if again.cool.cooling(h.now.Add(25*time.Hour).Unix(), destinationKey(account)) {
		t.Fatal("a cooldown outlived its day")
	}
}

func TestRepeatedFailuresPauseRelayingAndRaiseTheFee(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.BreakerFailures = 1 })
	h.setTxStatus(failedOnChain())
	if code, _ := h.post(fixture(t, "unshield_muxed")); code != http.StatusAccepted {
		t.Fatal("not sent")
	}
	h.waitIdle()
	if !h.r.alerts.Open("relaying_paused") {
		t.Fatal("no page")
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusServiceUnavailable || out["error"] != CodeUnavailable {
		t.Fatalf("relayed while paused: %d %v", code, out)
	}
	if code, health := h.get("/v1/health"); code != http.StatusServiceUnavailable || health["paused"] != true || health["ready"] != false {
		t.Fatalf("health %d %v", code, health)
	}
	// One failure in a hundred relays adds a basis point a relay, within the cap.
	if got := h.r.Margin(); got != 500+100 {
		t.Fatalf("margin %d", got)
	}
	for range 99 {
		h.r.results.add(false)
	}
	if got := h.r.Margin(); got != MaxMarginBps {
		t.Fatalf("capped margin %d", got)
	}
	h.mu.Lock()
	h.now = h.now.Add(31 * time.Minute)
	h.mu.Unlock()
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("still paused after the pause: %d %v", code, out)
	}
	h.setTxStatus(success(900_000))
	h.waitIdle()
}

func TestANativePayoutBelowOneXLMIsNotRelayedToAnAccount(t *testing.T) {
	h := newHarness(t, vault.Status{})
	body := fixture(t, "unshield_muxed")
	body["ext"].(map[string]any)["ext_amount"] = "-9999999"
	var sb SubmitBody
	raw, _ := json.Marshal(body)
	if err := json.Unmarshal(raw, &sb); err != nil {
		t.Fatal(err)
	}
	req, err := sb.Parse()
	if err != nil {
		t.Fatal(err)
	}
	f := h.r.check(req)
	if f == nil || f.code != CodeRejected {
		t.Fatalf("a payout below 1 XLM: %v", f)
	}
	// The same request a stroop above passes this check and fails only where its proof no longer
	// matches its ExtData, which comes later.
	req.Ext.ExtAmount = big.NewInt(-vault.MinNewAccountPayout)
	if f := h.r.belowNewAccount(req.Ext); f {
		t.Fatal("1 XLM counted as too small")
	}
	req.Ext.Recipient = vaulttest.Vault
	req.Ext.ExtAmount = big.NewInt(-1)
	if h.r.belowNewAccount(req.Ext) {
		t.Fatal("a contract destination counted")
	}
}

func TestCostlyStepsAreBudgetedOnlyAfterTheFreeChecks(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.r.costly = httpapi.NewLimiter(1, 1)
	// Garbage and invalid proofs spend nothing.
	for range 50 {
		h.post(map[string]any{"junk": true})
		forged := fixture(t, "transfer")
		forged["proof"].(map[string]any)["a"] = strings.Repeat("0", 128)
		h.post(forged)
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("an honest submission after garbage: %d %v", code, out)
	}
	h.waitIdle()
	if code, out := h.post(fixture(t, "unshield_muxed")); code != http.StatusTooManyRequests || out["error"] != CodeRateLimited {
		t.Fatalf("over the budget: %d %v", code, out)
	}
	if len(h.r.inflight) != 0 {
		t.Fatal("a request over the budget kept its notes in flight")
	}
}

func TestEachNullifierIsDedupedOnItsOwn(t *testing.T) {
	h := newHarness(t, vault.Status{})
	a, b, c, d := fr.SetUint64(1), fr.SetUint64(2), fr.SetUint64(3), fr.SetUint64(4)
	if !h.r.claim([2]fr.Element{a, b}) {
		t.Fatal("first claim")
	}
	if h.r.claim([2]fr.Element{c, b}) || h.r.claim([2]fr.Element{b, d}) {
		t.Fatal("a nullifier in flight was claimed again in either slot")
	}
	if !h.r.claim([2]fr.Element{c, d}) {
		t.Fatal("a failed claim kept its other nullifier")
	}
}

func TestARestartHoldsTheNotesAndChannelOfAPendingRelay(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.mu.Lock()
	h.status = protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}
	h.mu.Unlock()
	body := fixture(t, "transfer")
	nfs := body["proof"].(map[string]any)["input_nullifiers"].([]any)
	channel := h.r.channels.free[0].ID
	hash := strings.Repeat("ef", 32)
	if err := h.r.db.sent(context.Background(), Record{Hash: hash, Kind: "transfer", Fee: "5000000", Channel: channel,
		Nullifiers: [2]string{nfs[0].(string), nfs[1].(string)}}); err != nil {
		t.Fatal(err)
	}
	if err := h.r.Resume(); err != nil {
		t.Fatal(err)
	}
	if h.r.channels.ready() != 1 {
		t.Fatalf("%d channels free while a relay is pending on one", h.r.channels.ready())
	}
	if code, out := h.post(body); code != http.StatusConflict || out["error"] != CodeDuplicate {
		t.Fatalf("its notes were not held: %d %v", code, out)
	}
	h.setTxStatus(success(900_000))
	h.waitIdle()
	if code, out := h.post(body); code != http.StatusAccepted {
		t.Fatalf("after the outcome: %d %v", code, out)
	}
	h.waitIdle()
}

func TestAWithheldDestinationIsRefusedWithoutAReason(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.screen.err = ErrWithheld
	code, out := h.post(fixture(t, "unshield_muxed"))
	if code != http.StatusUnprocessableEntity || out["error"] != CodeRejected || out["reason"] != nil {
		t.Fatalf("withheld destination: %d %v", code, out)
	}
	if h.fake.CallCount("simulateTransaction") != 0 || len(h.r.inflight) != 0 {
		t.Fatal("a withheld destination was simulated or kept in flight")
	}
}
