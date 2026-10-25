package relayer

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// queuedPath is the transfer's simulation when its payment queues: 1.15 x 550,000 of rent and
// about 2,800 of write fees more, for a 330-byte exit entry at mainnet's rent today.
const queuedPath = mainnetSimulated + 635_300

// today is the UTC day of the harness's ledgers, as the vault counts its outflow window.
func (h *harness) today() uint64 {
	return uint64(h.fake.CloseTime) / 86_400
}

// With the exit queue empty but today's window used up, every payment queues, the fee of a
// transfer too; the published quote covers the queued path, and when the next day opens the
// window again, the quote is back where it was.
func TestARelayAtTheQuoteGoesWhenTodaysWindowIsFull(t *testing.T) {
	for _, unshield := range []bool{false, true} {
		h := mainnetRelays(t)
		before := h.publishedQuote()
		h.setVaultStatus(vault.Status{ExitHead: 5, ExitTail: 5, Outflow: big.NewInt(1_000_000_000_000), OutflowDay: h.today()})
		quote := h.requote()
		if quote <= before {
			t.Fatalf("the quote %d did not cover the queued path, from %d", quote, before)
		}
		h.queuedSimulation(5, queuedPath)
		if f := h.relayAt(quote, unshield, 5000); f != nil {
			t.Fatalf("unshield %t at the quote %d with today's window full: %s %d", unshield, quote, f.code, networkFeeOf(t, f))
		}
		// The next day's window has room again.
		h.setVaultStatus(vault.Status{ExitHead: 5, ExitTail: 5, Outflow: big.NewInt(1_000_000_000_000), OutflowDay: h.today() - 1})
		h.plainSimulation(mainnetSimulated)
		if back := h.requote(); back != before {
			t.Fatalf("the quote %d did not flip back to %d", back, before)
		}
		if f := h.relayAt(before, unshield, 5000); f != nil {
			t.Fatalf("unshield %t once the window opened: %s", unshield, f.code)
		}
	}
}

// Queued relays that confirm give the quote no sample, so once the queue drains the quote is back
// where it was, neither doubled nor lowered for the next 50 confirmations.
func TestQueuedRelaysDoNotLiftTheQuoteOnceTheQueueDrains(t *testing.T) {
	h := mainnetRelays(t)
	before := h.publishedQuote()
	ordinary := h.r.costs.ResourceFee()
	h.setVaultStatus(vault.Status{ExitHead: 5, ExitTail: 6})
	h.queuedSimulation(6, queuedPath)
	for i := range Samples {
		if f := h.relayAt(h.requote(), i%2 == 0, 5000); f != nil {
			t.Fatalf("queued relay %d: %s %d", i, f.code, networkFeeOf(t, f))
		}
	}
	if got := h.r.costs.ResourceFee(); got != ordinary {
		t.Fatalf("queued relays moved the cost from %d to %d", ordinary, got)
	}
	h.setVaultStatus(vault.Status{ExitHead: 6, ExitTail: 6})
	h.plainSimulation(mainnetSimulated)
	if back := h.requote(); back != before {
		t.Fatalf("the quote %d after the queue drained, from %d", back, before)
	}
}

// With room left today for a transfer but not for a large unshield, the published fee is the
// paid-at-once one and the quote names the queued fee besides: the unshield that would queue must
// pay it, and is refused before any simulation when it does not.
func TestAPaymentThatWouldQueuePaysTheQueuedFee(t *testing.T) {
	h := mainnetRelays(t)
	before := h.publishedQuote()
	h.setVaultStatus(vault.Status{ExitHead: 5, ExitTail: 5, Outflow: big.NewInt(1_000_000_000_000 - 10_000_000), OutflowDay: h.today()})
	if quote := h.requote(); quote != before {
		t.Fatalf("the published fee %d moved from %d", quote, before)
	}
	_, out := h.get("/v1/quote")
	queuedFee, ok := new(big.Int).SetString(out["queued_fee"].(string), 10)
	if !ok || queuedFee.Int64() <= before {
		t.Fatalf("quote %v", out)
	}
	simulated := h.fake.CallCount("simulateTransaction")
	if f := h.relayAt(before, true, 5000); f == nil || f.code != CodeFeeTooLow {
		t.Fatalf("an unshield that would queue at the paid-at-once fee: %v", f)
	}
	if h.fake.CallCount("simulateTransaction") != simulated {
		t.Fatal("a fee under the queued quote was simulated")
	}
	h.queuedSimulation(5, queuedPath)
	if f := h.relayAt(queuedFee.Int64(), true, 5000); f != nil {
		t.Fatalf("the unshield at the queued fee: %s %d", f.code, networkFeeOf(t, f))
	}
	h.plainSimulation(mainnetSimulated)
	if f := h.relayAt(before, false, 5000); f != nil {
		t.Fatalf("a transfer that fits today's window: %s", f.code)
	}
}

// setVaultLimit sets every limit of the vault, max_fee and max_daily_outflow among them, to limit.
func (h *harness) setVaultLimit(limit int64, status vault.Status) {
	h.t.Helper()
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: limit, Large: 5_000_000_000, Status: status, Domain: h.domain,
	}), 10, nil)
	h.mu.Lock()
	h.now = h.now.Add(QuoteLifetime + time.Second)
	h.mu.Unlock()
	h.fake.CloseTime = h.now.Unix()
}

// Above max_fee the queued fee is not quoted, and while every payment queues no quote is given.
func TestAQueuedFeeAboveMaxFeeIsNotQuoted(t *testing.T) {
	h := mainnetRelays(t)
	before := h.publishedQuote()
	h.setVaultLimit(before+100_000, vault.Status{})
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, out := h.get("/v1/quote"); out["queued_fee"] != nil || out["fee"] == nil {
		t.Fatalf("quote %v", out)
	}
	h.setVaultLimit(before+100_000, vault.Status{ExitHead: 5, ExitTail: 6})
	if err := h.r.Refresh(context.Background()); err == nil {
		t.Fatal("a quote above max_fee")
	}
	if code, out := h.get("/v1/quote"); code != http.StatusServiceUnavailable {
		t.Fatalf("every payment queues above max_fee: %d %v", code, out)
	}
}

// One RPC reporting a tip far ahead does not drop the day's losses; they go once they are both a
// window of ledgers behind and a day old.
func TestAFarAheadTipKeepsTheDaysLosses(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	l := losses{now: func() time.Time { return now }}
	l.sum(4_000_000_000)
	l.add("a", 1001, big.NewInt(1_000_000_000))
	if got := l.sum(1100); got.Int64() != 1_000_000_000 {
		t.Fatalf("after a far tip: %v", got)
	}
	if got := l.sum(4_000_000_000); got.Int64() != 1_000_000_000 {
		t.Fatalf("at a far tip: %v", got)
	}
	l.add("a", 1001, big.NewInt(1_000_000_000))
	if got := l.sum(1100); got.Int64() != 1_000_000_000 {
		t.Fatalf("the same transaction twice: %v", got)
	}
	now = now.Add(lossAge)
	if got := l.sum(1000 + lossWindow); got.Int64() != 1_000_000_000 {
		t.Fatalf("a day old, a window behind less one: %v", got)
	}
	if got := l.sum(1001 + lossWindow); got.Sign() != 0 {
		t.Fatalf("a day old and a window behind: %v", got)
	}
}

// A window stored with a few dear samples is held against its own median after a restart.
func TestAStoredWindowIsHeldAgainstItsOwnMedian(t *testing.T) {
	stored := make([]int64, Samples)
	for i := range stored {
		stored[i] = 600_000
		if i >= 44 {
			stored[i] = 50_000_000
		}
	}
	if got := NewCosts(1_000_000, stored).ResourceFee(); got != 1_200_000 {
		t.Fatalf("p90 %d", got)
	}
}

// Requests paying the published quote and refused for their network fee page once three with no
// note in common came within an hour; one note under many proofs counts once.
func TestRefusalsAtTheQuoteRaiseQuoteBelowCost(t *testing.T) {
	h := mainnetRelays(t)
	quote := h.publishedQuote()
	h.plainSimulation(mainnetSimulated * 2)
	first := h.forged(t, feeAddress, 0, quote)
	for range 10 {
		req := first
		req.Proof.Nullifiers[1] = randomField(t)
		if _, f := h.r.Submit(context.Background(), h.reforged(req)); f == nil || f.code != CodeNetworkFeeHigh {
			t.Fatalf("a refusal: %v", f)
		}
	}
	if h.r.alerts.Open("quote_below_cost") {
		t.Fatal("one note paged")
	}
	for range 2 {
		if f := h.relayAt(quote, false, 5000); f == nil || f.code != CodeNetworkFeeHigh {
			t.Fatalf("a refusal: %v", f)
		}
	}
	if !h.r.alerts.Open("quote_below_cost") {
		t.Fatal("three notes refused at the quote raised nothing")
	}
}
