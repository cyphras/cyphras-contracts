package relayer

import (
	"context"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// relayAt sends one request paying fee, a transfer or an unshield to a fresh funded account, with
// the given deadline, and waits for its outcome.
func (h *harness) relayAt(fee int64, unshield bool, deadline uint32) *failure {
	h.t.Helper()
	recipient, amount := feeAddress, int64(0)
	if unshield {
		recipient, amount = keypair.MustRandom().Address(), -20_000_000
		h.fund(recipient)
	}
	_, f := h.r.Submit(context.Background(), h.forgedUntil(h.t, recipient, amount, fee, deadline))
	h.waitIdle()
	return f
}

// requote lets the published quotes age out and publishes a new one.
func (h *harness) requote() int64 {
	h.t.Helper()
	h.mu.Lock()
	h.now = h.now.Add(QuoteLifetime + time.Second)
	h.mu.Unlock()
	h.fake.CloseTime = h.now.Unix()
	if err := h.r.Refresh(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	return h.publishedQuote()
}

func (h *harness) unthrottled() {
	h.r.costly = httpapi.NewLimiter(60_000, 1_000)
	h.r.simulateLimit = httpapi.NewLimiter(60_000, 1_000)
}

// Where 5% over the samples lands just above a tier boundary, the rounding leaves almost no room,
// and a relay at the quote still passes: the quote learns the measure the check takes.
func TestTheLearnedQuotePaysForTheNextRelayAtATierBoundary(t *testing.T) {
	for _, unshield := range []bool{false, true} {
		h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
		h.productionEngine()
		h.unthrottled()
		h.plainSimulation(560_000)
		h.confirmedAs(76_000, 400_000)
		for i := range Samples {
			if f := h.relayAt(h.publishedQuote(), unshield, 5000); f != nil {
				t.Fatalf("relay %d at the bootstrap quote: %s", i, f.code)
			}
		}
		quote := h.requote()
		if quote >= 1_100_000 {
			t.Fatalf("the quote %d did not follow the confirmed relays", quote)
		}
		if f := h.relayAt(quote, unshield, 5000); f != nil {
			t.Fatalf("unshield %t at the learned quote %d: %s %v", unshield, quote, f.code, *f.networkFee)
		}
	}
}

// A client who pays for a few dear relays, as to a contract destination whose new balance costs
// rent, cannot lift the quote for everyone past twice the median of the window.
func TestAFewDearRelaysCannotLiftTheQuotePastItsBound(t *testing.T) {
	c := NewCosts(1_000_000, nil)
	for range Samples {
		c.Add(600_000)
	}
	for range 10 {
		c.Add(6_000_000)
	}
	if got := c.ResourceFee(); got != SampleMultiple*600_000 {
		t.Fatalf("p90 %d after 10 dear relays", got)
	}
	// Lifting the median itself takes half the window, 25 relays, for each doubling.
	for range 14 {
		c.Add(6_000_000)
	}
	if got := c.ResourceFee(); got != SampleMultiple*600_000 {
		t.Fatalf("p90 %d after 24 dear relays", got)
	}
	for range 26 {
		c.Add(6_000_000)
	}
	if got := c.ResourceFee(); got != 2*SampleMultiple*600_000 {
		t.Fatalf("p90 %d after 50 dear relays", got)
	}
	// Before the window is full, a sample stays within twice the bootstrap value.
	early := NewCosts(1_000_000, nil)
	for range Samples {
		early.Add(50_000_000)
	}
	if got := early.ResourceFee(); got != 2_000_000 {
		t.Fatalf("p90 %d from an early window", got)
	}
	// A confirmation that reported no resource fee is not a sample.
	for range Samples {
		early.Add(0)
	}
	if got := early.ResourceFee(); got != 2_000_000 {
		t.Fatalf("p90 %d after empty samples", got)
	}

	// Through the relayer: 10 dear relays among 50 ordinary ones leave the quote within the bound.
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	h.unthrottled()
	h.plainSimulation(600_000)
	h.confirmedAs(100_000, 450_000)
	for range Samples {
		if f := h.relayAt(h.publishedQuote(), false, 5000); f != nil {
			t.Fatalf("an ordinary relay: %s", f.code)
		}
	}
	h.requote()
	ordinary := h.r.costs.ResourceFee()
	h.plainSimulation(6_000_000)
	for range 10 {
		if f := h.relayAt(8_000_000, false, 5000); f != nil {
			t.Fatalf("a dear relay: %s", f.code)
		}
	}
	if got := h.r.costs.ResourceFee(); got > SampleMultiple*ordinary {
		t.Fatalf("cost %d after dear relays, from %d", got, ordinary)
	}
}

// A relay charged above its fee raises a warning. Past the budget within a day, the check takes
// the envelope's whole fee until the window rolls, and a restart reads the day's losses back.
func TestChargesAboveTheFeeAreBudgetedPerDay(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.LossBudget = 1_000_000 })
	h.productionEngine()
	h.unthrottled()
	h.plainSimulation(500_000)
	// The bootstrap quote.
	const fee = 1_100_000
	h.confirmedAs(fee-100-400_000, 400_001)
	if f := h.relayAt(fee, false, 30_000); f != nil {
		t.Fatalf("one stroop over: %s", f.code)
	}
	if !h.r.alerts.Open("relay_below_cost") || h.r.alerts.Open("relay_loss_budget") || h.r.overBudget() {
		t.Fatal("a stroop over the fee: no warning, or the budget taken")
	}
	// Two relays charged 600,000 over pass the budget of 1,000,000.
	h.confirmedAs(fee-100, 600_000)
	for i := range 2 {
		if f := h.relayAt(fee, false, 30_000); f != nil {
			t.Fatalf("relay %d: %s", i, f.code)
		}
	}
	if !h.r.alerts.Open("relay_loss_budget") || !h.r.overBudget() {
		t.Fatal("the budget passed without an alert")
	}
	h.confirmedAs(100_000, 400_000)
	before := h.sends()
	f := h.relayAt(fee, false, 30_000)
	if worst := networkFeeOf(t, f); worst <= fee {
		t.Fatalf("over the budget: network fee %d", worst)
	}
	if h.sends() != before || h.r.channels.ready() != h.r.channels.total {
		t.Fatal("a relay over the budget was sent or kept a channel")
	}
	// A fee that covers the whole envelope still goes.
	if f := h.relayAt(10_000_000, false, 30_000); f != nil {
		t.Fatalf("a fee covering the envelope: %s", f.code)
	}

	// A restart reads the day's losses from the records.
	h.r.losses, h.r.lossesLoaded = losses{}, false
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.r.overBudget() {
		t.Fatal("the losses were not read back")
	}
	// Once the day has passed, the expected charge is taken again.
	h.setLatest(1001+lossWindow, true)
	if h.r.overBudget() || h.r.alerts.Open("relay_loss_budget") {
		t.Fatal("the window did not roll")
	}
	if f := h.relayAt(fee, false, 30_000); f != nil {
		t.Fatalf("after the window: %s", f.code)
	}
}

// When the guardian lowers max_fee under the quote floor, the relayer gives no quote and says why.
func TestAQuoteAboveMaxFeeRaisesAnAlertNamingTheFloor(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.QuoteFloor = 2_000_000 })
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_500_000, Large: 5_000_000_000, Domain: h.domain,
	}), 10, nil)
	if err := h.r.Refresh(context.Background()); err == nil {
		t.Fatal("a quote above max_fee was given")
	}
	if !h.r.alerts.Open("quote_above_max_fee") {
		t.Fatal("no alert")
	}
	h.r.cfg.QuoteFloor = 0
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.r.alerts.Open("quote_above_max_fee") {
		t.Fatal("the alert stayed open")
	}
}

// A state far above its target, or an RPC that says so, makes the rent reserve pass int64; it is
// held, the call is refused above the cap, and nothing is signed.
func TestARentReserveBeyondInt64IsRefusedAboveTheCap(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	huge := rpctest.Mainnet
	huge.StateTarget, huge.StateSize = 1_000, 10_000_000_000_000
	h.fake.SetSettings(huge)
	h.plainSimulation(500_000)
	_, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, 5_000_000))
	if fee := networkFeeOf(t, f); fee <= 50_000_000 {
		t.Fatalf("network fee %d", fee)
	}
	h.untouched("a reserve beyond int64")
}
