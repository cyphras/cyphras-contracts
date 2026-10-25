package relayer

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// steadyState gives the harness the production engine on the network's settings, and a quote
// learned from 50 confirmed relays charged the given resource fee.
func (h *harness) steadyState(settings rpctest.Settings, charged int64) {
	h.t.Helper()
	h.productionEngine()
	h.fake.SetSettings(settings)
	for range Samples {
		h.r.costs.Add(charged)
	}
	h.mu.Lock()
	h.now = h.now.Add(QuoteLifetime + time.Second)
	h.mu.Unlock()
	h.fake.CloseTime = h.now.Unix()
	if err := h.r.Refresh(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

// With mainnet's settings and a quote learned from relays charged about 550,000 stroops, a
// transfer and an unshield that pay the quote are relayed, at today's state size and at 85% of
// the target, where the exit queue's rent reserve alone is several times the quote.
func TestRelaysPayingTheLearnedQuoteAreSentWithProductionSettings(t *testing.T) {
	at85 := rpctest.Mainnet
	at85.StateSize = 2_550_000_000
	for _, tc := range []struct {
		name     string
		settings rpctest.Settings
	}{{"today", rpctest.Mainnet}, {"85 percent", at85}} {
		for _, unshield := range []bool{false, true} {
			kind := "transfer"
			if unshield {
				kind = "unshield"
			}
			t.Run(tc.name+" "+kind, func(t *testing.T) {
				h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
				h.steadyState(tc.settings, 550_000)
				quote := h.publishedQuote()
				if quote != 600_000 {
					t.Fatalf("quote %d", quote)
				}
				h.plainSimulation(500_000)
				recipient, amount := feeAddress, int64(0)
				if unshield {
					recipient, amount = keypair.MustRandom().Address(), -20_000_000
					h.fund(recipient)
				}
				sent := h.sentEnvelopes()
				if _, f := h.r.Submit(context.Background(), h.forged(t, recipient, amount, quote)); f != nil {
					t.Fatalf("unshield %t at the quote: %s %v", unshield, f.code, f.networkFee)
				}
				h.waitIdle()
				var env xdr.TransactionEnvelope
				if err := xdr.SafeUnmarshalBase64((*sent)[0], &env); err != nil {
					t.Fatal(err)
				}
				// The declared headroom stays within the cap.
				if fee := int64(env.Fee()); fee <= quote || fee > 50_000_000+100 {
					t.Fatalf("the envelope declares %d stroops", fee)
				}
			})
		}
	}
}

// A request whose fee does not cover what the call is charged as simulated is still refused.
func TestARequestBelowTheExpectedCostIsRefused(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.steadyState(rpctest.Mainnet, 550_000)
	quote := h.publishedQuote()
	h.plainSimulation(quote)
	_, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, quote))
	if fee := networkFeeOf(t, f); fee <= quote {
		t.Fatalf("network fee %d for a fee of %d", fee, quote)
	}
	h.untouched("below the expected cost")
}

func TestTheQuoteFloorLiftsThePublishedQuote(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	if _, quote := h.get("/v1/quote"); quote["fee"] != "1100000" || h.r.FloorFee() != nil {
		t.Fatalf("without a floor: %v", quote)
	}
	h.r.cfg.QuoteFloor = 2_950_001
	h.mu.Lock()
	h.now = h.now.Add(QuoteLifetime + time.Second)
	h.mu.Unlock()
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Rounded up to the tier.
	if _, quote := h.get("/v1/quote"); quote["fee"] != "3000000" {
		t.Fatalf("with a floor: %v", quote)
	}
	if _, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, 2_900_000)); f == nil || f.code != CodeFeeTooLow || f.status != http.StatusBadRequest {
		t.Fatalf("a fee under the floor: %v", f)
	}
	if _, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, 3_000_000)); f != nil {
		t.Fatalf("a fee at the floor: %v", f)
	}
	h.waitIdle()
	// A floor under the cost leaves the quote to the cost.
	h.r.cfg.QuoteFloor = 100
	if fee, err := h.r.Quote(context.Background()); err != nil || fee.Int64() != 1_100_000 {
		t.Fatalf("a low floor: %v %v", fee, err)
	}
}

func TestAQuoteFloorAboveTheVaultsMaxFeeIsRefused(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.QuoteFloor = 2_000_000 })
	if err := h.r.CheckQuoteFloor(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 2_000_000, Large: 5_000_000_000, Domain: h.domain,
	}), 10, nil)
	if err := h.r.CheckQuoteFloor(context.Background()); err != nil {
		t.Fatalf("a floor equal to max_fee: %v", err)
	}
	h.r.cfg.QuoteFloor = 2_000_001
	if err := h.r.CheckQuoteFloor(context.Background()); err == nil {
		t.Fatal("a floor above max_fee was taken")
	}
	h.r.cfg.QuoteFloor = 0
	if err := h.r.CheckQuoteFloor(context.Background()); err != nil {
		t.Fatalf("no floor: %v", err)
	}
}
