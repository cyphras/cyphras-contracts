package relayer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// productionEngine sets the engine as service.Engine builds it for the relayer.
func (h *harness) productionEngine() {
	h.r.engine.ResourceMarginPct = 15
	h.r.engine.MaxResourceFee = 50_000_000
}

// publishedQuote is the lowest quote a client may pay now, as the SDK pays it.
func (h *harness) publishedQuote() int64 {
	h.t.Helper()
	low := h.r.quotes.lowest(h.clock())
	if low == nil {
		h.t.Fatal("no quote published")
	}
	return low.Int64()
}

// A client pays the quote. When the network charges exactly the resource fee the quote was made
// from, the relay goes, as it did before the network fee check.
func TestARelayPayingTheQuoteAtTheCostItWasPricedFromIsSent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		unpaid bool
	}{{"transfer", false}, {"unshield", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
			h.productionEngine()
			// The harness starts from a bootstrap resource fee of 1,000,000 stroops.
			h.plainSimulation(1_000_000)
			quote := h.publishedQuote()
			recipient, amount := feeAddress, int64(0)
			if tc.unpaid {
				recipient, amount = keypair.MustRandom().Address(), -20_000_000
				h.fund(recipient)
			}
			_, f := h.r.Submit(context.Background(), h.forged(t, recipient, amount, quote))
			if f != nil {
				fee := int64(-1)
				if f.networkFee != nil {
					fee = *f.networkFee
				}
				t.Fatalf("quote %d at the priced cost: refused %s, network fee %d", quote, f.code, fee)
			}
			h.waitIdle()
		})
	}
}

// Once 50 confirmed relays priced the quote, a relay that costs what they cost is still sent.
func TestARelayPayingASteadyStateQuoteIsSent(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	const charged = 1_900_000
	for range Samples {
		h.r.costs.Add(charged)
	}
	// Past the lifetime of the quotes made from the bootstrap value.
	h.mu.Lock()
	h.now = h.now.Add(QuoteLifetime + time.Second)
	h.mu.Unlock()
	h.fake.CloseTime = h.now.Unix()
	if err := h.r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	quote := h.publishedQuote()
	h.plainSimulation(charged)
	if _, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, quote)); f != nil {
		fee := int64(-1)
		if f.networkFee != nil {
			fee = *f.networkFee
		}
		t.Fatalf("quote %d for a cost of %d: refused %s, network fee %d", quote, charged, f.code, fee)
	}
	h.waitIdle()
}

// Queued exits refused for their network fee at the same time hand the exit slot and every
// channel back, and none is sent.
func TestConcurrentQueuedExitsRefusedForTheirNetworkFeeLeaveNothingTaken(t *testing.T) {
	h := newHarness(t, vault.Status{ExitHead: 5, ExitTail: 5}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	h.r.screen = allowAll{}
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		fp := xdr.LedgerFootprint{ReadWrite: []xdr.LedgerKey{mustKey(vault.ExitKey(vaulttest.Vault, 9))}}
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{Resources: xdr.SorobanResources{Footprint: fp}})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 6_000_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	reqs := make([]Request, 8)
	for i := range reqs {
		dest := keypair.MustRandom().Address()
		h.fund(dest)
		reqs[i] = h.forged(t, dest, -20_000_000, 5_000_000)
	}
	codes := make([]string, len(reqs))
	var wg sync.WaitGroup
	for i, req := range reqs {
		wg.Go(func() {
			if _, f := h.r.Submit(context.Background(), req); f != nil {
				codes[i] = f.code
			}
		})
	}
	wg.Wait()
	for i, c := range codes {
		if c != CodeNetworkFeeHigh && c != CodeUnavailable && c != CodeRateLimited {
			t.Fatalf("request %d: %q", i, c)
		}
	}
	h.untouched("concurrent queued exits")
}

// allowAll clears every destination and may be asked from many goroutines.
type allowAll struct{}

func (allowAll) Screen(context.Context, string) (bool, uint32, error) { return true, 0, nil }
