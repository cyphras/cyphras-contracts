package relayer

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"strconv"
	"testing"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// The figures of the transfer confirmed on mainnet at ledger 64,939,967: the non-refundable fee
// of its declared resources, the refundable fee it used, and its simulated resource fee.
const (
	mainnetNonRefundable = 107_310
	mainnetRefundable    = 439_330
	mainnetSimulated     = 606_772
)

// restarted builds the relayer again on the same records, as a new process does: it resumes the
// relays left pending, waits for their outcomes, and then refreshes.
func (h *harness) restarted() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	r, err := New(ctx, h.r.cfg, h.fake, h.r.engine, h.r.channels.all, h.screen, h.r.db, 1_000_000, h.r.alerts, h.r.log)
	if err != nil {
		h.t.Fatal(err)
	}
	r.now = h.clock
	r.costly, r.simulateLimit = h.r.costly, h.r.simulateLimit
	h.r = r
	if err := r.Resume(); err != nil {
		h.t.Fatal(err)
	}
	h.waitIdle()
	if err := r.Refresh(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func randomHash(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := crand.Read(raw[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw[:])
}

// recorded stores n relays confirmed at a ledger, each paid fee and charged networkFee, of which
// resource was the resource fee; expected is the resource fee it was expected to be charged, 0 for
// a record that does not carry it.
func (h *harness) recorded(n int, fee, networkFee, resource, expected int64, ledger uint32) {
	h.t.Helper()
	ctx := context.Background()
	for range n {
		hash := randomHash(h.t)
		if err := h.r.db.sent(ctx, Record{Hash: hash, Kind: "transfer", Fee: strconv.FormatInt(fee, 10), ExpectedResourceFee: expected}); err != nil {
			h.t.Fatal(err)
		}
		if err := h.r.db.finish(ctx, Record{Hash: hash, Outcome: outcomeSuccess, Ledger: ledger, NetworkFee: networkFee, ResourceFee: resource}); err != nil {
			h.t.Fatal(err)
		}
	}
}

// queuedSimulation makes every simulation queue its payment at the tail, as the vault does while
// its exit queue holds an exit, at a resource fee of fee stroops.
func (h *harness) queuedSimulation(tail uint64, fee int64) {
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		fp := xdr.LedgerFootprint{ReadWrite: []xdr.LedgerKey{mustKey(vault.ExitKey(vaulttest.Vault, tail))}}
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{Resources: xdr.SorobanResources{Footprint: fp}})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: fee, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
}

func (h *harness) setVaultStatus(status vault.Status) {
	h.t.Helper()
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000, Status: status, Domain: h.domain,
	}), 10, nil)
}

// mainnetRelays sets up a harness with the production engine whose quote is learned from 50
// relays confirmed at the mainnet figures.
func mainnetRelays(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	h := newHarness(t, vault.Status{}, append([]func(*Config){func(c *Config) { c.Key = trapdoorKey(t) }}, mutate...)...)
	h.productionEngine()
	h.unthrottled()
	h.plainSimulation(mainnetSimulated)
	h.confirmedAs(mainnetNonRefundable, mainnetRefundable)
	for i := range Samples {
		if f := h.relayAt(h.publishedQuote(), i%2 == 1, 5000); f != nil {
			t.Fatalf("relay %d at the bootstrap quote: %s", i, f.code)
		}
	}
	h.requote()
	return h
}

// Relays recorded before the expected charge was kept carry only the fee they were charged. A
// window of them must not price the quote under what the next relay is expected to cost, or no
// relay confirms again and the window never fills with new samples.
func TestRelaysRecordedWithoutTheirExpectedChargeDoNotHoldTheQuoteUnderTheCost(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	h.unthrottled()
	charged := int64(mainnetNonRefundable + mainnetRefundable)
	h.recorded(Samples, 1_100_000, 100+charged, charged, 0, 900)
	h.restarted()
	h.plainSimulation(mainnetSimulated)
	h.confirmedAs(mainnetNonRefundable, mainnetRefundable)
	quote := h.publishedQuote()
	if f := h.relayAt(quote, false, 5000); f != nil {
		t.Fatalf("a transfer at the quote %d after records without the expected charge: %s, network fee %d", quote, f.code, networkFeeOf(t, f))
	}
}

// A quote learned above twice the bootstrap value, as after costs rose step by step, is the same
// after a restart: the stored samples were taken by the running relayer already.
func TestARestartKeepsAQuoteLearnedAboveTwiceTheBootstrap(t *testing.T) {
	stored := make([]int64, Samples)
	for i := range stored {
		stored[i] = 3_000_000
	}
	if got := NewCosts(1_000_000, stored).ResourceFee(); got != 3_000_000 {
		t.Fatalf("p90 %d from 50 stored samples of 3,000,000", got)
	}

	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	h.unthrottled()
	h.recorded(Samples, 3_200_000, 2_600_000, 2_500_000, 3_000_000, 900)
	h.restarted()
	h.plainSimulation(2_950_000)
	quote := h.publishedQuote()
	if f := h.relayAt(quote, false, 5000); f != nil {
		t.Fatalf("a transfer at the quote %d after a restart: %s, network fee %d", quote, f.code, networkFeeOf(t, f))
	}
}

// A relay left pending by the previous run that confirms charged above its fee before the first
// refresh is counted once against the loss budget, not once when it is followed and again when
// the day's records are read.
func TestALossConfirmedAcrossARestartIsCountedOnce(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.LossBudget = 1_000_000 })
	h.productionEngine()
	const fee = 1_100_000
	if err := h.r.db.sent(context.Background(), Record{Hash: randomHash(t), Kind: "transfer", Fee: strconv.Itoa(fee), ExpectedResourceFee: 500_000}); err != nil {
		t.Fatal(err)
	}
	// Charged 600,000 above the fee, under the budget of 1,000,000.
	h.confirmedAs(fee-100, 600_000)
	h.restarted()
	if got := h.r.losses.sum(0); got.Int64() != 600_000 || h.r.overBudget() {
		t.Fatalf("a loss of 600,000 counted as %v, over the budget %t", got, h.r.overBudget())
	}
}

// While the vault's exit queue holds an exit, every relayed call that pays anything, the fee of a
// private transfer included, queues behind it and writes a new exit entry, whose rent the
// simulation names. At mainnet's rent today that is about 550,000 stroops, so the call costs about
// twice an ordinary relay. A relay paying the published quote must still go, or relaying stops for
// everyone until the queue drains, and the quote cannot learn it, since no such relay confirms.
func TestARelayThatQueuesBehindAnExitIsSentAtThePublishedQuote(t *testing.T) {
	// The transfer's simulation plus 1.15 x 550,000 of rent and about 2,800 of non-refundable
	// write fees for a 330-byte exit entry.
	const queuedSimulated = mainnetSimulated + 635_300
	for _, tc := range []struct {
		name     string
		unshield bool
	}{{"transfer", false}, {"unshield", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := mainnetRelays(t)
			h.setVaultStatus(vault.Status{ExitHead: 5, ExitTail: 6})
			quote := h.requote()
			h.queuedSimulation(6, queuedSimulated)
			if f := h.relayAt(quote, tc.unshield, 5000); f != nil {
				t.Fatalf("a %s at the quote %d while an exit is queued: %s, network fee %d", tc.name, quote, f.code, networkFeeOf(t, f))
			}
		})
	}
}

// A network whose live state is still far under its target, as a local network or a test network
// shortly after a reset, prices relays as any other.
func TestARelayIsPricedOnANetworkWhoseStateIsStillSmall(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.productionEngine()
	small := rpctest.Mainnet
	small.StateSize = 20_000_000
	h.fake.SetSettings(small)
	h.plainSimulation(500_000)
	if f := h.relayAt(5_000_000, false, 5000); f != nil {
		t.Fatalf("a relay with 20 MB of live state against a 3 GB target: %s", f.code)
	}
}

// With the mainnet figures, transfers and unshields mixed, the quote follows costs that drift up
// and down by 2% every 5 relays, and every relay at the published quote goes.
func TestTheLearnedQuoteFollowsCostsThatDriftUpAndDown(t *testing.T) {
	h := mainnetRelays(t)
	first := h.publishedQuote()
	simulated, nonRefundable, refundable := float64(mainnetSimulated), float64(mainnetNonRefundable), float64(mainnetRefundable)
	run := func(factor float64, rounds int) {
		t.Helper()
		for i := range rounds {
			if i%5 == 0 {
				simulated, nonRefundable, refundable = simulated*factor, nonRefundable*factor, refundable*factor
				h.plainSimulation(int64(simulated))
				h.confirmedAs(int64(nonRefundable), int64(refundable))
			}
			quote := h.requote()
			if f := h.relayAt(quote, i%3 == 0, 5000); f != nil {
				t.Fatalf("relay %d at factor %v: quote %d refused %s, network fee %d", i, factor, quote, f.code, networkFeeOf(t, f))
			}
		}
	}
	run(1.02, 100)
	high := h.publishedQuote()
	if high <= first {
		t.Fatalf("the quote %d did not rise from %d", high, first)
	}
	run(1/1.02, 100)
	if low := h.publishedQuote(); low >= high {
		t.Fatalf("the quote %d did not fall from %d", low, high)
	}
}

// A step in cost above the quote's margin is refused, and once the cost falls back, relays at the
// same quote go again: the refusals left the samples as they were.
func TestRelayingResumesAfterACostStepFallsBack(t *testing.T) {
	h := mainnetRelays(t)
	quote := h.publishedQuote()
	h.plainSimulation(mainnetSimulated * 2)
	if f := h.relayAt(quote, false, 5000); f == nil || f.code != CodeNetworkFeeHigh {
		t.Fatalf("a relay at twice the cost: %v", f)
	}
	h.later()
	h.plainSimulation(mainnetSimulated)
	if again := h.requote(); again != quote {
		t.Fatalf("the quote moved from %d to %d without a confirmation", quote, again)
	}
	if f := h.relayAt(quote, false, 5000); f != nil {
		t.Fatalf("a relay once the cost fell back: %s", f.code)
	}
}

// A restart at ordinary costs gives the same quote, from the expected charges the records keep,
// and a relay at it goes.
func TestARestartGivesTheSameQuoteFromTheStoredExpectedCharges(t *testing.T) {
	h := mainnetRelays(t)
	before := h.publishedQuote()
	h.restarted()
	h.requote()
	if after := h.publishedQuote(); after != before {
		t.Fatalf("the quote %d became %d after a restart", before, after)
	}
	if f := h.relayAt(before, true, 5000); f != nil {
		t.Fatalf("an unshield after a restart: %s", f.code)
	}
}
