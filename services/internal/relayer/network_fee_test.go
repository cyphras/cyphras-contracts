package relayer

import (
	"context"
	"math/big"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// untouched fails the test unless every channel and the exit slot are free again and nothing was
// sent, so a refused relay consumed no channel, sequence number or exit slot.
func (h *harness) untouched(what string) {
	h.t.Helper()
	if h.sends() != 0 || h.fake.CallCount("sendTransaction") != 0 {
		h.t.Fatalf("%s: %d transactions sent", what, h.sends())
	}
	if h.r.channels.ready() != h.r.channels.total || len(h.r.exitSlot) != 1 {
		h.t.Fatalf("%s: %d of %d channels free, exit slot free %t", what, h.r.channels.ready(), h.r.channels.total, len(h.r.exitSlot) == 1)
	}
	h.r.mu.Lock()
	inflight := len(h.r.inflight)
	h.r.mu.Unlock()
	if inflight != 0 {
		h.t.Fatalf("%s: %d nullifiers kept in flight", what, inflight)
	}
}

// networkFeeOf returns the network fee a network_fee_high refusal names.
func networkFeeOf(t *testing.T, f *failure) int64 {
	t.Helper()
	if f == nil || f.code != CodeNetworkFeeHigh || f.status != http.StatusUnprocessableEntity || f.networkFee == nil {
		t.Fatalf("not refused for its network fee: %+v", f)
	}
	return *f.networkFee
}

// While the network's resource fee sits between the quote and the cap, the relayer would pay more
// than it is paid; it refuses before signing and names the network fee.
func TestASpikeBetweenTheQuoteAndTheCapIsRefusedBeforeAnythingIsSigned(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.r.engine.MaxResourceFee = 50_000_000
	h.plainSimulation(6_000_000)
	code, out := h.post(fixture(t, "transfer"))
	if code != http.StatusUnprocessableEntity || out["error"] != CodeNetworkFeeHigh || len(out) != 2 {
		t.Fatalf("a spike: %d %v", code, out)
	}
	fee, err := strconv.ParseInt(out["network_fee"].(string), 10, 64)
	if err != nil || fee <= 6_000_100 || fee > 50_000_100 {
		t.Fatalf("network fee %v", out["network_fee"])
	}
	h.untouched("a spike")

	// The same proof again within the minute is answered from memory, with the same network fee.
	simulated := h.fake.CallCount("simulateTransaction")
	if code, again := h.post(fixture(t, "transfer")); code != http.StatusUnprocessableEntity || again["network_fee"] != out["network_fee"] {
		t.Fatalf("the same proof again: %d %v", code, again)
	}
	if h.fake.CallCount("simulateTransaction") != simulated {
		t.Fatal("a remembered refusal was simulated again")
	}
	h.untouched("the same proof again")

	// Once the fee falls, the same proof is relayed after the minute.
	h.later()
	h.plainSimulation(800_000)
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("after the spike: %d %v", code, out)
	}
	h.waitIdle()
	if h.sends() != 1 {
		t.Fatalf("%d transactions sent", h.sends())
	}
}

// Above the cap the call is refused the same way, and the network fee it names is what the
// simulation asked for, not the cap.
func TestANetworkFeeAboveTheCapIsRefusedWithItsFee(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.r.engine.MaxResourceFee = 50_000_000
	h.plainSimulation(153_276_461)
	_, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, 5_000_000))
	if fee := networkFeeOf(t, f); fee <= 153_276_561 {
		t.Fatalf("network fee %d", fee)
	}
	h.untouched("above the cap")
}

// The check takes the fee the call is charged as simulated: one exactly equal to the fee paid is
// relayed, one stroop more is not.
func TestARelayIsSentWhenItsNetworkFeeEqualsTheFeePaid(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	const paid = 5_000_000
	// The extra room and the inclusion fee are the same for every transfer.
	h.plainSimulation(6_000_000)
	_, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, paid))
	over := networkFeeOf(t, f) - 6_000_000
	if over <= 100 {
		t.Fatalf("the extra room and inclusion fee add %d stroops", over)
	}
	h.untouched("probe")

	h.plainSimulation(paid - over + 1)
	_, f = h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, paid))
	if fee := networkFeeOf(t, f); fee != paid+1 {
		t.Fatalf("one stroop over: network fee %d", fee)
	}
	h.untouched("one stroop over")

	h.plainSimulation(paid - over)
	sent := h.sentEnvelopes()
	if _, f := h.r.Submit(context.Background(), h.forged(t, feeAddress, 0, paid)); f != nil {
		t.Fatalf("exactly the fee paid: %v", f)
	}
	h.waitIdle()
	if len(*sent) != 1 {
		t.Fatalf("%d transactions sent", len(*sent))
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64((*sent)[0], &env); err != nil {
		t.Fatal(err)
	}
	// The envelope declares the reserve for the exit queue's other path on top, refunded unless the
	// call takes that path.
	if env.Fee() <= paid {
		t.Fatalf("the envelope bids %d stroops", env.Fee())
	}
}

// An exit whose simulation queued it holds the exit slot while it is prepared; refused for its
// network fee, it gives the slot back.
func TestAQueuedExitRefusedForItsNetworkFeeFreesTheExitSlot(t *testing.T) {
	h := newHarness(t, vault.Status{ExitHead: 5, ExitTail: 5}, func(c *Config) { c.Key = trapdoorKey(t) })
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		fp := xdr.LedgerFootprint{ReadWrite: []xdr.LedgerKey{mustKey(vault.ExitKey(vaulttest.Vault, 9))}}
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{Resources: xdr.SorobanResources{Footprint: fp}})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 6_000_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	_, f := h.r.Submit(context.Background(), h.forged(t, dest, -20_000_000, 5_000_000))
	networkFeeOf(t, f)
	h.untouched("a queued exit")
	if len(h.screen.asked) != 1 {
		t.Fatalf("screened %d times", len(h.screen.asked))
	}
}

// A held request is priced when it is sent: a spike by then fails it with the same code.
func TestAHeldRequestSentDuringASpikeFailsForItsNetworkFee(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.plainSimulation(6_000_000)
	req := h.forged(t, feeAddress, 0, 5_000_000)
	notBefore := h.clock().Unix() + 1
	req.NotBefore = &notBefore
	accepted, f := h.r.Submit(context.Background(), req)
	if f != nil || !accepted.Held {
		t.Fatalf("held: %+v %v", accepted, f)
	}
	h.mu.Lock()
	h.now = h.now.Add(time.Second)
	h.mu.Unlock()
	for range 1000 {
		if _, st := h.get("/v1/held/" + accepted.ID); st["status"] != "held" {
			if st["status"] != "failed" || st["code"] != CodeNetworkFeeHigh {
				t.Fatalf("held status %v", st)
			}
			h.waitIdle()
			h.untouched("a held request")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the held request was never sent")
}

func TestACostConvertsToTheAssetRoundedUp(t *testing.T) {
	usdc := Pricing{PerStroopNum: big.NewInt(1), PerStroopDen: big.NewInt(3), Tier: big.NewInt(10)}
	if got := usdc.ToAsset(31); got.Int64() != 11 {
		t.Fatalf("converted cost %v", got)
	}
	if got := (Pricing{Native: true, Tier: big.NewInt(10)}).ToAsset(31); got.Int64() != 31 {
		t.Fatalf("native cost %v", got)
	}
}
