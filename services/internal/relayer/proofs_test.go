package relayer

import (
	"context"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// trapdoorHarness is a relayer whose verifying key the tests can make valid proofs for, so a
// request is refused only by the rule a test is about.
func trapdoorHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
}

func TestASmallPayoutIsRelayedOnlyToAnAccountThatExists(t *testing.T) {
	h := trapdoorHarness(t)
	ctx := context.Background()
	existing, missing := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	h.fund(existing)
	// Any payout reaches an account that exists, a muxed one included, as the vault pays it.
	if _, f := h.r.Submit(ctx, h.forged(t, muxed(t, existing, 3), -5_000_000, 5_000_000)); f != nil {
		t.Fatalf("a payout below 1 XLM to an existing account: %v", f)
	}
	h.waitIdle()
	// Below 1 XLM nothing can create a missing account, so the vault would refuse it.
	if _, f := h.r.Submit(ctx, h.forged(t, missing, -(vault.MinNewAccountPayout-1), 5_000_000)); f == nil || f.code != CodeRejected {
		t.Fatalf("a payout below 1 XLM to a missing account: %v", f)
	}
	if _, f := h.r.Submit(ctx, h.forged(t, missing, -vault.MinNewAccountPayout, 5_000_000)); f != nil {
		t.Fatalf("1 XLM to a missing account: %v", f)
	}
	h.waitIdle()
	if n := h.sends(); n != 2 {
		t.Fatalf("%d sent", n)
	}
}

func TestADepositOrALowFeeIsNeverRelayedEvenWithAValidProof(t *testing.T) {
	h := trapdoorHarness(t)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	if _, f := h.r.Submit(ctx, h.forged(t, dest, 20_000_000, 5_000_000)); f == nil || f.code != CodeBadRequest {
		t.Fatalf("a positive ext_amount: %v", f)
	}
	if _, f := h.r.Submit(ctx, h.forged(t, dest, -20_000_000, 1)); f == nil || f.code != CodeFeeTooLow {
		t.Fatalf("a fee below the quote: %v", f)
	}
	h.waitIdle()
	if n := h.sends(); n != 0 || h.fake.CallCount("simulateTransaction") != 0 {
		t.Fatalf("%d sent, %d simulated", n, h.fake.CallCount("simulateTransaction"))
	}
}

func TestAHeldRequestIsRefusedWhenItsDestinationCoolsDownDuringTheHold(t *testing.T) {
	h := trapdoorHarness(t)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	held := h.forged(t, dest, -20_000_000, 5_000_000)
	notBefore := h.clock().Unix() + 2
	held.NotBefore = &notBefore
	accepted, f := h.r.Submit(ctx, held)
	if f != nil || !accepted.Held {
		t.Fatalf("held request: %+v %v", accepted, f)
	}
	// While it waits, another relay to the same destination fails on chain.
	h.setTxStatus(failedOnChain())
	if _, f := h.r.Submit(ctx, h.forged(t, dest, -20_000_000, 5_000_000)); f != nil {
		t.Fatalf("the relay that fails: %v", f)
	}
	h.r.Wait()
	h.setTxStatus(success(900_000))
	h.mu.Lock()
	h.now = h.now.Add(time.Minute)
	h.mu.Unlock()
	for range 500 {
		if _, st := h.get("/v1/held/" + accepted.ID); st["status"] == "failed" {
			if st["code"] != CodeRejected || h.sends() != 1 {
				t.Fatalf("held request after the cooldown: %v, %d sent", st, h.sends())
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the held request was never refused; %d sent", h.sends())
}
