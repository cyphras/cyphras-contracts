package relayer

import (
	"context"
	"testing"

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
