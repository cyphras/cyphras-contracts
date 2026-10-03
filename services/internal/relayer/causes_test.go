package relayer

import (
	"context"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// lose sends the request build makes and waits for its outcome, which the harness's status sets.
func (h *harness) lose(t *testing.T, build func() Request) Request {
	t.Helper()
	req := build()
	if _, f := h.r.Submit(context.Background(), req); f != nil {
		t.Fatalf("not sent: %v", f)
	}
	h.waitIdle()
	return req
}

func TestOnlyFailuresOfTheRelayersOwnMakingPauseIt(t *testing.T) {
	newDest := func(h *harness) string {
		d := keypair.MustRandom().Address()
		h.fund(d)
		return d
	}
	// The vault says a party cannot receive, and it is the relayer's own fee address.
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedReceive())
	h.fake.DeleteEntry(mustKey(vault.AccountKey(feeAddress)))
	dest := newDest(h)
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if !h.r.brk.open(h.clock()) || h.r.cool.cooling(h.clock().Unix(), destinationKey(dest)) {
		t.Fatal("the fee address failing to receive was taken for the destination")
	}

	// The asset contract refused a transfer while the issuer did not let the vault hold the asset.
	h = newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedWith(vaulttest.Token, 13))
	h.fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vaulttest.Balance(big.NewInt(1_000_000_000), false), 10, nil)
	dest = newDest(h)
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if !h.r.brk.open(h.clock()) {
		t.Fatal("a vault that may not pay was taken for the destination")
	}

	// The same refusal while the vault may pay is the destination's doing.
	h = newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedWith(vaulttest.Token, 13))
	h.fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vaulttest.Balance(big.NewInt(1_000_000_000), true), 10, nil)
	dest = newDest(h)
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if h.r.brk.open(h.clock()) || !h.r.cool.cooling(h.clock().Unix(), destinationKey(dest)) {
		t.Fatal("a destination that stopped receiving paused relaying")
	}

	// With no error reported, notes found spent on chain tell a lost race.
	h = newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedOnChain())
	dest = newDest(h)
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	// Another transaction spends the notes in the same ledger as the relay.
	h.fake.Send = func(protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		for _, nf := range req.Proof.Nullifiers {
			h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, nf.Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 1001, nil)
		}
		return protocol.SendTransactionResponse{Status: "PENDING"}, nil
	}
	h.lose(t, func() Request { return req })
	if h.r.brk.open(h.clock()) || !h.r.known.any(req.Proof.Nullifiers) {
		t.Fatal("notes spent first counted against the relayer")
	}
}

func TestReplayedProofsAreAnsweredBeforeTheyCostAnything(t *testing.T) {
	h := trapdoorHarness(t)
	h.r.costly = httpapi.NewLimiter(60, 2)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	public := h.forged(t, dest, -20_000_000, 5_000_000)
	if _, f := h.r.Submit(ctx, public); f != nil {
		t.Fatalf("first relay: %v", f)
	}
	h.waitIdle()
	// Its proof is public on chain; anyone can send it again while its deadline holds.
	for range 100 {
		if _, f := h.r.Submit(ctx, public); f == nil || f.code != CodeRejected {
			t.Fatalf("a replay: %v", f)
		}
	}
	honest := keypair.MustRandom().Address()
	h.fund(honest)
	if _, f := h.r.Submit(ctx, h.forged(t, honest, -20_000_000, 5_000_000)); f != nil {
		t.Fatalf("an honest relay after the replays: %v", f)
	}
	h.waitIdle()
}

func TestNullifiersTheVaultReportsSpentAreRefusedForFree(t *testing.T) {
	h := trapdoorHarness(t)
	h.r.costly = httpapi.NewLimiter(1, 1)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	used := h.forged(t, dest, -20_000_000, 5_000_000)
	// Another transaction spent its notes, as the vault's events tell.
	for i, nf := range used.Proof.Nullifiers {
		h.fake.AddEvent(rpctest.EventInfo(vault.RawEvent{
			Ledger: 999, ClosedAt: h.clock().Unix(), TxHash: strings.Repeat("cd", 32), Tx: 1, Index: uint32(i), Contract: vaulttest.Vault,
			Topics: []string{mustB64(t, vault.Symbol("new_nullifier"))}, Value: mustB64(t, vault.Struct(vault.Field{Name: "nullifier", Value: vaulttest.Field(nf)})),
		}))
	}
	if err := h.r.FollowNullifiers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, f := h.r.Submit(ctx, used); f == nil || f.code != CodeRejected {
		t.Fatalf("spent notes: %v", f)
	}
	if _, f := h.r.Submit(ctx, h.forged(t, dest, -20_000_000, 5_000_000)); f != nil {
		t.Fatalf("the budget was spent on spent notes: %v", f)
	}
	h.waitIdle()
	if !h.r.known.any([2]fr.Element{used.Proof.Nullifiers[1], {}}) {
		t.Fatal("the second nullifier is not known")
	}
}

func TestAStatusLookupOverBudgetIsRateLimitedNotUnknown(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.r.lookups = httpapi.NewLimiter(1, 1)
	unknown := strings.Repeat("ab", 32)
	if code, _ := h.get("/v1/tx/" + unknown); code != http.StatusNotFound {
		t.Fatalf("an unknown hash answered %d", code)
	}
	if code, out := h.get("/v1/tx/" + unknown); code != http.StatusTooManyRequests || out["error"] != CodeRateLimited {
		t.Fatalf("over budget: %d %v", code, out)
	}
}

func mustB64(t *testing.T, v xdr.ScVal) string {
	t.Helper()
	s, err := xdr.MarshalBase64(v)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
