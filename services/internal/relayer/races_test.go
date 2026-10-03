package relayer

import (
	"context"
	"net/http"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// aged sets the vault's root history so that a root is the given number of insertions old.
func (h *harness) aged(root fr.Element, age uint32) {
	ring := make([]xdr.ScVal, vault.RootHistory)
	for i := range ring {
		ring[i] = vaulttest.Field(fr.Element{})
	}
	ring[0] = vaulttest.Field(root)
	newest := age % vault.RootHistory
	if newest != 0 {
		ring[newest] = vaulttest.Field(fr.SetUint64(uint64(age) + 1))
	}
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vault.Struct(vault.Field{Name: "roots", Value: vault.Vec(ring...)},
		vault.Field{Name: "newest", Value: vault.U32(newest)}), 10, nil)
}

func TestAProofMustUseOneOfTheNewestRoots(t *testing.T) {
	h := trapdoorHarness(t)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	// The root has 56 insertions left before the vault forgets it: too few to count on.
	h.aged(req.Proof.Root, 200)
	if err := h.r.readRoots(ctx); err != nil {
		t.Fatal(err)
	}
	if _, f := h.r.Submit(ctx, req); f == nil || f.code != CodeRejected {
		t.Fatalf("a root 200 insertions old: %v", f)
	}
	h.aged(req.Proof.Root, 199)
	if err := h.r.readRoots(ctx); err != nil {
		t.Fatal(err)
	}
	if _, f := h.r.Submit(ctx, req); f != nil {
		t.Fatalf("a root 199 insertions old: %v", f)
	}
	h.waitIdle()
}

func TestARootThatAgesPastTheWindowBeforeTheSendIsNotSent(t *testing.T) {
	h := trapdoorHarness(t)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	h.aged(req.Proof.Root, 150)
	if err := h.r.readRoots(ctx); err != nil {
		t.Fatal(err)
	}
	// Insertions land while the call is simulated.
	simulate := h.fake.Simulate
	h.fake.Simulate = func(r protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		h.aged(req.Proof.Root, 230)
		return simulate(r)
	}
	if _, f := h.r.Submit(ctx, req); f == nil || f.code != CodeRejected || h.sends() != 0 {
		t.Fatalf("a root that aged out before the send: %v, %d sent", f, h.sends())
	}
}

func TestAnUnknownRootIsARaceNotTheRelayersFault(t *testing.T) {
	h := trapdoorHarness(t)
	h.setTxStatus(failedWith(vaulttest.Vault, vaultUnknownRoot))
	for range 3 {
		dest := keypair.MustRandom().Address()
		h.fund(dest)
		req := h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
		// The notes are free to be proved again against a newer root.
		if h.r.cool.cooling(h.clock().Unix(), nullifierKey(req.Proof.Nullifiers[0].Hex()), destinationKey(dest)) {
			t.Fatal("an evicted root rested the notes or the destination")
		}
	}
	if code, health := h.get("/v1/health"); code != http.StatusOK || health["paused"] != false {
		t.Fatalf("after three evicted roots: %d %v", code, health)
	}
}
