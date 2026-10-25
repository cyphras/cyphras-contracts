package relayer

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// rerandomized returns the request with its proof re-randomized as anyone can without the
// witness: A divided and B multiplied by a fresh scalar, so the proof bytes differ and the same
// public inputs still verify.
func rerandomized(t *testing.T, req Request) Request {
	t.Helper()
	order := ecc.BN254.ScalarField()
	s, err := rand.Int(rand.Reader, new(big.Int).Sub(order, big.NewInt(2)))
	if err != nil {
		t.Fatal(err)
	}
	s.Add(s, big.NewInt(2))
	inv := new(big.Int).ModInverse(s, order)
	p := req.Proof
	var a bn254.G1Affine
	a.X.SetBytes(p.A[:32])
	a.Y.SetBytes(p.A[32:])
	a.ScalarMultiplication(&a, inv)
	var b bn254.G2Affine
	b.X.A1.SetBytes(p.B[:32])
	b.X.A0.SetBytes(p.B[32:64])
	b.Y.A1.SetBytes(p.B[64:96])
	b.Y.A0.SetBytes(p.B[96:])
	b.ScalarMultiplication(&b, s)
	ax, ay := a.X.Bytes(), a.Y.Bytes()
	copy(p.A[:32], ax[:])
	copy(p.A[32:], ay[:])
	for i, e := range [][32]byte{b.X.A1.Bytes(), b.X.A0.Bytes(), b.Y.A1.Bytes(), b.Y.A0.Bytes()} {
		copy(p.B[32*i:], e[:])
	}
	req.Proof = p
	return req
}

// A restore_needed refusal holds for the statement, so re-randomized copies of a proof are
// answered from memory too, while a broken proof with another's public inputs is refused without
// holding back that other's valid one.
func TestARestoreRefusalHoldsForEveryRandomizationOfTheProof(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.needsRestore(800_000)
	first := h.forged(t, feeAddress, 0, 5_000_000)
	if _, f := h.r.Submit(context.Background(), first); f == nil || f.code != CodeRestoreNeeded {
		t.Fatalf("the first proof: %v", f)
	}
	simulated := h.fake.CallCount("simulateTransaction")
	for range 5 {
		copied := rerandomized(t, first)
		if copied.Proof.A == first.Proof.A || proofKey(copied) == proofKey(first) {
			t.Fatal("the copy was not re-randomized")
		}
		if _, f := h.r.Submit(context.Background(), copied); f == nil || f.code != CodeRestoreNeeded {
			t.Fatalf("a re-randomized copy: %v", f)
		}
	}
	if got := h.fake.CallCount("simulateTransaction"); got != simulated {
		t.Fatalf("%d more simulations for re-randomized copies", got-simulated)
	}

	// A broken proof with a victim's public inputs is refused at verification, which remembers
	// only those bytes, and leaves the victim's own proof relayable.
	h.plainSimulation(800_000)
	victim := h.forged(t, feeAddress, 0, 5_000_000)
	broken := victim
	broken.Proof.C = first.Proof.A
	if _, f := h.r.Submit(context.Background(), broken); f == nil || f.code != CodeRejected {
		t.Fatalf("a broken proof: %v", f)
	}
	if _, f := h.r.Submit(context.Background(), victim); f != nil {
		t.Fatalf("the victim's proof: %v", f)
	}
	h.waitIdle()
	if h.sends() != 1 {
		t.Fatalf("%d transactions sent", h.sends())
	}
}

// needsRestore makes the simulation of every call mark the vault's instance as archived, for the
// call to restore within itself at a resource fee of fee stroops.
func (h *harness) needsRestore(fee int64) {
	instance := mustKey(vault.InstanceKey(vaulttest.Vault))
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{
			Ext:       xdr.SorobanTransactionDataExt{V: 1, ResourceExt: &xdr.SorobanResourcesExtV0{ArchivedSorobanEntries: []xdr.Uint32{0}}},
			Resources: xdr.SorobanResources{Footprint: xdr.LedgerFootprint{ReadWrite: []xdr.LedgerKey{instance}}},
		})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: fee, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
}

// plainSimulation makes the simulation of every call need no restore, at a resource fee of fee
// stroops.
func (h *harness) plainSimulation(fee int64) {
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: fee, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
}

// later moves the harness's clock past the time a restore_needed refusal is remembered.
func (h *harness) later() {
	h.t.Helper()
	h.mu.Lock()
	h.now = h.now.Add(briefVerdictLifetime)
	h.mu.Unlock()
	h.fake.CloseTime = h.now.Unix()
	if err := h.r.Refresh(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func TestARelayThatNeedsARestoreIsRefusedBeforeAnythingIsSigned(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.r.engine.MaxResourceFee = 50_000_000
	body := fixture(t, "transfer")
	refused := func(what string) {
		t.Helper()
		if code, out := h.post(body); code != http.StatusUnprocessableEntity || out["error"] != CodeRestoreNeeded {
			t.Fatalf("%s: %d %v", what, code, out)
		}
	}

	// About 111 XLM restores the vault's code, instance and tree on mainnet, far above what a relay
	// pays for; a restore under the cap is refused all the same.
	for _, fee := range []int64{1_110_000_000, 800_000} {
		h.needsRestore(fee)
		refused("a restore")
		h.later()
	}
	// So is a simulation that asks for a separate restore first.
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{})
		return protocol.SimulateTransactionResponse{RestorePreamble: &protocol.RestorePreamble{TransactionDataXDR: data, MinResourceFee: 1_080_000_000}}, nil
	}
	refused("a restore preamble")
	// The same proof again within the minute is answered from memory, without a simulation.
	simulated := h.fake.CallCount("simulateTransaction")
	h.plainSimulation(800_000)
	refused("the same proof again")
	if h.fake.CallCount("simulateTransaction") != simulated {
		t.Fatal("a remembered refusal was simulated again")
	}
	if h.sent != 0 {
		t.Fatalf("%d transactions sent", h.sent)
	}

	// The cost-only cap still refuses a call that needs no restore, for its network fee.
	h.plainSimulation(60_000_000)
	if code, out := h.post(fixture(t, "unshield_muxed")); code != http.StatusUnprocessableEntity || out["error"] != CodeNetworkFeeHigh {
		t.Fatalf("a call above the cap: %d %v", code, out)
	}
	// Once someone restored the entries, the same proof is relayed after the minute.
	h.later()
	h.plainSimulation(800_000)
	if code, out := h.post(body); code != http.StatusAccepted {
		t.Fatalf("after the restore: %d %v", code, out)
	}
	h.waitIdle()
}
