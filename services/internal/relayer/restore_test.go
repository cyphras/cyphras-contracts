package relayer

import (
	"context"
	"net/http"
	"testing"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

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
	h.now = h.now.Add(restoreVerdictLifetime)
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

	// The cost-only cap still refuses a call that needs no restore.
	h.plainSimulation(60_000_000)
	if code, out := h.post(fixture(t, "unshield_muxed")); code != http.StatusUnprocessableEntity || out["error"] != CodeRejected {
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
