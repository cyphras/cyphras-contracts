package keeper

import (
	"context"
	"fmt"
	"testing"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// conflictOnChain is a call that failed on the host's storage: the exit queue moved under it past
// the room its footprint was given.
func conflictOnChain() protocol.GetTransactionResponse {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{Result: xdr.TransactionResultResult{
		Code: xdr.TransactionResultCodeTxFailed,
		Results: &[]xdr.OperationResult{{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{
			Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionResult: &xdr.InvokeHostFunctionResult{Code: xdr.InvokeHostFunctionResultCodeInvokeHostFunctionTrapped},
		}}},
	}})
	code := xdr.ScErrorCodeScecExceededLimit
	sym := xdr.ScSymbol("error")
	event, _ := xdr.MarshalBase64(xdr.DiagnosticEvent{Event: xdr.ContractEvent{Type: xdr.ContractEventTypeDiagnostic,
		Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{
			{Type: xdr.ScValTypeScvSymbol, Sym: &sym},
			{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceStorage, Code: &code}},
		}, Data: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}}}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{
		Status: protocol.TransactionStatusFailed, ResultXDR: r, DiagnosticEventsXDR: []string{event},
	}}
}

func written(fp xdr.LedgerFootprint) map[string]bool {
	out := map[string]bool{}
	for _, k := range fp.ReadWrite {
		b, _ := k.MarshalBinary()
		out[string(b)] = true
	}
	return out
}

func TestAClaimHasRoomForExitsQueuedAheadOfIt(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.chain.Attest(1)
	h.chain.Admit(1)
	h.strand(1, 400, vaulttest.Depositor)
	h.status.ExitHead, h.status.ExitTail = 2, 2
	h.sync()
	// The simulated claim queues the exit at the tail.
	simulate := h.fake.Simulate
	h.fake.Simulate = func(req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		resp, err := simulate(req)
		var data xdr.SorobanTransactionData
		_ = xdr.SafeUnmarshalBase64(resp.TransactionDataXDR, &data)
		data.Resources.Footprint.ReadWrite = append(data.Resources.Footprint.ReadWrite, mustKey(vault.ExitKey(vaulttest.Vault, 2)))
		resp.TransactionDataXDR, _ = xdr.MarshalBase64(data)
		return resp, err
	}
	conflicts := 1
	h.conflict = func(d string) bool {
		if d != "claim 1" || conflicts == 0 {
			return false
		}
		conflicts--
		return true
	}
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A conflict is simulated and sent again, and pages nothing.
	if got := h.take(); !equal(got, []string{"claim 1", "claim 1"}) || h.has("call_failed") || h.has("claim_failed") {
		t.Fatalf("sent %v, pages %+v", got, h.pages)
	}
	for _, fp := range h.footprints {
		keys := written(fp)
		for id := uint64(2); id <= 6; id++ {
			b, _ := mustKey(vault.ExitKey(vaulttest.Vault, id)).MarshalBinary()
			if !keys[string(b)] {
				t.Fatalf("exit %d is not in the claim's footprint", id)
			}
		}
	}
}

func TestAReleaseHasRoomForReleasesAheadOfIt(t *testing.T) {
	h := newHarness(t)
	h.limit = 1000
	h.status.ExitHead, h.status.ExitTail = 1, 1
	h.queueExits(300, 250, 500)
	h.sync()
	h.sentHook = func(d string) {
		var n uint64
		if _, err := fmt.Sscanf(d, "release %d", &n); err == nil {
			h.release(n)
		}
	}
	if err := h.k.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"release 2"}) {
		t.Fatalf("releases %v", got)
	}
	keys := written(h.footprints[0])
	var want []xdr.LedgerKey
	for id := uint64(1); id <= 3; id++ {
		want = append(want, mustKey(vault.StrandedKey(vaulttest.Vault, id)))
	}
	// The exit after the two, which a release paying one from the head first leaves it, and its
	// payee: the exits pay the depositor and no fee.
	want = append(want, mustKey(vault.ExitKey(vaulttest.Vault, 3)), mustKey(vault.AccountKey(vaulttest.Depositor)))
	for _, k := range want {
		b, _ := k.MarshalBinary()
		if !keys[string(b)] {
			t.Fatalf("%d written entries lack one of the release's room", len(keys))
		}
	}
	if len(keys) != len(want) {
		t.Fatalf("%d written entries, want %d", len(keys), len(want))
	}
}
