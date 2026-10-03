package relayer

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// failedConflict is a relay that failed on the host's storage, as one does that writes an exit the
// queue's tail moved past its footprint: the diagnostics name no contract's error.
func failedConflict() protocol.GetTransactionResponse {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: 900_100, Result: xdr.TransactionResultResult{
		Code: xdr.TransactionResultCodeTxFailed,
		Results: &[]xdr.OperationResult{{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{
			Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionResult: &xdr.InvokeHostFunctionResult{Code: xdr.InvokeHostFunctionResultCodeInvokeHostFunctionTrapped},
		}}},
	}})
	raw, _ := strkey.Decode(strkey.VersionByteContract, vaulttest.Vault)
	id := xdr.ContractId(raw)
	code := xdr.ScErrorCodeScecExceededLimit
	sym := xdr.ScSymbol("error")
	event, _ := xdr.MarshalBase64(xdr.DiagnosticEvent{Event: xdr.ContractEvent{ContractId: &id, Type: xdr.ContractEventTypeDiagnostic,
		Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{
			{Type: xdr.ScValTypeScvSymbol, Sym: &sym},
			{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceStorage, Code: &code}},
		}, Data: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}}}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{
		Status: protocol.TransactionStatusFailed, ResultXDR: r, Ledger: 1001, DiagnosticEventsXDR: []string{event},
	}}
}

func TestAConflictOnTheExitQueueRestsNothingAndNeverPauses(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedConflict())
	var last Request
	var dest, hash string
	for range 3 {
		dest = keypair.MustRandom().Address()
		h.fund(dest)
		last = h.forged(t, dest, -20_000_000, 5_000_000)
		a, f := h.r.Submit(context.Background(), last)
		if f != nil {
			t.Fatalf("not sent: %v", f)
		}
		hash = a.Hash
		h.waitIdle()
	}
	now := h.clock().Unix()
	if h.r.brk.open(h.clock()) || h.r.cool.cooling(now, nullifierKey(last.Proof.Nullifiers[0].Hex()), requestKey(last), destinationKey(dest)) {
		t.Fatal("conflicts paused relaying or rested what the honest request carried")
	}
	if _, st := h.get("/v1/tx/" + hash); st["status"] != "failed" || st["code"] != CodeUnavailable {
		t.Fatalf("status %v", st)
	}
	// The request is taken again, simulated anew.
	h.setTxStatus(success(900_000))
	if _, f := h.r.Submit(context.Background(), last); f != nil {
		t.Fatalf("the same request after a conflict: %v", f)
	}
	h.waitIdle()
}

// queuedAt makes the harness's simulations queue the exit at the tail, as the vault does while
// the queue holds exits or the day's window is full; a tail of 0 pays at once.
func (h *harness) queuedAt(tail uint64, payees ...string) {
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		var fp xdr.LedgerFootprint
		for _, p := range payees {
			fp.ReadOnly = append(fp.ReadOnly, mustKey(vault.AccountKey(p)))
		}
		if tail > 0 {
			fp.ReadWrite = append(fp.ReadWrite, mustKey(vault.ExitKey(vaulttest.Vault, tail)))
		}
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{Resources: xdr.SorobanResources{Footprint: fp, Instructions: 40_000_000}})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 800_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
}

func keyNames(keys []xdr.LedgerKey) map[string]bool {
	out := map[string]bool{}
	for _, k := range keys {
		b, _ := k.MarshalBinary()
		out[string(b)] = true
	}
	return out
}

func TestARelayedExitHasRoomForTheOtherPathOfTheQueue(t *testing.T) {
	for _, tail := range []uint64{9, 0} {
		h := newHarness(t, vault.Status{ExitHead: 5, ExitTail: 5}, func(c *Config) { c.Key = trapdoorKey(t) })
		sent := h.sentEnvelopes()
		dest := keypair.MustRandom().Address()
		h.fund(dest)
		h.queuedAt(tail, dest, feeAddress)
		h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
		parsed, err := txnbuild.TransactionFromXDR((*sent)[0])
		if err != nil {
			t.Fatal(err)
		}
		tx, _ := parsed.Transaction()
		data := tx.ToXDR().V1.Tx.Ext.SorobanData
		written, read := keyNames(data.Resources.Footprint.ReadWrite), keyNames(data.Resources.Footprint.ReadOnly)
		first := tail
		if tail == 0 {
			// Paid at once in the simulation, it may queue at the vault's tail.
			first = 5
		}
		want := []xdr.LedgerKey{mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), mustKey(vault.AccountKey(dest)), mustKey(vault.AccountKey(feeAddress))}
		for id := first; id <= first+4; id++ {
			want = append(want, mustKey(vault.ExitKey(vaulttest.Vault, id)))
		}
		for name := range keyNames(want) {
			if !written[name] || read[name] {
				t.Fatalf("tail %d: an entry of the other path is not written", tail)
			}
		}
		if len(written) != len(want) || data.Resources.Instructions != 40_000_000+vault.SwitchInstructions {
			t.Fatalf("tail %d: %d written entries, %d instructions", tail, len(written), data.Resources.Instructions)
		}
	}
}

func TestTheRelayerQueuesOneExitAtATime(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.queuedAt(9)
	landed := make(chan struct{})
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		<-landed
		return success(900_000), nil
	}
	first, second := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	h.fund(first)
	h.fund(second)
	if _, f := h.r.Submit(context.Background(), h.forged(t, first, -20_000_000, 5_000_000)); f != nil {
		t.Fatalf("first exit: %v", f)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, f := h.r.Submit(context.Background(), h.forged(t, second, -20_000_000, 5_000_000)); f != nil {
			t.Errorf("second exit: %v", f)
		}
	}()
	for h.fake.CallCount("simulateTransaction") < 2 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if h.sends() != 1 {
		t.Fatalf("%d exits queueing at once", h.sends())
	}
	// Once the first lands, the second is simulated again against the tail it left, and sent.
	close(landed)
	<-done
	h.waitIdle()
	if h.sends() != 2 || h.fake.CallCount("simulateTransaction") != 3 {
		t.Fatalf("%d sent after %d simulations", h.sends(), h.fake.CallCount("simulateTransaction"))
	}
}

// failedArchived is a relay whose call touched an archived entry.
func failedArchived() protocol.GetTransactionResponse {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: 900_100, Result: xdr.TransactionResultResult{
		Code: xdr.TransactionResultCodeTxFailed,
		Results: &[]xdr.OperationResult{{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{
			Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionResult: &xdr.InvokeHostFunctionResult{Code: xdr.InvokeHostFunctionResultCodeInvokeHostFunctionEntryArchived},
		}}},
	}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusFailed, ResultXDR: r, Ledger: 1001}}
}

func TestAContractDestinationWhoseBalanceArchivedIsRestedNotTheRelayersFault(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedArchived())
	req := h.lose(t, func() Request { return h.forged(t, vaulttest.Token, -20_000_000, 5_000_000) })
	now := h.clock().Unix()
	if h.r.brk.open(h.clock()) || !h.r.cool.cooling(now, destinationKey(vaulttest.Token)) || !h.r.cool.cooling(now, nullifierKey(req.Proof.Nullifiers[0].Hex())) {
		t.Fatal("a contract destination's archived balance was taken for the relayer's fault")
	}
	if _, f := h.r.Submit(context.Background(), h.forged(t, vaulttest.Token, -20_000_000, 5_000_000)); f == nil || f.code != CodeRejected {
		t.Fatalf("the rested destination again: %v", f)
	}
	// An account's entries never archive: the vault's did, which the keeper keeps alive.
	h = newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedArchived())
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if !h.r.brk.open(h.clock()) {
		t.Fatal("an archived entry of the vault was not the relayer's to answer for")
	}
}

func TestAContractDestinationWhoseBalanceIsAboutToArchiveIsRefused(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	key := mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Token))
	latest := h.fake.Latest
	live := func(until uint32) {
		h.fake.SetContractData(key, vaulttest.Balance(big.NewInt(0), true), 10, &until)
	}
	live(latest + balanceMargin - 1)
	if _, f := h.r.Submit(context.Background(), h.forged(t, vaulttest.Token, -20_000_000, 5_000_000)); f == nil || f.code != CodeRejected {
		t.Fatalf("a balance archiving within the margin: %v", f)
	}
	// Extended by its owner, the same destination is taken.
	live(latest + balanceMargin)
	if _, f := h.r.Submit(context.Background(), h.forged(t, vaulttest.Token, -20_000_000, 5_000_000)); f != nil {
		t.Fatalf("a balance live past the margin: %v", f)
	}
	h.waitIdle()
}
