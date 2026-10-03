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
	// A root the vault keeps never grows fresh again, so the same proof is refused from memory; a
	// proof on a root one insertion younger is taken.
	h.aged(req.Proof.Root, 199)
	if err := h.r.readRoots(ctx); err != nil {
		t.Fatal(err)
	}
	if _, f := h.r.Submit(ctx, req); f == nil || f.code != CodeRejected {
		t.Fatalf("the refused proof again: %v", f)
	}
	if _, f := h.r.Submit(ctx, h.forged(t, dest, -20_000_000, 5_000_000)); f != nil {
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
	// Insertions land while the call is simulated, and take the root to the end of the window.
	simulate := h.fake.Simulate
	h.fake.Simulate = func(r protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		h.aged(req.Proof.Root, 200)
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

func TestTheSameRequestFailingForResourcesIsNotRepeated(t *testing.T) {
	h := trapdoorHarness(t)
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	h.setTxStatus(failedAs(xdr.InvokeHostFunctionResultCodeInvokeHostFunctionResourceLimitExceeded, vaulttest.Vault, 0))
	if _, f := h.r.Submit(ctx, req); f != nil {
		t.Fatalf("not sent: %v", f)
	}
	h.waitIdle()
	for range 2 {
		if _, f := h.r.Submit(ctx, req); f == nil || f.code != CodeRejected {
			t.Fatalf("the same request sent again: %v", f)
		}
	}
	if code, health := h.get("/v1/health"); code != http.StatusOK || health["paused"] != false {
		t.Fatalf("one request repeated: %d %v", code, health)
	}
}

// simulatedAt makes the harness's simulations read the chain at a ledger.
func (h *harness) simulatedAt(ledger uint32) {
	simulate := h.fake.Simulate
	h.fake.Simulate = func(r protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		resp, err := simulate(r)
		resp.LatestLedger = ledger
		return resp, err
	}
}

func TestAnAccountGrownAfterTheSimulationIsARaceItsOwnerRestsFor(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.simulatedAt(1000)
	h.setTxStatus(failedAs(xdr.InvokeHostFunctionResultCodeInvokeHostFunctionResourceLimitExceeded, vaulttest.Vault, 0))
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	// The destination adds signers to its account in the ledger after the simulation.
	send := h.fake.Send
	h.fake.Send = func(r protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		key := mustKey(vault.AccountKey(dest))
		h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, Balance: 10_000_000}}, 1001, nil)
		return send(r)
	}
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if h.r.brk.open(h.clock()) || !h.r.cool.cooling(h.clock().Unix(), destinationKey(dest)) {
		t.Fatal("a destination that grew paused relaying instead of resting")
	}

	// The fee address changing is a race too, which rests no destination.
	h = newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.simulatedAt(1000)
	h.setTxStatus(failedAs(xdr.InvokeHostFunctionResultCodeInvokeHostFunctionResourceLimitExceeded, vaulttest.Vault, 0))
	h.fake.SetEntry(mustKey(vault.AccountKey(feeAddress)), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{
		AccountId: mustKey(vault.AccountKey(feeAddress)).MustAccount().AccountId, Balance: 10_000_000}}, 1002, nil)
	dest = keypair.MustRandom().Address()
	h.fund(dest)
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if h.r.brk.open(h.clock()) || h.r.cool.cooling(h.clock().Unix(), destinationKey(dest)) {
		t.Fatal("a fee address that changed was taken for the relayer's fault or the destination's")
	}

	// Nothing changed after the simulation, which saw the destination's last change: the
	// simulation fell short on its own, which is the relayer's to answer for.
	h = newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.simulatedAt(1000)
	h.setTxStatus(failedAs(xdr.InvokeHostFunctionResultCodeInvokeHostFunctionResourceLimitExceeded, vaulttest.Vault, 0))
	dest = keypair.MustRandom().Address()
	h.fund(dest)
	key := mustKey(vault.AccountKey(dest))
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, Balance: 10_000_000}}, 1000, nil)
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	if !h.r.brk.open(h.clock()) {
		t.Fatal("a resource shortfall of the relayer's own did not count")
	}
}

func TestAFailureWithoutDiagnosticsIsARaceThatRestsEverythingItNamed(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t); c.BreakerFailures = 1 })
	h.setTxStatus(failedOnChain())
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	req := h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	now := h.clock().Unix()
	if h.r.brk.open(h.clock()) || !h.r.cool.cooling(now, destinationKey(dest)) || !h.r.cool.cooling(now, nullifierKey(req.Proof.Nullifiers[0].Hex())) {
		t.Fatal("a failure that cannot be told was not a race resting its notes and destination")
	}
	if !h.r.alerts.Open("rpc_no_diagnostics") {
		t.Fatal("no warning that the RPC gives no diagnostics")
	}
}

func TestTheRPCIsCheckedForDiagnosticEvents(t *testing.T) {
	h := newHarness(t, vault.Status{})
	ctx := context.Background()
	event, err := xdr.MarshalBase64(xdr.DiagnosticEvent{Event: xdr.ContractEvent{Type: xdr.ContractEventTypeDiagnostic,
		Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Data: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}}}})
	if err != nil {
		t.Fatal(err)
	}
	var asked protocol.SimulateTransactionRequest
	h.fake.Simulate = func(r protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		asked = r
		return protocol.SimulateTransactionResponse{Error: "HostError: Error(WasmVm, MissingValue)", EventsXDR: []string{event}}, nil
	}
	if ok, err := h.r.CheckDiagnostics(ctx); err != nil || !ok || h.r.alerts.Open("rpc_no_diagnostics") {
		t.Fatalf("an RPC with diagnostics: %v %v", ok, err)
	}
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(asked.Transaction, &env); err != nil || env.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.HostFunction.InvokeContract.FunctionName != "no_such_function" {
		t.Fatalf("simulated %v", err)
	}
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		return protocol.SimulateTransactionResponse{Error: "HostError: Error(WasmVm, MissingValue)"}, nil
	}
	if ok, err := h.r.CheckDiagnostics(ctx); err != nil || ok || !h.r.alerts.Open("rpc_no_diagnostics") {
		t.Fatalf("an RPC without diagnostics: %v %v", ok, err)
	}
}

// reforged proves the request again after its public inputs changed.
func (h *harness) reforged(req Request) Request {
	p := req.Proof
	p.A, p.B, p.C = forge([8]fr.Element{p.Root, p.PublicAmount, p.ExtDataHash, h.domain, p.Nullifiers[0], p.Nullifiers[1], p.Commitments[0], p.Commitments[1]})
	req.Proof = p
	return req
}

func TestReplaysOfAProofOnAnUnknownRootShareOneReadOfTheRootHistory(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	ctx := context.Background()
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	req.Proof.Root = fr.SetUint64(12345)
	req = h.reforged(req)
	before := h.fake.CallCount("getLedgerEntries")
	for range 100 {
		if _, f := h.r.Submit(ctx, req); f == nil || f.code != CodeRejected {
			t.Fatalf("a proof on an unknown root: %v", f)
		}
	}
	if reads := h.fake.CallCount("getLedgerEntries") - before; reads > 1 {
		t.Fatalf("%d reads of the root history in one ledger", reads)
	}
	// The root comes in the next ledger: its refusal was not kept.
	h.aged(req.Proof.Root, 0)
	h.setLatest(h.fake.Latest+1, true)
	if _, f := h.r.Submit(ctx, req); f != nil {
		t.Fatalf("a root the next ledger brought: %v", f)
	}
	h.waitIdle()
}
