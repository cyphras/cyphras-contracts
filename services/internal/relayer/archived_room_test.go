package relayer

import (
	"context"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// An exit that queues in its simulation is given the entries of the path that pays at once,
// the vault's balance in the asset contract first. When that balance is archived, the network
// fails the call with ENTRY_ARCHIVED whichever path it takes, at the channel's cost, so the
// relayer refuses it as a restore before anything is signed.
func TestARelayWhoseExtraRoomNamesAnArchivedEntryIsRefusedBeforeItIsSigned(t *testing.T) {
	h := newHarness(t, vault.Status{ExitHead: 5, ExitTail: 9}, func(c *Config) { c.Key = trapdoorKey(t) })
	archived := h.fake.LatestLedger() - 1
	h.fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vaulttest.Balance(big.NewInt(1_000_000_000_000), true), 10, &archived)
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	// The simulation queues the exit and so marks nothing archived.
	h.queuedAt(9, dest, feeAddress)

	_, f := h.r.Submit(context.Background(), h.forged(t, dest, -20_000_000, 5_000_000))
	h.waitIdle()
	if f == nil || f.code != CodeRestoreNeeded || f.status != http.StatusUnprocessableEntity {
		t.Fatalf("a relay whose room names an archived entry: %v, %d sent", f, h.sends())
	}
	if h.sends() != 0 {
		t.Fatalf("%d transactions sent", h.sends())
	}
}

// A normal call whose simulation carries the extension of protocol 23 with no archived entry is
// relayed as before.
func TestACallWithAnEmptyArchivedListIsRelayed(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{
			Ext: xdr.SorobanTransactionDataExt{V: 1, ResourceExt: &xdr.SorobanResourcesExtV0{ArchivedSorobanEntries: []xdr.Uint32{}}},
		})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 800_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	if code, out := h.post(fixture(t, "transfer")); code != http.StatusAccepted {
		t.Fatalf("a call that restores nothing: %d %v", code, out)
	}
	h.waitIdle()
}

// A held request that needs a restore when it is due is reported failed with restore_needed by
// its ID, rests nothing, and frees its notes, so the same proof goes once the entries are restored.
func TestAHeldRequestThatNeedsARestoreIsReportedByItsID(t *testing.T) {
	h := newHarness(t, vault.Status{})
	h.needsRestore(1_110_000_000)
	body := fixture(t, "transfer")
	body["not_before"] = h.now.Unix() + 2
	code, out := h.post(body)
	id, _ := out["id"].(string)
	if code != http.StatusAccepted || out["held"] != true {
		t.Fatalf("held request: %d %v", code, out)
	}
	h.mu.Lock()
	h.now = h.now.Add(2 * time.Second)
	h.mu.Unlock()
	var st map[string]any
	for range 1000 {
		_, st = h.get("/v1/held/" + id)
		if st["status"] != "held" {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if st["status"] != "failed" || st["code"] != CodeRestoreNeeded || st["hash"] != nil || h.sends() != 0 {
		t.Fatalf("held status %v, %d sent", st, h.sends())
	}
	if h.r.brk.open(h.clock()) || h.r.races.open(h.clock()) {
		t.Fatal("a refused restore counted as a failure on chain")
	}
	h.plainSimulation(800_000)
	delete(body, "not_before")
	if code, out := h.post(body); code != http.StatusAccepted {
		t.Fatalf("after the restore: %d %v", code, out)
	}
	h.waitIdle()
}
