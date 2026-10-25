package relayer

import (
	"context"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// queuedExitHarness relays exits that queue, so each one's footprint holds the vault's balance in
// the asset contract, live until liveUntil, which the simulation does not mark.
func queuedExitHarness(t *testing.T, liveUntil uint32) (*harness, string) {
	t.Helper()
	h := newHarness(t, vault.Status{ExitHead: 5, ExitTail: 9}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.setVaultBalanceLife(liveUntil)
	dest := keypair.MustRandom().Address()
	h.fund(dest)
	h.queuedAt(9, dest, feeAddress)
	return h, dest
}

func (h *harness) setVaultBalanceLife(liveUntil uint32) {
	h.fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vaulttest.Balance(big.NewInt(1_000_000_000_000), true), 10, &liveUntil)
}

// The vault's balance is live in the latest ledger and archived in the next: no ledger is left in
// which the relay could land, so it needs a restore like an entry archived already.
func TestARelayWhoseEntryLapsesAtTheNextLedgerNeedsARestore(t *testing.T) {
	h, dest := queuedExitHarness(t, 1000)
	if h.fake.LatestLedger() != 1000 {
		t.Fatalf("latest %d", h.fake.LatestLedger())
	}
	_, f := h.r.Submit(context.Background(), h.forged(t, dest, -20_000_000, 5_000_000))
	h.waitIdle()
	if f == nil || f.code != CodeRestoreNeeded {
		t.Fatalf("an entry live only in the latest ledger: %v, %d sent", f, h.sends())
	}
	if h.sends() != 0 {
		t.Fatalf("%d transactions sent", h.sends())
	}
}

// A relay whose footprint holds an entry that lapses a few ledgers on is bounded to the ledgers
// it is live in. Not included by then, it expires for free: nothing rests, nothing pauses, and the
// same proof, once the entry archived, is answered restore_needed.
func TestARelayWhoseEntryLapsesInFlightExpiresForFree(t *testing.T) {
	latest := uint32(1000)
	near := latest + 3
	h, dest := queuedExitHarness(t, near)
	sent := h.sentEnvelopes()
	h.setTxStatus(protocol.GetTransactionResponse{LatestLedger: near + 1, LatestLedgerCloseTime: h.now.Unix(),
		TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}})
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	acc, f := h.r.Submit(context.Background(), req)
	if f != nil {
		t.Fatalf("not sent: %v", f)
	}
	h.waitIdle()
	parsed, err := txnbuild.TransactionFromXDR((*sent)[0])
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := parsed.Transaction()
	if bounds := tx.ToXDR().V1.Tx.Cond.V2.LedgerBounds; bounds == nil || uint32(bounds.MaxLedger) != near+1 {
		t.Fatalf("ledger bound %+v, the entry is live until %d", bounds, near)
	}
	if _, st := h.get("/v1/tx/" + acc.Hash); st["status"] != "failed" || st["code"] != CodeUnavailable {
		t.Fatalf("status %v", st)
	}
	now := h.clock()
	if h.r.brk.open(now) || h.r.races.open(now) {
		t.Fatal("an expired relay paused or guarded relaying")
	}
	if h.r.cool.cooling(now.Unix(), requestKey(req), nullifierKey(req.Proof.Nullifiers[0].Hex()), destinationKey(dest)) {
		t.Fatal("an expired relay rested what it carried")
	}
	h.setVaultBalanceLife(latest - 1)
	if _, f := h.r.Submit(context.Background(), req); f == nil || f.code != CodeRestoreNeeded {
		t.Fatalf("the same proof once the entry archived: %v", f)
	}
	if len(*sent) != 1 {
		t.Fatalf("%d transactions sent", len(*sent))
	}
}

// When the footprint's entries cannot be read, the relay is answered unavailable, nothing is
// signed, the channels and the exit slot are freed, and the same proof goes once the RPC answers.
func TestARelayWhoseFootprintCannotBeReadIsUnavailableAndNotRemembered(t *testing.T) {
	h, dest := queuedExitHarness(t, 1000+100_000)
	// The network's settings are read once, by a relay that goes through.
	h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
	before := h.sends()
	simulate := h.fake.Simulate
	h.fake.Simulate = func(req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		h.fake.Fail["getLedgerEntries"] = errors.New("rpc down")
		return simulate(req)
	}
	req := h.forged(t, dest, -20_000_000, 5_000_000)
	_, f := h.r.Submit(context.Background(), req)
	if f == nil || f.code != CodeUnavailable || f.status != http.StatusServiceUnavailable {
		t.Fatalf("a footprint that cannot be read: %v", f)
	}
	h.waitIdle()
	if h.sends() != before {
		t.Fatalf("%d transactions sent", h.sends()-before)
	}
	select {
	case <-h.r.exitSlot:
		h.r.exitSlot <- struct{}{}
	default:
		t.Fatal("the exit slot was kept")
	}
	h.fake.Simulate = simulate
	delete(h.fake.Fail, "getLedgerEntries")
	if _, f := h.r.Submit(context.Background(), req); f != nil {
		t.Fatalf("the same proof once the RPC answers: %v", f)
	}
	h.waitIdle()
}

// A restore_needed answer is remembered for the proof that got it only: another request is
// simulated and relayed within the minute.
func TestARememberedRestoreRefusalHoldsBackNoOtherRequest(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.needsRestore(800_000)
	first := h.forged(t, feeAddress, 0, 5_000_000)
	if _, f := h.r.Submit(context.Background(), first); f == nil || f.code != CodeRestoreNeeded {
		t.Fatalf("first: %v", f)
	}
	h.plainSimulation(800_000)
	other := h.forged(t, feeAddress, 0, 5_000_000)
	if _, f := h.r.Submit(context.Background(), other); f != nil {
		t.Fatalf("another request within the minute: %v", f)
	}
	h.waitIdle()
	if _, f := h.r.Submit(context.Background(), first); f == nil || f.code != CodeRestoreNeeded {
		t.Fatalf("the first proof within the minute: %v", f)
	}
	h.later()
	if _, f := h.r.Submit(context.Background(), first); f != nil {
		t.Fatalf("the first proof after the minute: %v", f)
	}
	h.waitIdle()
}

// Concurrent refusals are each remembered, and the memory never holds more than maxVerdicts.
func TestRestoreRefusalsAreRememberedConcurrentlyWithinTheirBound(t *testing.T) {
	h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
	h.needsRestore(800_000)
	if h.r.brief.ttl != time.Minute || h.r.brief.max != maxVerdicts {
		t.Fatalf("remembered for %s, at most %d", h.r.brief.ttl, h.r.brief.max)
	}
	reqs := make([]Request, 16)
	for i := range reqs {
		reqs[i] = h.forged(t, feeAddress, 0, 5_000_000)
	}
	var wg sync.WaitGroup
	codes := make([]string, len(reqs))
	for i, req := range reqs {
		wg.Go(func() {
			if _, f := h.r.Submit(context.Background(), req); f != nil {
				codes[i] = f.code
			}
		})
	}
	wg.Wait()
	h.waitIdle()
	for i, req := range reqs {
		// Two channels serve sixteen requests; a request that waited too long is unavailable.
		if codes[i] != CodeRestoreNeeded && codes[i] != CodeUnavailable {
			t.Fatalf("request %d: %q", i, codes[i])
		}
		if remembered := h.r.brief.recall(statementKey(req), h.clock()) != nil; remembered != (codes[i] == CodeRestoreNeeded) {
			t.Fatalf("request %d answered %q, remembered %v", i, codes[i], remembered)
		}
	}
	if h.sends() != 0 {
		t.Fatalf("%d transactions sent", h.sends())
	}

	v := verdicts{ttl: briefVerdictLifetime, max: maxVerdicts}
	now := h.clock()
	var first [32]byte
	for i := range maxVerdicts + 5 {
		var k [32]byte
		k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16)
		if i == 0 {
			first = k
		}
		v.remember(k, *fail(http.StatusUnprocessableEntity, CodeRestoreNeeded), now)
	}
	if len(v.by) != maxVerdicts || len(v.order) != maxVerdicts || v.recall(first, now) != nil {
		t.Fatalf("%d remembered, %d in order, the oldest kept: %v", len(v.by), len(v.order), v.recall(first, now) != nil)
	}
}
