package indexer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// ready ingests what the chain published and checks the indexer is ready.
func (h *harness) ready() {
	h.t.Helper()
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	if hl := h.ix.Health(); !hl.Ready {
		h.t.Fatalf("not ready: %+v", hl)
	}
}

func TestAChainThatHeldFewerLeavesAtTheIndexersLedgerIsAMismatch(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.ready()
	// Read at or after the indexer's ledger, the chain says it has held only the first pair since
	// ledger 10: the indexer holds leaves the chain never had.
	leaves := h.leafValues()
	var tr tree.Tree
	if _, err := tr.AppendPair(leaves[0], leaves[1]); err != nil {
		t.Fatal(err)
	}
	h.fake.SetContractData(mustKey(vault.NextLeafKey(vaulttest.Vault)), vault.U64(tr.Len()), 10, nil)
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.RootRing(tr.Root(), 1), 10, nil)
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hl := h.ix.Health(); hl.Code != CodeMismatch {
		t.Fatalf("health %+v", hl)
	}
}

func TestAStatusTheChainDisagreesWithIsAMismatch(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.ready()
	status, modified := h.replayStatus()
	status.AttestedUpTo++
	h.setInstance(status, modified)
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if hl := h.ix.Health(); hl.Code != CodeMismatch {
		t.Fatalf("health %+v", hl)
	}
	if len(h.pages.alerts) == 0 || !strings.Contains(h.pages.alerts[0].Message, "attested_up_to") {
		t.Fatalf("alerts %+v", h.pages.alerts)
	}
}

func TestOnlyPagesTheChainVouchedForAreImmutable(t *testing.T) {
	h := newHarness(t)
	h.chain.Transact(0, 0, vaulttest.Relayer)
	h.chain.NextLedger(5)
	h.ready()
	// 511 more pairs fill page 0, but the chain's entries cannot be read to vouch for them; the
	// indexer stays ready on its earlier full match.
	h.chain.NextLedger(5)
	for range 511 {
		h.chain.Transact(0, 0, vaulttest.Relayer)
	}
	h.chain.NextLedger(5)
	h.fake.Fail["getLedgerEntries"] = errors.New("down")
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	leaves := func() (int, string, bool) {
		rec := httptest.NewRecorder()
		h.ix.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/leaves?page=0", nil))
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, rec.Header().Get("Cache-Control"), body["complete"] == true
	}
	if code, cache, complete := leaves(); code != http.StatusOK || !complete || strings.Contains(cache, "immutable") {
		t.Fatalf("a page the chain has not vouched for: %d %q complete %v", code, cache, complete)
	}
	delete(h.fake.Fail, "getLedgerEntries")
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, cache, _ := leaves(); code != http.StatusOK || !strings.Contains(cache, "immutable") {
		t.Fatalf("a page the chain vouched for: %d %q", code, cache)
	}
}

func TestAMismatchStaysLatchedWhenItsFirstWriteFails(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.ready()
	ctx := context.Background()
	if _, err := h.store.Pool.Exec(ctx, `ALTER TABLE indexer_meta RENAME TO indexer_meta_x`); err != nil {
		t.Fatal(err)
	}
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.RootRing(fr.SetUint64(1), 4), h.chain.Ledger, nil)
	if err := h.ix.Reconcile(ctx); err == nil || h.ix.Health().Code != CodeMismatch {
		t.Fatalf("the failed write: %v, %+v", err, h.ix.Health())
	}
	if _, err := h.store.Pool.Exec(ctx, `ALTER TABLE indexer_meta_x RENAME TO indexer_meta`); err != nil {
		t.Fatal(err)
	}
	// The chain agrees again, and the next round still writes the mismatch, so a restart keeps it.
	h.publish()
	if err := h.ix.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.drain()
	h.ix.Probe(ctx)
	if err := h.ix.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if hl := h.ix.Health(); hl.Code != CodeMismatch {
		t.Fatalf("after a restart: %+v", hl)
	}
}

func TestAFaultedWindowIsArchivedAgainOnceApplied(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.chain.Tx().Emit("attested", vault.Field{Name: "up_to", Value: vault.U64(999)})
	h.chain.NextLedger(5)
	h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.publish()
	h.drain()
	if h.ix.Health().Code != CodeFault {
		t.Fatalf("no fault: %+v", h.ix.Health())
	}
	// The RPC answers again without the event it made up.
	bogus := func(e vault.RawEvent) bool {
		ev, err := vault.Decode(e)
		a, ok := ev.Body.(vault.Attested)
		return err == nil && ok && a.UpTo == 999
	}
	var good []vault.RawEvent
	for _, e := range h.chain.Events {
		if !bogus(e) {
			good = append(good, e)
		}
	}
	h.chain.Events = good
	h.ready()
	got, err := archive.Reader{Dir: h.cfg.ArchiveDir, Vault: vaulttest.Vault}.Events(context.Background(), 10, h.chain.Ledger)
	if err != nil || len(got) != len(good) {
		t.Fatalf("archive holds %d of %d events: %v", len(got), len(good), err)
	}
	for _, e := range got {
		if bogus(e) {
			t.Fatal("the archive kept the faulted copy")
		}
	}
	// Rebuilt after RPC dropped the history, from the archive alone.
	if err := Rebuild(context.Background(), h.store); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.fake.Oldest = h.chain.Ledger
	h.f = &follow.Follower{RPC: h.fake, Live: follow.RPCSource{Client: h.fake, Contract: vaulttest.Vault, PageLimit: 10},
		History: []follow.Source{archive.Reader{Dir: h.cfg.ArchiveDir, Vault: vaulttest.Vault}}, Window: 5, Sink: h.ix}
	h.drain()
	h.ix.Probe(context.Background())
	if hl := h.ix.Health(); !hl.Ready || hl.LeafCount != 8 {
		t.Fatalf("after a rebuild from the archive: %+v", hl)
	}
}

func TestDepositFlagsAreCutAtCompleteTo(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.ready()
	// A window that flags deposit 4 lands in the database before the indexer moves its cursor.
	next := h.ix.state.Clone()
	d, err := next.Apply([]vault.Tx{{Ledger: h.chain.Ledger + 1, ClosedAt: h.chain.ClosedAt + 5, Hash: "late",
		Calls: []any{vault.DepositFlagged{ID: 4, Reason: 7}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.Commit(context.Background(), h.chain.Ledger+1, h.chain.Ledger+1, next, d, nil); err != nil {
		t.Fatal(err)
	}
	_, body := h.get("/v1/deposits")
	found := false
	for _, p := range body["pending"].([]any) {
		m := p.(map[string]any)
		if m["id"].(float64) == 4 {
			found = true
			if m["flag_reason"] != nil {
				t.Fatalf("a flag past complete_to %v was served: %v", body["complete_to"], m)
			}
		}
	}
	if !found {
		t.Fatalf("deposit 4 is missing: %v", body)
	}
}

func TestTheNullifierScanStartsAtTheLedgerAskedFor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.store.Pool.Exec(ctx, `INSERT INTO nullifiers (seq, nullifier, ledger, tx_hash)
		SELECT g, sha256(int8send(g)), 1000 + g/2, 'h' FROM generate_series(0, 199999) g`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Pool.Exec(ctx, `ANALYZE nullifiers`); err != nil {
		t.Fatal(err)
	}
	for _, since := range []int64{0, 50_000, 90_000, 100_999, 200_000} {
		var plan []map[string]any
		if err := h.store.Pool.QueryRow(ctx, `EXPLAIN (ANALYZE, FORMAT JSON) `+nullifiersQuery, since, int64(200_000), int64(0), MaxNullifiers+1).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		if removed := sumPlan(plan[0]["Plan"].(map[string]any), "Rows Removed by Filter"); removed > 1000 {
			t.Fatalf("since ledger %d the scan read past %v rows", since, removed)
		}
	}
	db := store{h.store.Pool}
	if got, next, err := db.nullifiers(ctx, 100_000, 200_000, 0); err != nil || len(got) != 2000 || next != "" || got[0].Ledger != 100_000 {
		t.Fatalf("since ledger 100000: %d, %q, %v", len(got), next, err)
	}
	if got, _, err := db.nullifiers(ctx, 200_000, 300_000, 0); err != nil || len(got) != 0 {
		t.Fatalf("past the last ledger: %d, %v", len(got), err)
	}
}

// sumPlan adds up a numeric field over a plan node and every node under it.
func sumPlan(node map[string]any, field string) float64 {
	total, _ := node[field].(float64)
	if children, ok := node["Plans"].([]any); ok {
		for _, c := range children {
			total += sumPlan(c.(map[string]any), field)
		}
	}
	return total
}

// lyingSource answers any range with no events and no error.
type lyingSource struct{}

func (lyingSource) Events(context.Context, uint32, uint32) ([]vault.RawEvent, error) { return nil, nil }

func TestAnRPCWhoseOldestLedgerIsPastItsLatestIsRefused(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.ready()
	archivedTo := h.ix.archivedTo
	h.fake.SetLatest(archivedTo + 2)
	h.fake.Oldest = h.fake.Latest + 3
	done := make(chan error, 1)
	go func() {
		_, err := h.ix.ArchiveStep(context.Background(), lyingSource{})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an inverted RPC range was archived")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the archive copy never returned")
	}
	if _, err := h.f.Step(context.Background()); !errors.Is(err, follow.ErrRange) {
		t.Fatalf("ingest from an inverted RPC: %v", err)
	}
	if _, err := (archive.Reader{Dir: h.cfg.ArchiveDir, Vault: vaulttest.Vault}).Events(context.Background(), 10, h.chain.Ledger); err != nil {
		t.Fatalf("the archive was damaged: %v", err)
	}
	if err := h.ix.keep(nil, 20, 19); !errors.Is(err, archive.ErrRange) {
		t.Fatalf("an inverted window was kept: %v", err)
	}
	if got := digests(nil, 4_294_967_294, 4_294_967_295); len(got) != 2 {
		t.Fatalf("digests at the end of the ledger range: %d", len(got))
	}
}
