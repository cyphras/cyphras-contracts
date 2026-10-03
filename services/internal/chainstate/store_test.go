package chainstate

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const testVault = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"

func openStore(t *testing.T) *Store {
	t.Helper()
	pool, err := Open(context.Background(), testdb.URL(t), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return &Store{Pool: pool, KeepLeaves: true}
}

func TestTheFixtureFlowSurvivesAStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, cursor, err := st.Load(ctx, testVault, 1000)
	if err != nil || cursor != 999 {
		t.Fatalf("fresh load: cursor %d, %v", cursor, err)
	}
	txs, roots := replay(t)
	// Commit the flow in two windows, reloading from the database in between.
	split := 3
	for i, window := range [][]vault.Tx{txs[:split], txs[split:]} {
		next := s.Clone()
		d, err := next.Apply(window)
		if err != nil {
			t.Fatal(err)
		}
		from, to := cursor+1, window[len(window)-1].Ledger
		if err := st.Commit(ctx, from, to, next, d, nil); err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
		s, cursor, err = st.Load(ctx, testVault, 1000)
		if err != nil || cursor != to {
			t.Fatalf("reload: cursor %d, %v", cursor, err)
		}
	}
	if s.Tree.Root() != field(t, roots["zero_value"]) || s.Tvl.Int64() != 90_000_000 || s.NullifierCount != 12 {
		t.Fatalf("reloaded state differs: root %s tvl %v", s.Tree.Root().Hex(), s.Tvl)
	}
	var leaves, nullifiers, admitted int
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM leaves`).Scan(&leaves)
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM nullifiers`).Scan(&nullifiers)
	_ = st.Pool.QueryRow(ctx, `SELECT count(*) FROM deposits WHERE outcome = 'admitted' AND leaf_index1 IS NOT NULL`).Scan(&admitted)
	if leaves != 12 || nullifiers != 12 || admitted != 2 {
		t.Fatalf("stored %d leaves, %d nullifiers, %d admitted", leaves, nullifiers, admitted)
	}
	if _, _, err := st.Load(ctx, "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U", 1000); !errors.Is(err, ErrOtherVault) {
		t.Fatalf("load for another vault: %v", err)
	}
}

func TestARepeatedNullifierAcrossWindowsIsCaughtByTheStore(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, _, err := st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	first := []vault.Tx{{Ledger: 10, ClosedAt: 1, Hash: "a", Calls: []any{shield(1, 5, 100)}}}
	d, err := s.Apply(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 10, 10, s, d, nil); err != nil {
		t.Fatal(err)
	}
	next := s.Clone()
	d, err = next.Apply([]vault.Tx{{Ledger: 11, ClosedAt: 2, Hash: "b", Calls: []any{shield(2, 6, 100)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 11, 11, next, d, nil); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("repeated nullifier: %v", err)
	}
	// Nothing of the failed window was kept.
	_, cursor, err := st.Load(ctx, testVault, 10)
	if err != nil || cursor != 10 {
		t.Fatalf("cursor %d after a refused window: %v", cursor, err)
	}
	if err := st.Commit(ctx, 13, 13, next, Delta{}, nil); !errors.Is(err, ErrMoved) {
		t.Fatalf("commit that skips ledgers: %v", err)
	}
}

func TestQueuedExitsReload(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, _, err := st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.Apply([]vault.Tx{{Ledger: 10, ClosedAt: 1_728_000_000, Hash: "a", Calls: []any{
		shield(1, 1, 1000), vault.Attested{UpTo: 1}, admission(1, 0), queued(10, 2, 1, -300, 5), queued(20, 4, 2, -100, 0),
		vault.ExitPaid{ID: 1, PayoutPaid: big.NewInt(50), FeePaid: new(big.Int), PayoutLeft: big.NewInt(250), FeeLeft: big.NewInt(5)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 10, 10, s, d, nil); err != nil {
		t.Fatal(err)
	}
	// The part payment survives a reload.
	reloaded, _, err := st.Load(ctx, testVault, 10)
	if err != nil || reloaded.Exits[1].Payout.Int64() != 250 || reloaded.QueuedTotal.Int64() != 355 {
		t.Fatalf("part paid exit reloaded as %+v, %v", reloaded.Exits[1], err)
	}
	next := s.Clone()
	d, err = next.Apply([]vault.Tx{{Ledger: 11, ClosedAt: 1_728_000_005, Hash: "b", Calls: []any{release(1, -250, 5)}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 11, 11, next, d, nil); err != nil {
		t.Fatal(err)
	}
	got, _, err := st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Exits) != 1 || got.Exits[2] == nil || got.Exits[2].Payout.Int64() != 100 || got.ExitHead != 2 || got.ExitTail != 3 || got.QueuedTotal.Int64() != 100 {
		t.Fatalf("exits reloaded as %+v, head %d tail %d", got.Exits, got.ExitHead, got.ExitTail)
	}
	var releasedAt int64
	_ = st.Pool.QueryRow(ctx, `SELECT released_at FROM exits WHERE id = 1`).Scan(&releasedAt)
	if releasedAt != 1_728_000_005 {
		t.Fatalf("release time %d", releasedAt)
	}
	// Exit 2 is stranded, survives a reload as a stranded exit, and is claimed.
	next = got.Clone()
	d, err = next.Apply([]vault.Tx{{Ledger: 12, ClosedAt: 1_728_000_010, Hash: "c", Calls: []any{vault.ExitStranded{ID: 2, Payout: big.NewInt(100), Fee: new(big.Int)}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 12, 12, next, d, nil); err != nil {
		t.Fatal(err)
	}
	got, _, err = st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Exits) != 0 || got.Stranded[2] == nil || got.Stranded[2].Payout.Int64() != 100 || got.ExitHead != 3 || got.QueuedTotal.Int64() != 100 {
		t.Fatalf("stranded exits reloaded as %+v", got.Stranded)
	}
	next = got.Clone()
	d, err = next.Apply([]vault.Tx{{Ledger: 13, ClosedAt: 1_728_000_015, Hash: "d", Calls: []any{
		vault.ExitRequeued{ID: 2, NewID: 3, Payout: big.NewInt(100), Fee: new(big.Int)},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 13, 13, next, d, nil); err != nil {
		t.Fatal(err)
	}
	got, _, err = st.Load(ctx, testVault, 10)
	if err != nil || len(got.Stranded) != 0 || got.QueuedTotal.Int64() != 100 || got.Exits[3] == nil || *got.Exits[3].RequeuedFrom != 2 || got.ExitTail != 4 {
		t.Fatalf("after the claim: %+v %+v, %v", got.Stranded, got.Exits, err)
	}
	var requeuedAt int64
	_ = st.Pool.QueryRow(ctx, `SELECT requeued_at FROM exits WHERE id = 2`).Scan(&requeuedAt)
	if requeuedAt != 1_728_000_015 {
		t.Fatalf("requeue time %d", requeuedAt)
	}
}

func TestPendingDepositsAndFlagsReload(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, _, err := st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	limits := vault.Limits{
		MinDeposit: big.NewInt(1), MaxDeposit: big.NewInt(2), MaxDailyPerDepositor: big.NewInt(3), TvlCap: big.NewInt(4),
		MaxDailyOutflow: big.NewInt(5), MaxFee: big.NewInt(6), LargeDepositThreshold: big.NewInt(7),
	}
	d, err := s.Apply([]vault.Tx{{Ledger: 10, ClosedAt: 1_728_000_000, Hash: "a", Calls: []any{
		shield(1, 5, 100), shield(2, 7, 300), vault.DepositFlagged{ID: 2, Reason: 3},
		vault.LimitsQueued{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: 44}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	marker := false
	if err := st.Commit(ctx, 10, 10, s, d, func(tx pgx.Tx) error {
		marker = true
		return nil
	}); err != nil || !marker {
		t.Fatalf("commit with hook: %v", err)
	}
	got, _, err := st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Pending) != 2 || got.Pending[2].Flag == nil || *got.Pending[2].Flag != 3 || got.Pending[2].FlaggedAt != 1_728_000_000 {
		t.Fatalf("pending deposits reloaded as %+v", got.Pending)
	}
	if got.Pending[1].Commitment1 != fr.SetUint64(103) || got.Pending[1].Amount.Int64() != 100 {
		t.Fatal("deposit fields reloaded wrongly")
	}
	if got.Queued == nil || got.Queued.ReadyAt != 44 || got.Queued.Limits.MaxFee.Int64() != 6 {
		t.Fatalf("queued limits reloaded as %+v", got.Queued)
	}
	if got.PendingTotal.Int64() != 400 {
		t.Fatalf("pending total %v", got.PendingTotal)
	}
	if err := st.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	_, cursor, err := st.Load(ctx, testVault, 10)
	if err != nil || cursor != 9 {
		t.Fatalf("after reset: cursor %d, %v", cursor, err)
	}
}

func TestOneWindowCanQueueStrandAndPartClaimAnExit(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, _, err := st.Load(ctx, testVault, 10)
	if err != nil {
		t.Fatal(err)
	}
	// Queued, stranded with both parts refused, then the fee moved back by a claim, and that new
	// exit paid in part: all in one window.
	d, err := s.Apply([]vault.Tx{
		{Ledger: 10, ClosedAt: 1_728_000_000, Hash: "a", Calls: []any{shield(1, 1, 1000), vault.Attested{UpTo: 1}, admission(1, 0), queued(10, 2, 1, -300, 5)}},
		{Ledger: 11, ClosedAt: 1_728_000_005, Hash: "b", Calls: []any{vault.ExitStranded{ID: 1, Payout: big.NewInt(300), Fee: big.NewInt(5)}}},
		{Ledger: 12, ClosedAt: 1_728_000_010, Hash: "c", Calls: []any{vault.ExitRequeued{ID: 1, NewID: 2, Payout: new(big.Int), Fee: big.NewInt(5)}}},
		{Ledger: 13, ClosedAt: 1_728_000_015, Hash: "e", Calls: []any{vault.ExitPaid{ID: 2, PayoutPaid: new(big.Int), FeePaid: big.NewInt(2), PayoutLeft: new(big.Int), FeeLeft: big.NewInt(3)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Commit(ctx, 10, 13, s, d, nil); err != nil {
		t.Fatalf("a window that strands and requeues an exit: %v", err)
	}
	got, _, err := st.Load(ctx, testVault, 10)
	if err != nil || got.Stranded[1] == nil || got.Stranded[1].Payout.Int64() != 300 || got.Stranded[1].Fee.Sign() != 0 || got.Stranded[1].MovedFee.Int64() != 5 {
		t.Fatalf("reloaded as %+v, %v", got.Stranded, err)
	}
	if e := got.Exits[2]; e == nil || *e.RequeuedFrom != 1 || e.Fee.Int64() != 3 || e.QueuedFee.Int64() != 5 || len(got.Stranded[1].RequeuedTo) != 1 {
		t.Fatalf("requeued exit reloaded as %+v", e)
	}
}
