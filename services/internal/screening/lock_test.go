package screening

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// dropLock ends the session that holds the database's advisory lock, as a dropped connection
// would, and waits until the lock is free.
func dropLock(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	const held = `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
		AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`
	var pid int32
	if err := pool.QueryRow(ctx, held).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	for range 200 {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM (`+held+`) l`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the lock outlived its session")
}

func TestAWriterWhoseConnectionDropsTakesItsLockAgain(t *testing.T) {
	ctx := context.Background()
	pool, err := chainstate.Open(ctx, testdb.URL(t), Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	lock, err := LockWriter(ctx, pool, "GASP")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	dropLock(t, pool)
	if err := lock.Held(ctx); err != nil {
		t.Fatalf("not taken again: %v", err)
	}
	if _, err := LockWriter(ctx, pool, "GASP"); !errors.Is(err, ErrWriterRunning) {
		t.Fatalf("a second writer while the lock is held again: %v", err)
	}
	select {
	case <-lock.Lost():
		t.Fatal("reported lost")
	default:
	}
}

func TestAWriterWhoseLockAnotherTookStopsWriting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id := h.shield(clean, 10_000_000)
	h.tick()
	// The connection drops, and another process takes the lock before this one notices.
	dropLock(t, h.s.db.pool)
	other, err := LockWriter(ctx, h.s.db.pool, vaulttest.Asp)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Release()
	keep, cancel := context.WithCancel(ctx)
	defer cancel()
	go h.s.lock.Keep(keep, 5*time.Millisecond)
	select {
	case <-h.s.lock.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("the loss went unnoticed")
	}
	if err := h.s.FlagManually(ctx, id, ReasonFraud, "reviewer", "report 1"); !errors.Is(err, ErrLockLost) {
		t.Fatalf("a flag without the lock: %v", err)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("sent without the lock: %v", got)
	}
}

func TestNothingIsSentWithoutTheLock(t *testing.T) {
	h := newHarness(t)
	id := h.shield(clean, 10_000_000)
	h.tick()
	h.s.UseLock(nil)
	if err := h.s.FlagManually(context.Background(), id, ReasonFraud, "reviewer", "report 1"); !errors.Is(err, errNoLock) {
		t.Fatalf("a flag without a lock: %v", err)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("sent without a lock: %v", got)
	}
}
