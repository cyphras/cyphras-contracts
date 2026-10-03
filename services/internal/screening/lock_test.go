package screening

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const heldLocks = `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
	AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`

// dropLock ends the session that holds the database's advisory lock, as a dropped connection
// would, and waits until the lock is free.
func dropLock(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	var pid int32
	if err := pool.QueryRow(ctx, heldLocks).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}
	lockFree(t, pool)
}

// lockFree waits until no session holds the database's advisory lock.
func lockFree(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for range 200 {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM (`+heldLocks+`) l`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the lock outlived its session")
}

func TestAWriterEndsItsLingeringSessionToTakeItsLockAgain(t *testing.T) {
	ctx := context.Background()
	url := testdb.URL(t)
	pool, err := chainstate.Open(ctx, url, Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	lock, err := LockWriter(ctx, pool, "GASP")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	// The network loses the lock's connection: its check fails, while the server keeps the
	// session, and the lock with it.
	lingering := lock.conn
	defer lingering.Close(ctx)
	broken, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	_ = broken.Close(ctx)
	lock.conn = broken
	if err := lock.Held(ctx); err != nil {
		t.Fatalf("not taken again: %v", err)
	}
	if _, err := lingering.Exec(ctx, `SELECT 1`); err == nil {
		t.Fatal("the lingering session still holds the lock")
	}
	var holder int32
	if err := pool.QueryRow(ctx, heldLocks).Scan(&holder); err != nil || holder != lock.pid {
		t.Fatalf("the lock is held by %d, not the new session %d: %v", holder, lock.pid, err)
	}
}

func TestAWriterWaitsForItsLockWhileAnotherHoldsIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id := h.shield(clean, 10_000_000)
	h.tick()
	// The connection drops, and an operator's command takes the lock for a moment.
	dropLock(t, h.s.db.pool)
	other, err := LockWriter(ctx, h.s.db.pool, vaulttest.Asp)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.s.FlagManually(ctx, id, ReasonFraud, "reviewer", "report 1"); !errors.Is(err, errLockMissing) {
		t.Fatalf("a flag while another holds the lock: %v", err)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("sent without the lock: %v", got)
	}
	select {
	case <-h.s.lock.Lost():
		t.Fatal("the lock was given up at once")
	default:
	}
	if _, err := other.conn.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatalf("the other holder's session was ended: %v", err)
	}
	other.Release()
	lockFree(t, h.s.db.pool)
	if err := h.s.FlagManually(ctx, id, ReasonFraud, "reviewer", "report 1"); err != nil {
		t.Fatalf("a flag once the lock is free again: %v", err)
	}
	if got := h.sent(); len(got) != 1 {
		t.Fatalf("sent %v", got)
	}
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
	h.s.lock.grace = 100 * time.Millisecond
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
