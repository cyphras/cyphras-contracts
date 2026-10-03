package screening

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrWriterRunning reports that another process writes as the asp account.
var ErrWriterRunning = errors.New("screening: another process writes as the asp account")

// ErrLockLost reports that the lock of the asp account was lost and could not be taken again.
var ErrLockLost = errors.New("screening: the lock of the asp account was lost")

// errLockMissing reports that the lock is not held at the moment and is being taken again.
var errLockMissing = errors.New("screening: the lock of the asp account is being taken again")

// lockGrace is how long the lock may stay missing before it is lost for good, long enough for the
// database to restart or an operator's command to finish.
const lockGrace = 5 * time.Minute

// Lock is the advisory lock of the asp account, so only one process, the service or an
// operator's command, sends transactions as it: two would race on its sequence number, and each
// attest or flag one made could be refused by the other's. The lock lives on a connection of its
// own, outside the pool, and ends with it.
type Lock struct {
	pool  *pgxpool.Pool
	key   string
	grace time.Duration

	mu sync.Mutex
	// conn is the connection of the session that holds the lock, nil while the lock is missing,
	// and pid and start name that session on the server.
	conn    *pgx.Conn
	pid     int32
	start   time.Time
	missing time.Time
	lost    chan struct{}
	gone    bool
}

// LockWriter takes the lock of the account, or reports ErrWriterRunning.
func LockWriter(ctx context.Context, pool *pgxpool.Pool, account string) (*Lock, error) {
	l := &Lock{pool: pool, key: "asp:" + account, grace: lockGrace, lost: make(chan struct{})}
	if err := l.take(ctx); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Lock) take(ctx context.Context) error {
	pooled, err := l.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	conn := pooled.Hijack()
	var ok bool
	var pid int32
	var start time.Time
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0)), pid, backend_start
		FROM pg_stat_activity WHERE pid = pg_backend_pid()`, l.key).Scan(&ok, &pid, &start); err != nil {
		_ = conn.Close(context.Background())
		return err
	}
	if !ok {
		_ = conn.Close(context.Background())
		return ErrWriterRunning
	}
	l.conn, l.pid, l.start = conn, pid, start
	return nil
}

// Held checks that the lock is still held, and takes it again when its connection fails the
// check. Until it is taken again, Held reports so and nothing is sent; once it has been missing
// for the grace, the lock is lost for good and Lost is closed.
func (l *Lock) Held(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone {
		return ErrLockLost
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if l.conn != nil {
		if _, err := l.conn.Exec(ctx, `SELECT 1`); err == nil {
			return nil
		}
		_ = l.conn.Close(context.Background())
		l.conn, l.missing = nil, time.Now()
	}
	err := l.retake(ctx)
	if err == nil {
		return nil
	}
	if time.Since(l.missing) >= l.grace {
		l.gone = true
		close(l.lost)
		return fmt.Errorf("%w: %w", ErrLockLost, err)
	}
	return fmt.Errorf("%w: %w", errLockMissing, err)
}

// retake ends the session that held the lock, then takes the lock on a new one. A session whose
// connection the network lost keeps its lock on the server until the server notices, which can
// take hours; it is known by its process id and start, so a process that reused the id is left
// alone.
func (l *Lock) retake(ctx context.Context) error {
	if _, err := l.pool.Exec(ctx, `SELECT pg_terminate_backend(pid, 5000) FROM pg_stat_activity
		WHERE pid = $1 AND backend_start = $2`, l.pid, l.start); err != nil {
		return err
	}
	return l.take(ctx)
}

// Lost is closed once the lock is lost for good.
func (l *Lock) Lost() <-chan struct{} {
	return l.lost
}

// Keep checks the lock at each interval, and while it is missing at a backoff from a second up to
// the interval, until ctx ends or the lock is lost for good.
func (l *Lock) Keep(ctx context.Context, every time.Duration) {
	misses := 0
	for {
		wait := every
		if misses > 0 {
			wait = min(every, time.Second<<min(misses-1, 6))
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		switch err := l.Held(ctx); {
		case err == nil:
			misses = 0
		case errors.Is(err, ErrLockLost):
			return
		default:
			misses++
		}
	}
}

// Release gives up the lock.
func (l *Lock) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn != nil {
		_ = l.conn.Close(context.Background())
	}
}
