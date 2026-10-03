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

// Lock is the advisory lock of the asp account, so only one process, the service or an
// operator's command, sends transactions as it: two would race on its sequence number, and each
// attest or flag one made could be refused by the other's. The lock lives on a connection of its
// own, outside the pool, and ends with it.
type Lock struct {
	pool *pgxpool.Pool
	key  string

	mu   sync.Mutex
	conn *pgx.Conn
	lost chan struct{}
	gone bool
}

// LockWriter takes the lock of the account, or reports ErrWriterRunning.
func LockWriter(ctx context.Context, pool *pgxpool.Pool, account string) (*Lock, error) {
	l := &Lock{pool: pool, key: "asp:" + account, lost: make(chan struct{})}
	conn, err := l.take(ctx)
	if err != nil {
		return nil, err
	}
	l.conn = conn
	return l, nil
}

func (l *Lock) take(ctx context.Context) (*pgx.Conn, error) {
	pooled, err := l.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn := pooled.Hijack()
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, l.key).Scan(&ok); err != nil {
		_ = conn.Close(context.Background())
		return nil, err
	}
	if !ok {
		_ = conn.Close(context.Background())
		return nil, ErrWriterRunning
	}
	return conn, nil
}

// Held checks that the lock is still held. A connection that dropped released it, so it is taken
// again on a new one; when another process took it meanwhile, or the database cannot be reached,
// the lock is lost for good and Lost is closed.
func (l *Lock) Held(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.gone {
		return ErrLockLost
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := l.conn.Exec(ctx, `SELECT 1`); err == nil {
		return nil
	}
	// A session that is still alive would keep the lock, so it is ended before the lock is taken
	// on a new one.
	_ = l.conn.Close(context.Background())
	conn, err := l.take(ctx)
	if err != nil {
		l.gone = true
		close(l.lost)
		return fmt.Errorf("%w: %w", ErrLockLost, err)
	}
	l.conn = conn
	return nil
}

// Lost is closed once the lock is lost for good.
func (l *Lock) Lost() <-chan struct{} {
	return l.lost
}

// Keep checks the lock at each interval until ctx ends or the lock is lost.
func (l *Lock) Keep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := l.Held(ctx); err != nil {
			return
		}
	}
}

// Release gives up the lock.
func (l *Lock) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.conn.Close(context.Background())
}
