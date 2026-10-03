package screening

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrWriterRunning reports that another process writes as the asp account.
var ErrWriterRunning = errors.New("screening: another process writes as the asp account")

// LockWriter takes the advisory lock of the asp account, so only one process, the service or an
// operator's command, sends transactions as it: two would race on its sequence number, and each
// attest or flag one made could be refused by the other's. The lock lives on a connection held
// until release is called.
func LockWriter(ctx context.Context, pool *pgxpool.Pool, account string) (func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, "asp:"+account).Scan(&ok); err != nil {
		conn.Release()
		return nil, err
	}
	if !ok {
		conn.Release()
		return nil, ErrWriterRunning
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, "asp:"+account)
		conn.Release()
	}, nil
}
