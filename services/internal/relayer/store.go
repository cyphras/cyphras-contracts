package relayer

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema holds the relay records, kept at least five years. A record holds no client address and
// no request time; its ledger is public.
const Schema = `
CREATE TABLE IF NOT EXISTS relays (
	tx_hash text PRIMARY KEY,
	ledger bigint NOT NULL,
	kind text NOT NULL,
	fee numeric NOT NULL,
	network_fee bigint NOT NULL,
	resource_fee bigint NOT NULL,
	destination text,
	screening text,
	exit_id bigint
);
CREATE INDEX IF NOT EXISTS relays_by_ledger ON relays (ledger);
`

// Record is one relayed transaction. ExitID is set when its payment, the fee included, waited in
// the exit queue.
type Record struct {
	Hash        string
	Ledger      uint32
	Kind        string
	Fee         string
	NetworkFee  int64
	ResourceFee int64
	Destination string
	Screening   string
	ExitID      *uint64
}

type store struct {
	pool *pgxpool.Pool
}

// NewStore keeps relay records in the pool's database.
func NewStore(pool *pgxpool.Pool) store {
	return store{pool: pool}
}

func (s store) record(ctx context.Context, r Record) error {
	var exitID *int64
	if r.ExitID != nil {
		id := int64(*r.ExitID)
		exitID = &id
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO relays (tx_hash, ledger, kind, fee, network_fee, resource_fee, destination, screening, exit_id)
		VALUES ($1, $2, $3, $4::numeric, $5, $6, NULLIF($7, ''), NULLIF($8, ''), $9) ON CONFLICT (tx_hash) DO NOTHING`,
		r.Hash, int64(r.Ledger), r.Kind, r.Fee, r.NetworkFee, r.ResourceFee, r.Destination, r.Screening, exitID)
	return err
}

func (s store) has(ctx context.Context, hash string) (bool, *uint64, error) {
	var exitID *int64
	err := s.pool.QueryRow(ctx, `SELECT exit_id FROM relays WHERE tx_hash = $1`, hash).Scan(&exitID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil || exitID == nil {
		return err == nil, nil, err
	}
	id := uint64(*exitID)
	return true, &id, nil
}

// recentResourceFees returns the resource fees of the last n relays, oldest first.
func (s store) recentResourceFees(ctx context.Context, n int) ([]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT resource_fee FROM relays ORDER BY ledger DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	fees, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, err
	}
	slices.Reverse(fees)
	return fees, nil
}
