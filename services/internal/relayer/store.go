package relayer

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema holds the relay records, kept at least five years. A record is written when the
// transaction is sent, as pending, and completed with its outcome, so a restart in between loses
// nothing. It holds no client address and no request time; its ledger is public.
const Schema = `
CREATE TABLE IF NOT EXISTS relays (
	tx_hash text PRIMARY KEY,
	outcome text NOT NULL,
	ledger bigint,
	kind text NOT NULL,
	fee numeric NOT NULL,
	network_fee bigint,
	resource_fee bigint,
	destination text,
	screening text,
	exit_id bigint
);
CREATE INDEX IF NOT EXISTS relays_confirmed ON relays (ledger) WHERE outcome = 'success';
CREATE INDEX IF NOT EXISTS relays_pending ON relays (tx_hash) WHERE outcome = 'pending';
`

// The outcomes of a relay record.
const (
	outcomePending = "pending"
	outcomeSuccess = "success"
	outcomeFailed  = "failed"
	outcomeExpired = "expired"
)

// Record is one relayed transaction. ExitID is set when its payment, the fee included, waited in
// the exit queue.
type Record struct {
	Hash        string
	Outcome     string
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

// sent records a transaction the network accepted, before its outcome is known.
func (s store) sent(ctx context.Context, r Record) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO relays (tx_hash, outcome, kind, fee, destination, screening)
		VALUES ($1, 'pending', $2, $3::numeric, NULLIF($4, ''), NULLIF($5, '')) ON CONFLICT (tx_hash) DO NOTHING`,
		r.Hash, r.Kind, r.Fee, r.Destination, r.Screening)
	return err
}

// finish completes a record with the transaction's outcome.
func (s store) finish(ctx context.Context, r Record) error {
	var exitID, ledger, networkFee, resourceFee *int64
	if r.ExitID != nil {
		id := int64(*r.ExitID)
		exitID = &id
	}
	if r.Outcome != outcomeExpired {
		l, n, f := int64(r.Ledger), r.NetworkFee, r.ResourceFee
		ledger, networkFee, resourceFee = &l, &n, &f
	}
	_, err := s.pool.Exec(ctx, `UPDATE relays SET outcome = $2, ledger = $3, network_fee = $4, resource_fee = $5, exit_id = $6
		WHERE tx_hash = $1 AND outcome = 'pending'`, r.Hash, r.Outcome, ledger, networkFee, resourceFee, exitID)
	return err
}

// pending lists the transactions sent but not yet finished.
func (s store) pending(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT tx_hash FROM relays WHERE outcome = 'pending' ORDER BY tx_hash`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// lookup returns a record's outcome and exit ID.
func (s store) lookup(ctx context.Context, hash string) (string, *uint64, bool, error) {
	var outcome string
	var exitID *int64
	err := s.pool.QueryRow(ctx, `SELECT outcome, exit_id FROM relays WHERE tx_hash = $1`, hash).Scan(&outcome, &exitID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	if exitID == nil {
		return outcome, nil, true, nil
	}
	id := uint64(*exitID)
	return outcome, &id, true, nil
}

// recentResourceFees returns the resource fees of the last n confirmed relays, oldest first.
func (s store) recentResourceFees(ctx context.Context, n int) ([]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT resource_fee FROM relays WHERE outcome = 'success' ORDER BY ledger DESC LIMIT $1`, n)
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
