package relayer

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema holds the relay records, kept at least five years, and the cooldowns of transactions
// that failed on chain. A record is written when the transaction is sent, as pending, and
// completed with its outcome, so a restart in between loses nothing. It holds no client address
// and no request time; its ledger, nullifiers and channel are public in the transaction itself.
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
ALTER TABLE relays ADD COLUMN IF NOT EXISTS nullifier0 text;
ALTER TABLE relays ADD COLUMN IF NOT EXISTS nullifier1 text;
ALTER TABLE relays ADD COLUMN IF NOT EXISTS channel text;
CREATE INDEX IF NOT EXISTS relays_confirmed ON relays (ledger) WHERE outcome = 'success';
CREATE INDEX IF NOT EXISTS relays_pending ON relays (tx_hash) WHERE outcome = 'pending';
CREATE INDEX IF NOT EXISTS relays_settled ON relays (ledger) WHERE outcome IN ('success', 'failed');
CREATE TABLE IF NOT EXISTS relay_cooldowns (
	key text PRIMARY KEY,
	until bigint NOT NULL
);
`

// The outcomes of a relay record.
const (
	outcomePending = "pending"
	outcomeSuccess = "success"
	outcomeFailed  = "failed"
	outcomeExpired = "expired"
)

// Record is one relayed transaction. ExitID is set when its payment, the fee included, waited in
// the exit queue. Nullifiers and Channel let a restart hold both until the outcome is known.
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
	Nullifiers  [2]string
	Channel     string
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
	_, err := s.pool.Exec(ctx, `INSERT INTO relays (tx_hash, outcome, kind, fee, destination, screening, nullifier0, nullifier1, channel)
		VALUES ($1, 'pending', $2, $3::numeric, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''))
		ON CONFLICT (tx_hash) DO NOTHING`,
		r.Hash, r.Kind, r.Fee, r.Destination, r.Screening, r.Nullifiers[0], r.Nullifiers[1], r.Channel)
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
func (s store) pending(ctx context.Context) ([]Record, error) {
	rows, err := s.pool.Query(ctx, `SELECT tx_hash, COALESCE(destination, ''), COALESCE(nullifier0, ''), COALESCE(nullifier1, ''),
		COALESCE(channel, '') FROM relays WHERE outcome = 'pending' ORDER BY tx_hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.Hash, &r.Destination, &r.Nullifiers[0], &r.Nullifiers[1], &r.Channel); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// recentOutcomes returns whether each of the last n relays that reached the chain succeeded,
// oldest first.
func (s store) recentOutcomes(ctx context.Context, n int) ([]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT outcome = 'success' FROM relays WHERE outcome IN ('success', 'failed')
		ORDER BY ledger DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[bool])
	if err != nil {
		return nil, err
	}
	slices.Reverse(out)
	return out, nil
}

// coolDown refuses keys until a time.
func (s store) coolDown(ctx context.Context, keys []string, until int64) error {
	batch := &pgx.Batch{}
	for _, k := range keys {
		batch.Queue(`INSERT INTO relay_cooldowns (key, until) VALUES ($1, $2)
			ON CONFLICT (key) DO UPDATE SET until = GREATEST(relay_cooldowns.until, EXCLUDED.until)`, k, until)
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

// forgetCooldowns drops the cooldowns that ended by a time.
func (s store) forgetCooldowns(ctx context.Context, now int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM relay_cooldowns WHERE until <= $1`, now)
	return err
}

// cooldowns returns every stored cooldown with its end.
func (s store) cooldowns(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, until FROM relay_cooldowns`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var until int64
		if err := rows.Scan(&k, &until); err != nil {
			return nil, err
		}
		out[k] = until
	}
	return out, rows.Err()
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
