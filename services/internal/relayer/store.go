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
// and no request time; its ledger, nullifiers and channel are public in the transaction itself,
// and the request and simulation ledger it holds while pending are dropped with the outcome.
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
ALTER TABLE relays ADD COLUMN IF NOT EXISTS request text;
ALTER TABLE relays ADD COLUMN IF NOT EXISTS simulated_at bigint;
CREATE INDEX IF NOT EXISTS relays_confirmed ON relays (ledger) WHERE outcome = 'success';
CREATE INDEX IF NOT EXISTS relays_pending ON relays (tx_hash) WHERE outcome = 'pending';
CREATE INDEX IF NOT EXISTS relays_settled ON relays (ledger) WHERE outcome IN ('success', 'failed');
CREATE TABLE IF NOT EXISTS relay_cooldowns (
	key text PRIMARY KEY,
	until bigint NOT NULL
);
ALTER TABLE relay_cooldowns ADD COLUMN IF NOT EXISTS strikes integer NOT NULL DEFAULT 0;
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
	// Request names the proof that was sent and SimulatedAt the ledger its simulation read; both
	// are kept only while the transaction is pending.
	Request     string
	SimulatedAt uint32
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
	_, err := s.pool.Exec(ctx, `INSERT INTO relays (tx_hash, outcome, kind, fee, destination, screening, nullifier0, nullifier1, channel,
		request, simulated_at)
		VALUES ($1, 'pending', $2, $3::numeric, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''),
		NULLIF($9, ''), NULLIF($10, 0))
		ON CONFLICT (tx_hash) DO NOTHING`,
		r.Hash, r.Kind, r.Fee, r.Destination, r.Screening, r.Nullifiers[0], r.Nullifiers[1], r.Channel, r.Request, int64(r.SimulatedAt))
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
	_, err := s.pool.Exec(ctx, `UPDATE relays SET outcome = $2, ledger = $3, network_fee = $4, resource_fee = $5, exit_id = $6,
		request = NULL, simulated_at = NULL
		WHERE tx_hash = $1 AND outcome = 'pending'`, r.Hash, r.Outcome, ledger, networkFee, resourceFee, exitID)
	return err
}

// pending lists the transactions sent but not yet finished.
func (s store) pending(ctx context.Context) ([]Record, error) {
	rows, err := s.pool.Query(ctx, `SELECT tx_hash, COALESCE(destination, ''), COALESCE(nullifier0, ''), COALESCE(nullifier1, ''),
		COALESCE(channel, ''), COALESCE(request, ''), COALESCE(simulated_at, 0) FROM relays WHERE outcome = 'pending' ORDER BY tx_hash`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		var simulated int64
		if err := rows.Scan(&r.Hash, &r.Destination, &r.Nullifiers[0], &r.Nullifiers[1], &r.Channel, &r.Request, &simulated); err != nil {
			return nil, err
		}
		r.SimulatedAt = uint32(simulated)
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

// strike stores a destination's rest with the receive failures in a row it counts.
func (s store) strike(ctx context.Context, key string, until int64, strikes int) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO relay_cooldowns (key, until, strikes) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET until = GREATEST(relay_cooldowns.until, EXCLUDED.until), strikes = EXCLUDED.strikes`, key, until, strikes)
	return err
}

// forgetCooldowns drops the cooldowns that ended by a time.
func (s store) forgetCooldowns(ctx context.Context, before int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM relay_cooldowns WHERE until <= $1`, before)
	return err
}

// storedCooldown is a cooldown as stored: its end, and for a destination its strikes.
type storedCooldown struct {
	until   int64
	strikes int
}

// cooldowns returns every stored cooldown.
func (s store) cooldowns(ctx context.Context) (map[string]storedCooldown, error) {
	rows, err := s.pool.Query(ctx, `SELECT key, until, strikes FROM relay_cooldowns`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]storedCooldown{}
	for rows.Next() {
		var k string
		var c storedCooldown
		if err := rows.Scan(&k, &c.until, &c.strikes); err != nil {
			return nil, err
		}
		out[k] = c
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
