package watcher

import (
	"context"
	"errors"
	"math/big"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema holds the watcher's records next to the chain state: the ledgers that carried transact
// calls, the delay each deposit was made under, funder lookups, and small values such as account
// fingerprints and Horizon cursors.
const Schema = `
CREATE TABLE IF NOT EXISTS watch_activity (
	ledger bigint PRIMARY KEY,
	closed_at bigint NOT NULL,
	transacts integer NOT NULL
);
CREATE INDEX IF NOT EXISTS watch_activity_by_time ON watch_activity (closed_at);
CREATE TABLE IF NOT EXISTS watch_delays (
	id bigint PRIMARY KEY,
	delay bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS watch_funders (
	address text PRIMARY KEY,
	funders text[] NOT NULL,
	fetched_at bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS watch_meta (
	key text PRIMARY KEY,
	value text NOT NULL
);
`

type store struct {
	pool *pgxpool.Pool
}

func (s store) recordActivity(ctx context.Context, tx pgx.Tx, ledger uint32, closedAt int64, transacts int) error {
	_, err := tx.Exec(ctx, `INSERT INTO watch_activity (ledger, closed_at, transacts) VALUES ($1, $2, $3)
		ON CONFLICT (ledger) DO UPDATE SET transacts = EXCLUDED.transacts`, int64(ledger), closedAt, transacts)
	return err
}

// transacts counts transact calls since each of two times.
func (s store) transacts(ctx context.Context, recent, day int64) (int64, int64, error) {
	var r, d int64
	err := s.pool.QueryRow(ctx, `SELECT coalesce(sum(transacts) FILTER (WHERE closed_at > $1), 0),
		coalesce(sum(transacts), 0) FROM watch_activity WHERE closed_at > $2`, recent, day).Scan(&r, &d)
	return r, d, err
}

// outflowSince sums what left the vault as payouts and fees since a time.
func (s store) outflowSince(ctx context.Context, since int64) (*big.Int, error) {
	var total string
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(sum(fee - ext_amount), 0)::text FROM settlements WHERE closed_at > $1`, since).Scan(&total); err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(total, 10)
	if !ok {
		return nil, errors.New("stored outflow sum")
	}
	return n, nil
}

func (s store) delay(ctx context.Context, id uint64) (uint64, bool, error) {
	var d int64
	err := s.pool.QueryRow(ctx, `SELECT delay FROM watch_delays WHERE id = $1`, int64(id)).Scan(&d)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return uint64(d), err == nil, err
}

func (s store) setDelay(ctx context.Context, id, delay uint64) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO watch_delays (id, delay) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, int64(id), int64(delay))
	return err
}

func (s store) meta(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.pool.QueryRow(ctx, `SELECT value FROM watch_meta WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s store) setMeta(ctx context.Context, key, value string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO watch_meta (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
	return err
}

func (s store) funders(ctx context.Context, address string, fresh int64) ([]string, bool, error) {
	var f []string
	err := s.pool.QueryRow(ctx, `SELECT funders FROM watch_funders WHERE address = $1 AND fetched_at > $2`, address, fresh).Scan(&f)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	return f, err == nil, err
}

func (s store) setFunders(ctx context.Context, address string, funders []string, at int64) error {
	if funders == nil {
		funders = []string{}
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO watch_funders (address, funders, fetched_at) VALUES ($1, $2, $3)
		ON CONFLICT (address) DO UPDATE SET funders = EXCLUDED.funders, fetched_at = EXCLUDED.fetched_at`, address, funders, at)
	return err
}

// forgetFunders drops lookups older than a time, so the watcher keeps no lasting map of who
// funds whom.
func (s store) forgetFunders(ctx context.Context, before int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM watch_funders WHERE fetched_at < $1`, before)
	return err
}

// flow is a deposit or a payment out of the vault.
type flow struct {
	address string
	amount  *big.Int
	at      int64
}

func scanFlows(rows pgx.Rows) ([]flow, error) {
	defer rows.Close()
	var out []flow
	for rows.Next() {
		var f flow
		var amount string
		if err := rows.Scan(&f.address, &amount, &f.at); err != nil {
			return nil, err
		}
		var ok bool
		if f.amount, ok = new(big.Int).SetString(amount, 10); !ok {
			return nil, errors.New("stored amount")
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// depositsSince lists deposits made since a time.
func (s store) depositsSince(ctx context.Context, since int64) ([]flow, error) {
	rows, err := s.pool.Query(ctx, `SELECT depositor, amount::text, created_at FROM deposits WHERE created_at > $1 ORDER BY created_at`, since)
	if err != nil {
		return nil, err
	}
	return scanFlows(rows)
}

// payoutsSince lists the payouts to recipients since a time; fees to relayers are left out.
func (s store) payoutsSince(ctx context.Context, since int64) ([]flow, error) {
	rows, err := s.pool.Query(ctx, `SELECT recipient, (-ext_amount)::text, closed_at FROM settlements
		WHERE closed_at > $1 AND ext_amount < 0 ORDER BY closed_at`, since)
	if err != nil {
		return nil, err
	}
	return scanFlows(rows)
}
