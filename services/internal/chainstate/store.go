package chainstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const schema = `
CREATE TABLE IF NOT EXISTS chain_meta (
	id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	vault text NOT NULL,
	deploy_ledger bigint NOT NULL,
	ingested_ledger bigint NOT NULL,
	state jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS leaves (
	leaf_index bigint PRIMARY KEY,
	commitment bytea NOT NULL,
	ciphertext bytea NOT NULL,
	ledger bigint NOT NULL,
	tx_hash text NOT NULL
);
CREATE TABLE IF NOT EXISTS nullifiers (
	seq bigint PRIMARY KEY,
	nullifier bytea NOT NULL UNIQUE,
	ledger bigint NOT NULL,
	tx_hash text NOT NULL,
	live_until bigint
);
CREATE INDEX IF NOT EXISTS nullifiers_by_ledger ON nullifiers (ledger, seq);
CREATE TABLE IF NOT EXISTS deposits (
	id bigint PRIMARY KEY,
	depositor text NOT NULL,
	amount numeric NOT NULL,
	commitment0 bytea NOT NULL,
	commitment1 bytea NOT NULL,
	created_at bigint NOT NULL,
	created_ledger bigint NOT NULL,
	created_tx text NOT NULL,
	flag_reason integer,
	flagged_at bigint,
	outcome text,
	outcome_reason integer,
	resolved_ledger bigint,
	resolved_at bigint,
	resolved_tx text,
	leaf_index0 bigint,
	leaf_index1 bigint
);
CREATE INDEX IF NOT EXISTS deposits_pending ON deposits (id) WHERE outcome IS NULL;
CREATE INDEX IF NOT EXISTS deposits_resolved ON deposits (resolved_at) WHERE outcome IS NOT NULL;
CREATE TABLE IF NOT EXISTS settlements (
	ledger bigint NOT NULL,
	closed_at bigint NOT NULL,
	tx_hash text NOT NULL,
	ext_amount numeric NOT NULL,
	fee numeric NOT NULL,
	recipient text NOT NULL,
	relayer text NOT NULL
);
CREATE INDEX IF NOT EXISTS settlements_by_time ON settlements (closed_at);
`

// Store persists a State and what each window changed in one Postgres database.
type Store struct {
	Pool *pgxpool.Pool
	// KeepLeaves stores every leaf with its ciphertext; only the indexer serves them.
	KeepLeaves bool
}

// Open connects and creates the tables, together with the service's own schema.
func Open(ctx context.Context, url string, serviceSchema string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if _, err := pool.Exec(ctx, schema+serviceSchema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return pool, nil
}

type limitsJSON struct {
	MinDeposit            string `json:"min_deposit"`
	MaxDeposit            string `json:"max_deposit"`
	MaxDailyPerDepositor  string `json:"max_daily_per_depositor"`
	TvlCap                string `json:"tvl_cap"`
	MaxDailyOutflow       string `json:"max_daily_outflow"`
	MaxFee                string `json:"max_fee"`
	LargeDepositThreshold string `json:"large_deposit_threshold"`
}

func limitsToJSON(l vault.Limits) limitsJSON {
	return limitsJSON{l.MinDeposit.String(), l.MaxDeposit.String(), l.MaxDailyPerDepositor.String(), l.TvlCap.String(),
		l.MaxDailyOutflow.String(), l.MaxFee.String(), l.LargeDepositThreshold.String()}
}

func limitsFromJSON(j limitsJSON) (vault.Limits, error) {
	var l vault.Limits
	for _, f := range []struct {
		dst **big.Int
		src string
	}{
		{&l.MinDeposit, j.MinDeposit}, {&l.MaxDeposit, j.MaxDeposit}, {&l.MaxDailyPerDepositor, j.MaxDailyPerDepositor},
		{&l.TvlCap, j.TvlCap}, {&l.MaxDailyOutflow, j.MaxDailyOutflow}, {&l.MaxFee, j.MaxFee},
		{&l.LargeDepositThreshold, j.LargeDepositThreshold},
	} {
		n, ok := new(big.Int).SetString(f.src, 10)
		if !ok {
			return vault.Limits{}, fmt.Errorf("stored limit %q", f.src)
		}
		*f.dst = n
	}
	return l, nil
}

type stateJSON struct {
	Tree            []byte      `json:"tree"`
	NextDepositID   uint64      `json:"next_deposit_id"`
	AttestedUpTo    uint64      `json:"attested_up_to"`
	NullifierCount  uint64      `json:"nullifier_count"`
	Tvl             string      `json:"tvl"`
	OutflowDay      uint64      `json:"outflow_day"`
	Outflow         string      `json:"outflow"`
	DepositsPaused  bool        `json:"deposits_paused"`
	TransfersPaused bool        `json:"transfers_paused"`
	HaltedUntil     uint64      `json:"halted_until"`
	NextHaltAt      uint64      `json:"next_halt_at"`
	Limits          *limitsJSON `json:"limits,omitempty"`
	Queued          *limitsJSON `json:"queued,omitempty"`
	QueuedReadyAt   uint64      `json:"queued_ready_at,omitempty"`
}

func encodeState(s *State) ([]byte, error) {
	t, err := s.Tree.MarshalBinary()
	if err != nil {
		return nil, err
	}
	j := stateJSON{
		Tree: t, NextDepositID: s.NextDepositID, AttestedUpTo: s.AttestedUpTo, NullifierCount: s.NullifierCount,
		Tvl: s.Tvl.String(), OutflowDay: s.OutflowDay, Outflow: s.Outflow.String(),
		DepositsPaused: s.DepositsPaused, TransfersPaused: s.TransfersPaused, HaltedUntil: s.HaltedUntil, NextHaltAt: s.NextHaltAt,
	}
	if s.Limits != nil {
		l := limitsToJSON(*s.Limits)
		j.Limits = &l
	}
	if s.Queued != nil {
		q := limitsToJSON(s.Queued.Limits)
		j.Queued = &q
		j.QueuedReadyAt = s.Queued.ReadyAt
	}
	return json.Marshal(j)
}

func decodeState(raw []byte) (*State, error) {
	var j stateJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, err
	}
	s := New()
	if err := s.Tree.UnmarshalBinary(j.Tree); err != nil {
		return nil, err
	}
	s.NextDepositID, s.AttestedUpTo, s.NullifierCount = j.NextDepositID, j.AttestedUpTo, j.NullifierCount
	var ok1, ok2 bool
	s.Tvl, ok1 = new(big.Int).SetString(j.Tvl, 10)
	s.Outflow, ok2 = new(big.Int).SetString(j.Outflow, 10)
	if !ok1 || !ok2 {
		return nil, errors.New("stored amounts")
	}
	s.OutflowDay = j.OutflowDay
	s.DepositsPaused, s.TransfersPaused, s.HaltedUntil, s.NextHaltAt = j.DepositsPaused, j.TransfersPaused, j.HaltedUntil, j.NextHaltAt
	if j.Limits != nil {
		l, err := limitsFromJSON(*j.Limits)
		if err != nil {
			return nil, err
		}
		s.Limits = &l
	}
	if j.Queued != nil {
		l, err := limitsFromJSON(*j.Queued)
		if err != nil {
			return nil, err
		}
		s.Queued = &vault.QueuedLimits{Limits: l, ReadyAt: j.QueuedReadyAt}
	}
	return s, nil
}

// ErrOtherVault reports a database that belongs to another vault.
var ErrOtherVault = errors.New("chainstate: database holds another vault")

// Load returns the stored state and the last ingested ledger, initializing an empty database to
// the vault's deploy ledger.
func (st *Store) Load(ctx context.Context, vaultID string, deployLedger uint32) (*State, uint32, error) {
	var storedVault string
	var ingested int64
	var raw []byte
	err := st.Pool.QueryRow(ctx, `SELECT vault, ingested_ledger, state FROM chain_meta WHERE id = 1`).Scan(&storedVault, &ingested, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		fresh := New()
		blob, err := encodeState(fresh)
		if err != nil {
			return nil, 0, err
		}
		if _, err := st.Pool.Exec(ctx,
			`INSERT INTO chain_meta (id, vault, deploy_ledger, ingested_ledger, state) VALUES (1, $1, $2, $3, $4)`,
			vaultID, deployLedger, int64(deployLedger)-1, blob); err != nil {
			return nil, 0, err
		}
		return fresh, deployLedger - 1, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if storedVault != vaultID {
		return nil, 0, ErrOtherVault
	}
	s, err := decodeState(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("stored state: %w", err)
	}
	rows, err := st.Pool.Query(ctx, `SELECT id, depositor, amount::text, commitment0, commitment1, created_at, created_ledger,
		created_tx, flag_reason, flagged_at FROM deposits WHERE outcome IS NULL ORDER BY id`)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var d Deposit
		var amount string
		var c0, c1 []byte
		var flag *int32
		var flaggedAt *int64
		var createdAt, createdLedger int64
		if err := rows.Scan(&d.ID, &d.Depositor, &amount, &c0, &c1, &createdAt, &createdLedger, &d.CreatedTx, &flag, &flaggedAt); err != nil {
			return nil, 0, err
		}
		d.CreatedAt, d.CreatedLedger = uint64(createdAt), uint32(createdLedger)
		var ok bool
		if d.Amount, ok = new(big.Int).SetString(amount, 10); !ok {
			return nil, 0, fmt.Errorf("stored amount %q", amount)
		}
		if d.Commitment0, err = fr.SetBytes([32]byte(c0)); err != nil {
			return nil, 0, err
		}
		if d.Commitment1, err = fr.SetBytes([32]byte(c1)); err != nil {
			return nil, 0, err
		}
		if flag != nil {
			f := uint32(*flag)
			d.Flag = &f
		}
		if flaggedAt != nil {
			d.FlaggedAt = uint64(*flaggedAt)
		}
		s.Pending[d.ID] = &d
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return s, uint32(ingested), nil
}

// ErrMoved reports a commit whose window does not follow the stored cursor.
var ErrMoved = errors.New("chainstate: the stored cursor moved")

// Commit writes one window atomically: what it changed, the new state and the cursor. The hook
// runs inside the same transaction for the service's own tables.
func (st *Store) Commit(ctx context.Context, from, to uint32, s *State, d Delta, hook func(pgx.Tx) error) error {
	blob, err := encodeState(s)
	if err != nil {
		return err
	}
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `UPDATE chain_meta SET ingested_ledger = $1, state = $2 WHERE id = 1 AND ingested_ledger = $3`,
		to, blob, int64(from)-1)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrMoved
	}
	if st.KeepLeaves && len(d.Leaves) > 0 {
		rows := make([][]any, len(d.Leaves))
		for i, l := range d.Leaves {
			c := l.Commitment.Bytes()
			rows[i] = []any{int64(l.Index), c[:], l.Ciphertext, int64(l.Ledger), l.TxHash}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"leaves"}, []string{"leaf_index", "commitment", "ciphertext", "ledger", "tx_hash"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
	}
	if len(d.Nullifiers) > 0 {
		rows := make([][]any, len(d.Nullifiers))
		for i, n := range d.Nullifiers {
			b := n.Nullifier.Bytes()
			rows[i] = []any{int64(n.Seq), b[:], int64(n.Ledger), n.TxHash}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"nullifiers"}, []string{"seq", "nullifier", "ledger", "tx_hash"}, pgx.CopyFromRows(rows)); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return inconsistent("a nullifier was spent twice")
			}
			return err
		}
	}
	for _, dep := range d.Created {
		c0, c1 := dep.Commitment0.Bytes(), dep.Commitment1.Bytes()
		if _, err := tx.Exec(ctx, `INSERT INTO deposits (id, depositor, amount, commitment0, commitment1, created_at, created_ledger, created_tx)
			VALUES ($1, $2, $3::numeric, $4, $5, $6, $7, $8)`,
			int64(dep.ID), dep.Depositor, dep.Amount.String(), c0[:], c1[:], int64(dep.CreatedAt), int64(dep.CreatedLedger), dep.CreatedTx); err != nil {
			return err
		}
	}
	for _, dep := range d.Updated {
		var flag *int32
		var flaggedAt *int64
		if dep.Flag != nil {
			f, at := int32(*dep.Flag), int64(dep.FlaggedAt)
			flag, flaggedAt = &f, &at
		}
		if _, err := tx.Exec(ctx, `UPDATE deposits SET flag_reason = $2, flagged_at = $3 WHERE id = $1 AND outcome IS NULL`,
			int64(dep.ID), flag, flaggedAt); err != nil {
			return err
		}
	}
	for _, r := range d.Resolved {
		var leaf0, leaf1 *int64
		if r.Outcome == Admitted {
			l0, l1 := int64(r.LeafIndex0), int64(r.LeafIndex1)
			leaf0, leaf1 = &l0, &l1
		}
		tag, err := tx.Exec(ctx, `UPDATE deposits SET outcome = $2, outcome_reason = $3, resolved_ledger = $4, resolved_at = $5,
			resolved_tx = $6, leaf_index0 = $7, leaf_index1 = $8 WHERE id = $1 AND outcome IS NULL`,
			int64(r.Deposit.ID), string(r.Outcome), int32(r.Reason), int64(r.Ledger), r.ClosedAt, r.TxHash, leaf0, leaf1)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return inconsistent("deposit %d resolved twice", r.Deposit.ID)
		}
	}
	for _, se := range d.Settlements {
		if _, err := tx.Exec(ctx, `INSERT INTO settlements (ledger, closed_at, tx_hash, ext_amount, fee, recipient, relayer)
			VALUES ($1, $2, $3, $4::numeric, $5::numeric, $6, $7)`,
			int64(se.Ledger), se.ClosedAt, se.TxHash, se.ExtAmount.String(), se.Fee.String(), se.Recipient, se.Relayer); err != nil {
			return err
		}
	}
	if hook != nil {
		if err := hook(tx); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Reset deletes everything the chain state holds, for a rebuild from the deploy ledger.
func (st *Store) Reset(ctx context.Context) error {
	_, err := st.Pool.Exec(ctx, `TRUNCATE chain_meta, leaves, nullifiers, deposits, settlements`)
	return err
}
