package indexer

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema is the indexer's own table, next to the chain state.
const Schema = `
CREATE TABLE IF NOT EXISTS indexer_meta (
	id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	mismatch_ledger bigint,
	mismatch_detail text
);
`

// PageSize is the number of leaves per page.
const PageSize = 1024

// MaxNullifiers is the most nullifiers one response carries.
const MaxNullifiers = 4096

type store struct {
	pool *pgxpool.Pool
}

func (s store) mismatch(ctx context.Context) (bool, error) {
	var ledger *int64
	err := s.pool.QueryRow(ctx, `SELECT mismatch_ledger FROM indexer_meta WHERE id = 1`).Scan(&ledger)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ledger != nil, err
}

func (s store) setMismatch(ctx context.Context, ledger uint32, detail string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO indexer_meta (id, mismatch_ledger, mismatch_detail) VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE SET mismatch_ledger = EXCLUDED.mismatch_ledger, mismatch_detail = EXCLUDED.mismatch_detail`, int64(ledger), detail)
	return err
}

func (s store) reset(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE indexer_meta`)
	return err
}

// Leaf is one entry of a leaves page.
type Leaf struct {
	Index      uint64 `json:"index"`
	Commitment string `json:"commitment"`
	Ciphertext string `json:"ciphertext"`
	Ledger     uint32 `json:"ledger"`
	TxHash     string `json:"tx_hash"`
}

// Every query is cut at upTo, the ledger the response reports as complete. A window committed
// after the response read it may already be in the database, and must not show.

func (s store) leaves(ctx context.Context, page uint64, upTo uint32) ([]Leaf, error) {
	rows, err := s.pool.Query(ctx, `SELECT leaf_index, commitment, ciphertext, ledger, tx_hash FROM leaves
		WHERE leaf_index >= $1 AND leaf_index < $2 AND ledger <= $3 ORDER BY leaf_index`, int64(page*PageSize), int64((page+1)*PageSize), int64(upTo))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Leaf{}
	for rows.Next() {
		var l Leaf
		var index, ledger int64
		var commitment, ciphertext []byte
		if err := rows.Scan(&index, &commitment, &ciphertext, &ledger, &l.TxHash); err != nil {
			return nil, err
		}
		l.Index, l.Ledger = uint64(index), uint32(ledger)
		l.Commitment, l.Ciphertext = hex.EncodeToString(commitment), hex.EncodeToString(ciphertext)
		out = append(out, l)
	}
	return out, rows.Err()
}

// Nullifier is one entry of a nullifiers response.
type Nullifier struct {
	Nullifier string `json:"nullifier"`
	Ledger    uint32 `json:"ledger"`
	TxHash    string `json:"tx_hash"`
}

// nullifiers returns up to MaxNullifiers nullifiers spent from the ledger since to upTo, from the
// cursor on, and the cursor of the next page, empty when this is the last.
func (s store) nullifiers(ctx context.Context, sinceLedger, upTo uint32, cursor uint64) ([]Nullifier, string, error) {
	rows, err := s.pool.Query(ctx, `SELECT seq, nullifier, ledger, tx_hash FROM nullifiers
		WHERE ledger >= $1 AND ledger <= $2 AND seq >= $3 ORDER BY seq LIMIT $4`, int64(sinceLedger), int64(upTo), int64(cursor), MaxNullifiers+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []Nullifier{}
	next := ""
	for rows.Next() {
		var seq, ledger int64
		var nf []byte
		var n Nullifier
		if err := rows.Scan(&seq, &nf, &ledger, &n.TxHash); err != nil {
			return nil, "", err
		}
		if len(out) == MaxNullifiers {
			next = strconv.FormatInt(seq, 10)
			break
		}
		n.Nullifier, n.Ledger = hex.EncodeToString(nf), uint32(ledger)
		out = append(out, n)
	}
	return out, next, rows.Err()
}

// PendingDeposit is a deposit in the entry queue as the API shows it.
type PendingDeposit struct {
	ID                uint64  `json:"id"`
	Depositor         string  `json:"depositor"`
	Amount            string  `json:"amount"`
	CreatedAt         uint64  `json:"created_at"`
	EarliestAdmission *uint64 `json:"earliest_admission"`
	Attested          bool    `json:"attested"`
	FlagReason        *uint32 `json:"flag_reason"`
	FlaggedAt         *uint64 `json:"flagged_at"`
}

// ResolvedDeposit is a deposit that left the queue.
type ResolvedDeposit struct {
	ID         uint64  `json:"id"`
	Depositor  string  `json:"depositor"`
	Amount     string  `json:"amount"`
	CreatedAt  uint64  `json:"created_at"`
	Outcome    string  `json:"outcome"`
	Reason     uint32  `json:"reason"`
	ResolvedAt uint64  `json:"resolved_at"`
	LeafIndex0 *uint64 `json:"leaf_index0"`
	LeafIndex1 *uint64 `json:"leaf_index1"`
}

type depositRow struct {
	id, createdAt     int64
	depositor, amount string
	flag              *int32
	flaggedAt         *int64
}

func (s store) pending(ctx context.Context, upTo uint32) ([]depositRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, depositor, amount::text, created_at, flag_reason, flagged_at
		FROM deposits WHERE created_ledger <= $1 AND (resolved_ledger IS NULL OR resolved_ledger > $1) ORDER BY id`, int64(upTo))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []depositRow
	for rows.Next() {
		var d depositRow
		if err := rows.Scan(&d.id, &d.depositor, &d.amount, &d.createdAt, &d.flag, &d.flaggedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s store) resolved(ctx context.Context, since int64, upTo uint32) ([]ResolvedDeposit, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, depositor, amount::text, created_at, outcome, outcome_reason, resolved_at, leaf_index0, leaf_index1
		FROM deposits WHERE outcome IS NOT NULL AND resolved_at >= $1 AND resolved_ledger <= $2 ORDER BY id`, since, int64(upTo))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResolvedDeposit{}
	for rows.Next() {
		var d ResolvedDeposit
		var id, createdAt, resolvedAt int64
		var reason int32
		var leaf0, leaf1 *int64
		if err := rows.Scan(&id, &d.Depositor, &d.Amount, &createdAt, &d.Outcome, &reason, &resolvedAt, &leaf0, &leaf1); err != nil {
			return nil, err
		}
		d.ID, d.CreatedAt, d.ResolvedAt, d.Reason = uint64(id), uint64(createdAt), uint64(resolvedAt), uint32(reason)
		if leaf0 != nil && leaf1 != nil {
			l0, l1 := uint64(*leaf0), uint64(*leaf1)
			d.LeafIndex0, d.LeafIndex1 = &l0, &l1
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Stats is the anonymity-set summary.
type Stats struct {
	LeafCount          uint64 `json:"leaf_count"`
	AdmittedDeposits   uint64 `json:"admitted_deposits"`
	DistinctDepositors uint64 `json:"distinct_depositors"`
	PendingDeposits    uint64 `json:"pending_deposits"`
}

func (s store) stats(ctx context.Context, upTo uint32) (Stats, error) {
	var admitted, distinct, pending int64
	err := s.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE outcome = 'admitted' AND resolved_ledger <= $1),
		count(DISTINCT depositor) FILTER (WHERE outcome = 'admitted' AND resolved_ledger <= $1),
		count(*) FILTER (WHERE resolved_ledger IS NULL OR resolved_ledger > $1)
		FROM deposits WHERE created_ledger <= $1`, int64(upTo)).Scan(&admitted, &distinct, &pending)
	if err != nil {
		return Stats{}, err
	}
	return Stats{AdmittedDeposits: uint64(admitted), DistinctDepositors: uint64(distinct), PendingDeposits: uint64(pending)}, nil
}

// ResolvedExit is an exit paid in full in the last week: by release, its last step, or by claim.
type ResolvedExit struct {
	ID            uint64 `json:"id"`
	Payout        string `json:"payout"`
	Fee           string `json:"fee"`
	Recipient     string `json:"recipient"`
	Relayer       string `json:"relayer"`
	QueuedAt      uint64 `json:"queued_at"`
	TxHash        string `json:"tx_hash"`
	Outcome       string `json:"outcome"`
	SettledLedger uint32 `json:"settled_ledger"`
	SettledAt     uint64 `json:"settled_at"`
	SettledTx     string `json:"settled_tx"`
}

// resolvedExits lists the exits paid in full since a time, up to a ledger. Payout and fee are
// what the exit owed when it was queued.
func (s store) resolvedExits(ctx context.Context, since int64, upTo uint32) ([]ResolvedExit, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, payout::text, fee::text, recipient, relayer, queued_at, tx_hash,
		CASE WHEN claimed_ledger IS NULL THEN 'released' ELSE 'claimed' END,
		coalesce(claimed_ledger, released_ledger), coalesce(claimed_at, released_at), coalesce(claimed_tx, released_tx)
		FROM exits
		WHERE (unpaid_payout IS NULL AND released_ledger <= $2 AND released_at >= $1)
		   OR (claimed_ledger <= $2 AND claimed_at >= $1)
		ORDER BY id`, since, int64(upTo))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResolvedExit{}
	for rows.Next() {
		var e ResolvedExit
		var id, queuedAt, ledger, at int64
		if err := rows.Scan(&id, &e.Payout, &e.Fee, &e.Recipient, &e.Relayer, &queuedAt, &e.TxHash, &e.Outcome, &ledger, &at, &e.SettledTx); err != nil {
			return nil, err
		}
		e.ID, e.QueuedAt, e.SettledLedger, e.SettledAt = uint64(id), uint64(queuedAt), uint32(ledger), uint64(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
