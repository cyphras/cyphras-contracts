package screening

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Schema holds the screening state of each deposit and the decision records. Records hold public
// addresses, amounts and the service's own decisions, never anything about a client request.
const Schema = `
CREATE TABLE IF NOT EXISTS screening (
	deposit_id bigint PRIMARY KEY,
	delay bigint,
	first_check text,
	refuse_reason integer,
	review text,
	recheck text,
	flag_sent integer
);
CREATE TABLE IF NOT EXISTS decisions (
	id bigserial PRIMARY KEY,
	at bigint NOT NULL,
	kind text NOT NULL,
	deposit_id bigint,
	address text,
	amount numeric,
	outcome text NOT NULL,
	reason integer,
	detail text,
	sources jsonb,
	tx_hash text
);
CREATE INDEX IF NOT EXISTS decisions_by_deposit ON decisions (deposit_id);
CREATE TABLE IF NOT EXISTS self_reports (
	address text PRIMARY KEY,
	report_date text NOT NULL,
	signature text NOT NULL,
	received_day text NOT NULL
);
CREATE TABLE IF NOT EXISTS unshield_refusals (
	reason integer PRIMARY KEY,
	refused bigint NOT NULL
);
CREATE TABLE IF NOT EXISTS registers (
	id bigserial PRIMARY KEY,
	kind text NOT NULL,
	day text NOT NULL,
	answered boolean NOT NULL DEFAULT false,
	note text NOT NULL
);
`

type store struct {
	pool *pgxpool.Pool
}

// Decision is one record.
type Decision struct {
	Kind      string
	DepositID *uint64
	Address   string
	Amount    string
	Outcome   string
	Reason    *uint32
	Detail    string
	Sources   []SourceStatus
	TxHash    string
}

func (s store) record(ctx context.Context, at time.Time, d Decision) error {
	var sources []byte
	if d.Sources != nil {
		sources, _ = json.Marshal(d.Sources)
	}
	var amount *string
	if d.Amount != "" {
		amount = &d.Amount
	}
	var deposit *int64
	if d.DepositID != nil {
		id := int64(*d.DepositID)
		deposit = &id
	}
	var reason *int32
	if d.Reason != nil {
		r := int32(*d.Reason)
		reason = &r
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO decisions (at, kind, deposit_id, address, amount, outcome, reason, detail, sources, tx_hash)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5::numeric, $6, $7, NULLIF($8, ''), $9, NULLIF($10, ''))`,
		at.Unix(), d.Kind, deposit, d.Address, amount, d.Outcome, reason, d.Detail, sources, d.TxHash)
	return err
}

// row is a pending deposit with its screening state.
type row struct {
	id           uint64
	depositor    string
	amount       string
	createdAt    uint64
	flag         *uint32
	delay        *uint64
	firstCheck   string
	refuseReason *uint32
	review       string
	recheck      string
	flagSent     *uint32
	// needsFlag marks a refusal whose flag has not been sent yet.
	needsFlag bool
}

func (s store) pending(ctx context.Context) ([]row, error) {
	rows, err := s.pool.Query(ctx, `SELECT d.id, d.depositor, d.amount::text, d.created_at, d.flag_reason,
		s.delay, COALESCE(s.first_check, ''), s.refuse_reason, COALESCE(s.review, ''), COALESCE(s.recheck, ''), s.flag_sent
		FROM deposits d LEFT JOIN screening s ON s.deposit_id = d.id
		WHERE d.outcome IS NULL ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var r row
		var id, created int64
		var flag, refuseReason, flagSent *int32
		var delay *int64
		if err := rows.Scan(&id, &r.depositor, &r.amount, &created, &flag, &delay, &r.firstCheck, &refuseReason, &r.review, &r.recheck, &flagSent); err != nil {
			return nil, err
		}
		r.id, r.createdAt = uint64(id), uint64(created)
		r.flag, r.refuseReason, r.flagSent = u32p(flag), u32p(refuseReason), u32p(flagSent)
		if delay != nil {
			d := uint64(*delay)
			r.delay = &d
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func u32p(v *int32) *uint32 {
	if v == nil {
		return nil
	}
	u := uint32(*v)
	return &u
}

func (s store) update(ctx context.Context, id uint64, column string, value any) error {
	switch column {
	case "delay", "first_check", "refuse_reason", "review", "recheck", "flag_sent":
	default:
		return errors.New("screening: unknown column")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO screening (deposit_id, `+column+`) VALUES ($1, $2)
		ON CONFLICT (deposit_id) DO UPDATE SET `+column+` = EXCLUDED.`+column, int64(id), value)
	return err
}

func (s store) selfReports(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT address FROM self_reports`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// addSelfReport stores a verified report and reports whether it is new.
func (s store) addSelfReport(ctx context.Context, address, date, signature string, at time.Time) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO self_reports (address, report_date, signature, received_day) VALUES ($1, $2, $3, $4)
		ON CONFLICT (address) DO NOTHING`, address, date, signature, at.UTC().Format(time.DateOnly))
	return tag.RowsAffected() == 1, err
}

func (s store) countUnshieldRefusal(ctx context.Context, reason uint32) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO unshield_refusals (reason, refused) VALUES ($1, 1)
		ON CONFLICT (reason) DO UPDATE SET refused = unshield_refusals.refused + 1`, int32(reason))
	return err
}

func (s store) register(ctx context.Context, kind, note string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO registers (kind, day, note) VALUES ($1, $2, $3)`, kind, at.UTC().Format(time.DateOnly), note)
	return err
}

// Stats are the public statistics of the screening policy.
type Stats struct {
	Admitted         Tally            `json:"admitted"`
	Refused          map[string]Tally `json:"refused_by_reason"`
	Refunded         Tally            `json:"refunded"`
	Cancelled        Tally            `json:"cancelled"`
	MedianAdmission  int64            `json:"median_seconds_to_admission"`
	LongestAdmission int64            `json:"longest_seconds_to_admission"`
	UnshieldRefusals map[string]int64 `json:"unshields_refused_by_reason"`
	SelfReports      int64            `json:"self_reports"`
	FraudReports     int64            `json:"fraud_reports"`
	LegalRequests    int64            `json:"law_enforcement_requests"`
	LegalAnswered    int64            `json:"law_enforcement_requests_answered"`
}

// Tally is a count with its total value in the asset's smallest unit.
type Tally struct {
	Count int64  `json:"count"`
	Value string `json:"value"`
}

func (s store) stats(ctx context.Context) (Stats, error) {
	st := Stats{Refused: map[string]Tally{}, UnshieldRefusals: map[string]int64{}}
	tally := func(where string) (Tally, error) {
		var t Tally
		err := s.pool.QueryRow(ctx, `SELECT count(*), COALESCE(sum(amount), 0)::text FROM deposits WHERE `+where).Scan(&t.Count, &t.Value)
		return t, err
	}
	var err error
	if st.Admitted, err = tally("outcome = 'admitted'"); err != nil {
		return Stats{}, err
	}
	if st.Refunded, err = tally("outcome = 'refunded'"); err != nil {
		return Stats{}, err
	}
	if st.Cancelled, err = tally("outcome = 'cancelled'"); err != nil {
		return Stats{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT COALESCE(outcome_reason, flag_reason), count(*), sum(amount)::text FROM deposits
		WHERE outcome = 'refunded' OR (outcome IS NULL AND flag_reason IS NOT NULL) GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return Stats{}, err
	}
	for rows.Next() {
		var reason int32
		var t Tally
		if err := rows.Scan(&reason, &t.Count, &t.Value); err != nil {
			rows.Close()
			return Stats{}, err
		}
		st.Refused[itoa(int64(reason))] = t
	}
	rows.Close()
	var median, longest *float64
	if err := s.pool.QueryRow(ctx, `SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY resolved_at - created_at), max(resolved_at - created_at)
		FROM deposits WHERE outcome = 'admitted'`).Scan(&median, &longest); err != nil {
		return Stats{}, err
	}
	if median != nil {
		st.MedianAdmission, st.LongestAdmission = int64(*median), int64(*longest)
	}
	rows, err = s.pool.Query(ctx, `SELECT reason, refused FROM unshield_refusals ORDER BY reason`)
	if err != nil {
		return Stats{}, err
	}
	for rows.Next() {
		var reason int32
		var n int64
		if err := rows.Scan(&reason, &n); err != nil {
			rows.Close()
			return Stats{}, err
		}
		st.UnshieldRefusals[itoa(int64(reason))] = n
	}
	rows.Close()
	err = s.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM self_reports),
		(SELECT count(*) FROM registers WHERE kind = 'fraud_report'),
		(SELECT count(*) FROM registers WHERE kind = 'legal_request'),
		(SELECT count(*) FROM registers WHERE kind = 'legal_request' AND answered)`).Scan(&st.SelfReports, &st.FraudReports, &st.LegalRequests, &st.LegalAnswered)
	return st, err
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
