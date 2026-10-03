package alert

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Queue delivers alerts in the background. Each channel's copy of an alert is retried with backoff
// until the channel takes it, so a slow or failing webhook never holds up the service that raised
// the alert and never loses it. With a Store, the copies not yet delivered survive a restart.
type Queue struct {
	// Name tells apart the queues that share a store, such as an operator and a public one.
	Name     string
	Channels []Channel
	Store    *Store
	Log      *slog.Logger
	Now      func() time.Time

	mu      sync.Mutex
	pending []delivery
	nextID  int64
	wake    chan struct{}
}

// delivery is one channel's copy of an alert.
type delivery struct {
	id       int64
	channel  int
	alert    Alert
	attempts int
	next     time.Time
}

const (
	// maxPending bounds the copies kept in memory when there is no store.
	maxPending = 10_000
	// maxAge drops a copy no channel took within a week; the condition has been logged meanwhile.
	maxAge = 7 * 24 * time.Hour
	// sendTimeout bounds one attempt.
	sendTimeout = 15 * time.Second
)

func (q *Queue) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

// backoff is the wait after the given number of failed attempts: 5 seconds doubling up to 10
// minutes.
func backoff(attempts int) time.Duration {
	d := 5 * time.Second
	for range min(attempts, 8) {
		d *= 2
	}
	return min(d, 10*time.Minute)
}

// Put takes an alert for every channel and returns at once.
func (q *Queue) Put(a Alert) {
	if q.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := q.Store.add(ctx, q.Name, a, len(q.Channels), q.now())
		cancel()
		if err == nil {
			q.signal()
			return
		}
		q.logError("alert outbox write failed; the alert waits in memory", a.Code, err)
	}
	q.mu.Lock()
	for i := range q.Channels {
		q.nextID--
		q.pending = append(q.pending, delivery{id: q.nextID, channel: i, alert: a, next: q.now()})
	}
	if over := len(q.pending) - maxPending; over > 0 {
		for _, d := range q.pending[:over] {
			q.logError("alert dropped from a full queue", d.alert.Code, nil)
		}
		q.pending = append([]delivery(nil), q.pending[over:]...)
	}
	q.mu.Unlock()
	q.signal()
}

func (q *Queue) signal() {
	q.mu.Lock()
	if q.wake == nil {
		q.wake = make(chan struct{}, 1)
	}
	wake := q.wake
	q.mu.Unlock()
	select {
	case wake <- struct{}{}:
	default:
	}
}

func (q *Queue) logError(msg, code string, err error) {
	if q.Log == nil {
		return
	}
	if err != nil {
		q.Log.Error(msg, "queue", q.Name, "code", code, "error", err.Error())
		return
	}
	q.Log.Error(msg, "queue", q.Name, "code", code)
}

// Run delivers until ctx ends.
func (q *Queue) Run(ctx context.Context) {
	q.signal()
	for ctx.Err() == nil {
		wait := q.Flush(ctx)
		q.mu.Lock()
		wake := q.wake
		q.mu.Unlock()
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
		case <-wake:
		case <-t.C:
		}
		t.Stop()
	}
}

// Flush attempts every copy that is due and returns how long until the next one is.
func (q *Queue) Flush(ctx context.Context) time.Duration {
	now := q.now()
	due, err := q.due(ctx, now)
	if err != nil {
		q.logError("alert outbox read failed", "", err)
		return 5 * time.Second
	}
	var wg sync.WaitGroup
	results := make([]error, len(due))
	for i, d := range due {
		if d.channel >= len(q.Channels) || now.Sub(d.alert.Time) > maxAge {
			results[i] = errDropped
			continue
		}
		wg.Go(func() {
			sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendTimeout)
			defer cancel()
			results[i] = q.Channels[d.channel].Send(sendCtx, d.alert)
		})
	}
	wg.Wait()
	for i, d := range due {
		switch {
		case results[i] == nil || errors.Is(results[i], errDropped):
			if errors.Is(results[i], errDropped) {
				q.logError("alert dropped: its channel is gone or it is a week old", d.alert.Code, nil)
			}
			q.done(ctx, d)
		default:
			q.logError("alert delivery failed; it will be retried", d.alert.Code, results[i])
			q.retry(ctx, d, now.Add(backoff(d.attempts)))
		}
	}
	return q.untilNext(ctx, q.now())
}

var errDropped = errors.New("alert: dropped")

func (q *Queue) due(ctx context.Context, now time.Time) ([]delivery, error) {
	var out []delivery
	if q.Store != nil {
		stored, err := q.Store.due(ctx, q.Name, now, 100)
		if err != nil {
			return nil, err
		}
		out = append(out, stored...)
	}
	q.mu.Lock()
	for _, d := range q.pending {
		if !d.next.After(now) && len(out) < 200 {
			out = append(out, d)
		}
	}
	q.mu.Unlock()
	return out, nil
}

func (q *Queue) done(ctx context.Context, d delivery) {
	if d.id > 0 {
		if err := q.Store.done(ctx, d.id); err != nil {
			q.logError("alert outbox update failed", d.alert.Code, err)
		}
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.pending {
		if q.pending[i].id == d.id {
			q.pending = append(q.pending[:i], q.pending[i+1:]...)
			return
		}
	}
}

func (q *Queue) retry(ctx context.Context, d delivery, next time.Time) {
	if d.id > 0 {
		if err := q.Store.retry(ctx, d.id, next); err != nil {
			q.logError("alert outbox update failed", d.alert.Code, err)
		}
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.pending {
		if q.pending[i].id == d.id {
			q.pending[i].attempts++
			q.pending[i].next = next
			return
		}
	}
}

func (q *Queue) untilNext(ctx context.Context, now time.Time) time.Duration {
	next := now.Add(5 * time.Second)
	if q.Store != nil {
		if at, ok, err := q.Store.next(ctx, q.Name); err == nil && ok && at.Before(next) {
			next = at
		}
	}
	q.mu.Lock()
	for _, d := range q.pending {
		if d.next.Before(next) {
			next = d.next
		}
	}
	q.mu.Unlock()
	return max(next.Sub(now), 50*time.Millisecond)
}

// Waiting reports how many copies are not delivered yet.
func (q *Queue) Waiting(ctx context.Context) (int, error) {
	q.mu.Lock()
	n := len(q.pending)
	q.mu.Unlock()
	if q.Store != nil {
		var stored int
		if err := q.Store.Pool.QueryRow(ctx, `SELECT count(*) FROM alert_outbox WHERE queue = $1`, q.Name).Scan(&stored); err != nil {
			return 0, err
		}
		n += stored
	}
	return n, nil
}

// OutboxSchema is the table a Store keeps alerts in.
const OutboxSchema = `
CREATE TABLE IF NOT EXISTS alert_outbox (
	id bigserial PRIMARY KEY,
	queue text NOT NULL,
	channel integer NOT NULL,
	alert jsonb NOT NULL,
	attempts integer NOT NULL DEFAULT 0,
	next_at bigint NOT NULL
);
CREATE INDEX IF NOT EXISTS alert_outbox_due ON alert_outbox (queue, next_at);
`

// Store keeps the copies of alerts that wait for delivery in a service's own database.
type Store struct {
	Pool *pgxpool.Pool
}

// Init creates the table.
func (s *Store) Init(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, OutboxSchema)
	return err
}

func (s *Store) add(ctx context.Context, queue string, a Alert, channels int, now time.Time) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for i := range channels {
		batch.Queue(`INSERT INTO alert_outbox (queue, channel, alert, next_at) VALUES ($1, $2, $3, $4)`, queue, i, body, now.UnixMilli())
	}
	return s.Pool.SendBatch(ctx, batch).Close()
}

func (s *Store) due(ctx context.Context, queue string, now time.Time, limit int) ([]delivery, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, channel, alert, attempts, next_at FROM alert_outbox
		WHERE queue = $1 AND next_at <= $2 ORDER BY id LIMIT $3`, queue, now.UnixMilli(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []delivery
	for rows.Next() {
		var d delivery
		var body []byte
		var next int64
		if err := rows.Scan(&d.id, &d.channel, &body, &d.attempts, &next); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &d.alert); err != nil {
			return nil, err
		}
		d.next = time.UnixMilli(next)
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) done(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM alert_outbox WHERE id = $1`, id)
	return err
}

func (s *Store) retry(ctx context.Context, id int64, next time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE alert_outbox SET attempts = attempts + 1, next_at = $2 WHERE id = $1`, id, next.UnixMilli())
	return err
}

func (s *Store) next(ctx context.Context, queue string) (time.Time, bool, error) {
	var at *int64
	if err := s.Pool.QueryRow(ctx, `SELECT min(next_at) FROM alert_outbox WHERE queue = $1`, queue).Scan(&at); err != nil || at == nil {
		return time.Time{}, false, err
	}
	return time.UnixMilli(*at), true, nil
}
