package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Queue delivers alerts in the background, on a lane of its own for each channel, so a channel
// that is slow, down or rate limited holds up only itself. A lane sends Critical alerts before
// Warnings, each on its own, and gathers Info alerts into one digest at most every DigestEvery.
// A copy a channel fails to take is retried with backoff until the channel takes it, and one it
// refuses with a 4xx answer other than 408 or 429 is dropped, as it would be refused again; a
// lane whose channel keeps failing rests, as long as a 429 answer asks or at a backoff. With a
// Store, the copies not yet delivered survive a restart.
type Queue struct {
	// Name tells apart the queues that share a store, such as an operator and a public one.
	Name     string
	Channels []Channel
	Store    *Store
	Log      *slog.Logger
	Now      func() time.Time
	// DigestEvery is how often a lane sends its digest of Info alerts; 5 minutes unless set.
	DigestEvery time.Duration

	mu      sync.Mutex
	pending []delivery
	nextID  int64
	lanes   []*lane
}

// delivery is one channel's copy of an alert.
type delivery struct {
	id       int64
	channel  int
	alert    Alert
	attempts int
	next     time.Time
}

// lane is the delivery state of one channel.
type lane struct {
	wake chan struct{}
	// failures counts the sends the channel refused in a row, from the time failing.
	failures int
	failing  time.Time
	// rest is when the lane may send again, and digestAt when its next digest may go.
	rest     time.Time
	digestAt time.Time
}

const (
	// maxPending bounds the copies kept in memory when there is no store.
	maxPending = 10_000
	// maxAge drops a copy no channel took within a week; the condition has been logged meanwhile.
	maxAge = 7 * 24 * time.Hour
	// sendTimeout bounds one attempt.
	sendTimeout = 15 * time.Second
	// laneBatch bounds the copies one pass of a lane reads.
	laneBatch = 100
	// failuresToRest is how many refused sends in a row rest a lane: one is a copy's problem, a run
	// of them the channel's.
	failuresToRest = 3
	// digestShown is how many Info alerts a digest names in full.
	digestShown = 10
)

func (q *Queue) now() time.Time {
	if q.Now != nil {
		return q.Now()
	}
	return time.Now()
}

func (q *Queue) digestEvery() time.Duration {
	if q.DigestEvery > 0 {
		return q.DigestEvery
	}
	return 5 * time.Minute
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

// rank orders the severities a lane sends in.
func rank(s Severity) int {
	switch s {
	case Critical:
		return 0
	case Info:
		return 2
	}
	return 1
}

func (q *Queue) lane(i int) *lane {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.lanes) < len(q.Channels) {
		q.lanes = append(q.lanes, &lane{wake: make(chan struct{}, 1)})
	}
	return q.lanes[i]
}

// Put takes an alert for every channel and returns at once.
func (q *Queue) Put(a Alert) {
	defer q.wakeAll()
	if q.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := q.Store.add(ctx, q.Name, a, len(q.Channels), q.now())
		cancel()
		if err == nil {
			return
		}
		q.logError("alert outbox write failed; the alert waits in memory", a.Code, err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.Channels {
		q.nextID--
		q.pending = append(q.pending, delivery{id: q.nextID, channel: i, alert: a, next: q.now()})
	}
	// A full queue drops its oldest copies of the lowest severity first, Info before Warning
	// before Critical.
	for over := len(q.pending) - maxPending; over > 0; {
		r := 0
		for _, d := range q.pending {
			r = max(r, rank(d.alert.Severity))
		}
		kept := q.pending[:0]
		for _, d := range q.pending {
			if over > 0 && rank(d.alert.Severity) == r {
				q.logError("alert dropped from a full queue", d.alert.Code, nil)
				over--
				continue
			}
			kept = append(kept, d)
		}
		q.pending = kept
	}
}

func (q *Queue) wakeAll() {
	for i := range q.Channels {
		select {
		case q.lane(i).wake <- struct{}{}:
		default:
		}
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

// Run delivers on every lane until ctx ends.
func (q *Queue) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := range q.Channels {
		wg.Go(func() {
			l := q.lane(i)
			for ctx.Err() == nil {
				t := time.NewTimer(q.flushLane(ctx, i))
				select {
				case <-ctx.Done():
				case <-l.wake:
				case <-t.C:
				}
				t.Stop()
			}
		})
	}
	wg.Wait()
}

// Flush runs one pass of every lane and returns how long until a lane has work again.
func (q *Queue) Flush(ctx context.Context) time.Duration {
	waits := make([]time.Duration, len(q.Channels))
	var wg sync.WaitGroup
	for i := range q.Channels {
		wg.Go(func() { waits[i] = q.flushLane(ctx, i) })
	}
	wg.Wait()
	wait := 5 * time.Second
	for _, w := range waits {
		wait = min(wait, w)
	}
	return wait
}

// flushLane sends what is due on one channel and returns how long until the lane has work again.
func (q *Queue) flushLane(ctx context.Context, ch int) time.Duration {
	l := q.lane(ch)
	now := q.now()
	q.mu.Lock()
	rest, digestAt := l.rest, l.digestAt
	q.mu.Unlock()
	if now.Before(rest) {
		return rest.Sub(now)
	}
	var infos []delivery
	for _, d := range q.due(ctx, ch, now) {
		switch {
		case now.Sub(d.alert.Time) > maxAge:
			q.logError("alert dropped: no channel took it within a week", d.alert.Code, nil)
			q.done(ctx, d)
		case d.alert.Severity == Info:
			infos = append(infos, d)
		default:
			if !q.attempt(ctx, l, ch, now, []delivery{d}, d.alert) {
				return q.restLeft(l, now)
			}
		}
	}
	if len(infos) > 0 && !now.Before(digestAt) {
		a := infos[0].alert
		if len(infos) > 1 {
			a = digest(infos, now)
		}
		if !q.attempt(ctx, l, ch, now, infos, a) {
			return q.restLeft(l, now)
		}
		q.mu.Lock()
		l.digestAt = now.Add(q.digestEvery())
		q.mu.Unlock()
	}
	return max(q.restLeft(l, now), 50*time.Millisecond)
}

// attempt sends one message standing for the copies given, and reports whether the lane may go
// on. A 429 rests the lane for as long as it asks, and a refusal that would repeat drops the
// copies; any other failure retries them later, and a run of them rests the lane.
func (q *Queue) attempt(ctx context.Context, l *lane, ch int, now time.Time, ds []delivery, a Alert) bool {
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sendTimeout)
	err := q.Channels[ch].Send(sendCtx, a)
	cancel()
	if err == nil {
		for _, d := range ds {
			q.done(ctx, d)
		}
		q.mu.Lock()
		l.failures, l.failing = 0, time.Time{}
		q.mu.Unlock()
		return true
	}
	var refused Refused
	if errors.As(err, &refused) {
		q.logError("alert refused by its channel and dropped", a.Code, err)
		for _, d := range ds {
			q.done(ctx, d)
		}
		// The lane goes on without a rest, but until a send succeeds it counts as failing, so a
		// channel that refuses every copy, such as a deleted webhook, still stalls the heartbeat.
		q.mu.Lock()
		if l.failing.IsZero() {
			l.failing = now
		}
		q.mu.Unlock()
		return true
	}
	q.logError("alert delivery failed; it will be retried", a.Code, err)
	var limited RetryAfter
	isLimited := errors.As(err, &limited)
	if !isLimited {
		for _, d := range ds {
			q.retry(ctx, d, now.Add(backoff(d.attempts)))
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if l.failing.IsZero() {
		l.failing = now
	}
	if isLimited {
		l.rest = now.Add(limited.Wait)
		return false
	}
	l.failures++
	if l.failures >= failuresToRest {
		l.rest = now.Add(backoff(l.failures - failuresToRest))
		return false
	}
	return true
}

func (q *Queue) restLeft(l *lane, now time.Time) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	if now.Before(l.rest) {
		return l.rest.Sub(now)
	}
	return 5 * time.Second
}

// digest gathers Info alerts into one message, which names the first of them in full; a lone one
// goes as itself.
func digest(ds []delivery, now time.Time) Alert {
	var parts []string
	for _, d := range ds[:min(len(ds), digestShown)] {
		parts = append(parts, d.alert.Code+": "+d.alert.Message)
	}
	if more := len(ds) - digestShown; more > 0 {
		parts = append(parts, fmt.Sprintf("and %d more in the log", more))
	}
	return Alert{Service: ds[0].alert.Service, Severity: Info, Code: "digest", Message: fmt.Sprintf("%d notices: %s", len(ds), strings.Join(parts, "; ")), Time: now.UTC()}
}

// Stalled reports a channel that has refused every send for longer than after, so a heartbeat
// can stop while alerts do not get through.
func (q *Queue) Stalled(now time.Time, after time.Duration) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, l := range q.lanes {
		if !l.failing.IsZero() && now.Sub(l.failing) > after {
			return true
		}
	}
	return false
}

// due lists one channel's copies due now in the order a lane sends them: those in the store, and
// those kept in memory, which are the ones the store could not take, so a store that fails never
// holds them back.
func (q *Queue) due(ctx context.Context, ch int, now time.Time) []delivery {
	var out []delivery
	if q.Store != nil {
		stored, err := q.Store.due(ctx, q.Name, ch, now, laneBatch)
		if err != nil {
			q.logError("alert outbox read failed", "", err)
		}
		out = append(out, stored...)
	}
	q.mu.Lock()
	for _, d := range q.pending {
		if d.channel == ch && !d.next.After(now) {
			out = append(out, d)
		}
	}
	q.mu.Unlock()
	slices.SortStableFunc(out, func(a, b delivery) int { return rank(a.alert.Severity) - rank(b.alert.Severity) })
	return out[:min(len(out), 2*laneBatch)]
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
ALTER TABLE alert_outbox ADD COLUMN IF NOT EXISTS rank smallint NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS alert_outbox_lane ON alert_outbox (queue, channel, rank, id);
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
		batch.Queue(`INSERT INTO alert_outbox (queue, channel, alert, next_at, rank) VALUES ($1, $2, $3, $4, $5)`, queue, i, body, now.UnixMilli(), rank(a.Severity))
	}
	return s.Pool.SendBatch(ctx, batch).Close()
}

func (s *Store) due(ctx context.Context, queue string, channel int, now time.Time, limit int) ([]delivery, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, channel, alert, attempts, next_at FROM alert_outbox
		WHERE queue = $1 AND channel = $2 AND next_at <= $3 ORDER BY rank, id LIMIT $4`, queue, channel, now.UnixMilli(), limit)
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
