package alert

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
)

// flaky refuses the first fails alerts, and blocks every send while hold is set.
type flaky struct {
	mu    sync.Mutex
	fails int
	sent  []Alert
	hold  chan struct{}
}

func (f *flaky) Send(ctx context.Context, a Alert) error {
	if f.hold != nil {
		select {
		case <-f.hold:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fails > 0 {
		f.fails--
		return errors.New("webhook down")
	}
	f.sent = append(f.sent, a)
	return nil
}

func (f *flaky) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func TestRaiseDoesNotWaitForAHangingWebhook(t *testing.T) {
	hung := &flaky{hold: make(chan struct{})}
	q := &Queue{Name: "operator", Channels: []Channel{hung}}
	a := &Alerter{Service: "screening", Channels: q.Channels, Queue: q, Cooldown: time.Hour}
	start := time.Now()
	a.Raise(context.Background(), Critical, "flag_failed", "deposit %d", 7)
	if time.Since(start) > time.Second {
		t.Fatal("raising waited for the webhook")
	}
	done := make(chan struct{})
	go func() {
		q.Flush(context.Background())
		close(done)
	}()
	close(hung.hold)
	<-done
	if hung.count() != 1 {
		t.Fatalf("delivered %d", hung.count())
	}
}

func TestAFailedDeliveryIsRetriedUntilTheChannelTakesIt(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	down, up := &flaky{fails: 3}, &flaky{}
	q := &Queue{Name: "operator", Channels: []Channel{down, up}, Now: func() time.Time { return now }}
	q.Put(Alert{Code: "state_mismatch", Time: now})
	for range 10 {
		q.Flush(context.Background())
		now = now.Add(15 * time.Minute)
	}
	if down.count() != 1 || up.count() != 1 {
		t.Fatalf("down got %d, up got %d", down.count(), up.count())
	}
	if n, _ := q.Waiting(context.Background()); n != 0 {
		t.Fatalf("%d copies still wait", n)
	}
}

func TestUndeliveredAlertsSurviveARestart(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := &Store{Pool: pool}
	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_728_000_000, 0)
	clock := func() time.Time { return now }
	first := &Queue{Name: "operator", Channels: []Channel{&flaky{fails: 100}}, Store: store, Now: clock}
	first.Put(Alert{Code: "invariant", Message: "tvl", Time: now})
	first.Flush(ctx)
	// The process restarts with the webhook working again.
	working := &flaky{}
	second := &Queue{Name: "operator", Channels: []Channel{working}, Store: store, Now: clock}
	now = now.Add(time.Hour)
	second.Flush(ctx)
	if working.count() != 1 || working.sent[0].Message != "tvl" {
		t.Fatalf("after the restart %+v", working.sent)
	}
	if n, err := second.Waiting(ctx); err != nil || n != 0 {
		t.Fatalf("%d copies still wait, %v", n, err)
	}
	// A public queue sharing the store does not take the operator's alerts.
	public := &Queue{Name: "public", Channels: []Channel{working}, Store: store, Now: clock}
	public.Put(Alert{Code: "governance", Time: now})
	second.Flush(ctx)
	if working.count() != 1 {
		t.Fatal("the operator queue sent a public alert")
	}
}

func TestAlertsAreDeliveredWhileTheirDatabaseIsDown(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := &Store{Pool: pool}
	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}
	working := &flaky{}
	q := &Queue{Name: "operator", Channels: []Channel{working}, Store: store}
	// The database goes away: neither writing nor reading the outbox works.
	pool.Close()
	q.Put(Alert{Code: "invariant", Message: "tvl", Time: time.Now()})
	q.Flush(ctx)
	if working.count() != 1 || working.sent[0].Message != "tvl" {
		t.Fatalf("delivered %+v", working.sent)
	}
	if n := len(q.pending); n != 0 {
		t.Fatalf("%d copies still wait in memory", n)
	}
}

func TestARepeatWithinTheCooldownIsStillLogged(t *testing.T) {
	var logs bytes.Buffer
	a := &Alerter{Service: "keeper", Log: slog.New(slog.NewTextHandler(&logs, nil)), Cooldown: time.Hour}
	a.Raise(context.Background(), Warning, "balance_low", "holds %d", 5)
	a.Raise(context.Background(), Warning, "balance_low", "holds %d", 4)
	if !strings.Contains(logs.String(), "alert repeated") || !strings.Contains(logs.String(), "holds 4") {
		t.Fatalf("logs %q", logs.String())
	}
}

func outboxStore(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store := &Store{Pool: pool}
	if err := store.Init(ctx); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestADeadChannelNeverHoldsUpALiveOne(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_728_000_000, 0)
	live, dead := &flaky{}, &flaky{fails: 1 << 30}
	q := &Queue{Name: "operator", Channels: []Channel{live, dead}, Store: outboxStore(t), Now: func() time.Time { return now }}
	for i := range 1300 {
		q.Put(Alert{Code: fmt.Sprintf("exit_stranded_%d", i), Severity: Warning, Time: now})
	}
	for range 20 {
		q.Flush(ctx)
	}
	if live.count() != 1300 {
		t.Fatalf("the live channel got %d of 1300", live.count())
	}
	// The dead channel's backlog comes due again, and a Critical arrives.
	now = now.Add(11 * time.Minute)
	q.Put(Alert{Code: "balance_below_tvl", Severity: Critical, Time: now})
	q.Flush(ctx)
	if live.count() != 1301 || live.sent[1300].Code != "balance_below_tvl" {
		t.Fatalf("the Critical waited behind a dead channel: %d sent", live.count())
	}
	// The dead lane tried a few copies and rests, rather than trying all of them each pass.
	if dead.count() != 0 || !q.Stalled(now, 10*time.Minute) {
		t.Fatal("a channel refusing everything for 11 minutes is not stalled")
	}
}

// limited takes at most perMinute sends per minute of the fake clock and answers the rest with a
// plain error, as a webhook behind a rate limit without Retry-After does.
type limited struct {
	mu        sync.Mutex
	now       *time.Time
	perMinute int
	window    time.Time
	used      int
	sent      []Alert
}

func (l *limited) Send(_ context.Context, a Alert) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.now.Sub(l.window) >= time.Minute {
		l.window, l.used = *l.now, 0
	}
	if l.used >= l.perMinute {
		return errors.New("alert: telegram webhook answered 429")
	}
	l.used++
	l.sent = append(l.sent, a)
	return nil
}

func TestACriticalGoesFirstAndInfoIsDigested(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_728_000_000, 0)
	ch := &limited{now: &now, perMinute: 20}
	q := &Queue{Name: "operator", Channels: []Channel{ch}, Store: outboxStore(t), Now: func() time.Time { return now }}
	// A burst of Info alerts, such as flags an attacker provokes.
	for i := range 200 {
		q.Put(Alert{Code: fmt.Sprintf("deposit_flagged_%d", i), Severity: Info, Time: now})
	}
	q.Flush(ctx)
	now = now.Add(time.Second)
	q.Put(Alert{Code: "balance_below_tvl", Severity: Critical, Time: now})
	q.Flush(ctx)
	ch.mu.Lock()
	sent := slices.Clone(ch.sent)
	ch.mu.Unlock()
	if len(sent) != 2 || sent[0].Code != "digest" || !strings.Contains(sent[0].Message, "100 notices") || sent[1].Severity != Critical {
		t.Fatalf("sent %+v", sent)
	}
	// The rest of the burst goes out as the next digest, not before it is due.
	q.Flush(ctx)
	now = now.Add(5 * time.Minute)
	q.Flush(ctx)
	if len(ch.sent) != 3 || !strings.Contains(ch.sent[2].Message, "100 notices") {
		t.Fatalf("sent %d", len(ch.sent))
	}
	if n, _ := q.Waiting(ctx); n != 0 {
		t.Fatalf("%d copies wait", n)
	}
	// A lone notice goes as itself once the digest is due.
	now = now.Add(5 * time.Minute)
	q.Put(Alert{Code: "governance_paused", Severity: Info, Message: "paused", Time: now})
	q.Flush(ctx)
	if last := ch.sent[len(ch.sent)-1]; last.Code != "governance_paused" || last.Message != "paused" {
		t.Fatalf("a lone notice went as %+v", last)
	}
}

func TestARateLimitedChannelRestsAsLongAsItAsks(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requests++
		if requests == 1 {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()
	now := time.Unix(1_728_000_000, 0)
	q := &Queue{Name: "operator", Channels: []Channel{Webhook{Format: "json", URL: srv.URL, HTTP: srv.Client()}}, Now: func() time.Time { return now }}
	q.Put(Alert{Code: "invariant", Severity: Critical, Time: now})
	if wait := q.flushLane(ctx, 0); wait != 120*time.Second {
		t.Fatalf("rests %v", wait)
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		return requests
	}
	now = now.Add(time.Minute)
	q.Flush(ctx)
	if count() != 1 {
		t.Fatalf("%d requests while resting", count())
	}
	now = now.Add(61 * time.Second)
	q.Flush(ctx)
	if n, _ := q.Waiting(ctx); count() != 2 || n != 0 {
		t.Fatalf("%d requests, %d waiting", count(), n)
	}
}

func TestA429SaysHowLongToWait(t *testing.T) {
	answer := func(header, body string) *http.Response {
		r := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
		if header != "" {
			r.Header.Set("Retry-After", header)
		}
		return r
	}
	for name, c := range map[string]struct {
		resp *http.Response
		want time.Duration
	}{
		"seconds":  {answer("7", ""), 7 * time.Second},
		"discord":  {answer("", `{"retry_after": 2.5}`), 2500 * time.Millisecond},
		"telegram": {answer("", `{"ok": false, "parameters": {"retry_after": 9}}`), 9 * time.Second},
		"nothing":  {answer("", "busy"), 30 * time.Second},
		"too long": {answer("86400", ""), time.Hour},
		"zero":     {answer("0", ""), time.Second},
	} {
		if got := retryAfter(c.resp); got != c.want {
			t.Fatalf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// counted refuses every alert and counts the tries.
type counted struct {
	mu    sync.Mutex
	tries int
}

func (c *counted) Send(context.Context, Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tries++
	return errors.New("webhook down")
}

func TestADeadChannelRestsAfterAFewTries(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	dead := &counted{}
	q := &Queue{Name: "operator", Channels: []Channel{dead}, Now: func() time.Time { return now }}
	for i := range 10 {
		q.Put(Alert{Code: fmt.Sprintf("exit_stranded_%d", i), Severity: Warning, Time: now})
	}
	for range 5 {
		q.Flush(context.Background())
	}
	if dead.tries != failuresToRest {
		t.Fatalf("%d tries before the lane rested", dead.tries)
	}
}

func TestACriticalGoesBeforeEarlierWarnings(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	ch := &limited{now: &now, perMinute: 20}
	q := &Queue{Name: "operator", Channels: []Channel{ch}, Now: func() time.Time { return now }}
	for i := range 30 {
		q.Put(Alert{Code: fmt.Sprintf("hot_balance_low_%d", i), Severity: Warning, Time: now})
	}
	q.Put(Alert{Code: "balance_below_tvl", Severity: Critical, Time: now})
	q.Flush(context.Background())
	if len(ch.sent) == 0 || ch.sent[0].Code != "balance_below_tvl" {
		t.Fatalf("the Critical waited behind the Warnings: %d sent", len(ch.sent))
	}
}

func TestInMemoryACriticalGoesBeforeAFloodOfInfo(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	ch := &recorder{}
	q := &Queue{Name: "operator", Channels: []Channel{ch}, Now: func() time.Time { return now }}
	for i := range 1000 {
		q.Put(Alert{Severity: Info, Code: fmt.Sprintf("deposit_flagged_%d", i), Time: now})
	}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	q.Flush(context.Background())
	if len(ch.sent) == 0 || ch.sent[0].Code != "invariant" {
		t.Fatalf("the Critical waited behind the Info alerts: %+v", ch.sent)
	}
}

func TestAFullQueueDropsItsLowestSeverityFirst(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_728_000_000, 0)
	live := &recorder{}
	q := &Queue{Name: "operator", Channels: []Channel{live, &recorder{}}, Now: func() time.Time { return now }}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	q.Put(Alert{Severity: Warning, Code: "hot_balance_low", Time: now})
	for i := range maxPending / 2 {
		q.Put(Alert{Severity: Info, Code: fmt.Sprintf("exit_requeued_%d", i), Time: now})
	}
	kept := map[string]int{}
	for _, d := range q.pending {
		kept[d.alert.Code]++
	}
	if len(q.pending) != maxPending || kept["invariant"] != 2 || kept["hot_balance_low"] != 2 || kept["exit_requeued_1"] != 0 || kept["exit_requeued_2"] != 2 {
		t.Fatalf("kept %d copies: %d of the Critical, %d of the Warning", len(q.pending), kept["invariant"], kept["hot_balance_low"])
	}
	q.Flush(ctx)
	if len(live.sent) == 0 || live.sent[0].Code != "invariant" {
		t.Fatalf("sent %+v", live.sent)
	}
	// With no Info to drop, the oldest Warning goes before any Critical.
	q = &Queue{Name: "operator", Channels: []Channel{live}, Now: func() time.Time { return now }}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	for i := range maxPending {
		q.Put(Alert{Severity: Warning, Code: fmt.Sprintf("exit_stranded_%d", i), Time: now})
	}
	if len(q.pending) != maxPending || q.pending[0].alert.Code != "invariant" || q.pending[1].alert.Code != "exit_stranded_1" {
		t.Fatalf("kept %d copies, from %s", len(q.pending), q.pending[0].alert.Code)
	}
}
