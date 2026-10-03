package alert

import (
	"bytes"
	"context"
	"encoding/json"
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
		"seconds":       {answer("7", ""), 7 * time.Second},
		"discord":       {answer("", `{"retry_after": 2.5}`), 2500 * time.Millisecond},
		"telegram":      {answer("", `{"ok": false, "parameters": {"retry_after": 9}}`), 9 * time.Second},
		"nothing":       {answer("", "busy"), 30 * time.Second},
		"too long":      {answer("86400", ""), time.Hour},
		"zero":          {answer("0", ""), time.Second},
		"huge":          {answer("1e300", ""), time.Hour},
		"infinite":      {answer("Inf", ""), time.Hour},
		"negative":      {answer("-5", ""), 30 * time.Second},
		"nan":           {answer("NaN", ""), 30 * time.Second},
		"huge body":     {answer("", `{"retry_after": 1e300}`), time.Hour},
		"huge telegram": {answer("", `{"parameters": {"retry_after": 1e300}}`), time.Hour},
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

func TestCopiesForARemovedChannelAreDropped(t *testing.T) {
	ctx := context.Background()
	store := outboxStore(t)
	now := time.Unix(1_728_000_000, 0)
	clock := func() time.Time { return now }
	q := &Queue{Name: "operator", Channels: []Channel{&recorder{}, &counted{}}, Store: store, Now: clock}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	q.Flush(ctx)
	if n, err := q.Waiting(ctx); err != nil || n != 1 {
		t.Fatalf("%d copies wait, %v", n, err)
	}
	public := &Queue{Name: "public", Channels: []Channel{&counted{}, &counted{}}, Store: store, Now: clock}
	public.Put(Alert{Severity: Info, Code: "governance", Time: now})
	// The process restarts with the dead channel taken out of its configuration.
	now = now.Add(time.Hour)
	restarted := &Queue{Name: "operator", Channels: []Channel{&recorder{}}, Store: store, Now: clock}
	restarted.Flush(ctx)
	if n, err := restarted.Waiting(ctx); err != nil || n != 0 {
		t.Fatalf("%d copies of the removed channel still wait, %v", n, err)
	}
	if n, err := public.Waiting(ctx); err != nil || n != 2 {
		t.Fatalf("the public queue keeps %d of its 2 copies, %v", n, err)
	}
}

// discordLike answers as Discord does: 400 to a message over 2000 characters or one it cannot
// take, 404 once its webhook is deleted, and takes the rest.
type discordLike struct {
	mu      sync.Mutex
	deleted bool
	got     []string
}

func (d *discordLike) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.deleted:
		w.WriteHeader(http.StatusNotFound)
	case len(body.Content) > 2000 || strings.Contains(body.Content, "malformed"):
		w.WriteHeader(http.StatusBadRequest)
	default:
		d.got = append(d.got, body.Content)
	}
}

func (d *discordLike) delivered() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.got)
}

func TestADigestIsCutToWhatItsChannelTakes(t *testing.T) {
	ctx := context.Background()
	discord := &discordLike{}
	srv := httptest.NewServer(discord)
	defer srv.Close()
	now := time.Unix(1_728_000_000, 0)
	q := &Queue{Name: "operator", Channels: []Channel{Webhook{Format: "discord", URL: srv.URL, HTTP: srv.Client()}}, Now: func() time.Time { return now }}
	for i := range 12 {
		q.Put(Alert{Severity: Info, Code: fmt.Sprintf("governance_limits_queued_%d", i), Message: strings.Repeat("m", 250), Time: now})
	}
	q.Flush(ctx)
	got := discord.delivered()
	if len(got) != 1 || !strings.Contains(got[0], "12 notices") || !strings.HasSuffix(got[0], " [truncated]") || len(got[0]) != 2000 {
		t.Fatalf("delivered %q", got)
	}
	if n, _ := q.Waiting(ctx); n != 0 {
		t.Fatalf("%d copies wait", n)
	}
}

func TestACopyItsChannelRefusesIsDroppedWithoutRestingTheLane(t *testing.T) {
	ctx := context.Background()
	discord := &discordLike{}
	srv := httptest.NewServer(discord)
	defer srv.Close()
	now := time.Unix(1_728_000_000, 0)
	q := &Queue{Name: "operator", Channels: []Channel{Webhook{Format: "discord", URL: srv.URL, HTTP: srv.Client()}}, Now: func() time.Time { return now }}
	for i := range 2 * failuresToRest {
		q.Put(Alert{Severity: Critical, Code: fmt.Sprintf("malformed_%d", i), Time: now})
	}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	q.Flush(ctx)
	if got := discord.delivered(); len(got) != 1 || !strings.Contains(got[0], "invariant") {
		t.Fatalf("delivered %q", got)
	}
	if n, _ := q.Waiting(ctx); n != 0 {
		t.Fatalf("%d refused copies wait for a retry", n)
	}
	if q.Stalled(now.Add(time.Hour), 10*time.Minute) {
		t.Fatal("a channel taking alerts is stalled")
	}
	// A deleted webhook refuses every copy, which still stops the heartbeat.
	discord.mu.Lock()
	discord.deleted = true
	discord.mu.Unlock()
	q.Put(Alert{Severity: Warning, Code: "hot_balance_low", Time: now})
	q.Flush(ctx)
	if q.Stalled(now.Add(9*time.Minute), 10*time.Minute) || !q.Stalled(now.Add(11*time.Minute), 10*time.Minute) {
		t.Fatal("a channel refusing every copy for 11 minutes is not stalled")
	}
}

// hook answers status to its first refusals requests, as a Telegram chat being re-added answers
// 400, then takes every message.
type hook struct {
	mu       sync.Mutex
	status   int
	refusals int
	taken    []string
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.refusals != 0 {
		h.refusals--
		w.WriteHeader(h.status)
		return
	}
	h.taken = append(h.taken, string(b))
}

func (h *hook) got(s string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, b := range h.taken {
		if strings.Contains(b, s) {
			n++
		}
	}
	return n
}

func TestARefusedCriticalGoesToTheOtherChannelsAndTestsGoOnUntilAnAlertIsTaken(t *testing.T) {
	ctx := context.Background()
	telegram, discord := &hook{status: http.StatusBadRequest, refusals: 1}, &hook{}
	st, sd := httptest.NewServer(telegram), httptest.NewServer(discord)
	defer st.Close()
	defer sd.Close()
	now := time.Unix(1_728_000_000, 0)
	q := &Queue{Name: "operator", Service: "watcher", TestEvery: 5 * time.Minute, Now: func() time.Time { return now }, Channels: []Channel{
		Webhook{Format: "telegram", URL: st.URL + "/bot1/sendMessage?chat_id=1", HTTP: st.Client()},
		Webhook{Format: "discord", URL: sd.URL, HTTP: sd.Client()},
	}}
	q.Put(Alert{Service: "watcher", Severity: Critical, Code: "early_attestation_7", Message: "asp key stolen", Time: now})
	q.Flush(ctx)
	q.Flush(ctx)
	name := q.channelName(0)
	if discord.got("early_attestation_7") != 2 || discord.got("the "+name+" channel refused this alert") != 1 || telegram.got("early_attestation_7") != 0 {
		t.Fatalf("discord took %d copies, telegram %d", discord.got("early_attestation_7"), telegram.got("early_attestation_7"))
	}
	if telegram.got("channel_test") != 0 {
		t.Fatal("tested right after the refusal")
	}
	// Nothing else comes: a test the refusing channel takes clears its failing, so the heartbeat
	// goes on, but not its refusal, so it is tested again until it takes an alert.
	for range 20 {
		now = now.Add(time.Minute)
		q.Flush(ctx)
	}
	if telegram.got("channel_test") != 4 || q.Stalled(now, 10*time.Minute) || !q.lane(0).refusing {
		t.Fatalf("%d tests, stalled %v", telegram.got("channel_test"), q.Stalled(now, 10*time.Minute))
	}
	q.Put(Alert{Service: "watcher", Severity: Warning, Code: "hot_balance_low", Time: now})
	q.Flush(ctx)
	for range 20 {
		now = now.Add(time.Minute)
		q.Flush(ctx)
	}
	if telegram.got("hot_balance_low") != 1 || telegram.got("channel_test") != 4 || q.lane(0).refusing {
		t.Fatalf("after an alert it took: %d tests", telegram.got("channel_test"))
	}
	// A channel that keeps refusing, as a deleted webhook does, stays stalled though tested.
	telegram.mu.Lock()
	telegram.status, telegram.refusals = http.StatusNotFound, -1
	telegram.mu.Unlock()
	q.Put(Alert{Service: "watcher", Severity: Warning, Code: "hot_balance_low_again", Time: now})
	for range 20 {
		q.Flush(ctx)
		now = now.Add(time.Minute)
	}
	if !q.Stalled(now, 10*time.Minute) {
		t.Fatal("a channel refusing every test is not stalled")
	}
	// A rerouted alert the other channel refuses too is not rerouted back.
	discord.mu.Lock()
	discord.status, discord.refusals = http.StatusBadRequest, -1
	discord.mu.Unlock()
	q.Put(Alert{Service: "watcher", Severity: Critical, Code: "invariant", Time: now})
	for range 3 {
		q.Flush(ctx)
	}
	if n, _ := q.Waiting(ctx); n != 0 {
		t.Fatalf("%d copies circle between refusing channels", n)
	}
}

// named is a channel with a name of its own.
type named struct {
	Channel
	name string
}

func (n named) Name() string { return n.name }

func TestStoredCopiesFollowTheirChannelWhereverTheConfigurationPutsIt(t *testing.T) {
	ctx := context.Background()
	store := outboxStore(t)
	now := time.Unix(1_728_000_000, 0)
	clock := func() time.Time { return now }
	a, b := &recorder{}, &recorder{}
	q := &Queue{Name: "operator", Store: store, Now: clock, Channels: []Channel{named{a, "a"}, named{b, "b"}, named{&counted{}, "c"}}}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	q.Flush(ctx)
	// The middle channel is taken out: the third one, now second, still gets its own copy.
	now = now.Add(time.Hour)
	c := &recorder{}
	restarted := &Queue{Name: "operator", Store: store, Now: clock, Channels: []Channel{named{a, "a"}, named{c, "c"}}}
	restarted.Flush(ctx)
	if len(c.sent) != 1 || len(a.sent) != 1 {
		t.Fatalf("the third channel got %d, the first %d", len(c.sent), len(a.sent))
	}
	if n, err := restarted.Waiting(ctx); err != nil || n != 0 {
		t.Fatalf("%d copies wait, %v", n, err)
	}
	// A copy stored by place before names is named by the channel now at its place.
	old := fmt.Sprintf(`{"code": "old", "time": %q}`, now.UTC().Format(time.RFC3339))
	if _, err := store.Pool.Exec(ctx, `INSERT INTO alert_outbox (queue, channel, alert, next_at, rank) VALUES ('operator', 1, $1, 0, 0)`, old); err != nil {
		t.Fatal(err)
	}
	upgraded := &Queue{Name: "operator", Store: store, Now: clock, Channels: []Channel{named{a, "a"}, named{c, "c"}}}
	upgraded.Flush(ctx)
	if len(c.sent) != 2 || c.sent[1].Code != "old" {
		t.Fatalf("the old copy went to %+v", c.sent)
	}
}

func TestAStoredRerouteIsKeptBeforeTheRefusedCopyGoes(t *testing.T) {
	ctx := context.Background()
	store := outboxStore(t)
	now := time.Unix(1_728_000_000, 0)
	refusing, other := &hook{status: http.StatusBadRequest, refusals: -1}, &hook{status: http.StatusServiceUnavailable, refusals: -1}
	sr, so := httptest.NewServer(refusing), httptest.NewServer(other)
	defer sr.Close()
	defer so.Close()
	channels := []Channel{Webhook{Format: "discord", URL: sr.URL, HTTP: sr.Client()}, Webhook{Format: "discord", URL: so.URL, HTTP: so.Client()}}
	q := &Queue{Name: "operator", Store: store, Now: func() time.Time { return now }, Channels: channels}
	codes := func() map[string]int {
		rows, err := store.Pool.Query(ctx, `SELECT name, alert->>'code' FROM alert_outbox`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]int{}
		for rows.Next() {
			var name, code string
			if err := rows.Scan(&name, &code); err != nil {
				t.Fatal(err)
			}
			out[name+" "+code]++
		}
		return out
	}
	q.Put(Alert{Severity: Critical, Code: "invariant", Time: now})
	q.flushLane(ctx, 0)
	// The refused copy is gone and the other channel holds the reroute beside its own copy, which
	// it could not take yet.
	got := codes()
	if len(got) != 2 || got[q.channelName(1)+" invariant"] != 1 || got[q.channelName(1)+" invariant_rerouted"] != 1 {
		t.Fatalf("outbox %v", got)
	}
	// When the store cannot keep the reroute, it waits in memory and the refused copy still goes.
	if _, err := store.Pool.Exec(ctx, `DELETE FROM alert_outbox`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool.Exec(ctx, `ALTER TABLE alert_outbox ADD CONSTRAINT no_reroutes CHECK (alert->>'code' NOT LIKE '%_rerouted')`); err != nil {
		t.Fatal(err)
	}
	q.Put(Alert{Severity: Critical, Code: "invariant_2", Time: now})
	q.flushLane(ctx, 0)
	if got := codes(); got[q.channelName(0)+" invariant_2"] != 0 || got[q.channelName(1)+" invariant_2"] != 1 {
		t.Fatalf("outbox %v", got)
	}
	q.mu.Lock()
	kept := len(q.pending) == 1 && q.pending[0].channel == 1 && q.pending[0].alert.Code == "invariant_2_rerouted"
	q.pending = nil
	q.mu.Unlock()
	if !kept {
		t.Fatalf("in memory %+v", q.pending)
	}
	// The reroute and the drop are one transaction: a drop that fails takes the stored reroute
	// back with it.
	for _, stmt := range []string{
		`DELETE FROM alert_outbox`, `ALTER TABLE alert_outbox DROP CONSTRAINT no_reroutes`,
		`CREATE FUNCTION keep_rows() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'kept'; END $$`,
		`CREATE TRIGGER keep_rows BEFORE DELETE ON alert_outbox FOR EACH ROW EXECUTE FUNCTION keep_rows()`,
	} {
		if _, err := store.Pool.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	q.Put(Alert{Severity: Critical, Code: "invariant_3", Time: now})
	q.flushLane(ctx, 0)
	if got := codes(); got[q.channelName(1)+" invariant_3_rerouted"] != 0 {
		t.Fatalf("a reroute outlived its failed drop: %v", got)
	}
}

func TestTheLanesShowTheirChannelsByNameAndWhetherTheyTakeAlerts(t *testing.T) {
	ctx := context.Background()
	refusing := &hook{status: http.StatusNotFound, refusals: -1}
	srv := httptest.NewServer(refusing)
	defer srv.Close()
	now := time.Unix(1_728_000_000, 0)
	web := Webhook{Format: "discord", URL: srv.URL + "/api/webhooks/1/TOKEN", HTTP: srv.Client()}
	q := &Queue{Name: "operator", Now: func() time.Time { return now }, Channels: []Channel{web, named{&recorder{}, "spare"}}}
	if got := q.Lanes(now); len(got) != 2 || got[0] != (LaneState{Channel: web.Name()}) || got[1] != (LaneState{Channel: "spare"}) {
		t.Fatalf("lanes %+v", got)
	}
	q.Put(Alert{Severity: Warning, Code: "hot_balance_low", Time: now})
	q.Flush(ctx)
	later := now.Add(StalledAfter + time.Second)
	got := q.Lanes(later)
	if got[0] != (LaneState{Channel: web.Name(), Failing: now.Unix(), Refusing: true, Stalled: true}) || got[1] != (LaneState{Channel: "spare"}) {
		t.Fatalf("lanes %+v", got)
	}
	if body, _ := json.Marshal(got); strings.Contains(string(body), "TOKEN") {
		t.Fatalf("a lane shows its URL: %s", body)
	}
	if (&Alerter{}).Lanes(now) == nil {
		t.Fatal("an alerter without a queue shows no list")
	}
}
