package alert

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
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

func TestARepeatWithinTheCooldownIsStillLogged(t *testing.T) {
	var logs bytes.Buffer
	a := &Alerter{Service: "keeper", Log: slog.New(slog.NewTextHandler(&logs, nil)), Cooldown: time.Hour}
	a.Raise(context.Background(), Warning, "balance_low", "holds %d", 5)
	a.Raise(context.Background(), Warning, "balance_low", "holds %d", 4)
	if !strings.Contains(logs.String(), "alert repeated") || !strings.Contains(logs.String(), "holds 4") {
		t.Fatalf("logs %q", logs.String())
	}
}
