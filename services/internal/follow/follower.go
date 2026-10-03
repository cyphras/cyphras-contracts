package follow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Batch is one window of ledgers with the vault's events.
type Batch struct {
	From, To uint32
	Raw      []vault.RawEvent
	Txs      []vault.Tx
	// Latest is the RPC's latest ledger when the window was read, and LatestCloseTime its close
	// time in Unix seconds.
	Latest          uint32
	LatestCloseTime int64
}

// Sink receives windows in order. Apply must persist the window atomically.
type Sink interface {
	// Cursor returns the last ledger applied.
	Cursor() uint32
	Apply(ctx context.Context, b Batch) error
}

// ErrFault reports data that cannot be applied: an unknown topic, a malformed event or events that
// contradict the vault.
var ErrFault = errors.New("follow: ingest fault")

// Follower moves a sink from its cursor to the chain tip.
type Follower struct {
	RPC  rpc.Client
	Live Source
	// History serves ledgers older than the RPC keeps, tried in order.
	History []Source
	// Window is the most ledgers applied at once while catching up.
	Window uint32
	Sink   Sink
}

// Step applies the next window, if any ledger is new, and reports whether it applied one.
func (f *Follower) Step(ctx context.Context) (bool, error) {
	health, err := f.RPC.GetHealth(ctx)
	if err != nil {
		return false, fmt.Errorf("rpc health: %w", err)
	}
	if health.OldestLedger > health.LatestLedger {
		return false, fmt.Errorf("%w: the RPC keeps ledgers %d to %d", ErrRange, health.OldestLedger, health.LatestLedger)
	}
	next := f.Sink.Cursor() + 1
	if next > health.LatestLedger {
		return false, nil
	}
	window := max(f.Window, 1)
	to := min(next+window-1, health.LatestLedger)
	if next < health.OldestLedger {
		// Hand over to RPC as soon as it covers the range.
		to = min(to, health.OldestLedger-1)
	}
	raw, err := f.read(ctx, next, to, health.OldestLedger)
	if errors.Is(err, vault.ErrMalformed) {
		// Data the vault cannot have emitted is a fault whichever source gave it.
		return false, fmt.Errorf("%w: %w", ErrFault, err)
	}
	if err != nil {
		return false, err
	}
	events := make([]vault.Event, 0, len(raw))
	for _, r := range raw {
		if err := r.Valid(); err != nil {
			return false, fmt.Errorf("%w: ledger %d: %w", ErrFault, r.Ledger, err)
		}
		e, err := vault.Decode(r)
		if err != nil {
			return false, fmt.Errorf("%w: ledger %d: %w", ErrFault, r.Ledger, err)
		}
		events = append(events, e)
	}
	txs, err := vault.ParseTxs(events)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrFault, err)
	}
	b := Batch{From: next, To: to, Raw: raw, Txs: txs, Latest: health.LatestLedger, LatestCloseTime: health.LatestLedgerCloseTime}
	if err := f.Sink.Apply(ctx, b); err != nil {
		return false, err
	}
	return true, nil
}

func (f *Follower) read(ctx context.Context, from, to, oldest uint32) ([]vault.RawEvent, error) {
	if from >= oldest {
		return f.Live.Events(ctx, from, to)
	}
	if len(f.History) == 0 {
		return nil, fmt.Errorf("%w: ledger %d, RPC keeps from %d", ErrRetention, from, oldest)
	}
	var errs []error
	for _, h := range f.History {
		raw, err := h.Events(ctx, from, to)
		if err == nil {
			return raw, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// Run follows until ctx ends. Errors are passed to onError and retried with backoff; a fault is
// retried too, because the data might have come from a faulty RPC.
func (f *Follower) Run(ctx context.Context, poll time.Duration, onError func(error)) {
	poll = max(poll, 100*time.Millisecond)
	backoff := poll
	for ctx.Err() == nil {
		progressed, err := f.Step(ctx)
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			onError(err)
			sleep(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
		case progressed:
			backoff = poll
		default:
			backoff = poll
			sleep(ctx, poll)
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
