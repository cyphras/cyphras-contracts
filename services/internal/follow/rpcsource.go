// Package follow ingests the vault's events ledger by ledger, from RPC for the recent window and
// from archives for anything older, and hands each window to a sink in chain order.
package follow

import (
	"context"
	"errors"
	"fmt"
	"time"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Source returns the vault's raw events of the ledgers [from, to] in chain order.
type Source interface {
	Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error)
}

var (
	// ErrRetention reports ledgers older than the source keeps.
	ErrRetention = errors.New("follow: ledgers older than the source keeps")
	// ErrStalled reports a source that stopped short of the requested range.
	ErrStalled = errors.New("follow: source stopped before the end of the range")
)

// RPCSource reads getEvents, following the cursor inside each range, so a full page only means
// there is another page.
type RPCSource struct {
	Client rpc.Client
	Vault  string
	// PageLimit is the number of events per request.
	PageLimit uint
}

// Events implements Source.
func (s RPCSource) Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error) {
	limit := s.PageLimit
	if limit == 0 {
		limit = 1000
	}
	filter := []protocol.EventFilter{{
		EventType:   protocol.EventTypeSet{protocol.EventTypeContract: nil},
		ContractIDs: []string{s.Vault},
	}}
	req := protocol.GetEventsRequest{
		StartLedger: from, EndLedger: to + 1, Filters: filter,
		Pagination: &protocol.PaginationOptions{Limit: limit},
	}
	var out []vault.RawEvent
	progress := protocol.Cursor{Ledger: from}
	for {
		resp, err := s.Client.GetEvents(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.OldestLedger > from {
			return nil, fmt.Errorf("%w: ledger %d, oldest %d", ErrRetention, from, resp.OldestLedger)
		}
		for _, e := range resp.Events {
			c, err := protocol.ParseCursor(e.ID)
			if err != nil {
				return nil, fmt.Errorf("event id %q: %w", e.ID, err)
			}
			if c.Ledger > to {
				return out, nil
			}
			raw, err := toRaw(e, c)
			if err != nil {
				return nil, err
			}
			if raw.Contract != s.Vault {
				return nil, fmt.Errorf("%w: event of contract %s", vault.ErrMalformed, raw.Contract)
			}
			out = append(out, raw)
		}
		cursor, err := protocol.ParseCursor(resp.Cursor)
		if err != nil {
			return nil, fmt.Errorf("cursor %q: %w", resp.Cursor, err)
		}
		if uint(len(resp.Events)) < limit && cursor.Ledger >= to {
			return out, nil
		}
		if cursor.Cmp(progress) <= 0 {
			return nil, fmt.Errorf("%w: at ledger %d of %d", ErrStalled, cursor.Ledger, to)
		}
		progress = cursor
		req = protocol.GetEventsRequest{Filters: filter, Pagination: &protocol.PaginationOptions{Cursor: &cursor, Limit: limit}}
	}
}

func toRaw(e protocol.EventInfo, c protocol.Cursor) (vault.RawEvent, error) {
	if e.EventType != protocol.EventTypeContract {
		return vault.RawEvent{}, fmt.Errorf("%w: %s event", vault.ErrMalformed, e.EventType)
	}
	closed, err := time.Parse(time.RFC3339, e.LedgerClosedAt)
	if err != nil {
		return vault.RawEvent{}, fmt.Errorf("close time %q: %w", e.LedgerClosedAt, err)
	}
	if uint32(e.Ledger) != c.Ledger {
		return vault.RawEvent{}, fmt.Errorf("%w: event id and ledger disagree", vault.ErrMalformed)
	}
	return vault.RawEvent{
		Ledger: c.Ledger, ClosedAt: closed.Unix(), TxHash: e.TransactionHash,
		Tx: c.Tx, Op: c.Op, Index: c.Event,
		Contract: e.ContractID, Topics: e.TopicXDR, Value: e.ValueXDR,
	}, nil
}
