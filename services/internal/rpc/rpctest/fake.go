// Package rpctest is an in-memory Stellar RPC for tests. Its getEvents follows the server's
// paging rules: a scan window of 10,000 ledgers, an exclusive end ledger and a cursor that points
// at the last event of a full page or at the end of the scanned range.
package rpctest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// ScanLimit is the number of ledgers one getEvents request scans.
const ScanLimit = 10_000

// Fake implements rpc.Client.
type Fake struct {
	mu sync.Mutex

	Passphrase string
	Latest     uint32
	Oldest     uint32
	CloseTime  int64
	// BaseReserve is the base reserve, in stroops, the latest ledger's header carries.
	BaseReserve uint32
	FeeStats    protocol.GetFeeStatsResponse
	// Events must be in chain order.
	Events  []protocol.EventInfo
	entries map[string]protocol.LedgerEntryResult

	Simulate func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error)
	Send     func(protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error)
	Get      func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error)

	// Fail makes the named method fail.
	Fail  map[string]error
	Calls map[string]int
}

var _ rpc.Client = (*Fake)(nil)

// New returns a fake at the given latest ledger.
func New(passphrase string, latest uint32) *Fake {
	return &Fake{Passphrase: passphrase, Latest: latest, Oldest: 1, entries: map[string]protocol.LedgerEntryResult{}, Fail: map[string]error{}, Calls: map[string]int{}}
}

func (f *Fake) call(name string) error {
	f.Calls[name]++
	return f.Fail[name]
}

// SetEntry stores a ledger entry.
func (f *Fake) SetEntry(key xdr.LedgerKey, data xdr.LedgerEntryData, lastModified uint32, liveUntil *uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, err := rpc.KeyString(key)
	if err != nil {
		panic(err)
	}
	d, err := xdr.MarshalBase64(data)
	if err != nil {
		panic(err)
	}
	f.entries[k] = protocol.LedgerEntryResult{KeyXDR: k, DataXDR: d, LastModifiedLedger: lastModified, LiveUntilLedgerSeq: liveUntil}
}

// DeleteEntry removes a ledger entry.
func (f *Fake) DeleteEntry(key xdr.LedgerKey) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, _ := rpc.KeyString(key)
	delete(f.entries, k)
}

// LiveUntil returns the last ledger an entry is live in, and whether the entry exists with a TTL.
func (f *Fake) LiveUntil(key xdr.LedgerKey) (uint32, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, _ := rpc.KeyString(key)
	e, ok := f.entries[k]
	if !ok || e.LiveUntilLedgerSeq == nil {
		return 0, false
	}
	return *e.LiveUntilLedgerSeq, true
}

// SetLiveUntil moves the last ledger an existing entry is live in, as an extension or a
// restoration does.
func (f *Fake) SetLiveUntil(key xdr.LedgerKey, liveUntil uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, _ := rpc.KeyString(key)
	if e, ok := f.entries[k]; ok {
		e.LiveUntilLedgerSeq = &liveUntil
		f.entries[k] = e
	}
}

// SetContractData stores a contract data entry holding val.
func (f *Fake) SetContractData(key xdr.LedgerKey, val xdr.ScVal, lastModified uint32, liveUntil *uint32) {
	cd := key.MustContractData()
	data := xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractData, ContractData: &xdr.ContractDataEntry{
		Contract: cd.Contract, Key: cd.Key, Durability: cd.Durability, Val: val,
	}}
	f.SetEntry(key, data, lastModified, liveUntil)
}

// AddEvent appends an event and moves the latest ledger forward to it.
func (f *Fake) AddEvent(e protocol.EventInfo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Events = append(f.Events, e)
	f.Latest = max(f.Latest, uint32(e.Ledger))
}

// SetLatest moves the chain tip.
func (f *Fake) SetLatest(latest uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Latest = latest
}

// GetHealth implements rpc.Client.
func (f *Fake) GetHealth(context.Context) (protocol.GetHealthResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("getHealth"); err != nil {
		return protocol.GetHealthResponse{}, err
	}
	return protocol.GetHealthResponse{Status: "healthy", LatestLedger: f.Latest, OldestLedger: f.Oldest, LatestLedgerCloseTime: f.CloseTime}, nil
}

// GetLatestLedger implements rpc.Client.
func (f *Fake) GetLatestLedger(context.Context) (protocol.GetLatestLedgerResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("getLatestLedger"); err != nil {
		return protocol.GetLatestLedgerResponse{}, err
	}
	header, err := xdr.MarshalBase64(xdr.LedgerHeaderHistoryEntry{Header: xdr.LedgerHeader{
		LedgerSeq: xdr.Uint32(f.Latest), BaseReserve: xdr.Uint32(f.BaseReserve), ScpValue: xdr.StellarValue{CloseTime: xdr.TimePoint(f.CloseTime)},
	}})
	if err != nil {
		return protocol.GetLatestLedgerResponse{}, err
	}
	return protocol.GetLatestLedgerResponse{Sequence: f.Latest, LedgerCloseTime: f.CloseTime, LedgerHeader: header, ProtocolVersion: 26}, nil
}

// GetNetwork implements rpc.Client.
func (f *Fake) GetNetwork(context.Context) (protocol.GetNetworkResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("getNetwork"); err != nil {
		return protocol.GetNetworkResponse{}, err
	}
	return protocol.GetNetworkResponse{Passphrase: f.Passphrase, ProtocolVersion: 26}, nil
}

// GetFeeStats implements rpc.Client.
func (f *Fake) GetFeeStats(context.Context) (protocol.GetFeeStatsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("getFeeStats"); err != nil {
		return protocol.GetFeeStatsResponse{}, err
	}
	return f.FeeStats, nil
}

// GetLedgerEntries implements rpc.Client.
func (f *Fake) GetLedgerEntries(_ context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("getLedgerEntries"); err != nil {
		return protocol.GetLedgerEntriesResponse{}, err
	}
	if len(req.Keys) > 200 {
		return protocol.GetLedgerEntriesResponse{}, errors.New("too many keys")
	}
	resp := protocol.GetLedgerEntriesResponse{LatestLedger: f.Latest}
	for _, k := range req.Keys {
		if e, ok := f.entries[k]; ok {
			resp.Entries = append(resp.Entries, e)
		}
	}
	return resp, nil
}

// GetEvents implements rpc.Client with the server's paging rules.
func (f *Fake) GetEvents(_ context.Context, req protocol.GetEventsRequest) (protocol.GetEventsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.call("getEvents"); err != nil {
		return protocol.GetEventsResponse{}, err
	}
	if len(req.Filters) > protocol.MaxFiltersLimit {
		return protocol.GetEventsResponse{}, errors.New("maximum 5 filters per request")
	}
	for _, flt := range req.Filters {
		if len(flt.ContractIDs) > protocol.MaxContractIDsLimit || len(flt.Topics) > protocol.MaxTopicsLimit {
			return protocol.GetEventsResponse{}, errors.New("maximum 5 contract IDs and 5 topics per filter")
		}
	}
	start := protocol.Cursor{Ledger: req.StartLedger}
	limit := uint(100)
	if req.Pagination != nil {
		if req.Pagination.Cursor != nil {
			if req.StartLedger != 0 || req.EndLedger != 0 {
				return protocol.GetEventsResponse{}, errors.New("ledger ranges and cursor cannot both be set")
			}
			start = *req.Pagination.Cursor
			start.Event++
		}
		if req.Pagination.Limit > 0 {
			limit = req.Pagination.Limit
		}
	}
	if start.Ledger < f.Oldest || start.Ledger > f.Latest {
		return protocol.GetEventsResponse{}, fmt.Errorf("startLedger must be within the ledger range: %d - %d", f.Oldest, f.Latest)
	}
	end := min(start.Ledger+ScanLimit, f.Latest+1)
	if req.EndLedger != 0 {
		end = min(req.EndLedger, end)
	}
	var out []protocol.EventInfo
	for _, e := range f.Events {
		c, err := protocol.ParseCursor(e.ID)
		if err != nil {
			return protocol.GetEventsResponse{}, err
		}
		if c.Cmp(start) < 0 || c.Ledger >= end || !matches(req, e) {
			continue
		}
		out = append(out, e)
		if uint(len(out)) == limit {
			break
		}
	}
	resp := protocol.GetEventsResponse{Events: out, LatestLedger: f.Latest, OldestLedger: f.Oldest}
	if uint(len(out)) == limit {
		resp.Cursor = out[len(out)-1].ID
	} else {
		c := protocol.MaxCursor
		c.Ledger = end - 1
		resp.Cursor = c.String()
	}
	return resp, nil
}

func matches(req protocol.GetEventsRequest, e protocol.EventInfo) bool {
	if len(req.Filters) == 0 {
		return true
	}
	topics := make([]xdr.ScVal, len(e.TopicXDR))
	for i, t := range e.TopicXDR {
		if err := xdr.SafeUnmarshalBase64(t, &topics[i]); err != nil {
			return false
		}
	}
	for _, flt := range req.Filters {
		if len(flt.ContractIDs) > 0 && !slices.Contains(flt.ContractIDs, e.ContractID) {
			continue
		}
		if len(flt.Topics) == 0 {
			return true
		}
		for _, tf := range flt.Topics {
			if tf.Matches(topics) {
				return true
			}
		}
	}
	return false
}

// SimulateTransaction implements rpc.Client.
func (f *Fake) SimulateTransaction(_ context.Context, req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
	f.mu.Lock()
	err := f.call("simulateTransaction")
	hook := f.Simulate
	f.mu.Unlock()
	if err != nil {
		return protocol.SimulateTransactionResponse{}, err
	}
	if hook == nil {
		return protocol.SimulateTransactionResponse{}, errors.New("no simulation")
	}
	return hook(req)
}

// SendTransaction implements rpc.Client.
func (f *Fake) SendTransaction(_ context.Context, req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
	f.mu.Lock()
	err := f.call("sendTransaction")
	hook := f.Send
	f.mu.Unlock()
	if err != nil {
		return protocol.SendTransactionResponse{}, err
	}
	if hook == nil {
		return protocol.SendTransactionResponse{}, errors.New("no send")
	}
	return hook(req)
}

// GetTransaction implements rpc.Client.
func (f *Fake) GetTransaction(_ context.Context, req protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
	f.mu.Lock()
	err := f.call("getTransaction")
	hook := f.Get
	f.mu.Unlock()
	if err != nil {
		return protocol.GetTransactionResponse{}, err
	}
	if hook == nil {
		return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}, nil
	}
	return hook(req)
}

// CallCount returns how often a method was called.
func (f *Fake) CallCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Calls[name]
}

// EventInfo turns a raw vault event into what getEvents returns for it.
func EventInfo(r vault.RawEvent) protocol.EventInfo {
	return protocol.EventInfo{
		EventType:       protocol.EventTypeContract,
		Ledger:          int32(r.Ledger),
		LedgerClosedAt:  time.Unix(r.ClosedAt, 0).UTC().Format(time.RFC3339),
		ContractID:      r.Contract,
		ID:              protocol.Cursor{Ledger: r.Ledger, Tx: r.Tx, Op: r.Op, Event: r.Index}.String(),
		OpIndex:         r.Op,
		TxIndex:         r.Tx,
		TransactionHash: r.TxHash,
		TopicXDR:        r.Topics,
		ValueXDR:        r.Value,
	}
}
