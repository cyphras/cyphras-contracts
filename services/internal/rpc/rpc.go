// Package rpc is the narrow view of Stellar RPC the services use, so tests can replace it.
package rpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Client is the part of *rpcclient.Client the services use.
type Client interface {
	GetHealth(ctx context.Context) (protocol.GetHealthResponse, error)
	GetLatestLedger(ctx context.Context) (protocol.GetLatestLedgerResponse, error)
	GetNetwork(ctx context.Context) (protocol.GetNetworkResponse, error)
	GetEvents(ctx context.Context, req protocol.GetEventsRequest) (protocol.GetEventsResponse, error)
	GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error)
	GetFeeStats(ctx context.Context) (protocol.GetFeeStatsResponse, error)
	SimulateTransaction(ctx context.Context, req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error)
	SendTransaction(ctx context.Context, req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error)
	GetTransaction(ctx context.Context, req protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error)
}

var _ Client = (*rpcclient.Client)(nil)

// Dial returns a client for the RPC at url with bounded request times. Its errors never show the
// URL, which may carry an access key.
func Dial(rawURL string) Client {
	hide := []string{rawURL}
	if u, err := url.Parse(rawURL); err == nil {
		if rest := strings.TrimPrefix(u.RequestURI(), "/"); rest != "" {
			hide = append(hide, rest, url.PathEscape(rest))
		}
	}
	return scrubbed{inner: rpcclient.NewClient(rawURL, &http.Client{Timeout: 30 * time.Second}), hide: hide}
}

type scrubbed struct {
	inner *rpcclient.Client
	hide  []string
}

// hiddenError keeps the cause for errors.Is while its text leaves the URL out.
type hiddenError struct {
	text  string
	cause error
}

func (e hiddenError) Error() string { return e.text }
func (e hiddenError) Unwrap() error { return e.cause }

func (s scrubbed) clean(err error) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	for _, h := range s.hide {
		text = strings.ReplaceAll(text, h, "[rpc]")
	}
	if text == err.Error() {
		return err
	}
	return hiddenError{text: text, cause: err}
}

func (s scrubbed) GetHealth(ctx context.Context) (protocol.GetHealthResponse, error) {
	r, err := s.inner.GetHealth(ctx)
	return r, s.clean(err)
}

func (s scrubbed) GetLatestLedger(ctx context.Context) (protocol.GetLatestLedgerResponse, error) {
	r, err := s.inner.GetLatestLedger(ctx)
	return r, s.clean(err)
}

func (s scrubbed) GetNetwork(ctx context.Context) (protocol.GetNetworkResponse, error) {
	r, err := s.inner.GetNetwork(ctx)
	return r, s.clean(err)
}

func (s scrubbed) GetEvents(ctx context.Context, req protocol.GetEventsRequest) (protocol.GetEventsResponse, error) {
	r, err := s.inner.GetEvents(ctx, req)
	return r, s.clean(err)
}

func (s scrubbed) GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error) {
	r, err := s.inner.GetLedgerEntries(ctx, req)
	return r, s.clean(err)
}

func (s scrubbed) GetFeeStats(ctx context.Context) (protocol.GetFeeStatsResponse, error) {
	r, err := s.inner.GetFeeStats(ctx)
	return r, s.clean(err)
}

func (s scrubbed) SimulateTransaction(ctx context.Context, req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
	r, err := s.inner.SimulateTransaction(ctx, req)
	return r, s.clean(err)
}

func (s scrubbed) SendTransaction(ctx context.Context, req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
	r, err := s.inner.SendTransaction(ctx, req)
	return r, s.clean(err)
}

func (s scrubbed) GetTransaction(ctx context.Context, req protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
	r, err := s.inner.GetTransaction(ctx, req)
	return r, s.clean(err)
}

// NetworkID is the SHA-256 of the network passphrase.
func NetworkID(passphrase string) [32]byte {
	return sha256.Sum256([]byte(passphrase))
}

// CheckNetwork refuses an RPC that serves another network.
func CheckNetwork(ctx context.Context, c Client, passphrase string) error {
	n, err := c.GetNetwork(ctx)
	if err != nil {
		return fmt.Errorf("get network: %w", err)
	}
	if n.Passphrase != passphrase {
		return fmt.Errorf("the RPC serves %q, not %q", n.Passphrase, passphrase)
	}
	return nil
}

// Entry is one ledger entry with its archival state.
type Entry struct {
	Data         xdr.LedgerEntryData
	LastModified uint32
	// LiveUntil is the last ledger the entry is live in; nil for entries without a TTL. An archived
	// entry has one below the latest ledger.
	LiveUntil *uint32
}

// maxKeysPerRequest is the getLedgerEntries limit.
const maxKeysPerRequest = 200

// KeyString is the map key Entries uses for a ledger key.
func KeyString(k xdr.LedgerKey) (string, error) {
	return xdr.MarshalBase64(k)
}

// Entries reads ledger entries in batches and returns those that exist, keyed by KeyString, with
// the lowest latest ledger the batches reported.
func Entries(ctx context.Context, c Client, keys []xdr.LedgerKey) (map[string]Entry, uint32, error) {
	out := make(map[string]Entry, len(keys))
	var latest uint32
	for start := 0; start < len(keys); start += maxKeysPerRequest {
		batch := keys[start:min(start+maxKeysPerRequest, len(keys))]
		encoded := make([]string, len(batch))
		for i, k := range batch {
			s, err := KeyString(k)
			if err != nil {
				return nil, 0, err
			}
			encoded[i] = s
		}
		resp, err := c.GetLedgerEntries(ctx, protocol.GetLedgerEntriesRequest{Keys: encoded})
		if err != nil {
			return nil, 0, err
		}
		if latest == 0 || resp.LatestLedger < latest {
			latest = resp.LatestLedger
		}
		for _, e := range resp.Entries {
			var data xdr.LedgerEntryData
			if err := xdr.SafeUnmarshalBase64(e.DataXDR, &data); err != nil {
				return nil, 0, fmt.Errorf("decode entry: %w", err)
			}
			out[e.KeyXDR] = Entry{Data: data, LastModified: e.LastModifiedLedger, LiveUntil: e.LiveUntilLedgerSeq}
		}
	}
	return out, latest, nil
}

// ErrMissing reports a ledger entry that does not exist. An archived entry is still returned,
// with a LiveUntil below the latest ledger.
var ErrMissing = errors.New("rpc: ledger entry missing")

// One reads a single ledger entry.
func One(ctx context.Context, c Client, key xdr.LedgerKey) (Entry, uint32, error) {
	entries, latest, err := Entries(ctx, c, []xdr.LedgerKey{key})
	if err != nil {
		return Entry{}, 0, err
	}
	s, err := KeyString(key)
	if err != nil {
		return Entry{}, 0, err
	}
	e, ok := entries[s]
	if !ok {
		return Entry{}, latest, ErrMissing
	}
	return e, latest, nil
}

// ContractValue returns the value of a contract data entry.
func ContractValue(e Entry) (xdr.ScVal, error) {
	if e.Data.Type != xdr.LedgerEntryTypeContractData || e.Data.ContractData == nil {
		return xdr.ScVal{}, errors.New("rpc: not a contract data entry")
	}
	return e.Data.ContractData.Val, nil
}

// VaultInstance reads and decodes the vault's instance storage.
func VaultInstance(ctx context.Context, c Client, vaultID string) (vault.Instance, Entry, uint32, error) {
	key, err := vault.InstanceKey(vaultID)
	if err != nil {
		return vault.Instance{}, Entry{}, 0, err
	}
	e, latest, err := One(ctx, c, key)
	if err != nil {
		return vault.Instance{}, Entry{}, latest, err
	}
	v, err := ContractValue(e)
	if err != nil {
		return vault.Instance{}, Entry{}, latest, err
	}
	inst, err := vault.DecodeInstance(v)
	return inst, e, latest, err
}

// MaxEntryTTL reads the network's maximum entry TTL in ledgers.
func MaxEntryTTL(ctx context.Context, c Client) (uint32, error) {
	e, _, err := One(ctx, c, vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingStateArchival))
	if err != nil {
		return 0, err
	}
	if e.Data.ConfigSetting == nil || e.Data.ConfigSetting.StateArchivalSettings == nil {
		return 0, errors.New("rpc: no state archival settings")
	}
	return uint32(e.Data.ConfigSetting.StateArchivalSettings.MaxEntryTtl), nil
}

// BaseReserve reads the network's base reserve, in stroops, from the latest ledger's header.
func BaseReserve(ctx context.Context, c Client) (int64, error) {
	l, err := c.GetLatestLedger(ctx)
	if err != nil {
		return 0, err
	}
	// getLedgers gives the header as its history entry; the bare header is accepted too.
	var entry xdr.LedgerHeaderHistoryEntry
	if err := xdr.SafeUnmarshalBase64(l.LedgerHeader, &entry); err == nil {
		return int64(entry.Header.BaseReserve), nil
	}
	var header xdr.LedgerHeader
	if err := xdr.SafeUnmarshalBase64(l.LedgerHeader, &header); err != nil {
		return 0, fmt.Errorf("rpc: the latest ledger's header: %w", err)
	}
	return int64(header.BaseReserve), nil
}

// SorobanState is the size of the live Soroban state the network prices rent by, in bytes, and
// the rent of 1 KiB of persistent state over a rent period at it and at the network's target size,
// above which rent grows by the growth factor.
type SorobanState struct {
	Average, Target, Growth int64
	Rent1KB, TargetRent1KB  int64
}

// ReadSorobanState reads the window of live Soroban state sizes and the rent settings.
func ReadSorobanState(ctx context.Context, c Client) (SorobanState, error) {
	windowKey := vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingLiveSorobanStateSizeWindow)
	costKey := vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingContractLedgerCostV0)
	entries, _, err := Entries(ctx, c, []xdr.LedgerKey{windowKey, costKey})
	if err != nil {
		return SorobanState{}, err
	}
	var window []xdr.Uint64
	var cost *xdr.ConfigSettingContractLedgerCostV0
	for _, e := range entries {
		if s := e.Data.ConfigSetting; s != nil && s.LiveSorobanStateSizeWindow != nil {
			window = *s.LiveSorobanStateSizeWindow
		} else if s != nil && s.ContractLedgerCost != nil {
			cost = s.ContractLedgerCost
		}
	}
	if cost == nil {
		return SorobanState{}, errors.New("rpc: the network's state size settings are missing")
	}
	if err := CheckStateWindow(window, int64(cost.SorobanStateTargetSizeBytes)); err != nil {
		return SorobanState{}, err
	}
	// A near-empty reading would clear every alert on the state's size; a network that holds so
	// little is far from any level anyway.
	if StateAverage(window) < int64(cost.SorobanStateTargetSizeBytes)/100 {
		return SorobanState{}, errors.New("rpc: the network's state size window averages under 1% of its target")
	}
	st := SorobanState{Average: StateAverage(window), Target: int64(cost.SorobanStateTargetSizeBytes), Growth: int64(cost.SorobanStateRentFeeGrowthFactor)}
	low, high := int64(cost.RentFee1KbSorobanStateSizeLow), int64(cost.RentFee1KbSorobanStateSizeHigh)
	st.Rent1KB = RentPerKB(st.Average, low, high, st.Target, st.Growth)
	st.TargetRent1KB = RentPerKB(st.Target, low, high, st.Target, st.Growth)
	return st, nil
}

// maxStateSample bounds a plausible sample of the live Soroban state size, 10 TB, far above any
// network's and low enough that sums and products of it cannot overflow.
const maxStateSample = 10_000_000_000_000

// CheckStateWindow refuses a window of live Soroban state sizes, or a target, that no network
// holds: an empty window, an empty or oversized sample, or a target beyond maxStateSample. Such a
// reading is a broken or hostile RPC, not a state to price by.
func CheckStateWindow(window []xdr.Uint64, target int64) error {
	if len(window) == 0 {
		return errors.New("rpc: the network's state size window is empty")
	}
	if target <= 0 || target > maxStateSample {
		return fmt.Errorf("rpc: the network's state size target of %d bytes is implausible", target)
	}
	for _, n := range window {
		if n == 0 || uint64(n) > maxStateSample {
			return fmt.Errorf("rpc: the network's state size window holds an implausible %d bytes", uint64(n))
		}
	}
	return nil
}

// StateAverage is the mean of the network's window of live Soroban state sizes.
func StateAverage(window []xdr.Uint64) int64 {
	var sum uint64
	for _, n := range window {
		sum += uint64(n)
	}
	return int64(sum / uint64(len(window)))
}

// RentPerKB is the network's rent for 1 KiB of persistent state over a rent period, which grows
// with the size of the Soroban state as the host computes it.
func RentPerKB(size, low, high, target, growth int64) int64 {
	target = max(target, 1)
	ceilDiv := func(a, b int64) int64 { return (a + b - 1) / b }
	var fee int64
	if size < target {
		fee = ceilDiv((high-low)*size, target) + low
	} else {
		// The product passes int64 for a state far above its target; the fee then saturates.
		over := new(big.Int).Mul(big.NewInt(high-low), big.NewInt(size-target))
		over.Mul(over, big.NewInt(growth))
		over.Add(over, big.NewInt(target-1))
		over.Quo(over, big.NewInt(target))
		over.Add(over, big.NewInt(high))
		fee = math.MaxInt64
		if over.IsInt64() {
			fee = over.Int64()
		}
	}
	return max(fee, 1000)
}
