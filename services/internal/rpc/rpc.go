// Package rpc is the narrow view of Stellar RPC the services use, so tests can replace it.
package rpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Client is implemented by *rpcclient.Client.
type Client interface {
	GetHealth(ctx context.Context) (protocol.GetHealthResponse, error)
	GetNetwork(ctx context.Context) (protocol.GetNetworkResponse, error)
	GetEvents(ctx context.Context, req protocol.GetEventsRequest) (protocol.GetEventsResponse, error)
	GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error)
	GetFeeStats(ctx context.Context) (protocol.GetFeeStatsResponse, error)
	SimulateTransaction(ctx context.Context, req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error)
	SendTransaction(ctx context.Context, req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error)
	GetTransaction(ctx context.Context, req protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error)
}

var _ Client = (*rpcclient.Client)(nil)

// Dial returns a client for the RPC at url with bounded request times.
func Dial(url string) *rpcclient.Client {
	return rpcclient.NewClient(url, &http.Client{Timeout: 30 * time.Second})
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
	// LiveUntil is the last ledger the entry is live in; nil for entries without a TTL.
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

// ErrMissing reports a ledger entry that does not exist or is archived.
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
