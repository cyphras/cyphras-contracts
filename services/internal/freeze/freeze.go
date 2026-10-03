// Package freeze reads the ledger keys validators have frozen under CAP-77 and tells which
// accounts and contracts they touch.
package freeze

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Set is the frozen list, indexed by what it touches.
type Set struct {
	// Keys holds every frozen key in its base64 XDR encoding.
	Keys map[string]bool
	// Accounts holds G accounts whose entries are frozen: the account, its trustlines, offers or
	// data, or a contract entry keyed by the account, such as its balance in an asset contract.
	Accounts map[string]bool
	// Contracts holds C addresses whose instance or data entries are frozen, or which appear in a
	// frozen contract entry's key.
	Contracts map[string]bool
	// Codes holds frozen wasm hashes.
	Codes map[[32]byte]bool
}

// Read fetches the frozen list from the ledger.
func Read(ctx context.Context, c rpc.Client) (Set, error) {
	entry, _, err := rpc.One(ctx, c, vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingFrozenLedgerKeys))
	if errors.Is(err, rpc.ErrMissing) {
		return Parse(nil)
	}
	if err != nil {
		return Set{}, err
	}
	if entry.Data.ConfigSetting == nil || entry.Data.ConfigSetting.FrozenLedgerKeys == nil {
		return Set{}, errors.New("freeze: not a frozen ledger keys setting")
	}
	return Parse(entry.Data.ConfigSetting.FrozenLedgerKeys.Keys)
}

// Parse indexes encoded ledger keys.
func Parse(keys []xdr.EncodedLedgerKey) (Set, error) {
	s := Set{Keys: map[string]bool{}, Accounts: map[string]bool{}, Contracts: map[string]bool{}, Codes: map[[32]byte]bool{}}
	for _, raw := range keys {
		var k xdr.LedgerKey
		if err := k.UnmarshalBinary(raw); err != nil {
			return Set{}, fmt.Errorf("freeze: frozen key: %w", err)
		}
		s.Keys[base64.StdEncoding.EncodeToString(raw)] = true
		switch k.Type {
		case xdr.LedgerEntryTypeAccount:
			s.addAccount(k.Account.AccountId)
		case xdr.LedgerEntryTypeTrustline:
			s.addAccount(k.TrustLine.AccountId)
		case xdr.LedgerEntryTypeOffer:
			s.addAccount(k.Offer.SellerId)
		case xdr.LedgerEntryTypeData:
			s.addAccount(k.Data.AccountId)
		case xdr.LedgerEntryTypeContractData:
			s.addAddress(k.ContractData.Contract)
			s.walk(k.ContractData.Key)
		case xdr.LedgerEntryTypeContractCode:
			s.Codes[k.ContractCode.Hash] = true
		}
	}
	return s, nil
}

func (s Set) addAccount(id xdr.AccountId) {
	if addr, err := id.GetAddress(); err == nil {
		s.Accounts[addr] = true
	}
}

func (s Set) addAddress(a xdr.ScAddress) {
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		s.addAccount(*a.AccountId)
	case xdr.ScAddressTypeScAddressTypeContract:
		if c, err := strkey.Encode(strkey.VersionByteContract, a.ContractId[:]); err == nil {
			s.Contracts[c] = true
		}
	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		if g, err := strkey.Encode(strkey.VersionByteAccountID, a.MuxedAccount.Ed25519[:]); err == nil {
			s.Accounts[g] = true
		}
	}
}

// walk records every address inside a contract data key.
func (s Set) walk(v xdr.ScVal) {
	switch v.Type {
	case xdr.ScValTypeScvAddress:
		s.addAddress(*v.Address)
	case xdr.ScValTypeScvVec:
		if v.Vec != nil && *v.Vec != nil {
			for _, item := range **v.Vec {
				s.walk(item)
			}
		}
	case xdr.ScValTypeScvMap:
		if v.Map != nil && *v.Map != nil {
			for _, e := range **v.Map {
				s.walk(e.Key)
				s.walk(e.Val)
			}
		}
	}
}

// Touches reports whether the freeze touches a G, M or C address.
func (s Set) Touches(address string) bool {
	account, err := vault.AccountOf(address)
	if err != nil {
		return false
	}
	return s.Accounts[account] || s.Contracts[account]
}

// Has reports whether a ledger key is frozen.
func (s Set) Has(k xdr.LedgerKey) bool {
	raw, err := k.MarshalBinary()
	if err != nil {
		return false
	}
	return s.Keys[base64.StdEncoding.EncodeToString(raw)]
}
