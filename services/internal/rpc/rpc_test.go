package rpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const (
	passphrase = "Test SDF Network ; September 2015"
	vaultID    = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"
)

func TestEntriesAreReadInBatchesOfTheRPCLimit(t *testing.T) {
	f := rpctest.New(passphrase, 900)
	var keys []xdr.LedgerKey
	for i := range 450 {
		k, err := vault.NullifierKey(vaultID, fr.SetUint64(uint64(i)).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k)
		if i%3 == 0 {
			live := uint32(5000 + i)
			f.SetContractData(k, xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &live)
		}
	}
	got, latest, err := rpc.Entries(context.Background(), f, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 150 || latest != 900 || f.CallCount("getLedgerEntries") != 3 {
		t.Fatalf("%d entries in %d calls", len(got), f.CallCount("getLedgerEntries"))
	}
	s, _ := rpc.KeyString(keys[3])
	if e := got[s]; e.LiveUntil == nil || *e.LiveUntil != 5003 {
		t.Fatal("live-until ledger lost")
	}
	if _, _, err := rpc.One(context.Background(), f, keys[1]); !errors.Is(err, rpc.ErrMissing) {
		t.Fatalf("missing entry: %v", err)
	}
}

func TestTheNetworkIsChecked(t *testing.T) {
	f := rpctest.New(passphrase, 1)
	if err := rpc.CheckNetwork(context.Background(), f, passphrase); err != nil {
		t.Fatal(err)
	}
	if err := rpc.CheckNetwork(context.Background(), f, "Public Global Stellar Network ; September 2015"); err == nil {
		t.Fatal("another network accepted")
	}
	if rpc.NetworkID(passphrase) != [32]byte{0xce, 0xe0, 0x30, 0x2d, 0x59, 0x84, 0x4d, 0x32, 0xbd, 0xca, 0x91, 0x5c, 0x82, 0x03, 0xdd, 0x44, 0xb3, 0x3f, 0xbb, 0x7e, 0xdc, 0x19, 0x05, 0x1e, 0xa3, 0x7a, 0xbe, 0xdf, 0x28, 0xec, 0xd4, 0x72} {
		t.Fatal("network id")
	}
}

func TestTheMaximumEntryTTLIsRead(t *testing.T) {
	f := rpctest.New(passphrase, 1)
	f.SetEntry(vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingStateArchival), xdr.LedgerEntryData{
		Type: xdr.LedgerEntryTypeConfigSetting,
		ConfigSetting: &xdr.ConfigSettingEntry{
			ConfigSettingId:       xdr.ConfigSettingIdConfigSettingStateArchival,
			StateArchivalSettings: &xdr.StateArchivalSettings{MaxEntryTtl: 3_110_400},
		},
	}, 1, nil)
	got, err := rpc.MaxEntryTTL(context.Background(), f)
	if err != nil || got != 3_110_400 {
		t.Fatalf("max ttl %d, %v", got, err)
	}
}
