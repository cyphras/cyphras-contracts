package rpc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestTheBaseReserveIsReadFromEitherFormOfTheHeader(t *testing.T) {
	header := xdr.LedgerHeader{LedgerSeq: 7, BaseReserve: 7_500_000}
	entry, _ := xdr.MarshalBase64(xdr.LedgerHeaderHistoryEntry{Header: header})
	bare, _ := xdr.MarshalBase64(header)
	for _, h := range []string{entry, bare} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"id":"00","protocolVersion":26,"sequence":7,"closeTime":"1","headerXdr":"` + h + `"}}`))
		}))
		got, err := rpc.BaseReserve(context.Background(), rpc.Dial(srv.URL))
		srv.Close()
		if err != nil || got != 7_500_000 {
			t.Fatalf("reserve %d, %v", got, err)
		}
	}
	f := rpctest.New(passphrase, 1)
	f.BaseReserve = 5_000_000
	if got, err := rpc.BaseReserve(context.Background(), f); err != nil || got != 5_000_000 {
		t.Fatalf("reserve %d, %v", got, err)
	}
}

func TestErrorsLeaveTheAccessKeyOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusUnauthorized)
	}))
	defer srv.Close()
	for _, u := range []string{srv.URL + "/v1/aaaaaaaaaaaa?token=bbbbbbbbbbbb", "http://127.0.0.1:1/aaaaaaaaaaaa"} {
		_, err := rpc.Dial(u).GetHealth(context.Background())
		if err == nil || strings.Contains(err.Error(), "aaaa") || strings.Contains(err.Error(), "bbbb") {
			t.Fatalf("error %v", err)
		}
	}
	_, err := rpc.Dial("http://127.0.0.1:1/aaaaaaaaaaaa").GetHealth(canceled())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("the cause is lost: %v", err)
	}
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
