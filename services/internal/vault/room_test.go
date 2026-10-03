package vault

import (
	"math/big"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func mustKeys(t *testing.T, keys ...func() (xdr.LedgerKey, error)) []string {
	t.Helper()
	var out []string
	for _, f := range keys {
		k, err := f()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := k.MarshalBinary()
		out = append(out, string(b))
	}
	return out
}

func names(keys []xdr.LedgerKey) []string {
	var out []string
	for _, k := range keys {
		b, _ := k.MarshalBinary()
		out = append(out, string(b))
	}
	return out
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAPaymentWritesTheEntryTheAssetKeepsItsHoldersBalanceIn(t *testing.T) {
	token := strkey.MustEncode(strkey.VersionByteContract, make([]byte, 32))
	holder, issuer := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	contract := strkey.MustEncode(strkey.VersionByteContract, append(make([]byte, 31), 7))
	m, err := xdr.MuxedAccountFromAccountId(holder, 42)
	if err != nil {
		t.Fatal(err)
	}
	usdc := "USDC:" + issuer
	for _, c := range []struct {
		asset, to string
		want      []string
	}{
		{"native", holder, mustKeys(t, func() (xdr.LedgerKey, error) { return AccountKey(holder) })},
		{"native", m.Address(), mustKeys(t, func() (xdr.LedgerKey, error) { return AccountKey(holder) })},
		{usdc, holder, mustKeys(t, func() (xdr.LedgerKey, error) { return TrustlineKey(holder, usdc) })},
		{usdc, issuer, nil},
		{usdc, contract, mustKeys(t, func() (xdr.LedgerKey, error) { return BalanceKey(token, contract) })},
	} {
		got, err := PayKeys(token, c.asset, c.to)
		if err != nil || !same(names(got), c.want) {
			t.Fatalf("%s to %s: %d keys, %v", c.asset, c.to, len(got), err)
		}
	}
}

func TestATransactThatPaysIsGivenBothPathsOfTheQueue(t *testing.T) {
	vault := strkey.MustEncode(strkey.VersionByteContract, append(make([]byte, 31), 1))
	token := strkey.MustEncode(strkey.VersionByteContract, make([]byte, 32))
	recipient, relayer := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	exits := func(first uint64) []func() (xdr.LedgerKey, error) {
		var out []func() (xdr.LedgerKey, error)
		for id := first; id <= first+2; id++ {
			out = append(out, func() (xdr.LedgerKey, error) { return ExitKey(vault, id) })
		}
		return out
	}
	own := func() (xdr.LedgerKey, error) { return BalanceKey(token, vault) }
	paid := func() (xdr.LedgerKey, error) { return AccountKey(recipient) }
	fee := func() (xdr.LedgerKey, error) { return AccountKey(relayer) }
	for name, c := range map[string]struct {
		amount, fee int64
		want        []string
	}{
		"an unshield":           {-10, 2, mustKeys(t, append([]func() (xdr.LedgerKey, error){own, paid, fee}, exits(9)...)...)},
		"a transfer":            {0, 2, mustKeys(t, append([]func() (xdr.LedgerKey, error){own, fee}, exits(9)...)...)},
		"an exit paying no fee": {-10, 0, mustKeys(t, append([]func() (xdr.LedgerKey, error){own, paid}, exits(9)...)...)},
		"a transfer of nothing": {0, 0, nil},
	} {
		ext := ExtData{ExtAmount: big.NewInt(c.amount), Fee: big.NewInt(c.fee), Recipient: recipient, Relayer: relayer}
		got, err := TransactRoom(vault, token, "native", ext, 9, 2)
		if err != nil || !same(names(got), c.want) {
			t.Fatalf("%s: %d keys, %v", name, len(got), err)
		}
	}
	// The tail is the exit a simulation that queued wrote; another contract's entries are not.
	other := strkey.MustEncode(strkey.VersionByteContract, append(make([]byte, 31), 2))
	fp := xdr.LedgerFootprint{ReadWrite: []xdr.LedgerKey{
		mustKey(t, func() (xdr.LedgerKey, error) { return ExitKey(other, 99) }),
		mustKey(t, func() (xdr.LedgerKey, error) { return StrandedKey(vault, 50) }),
		mustKey(t, func() (xdr.LedgerKey, error) { return ExitKey(vault, 7) }),
	}}
	if tail, ok := QueuedExit(vault, fp); !ok || tail != 7 {
		t.Fatalf("tail %d, %v", tail, ok)
	}
	if _, ok := QueuedExit(vault, xdr.LedgerFootprint{ReadOnly: fp.ReadWrite}); ok {
		t.Fatal("an exit only read was taken for one written")
	}
}

func mustKey(t *testing.T, f func() (xdr.LedgerKey, error)) xdr.LedgerKey {
	t.Helper()
	k, err := f()
	if err != nil {
		t.Fatal(err)
	}
	return k
}
