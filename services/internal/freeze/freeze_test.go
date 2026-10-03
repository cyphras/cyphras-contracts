package freeze

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const (
	account  = "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH"
	holder   = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
	vaultID  = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"
	tokenID  = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"
	stranger = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
)

func encode(t *testing.T, k xdr.LedgerKey, err error) xdr.EncodedLedgerKey {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := k.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTheFrozenListIsIndexedByWhatItTouches(t *testing.T) {
	accountKey, err := vault.AccountKey(account)
	balanceKey, err2 := vault.BalanceKey(tokenID, holder)
	instance, err3 := vault.InstanceKey(vaultID)
	code := vault.CodeKey([32]byte{7})
	keys := []xdr.EncodedLedgerKey{encode(t, accountKey, err), encode(t, balanceKey, err2), encode(t, instance, err3), encode(t, code, nil)}

	f := rpctest.New("Test SDF Network ; September 2015", 1)
	f.SetEntry(vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingFrozenLedgerKeys), xdr.LedgerEntryData{
		Type: xdr.LedgerEntryTypeConfigSetting,
		ConfigSetting: &xdr.ConfigSettingEntry{
			ConfigSettingId:  xdr.ConfigSettingIdConfigSettingFrozenLedgerKeys,
			FrozenLedgerKeys: &xdr.FrozenLedgerKeys{Keys: keys},
		},
	}, 1, nil)
	s, err := Read(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var muxed xdr.MuxedAccount
	if err := muxed.SetEd25519Address(account); err != nil {
		t.Fatal(err)
	}
	m := xdr.MuxedAccount{Type: xdr.CryptoKeyTypeKeyTypeMuxedEd25519, Med25519: &xdr.MuxedAccountMed25519{Id: 7, Ed25519: *muxed.Ed25519}}
	muxedAddress, err := m.GetAddress()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{account, holder, vaultID, tokenID, muxedAddress} {
		if !s.Touches(a) {
			t.Fatalf("%s not frozen", a)
		}
	}
	if s.Touches(stranger) {
		t.Fatal("an unrelated account is frozen")
	}
	if !s.Has(instance) || !s.Codes[[32]byte{7}] {
		t.Fatal("instance or code not found")
	}
}

func TestAnEmptyListFreezesNothing(t *testing.T) {
	s, err := Read(context.Background(), rpctest.New("Test SDF Network ; September 2015", 1))
	if err != nil || s.Touches(account) {
		t.Fatalf("empty list: %v", err)
	}
	if _, err := Parse([]xdr.EncodedLedgerKey{{1, 2, 3}}); err == nil {
		t.Fatal("garbage key accepted")
	}
}
