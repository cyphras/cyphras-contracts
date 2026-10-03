package vault

import (
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func TestTransfersAndBalancesDecode(t *testing.T) {
	const muxed = "MA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QKAAAAEPXD6YEZNZKQ"
	b64 := func(v xdr.ScVal) string {
		s, err := xdr.MarshalBase64(v)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	asset := xdr.ScString("native")
	account, err := AccountOf(muxed)
	if err != nil {
		t.Fatal(err)
	}
	raw := RawEvent{
		Topics: []string{b64(Symbol("transfer")), b64(addr(t, testRelayer)), b64(addr(t, account)), b64(xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &asset})},
		Value:  b64(Struct(Field{"amount", i128(t, 70)}, Field{"to_muxed_id", U64(9)})),
	}
	tr, err := DecodeTransfer(raw)
	if err != nil || tr.From != testRelayer || tr.To != account || tr.Amount.Int64() != 70 {
		t.Fatalf("muxed transfer %+v, %v", tr, err)
	}
	raw.Value = b64(i128(t, 5))
	if tr, err = DecodeTransfer(raw); err != nil || tr.Amount.Int64() != 5 {
		t.Fatalf("plain transfer %+v, %v", tr, err)
	}
	raw.Topics[0] = b64(Symbol("mint"))
	if _, err := DecodeTransfer(raw); !errors.Is(err, ErrMalformed) {
		t.Fatalf("mint: %v", err)
	}
	n, authorized, err := DecodeBalance(Struct(Field{"amount", i128(t, 12)}, Field{"authorized", Bool(true)}, Field{"clawback", Bool(false)}))
	if err != nil || n.Int64() != 12 || !authorized {
		t.Fatalf("balance %v, %v", n, err)
	}
	if _, err := TrustlineKey(testRelayer, "USDC:"+testRelayer); err != nil {
		t.Fatal(err)
	}
	if _, err := TrustlineKey(testRelayer, "native"); err == nil {
		t.Fatal("a trustline for the native asset")
	}
}
