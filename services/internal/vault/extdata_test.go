package vault

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

func TestExtDataEncodingAndHashMatchTheVaultFixtures(t *testing.T) {
	f := loadFixtures(t)
	checked := 0
	for _, step := range f.Steps {
		if step.Call == "admit" {
			continue
		}
		e := step.Ext
		ext := ExtData{
			Vault:       e.Vault,
			NetworkID:   [32]byte(mustHex(t, e.NetworkID)),
			Deadline:    e.Deadline,
			ExtAmount:   mustInt(t, e.ExtAmount),
			Fee:         mustInt(t, e.Fee),
			Recipient:   e.Recipient,
			Relayer:     e.Relayer,
			Ciphertext0: mustHex(t, e.Ciphertext0),
			Ciphertext1: mustHex(t, e.Ciphertext1),
		}
		v, err := ext.ScVal()
		if err != nil {
			t.Fatalf("%s: %v", step.Name, err)
		}
		raw, err := v.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(raw) != step.ExtXDR {
			t.Fatalf("%s: ExtData XDR differs from the vault's encoding", step.Name)
		}
		hash, err := ext.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if hash != mustField(t, step.Proof.ExtDataHash) {
			t.Fatalf("%s: ext data hash %s, want %s", step.Name, hash.Hex(), step.Proof.ExtDataHash)
		}
		if PublicAmount(ext.ExtAmount, ext.Fee) != mustField(t, step.Proof.PublicAmount) {
			t.Fatalf("%s: public amount differs", step.Name)
		}
		checked++
	}
	if checked != 6 {
		t.Fatalf("checked %d steps", checked)
	}
}

func TestProofEncodingHasTheContractTypeShape(t *testing.T) {
	f := loadFixtures(t)
	step := f.Steps[0]
	p := Proof{
		A:            [64]byte(mustHex(t, step.Proof.A)),
		B:            [128]byte(mustHex(t, step.Proof.B)),
		C:            [64]byte(mustHex(t, step.Proof.C)),
		Root:         mustField(t, step.Proof.Root),
		PublicAmount: mustField(t, step.Proof.PublicAmount),
		ExtDataHash:  mustField(t, step.Proof.ExtDataHash),
		Nullifiers:   [2]fr.Element{mustField(t, step.Proof.Nullifiers[0]), mustField(t, step.Proof.Nullifiers[1])},
		Commitments:  [2]fr.Element{mustField(t, step.Proof.Commitments[0]), mustField(t, step.Proof.Commitments[1])},
	}
	v := p.ScVal()
	m, ok := v.GetMap()
	if !ok {
		t.Fatal("proof is not a map")
	}
	var keys []string
	for _, e := range *m {
		name, _ := symbolOf(e.Key)
		keys = append(keys, name)
	}
	want := []string{"ext_data_hash", "input_nullifiers", "output_commitments", "proof", "public_amount", "root"}
	if len(keys) != len(want) {
		t.Fatalf("keys %v", keys)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("keys %v, want %v", keys, want)
		}
	}
	inner, err := structOf((*m)[3].Val, "a", "b", "c")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := bytesOf(inner["b"]); len(b) != 128 {
		t.Fatalf("b has %d bytes", len(b))
	}
	nfs, err := vecOf((*m)[1].Val)
	if err != nil || len(nfs) != 2 {
		t.Fatalf("nullifiers: %v", err)
	}
	if got, _ := fieldOf(nfs[1]); got != p.Nullifiers[1] {
		t.Fatal("second nullifier differs")
	}
}

func TestAddressesRoundTrip(t *testing.T) {
	f := loadFixtures(t)
	for _, s := range []string{
		"GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH",
		"MA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QKAAAAEPXD6YEZNZKQ",
		f.Vault,
	} {
		v, err := Address(s)
		if err != nil {
			t.Fatal(err)
		}
		back, err := addressOf(v)
		if err != nil || back != s {
			t.Fatalf("%s round tripped to %s: %v", s, back, err)
		}
	}
	account, err := AccountOf("MA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QKAAAAEPXD6YEZNZKQ")
	if err != nil || account != "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3" {
		t.Fatalf("account of muxed address: %s %v", account, err)
	}
	for _, bad := range []string{"", "G", "GABC", "SA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3", "XYZ"} {
		if _, err := Address(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	pool := xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeLiquidityPool, LiquidityPoolId: &xdr.PoolId{}}
	if _, err := addressOf(xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &pool}); err == nil {
		t.Fatal("liquidity pool address accepted")
	}
}

func TestI128RoundTripsAndRefusesOverflow(t *testing.T) {
	for _, s := range []string{"0", "1", "-1", "-700000000", "170141183460469231731687303715884105727", "-170141183460469231731687303715884105728"} {
		n := mustInt(t, s)
		v, err := I128(n)
		if err != nil {
			t.Fatal(err)
		}
		back, err := i128Of(v)
		if err != nil || back.Cmp(n) != 0 {
			t.Fatalf("%s round tripped to %v", s, back)
		}
	}
	if _, err := I128(new(big.Int).Lsh(big.NewInt(1), 127)); err == nil {
		t.Fatal("2^127 accepted")
	}
}
