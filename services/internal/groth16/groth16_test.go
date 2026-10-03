package groth16

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

type fixtureProof struct {
	A            string   `json:"a"`
	B            string   `json:"b"`
	C            string   `json:"c"`
	Root         string   `json:"root"`
	PublicAmount string   `json:"public_amount"`
	ExtDataHash  string   `json:"ext_data_hash"`
	Domain       string   `json:"domain"`
	Nullifiers   []string `json:"input_nullifiers"`
	Commitments  []string `json:"output_commitments"`
}

func load(t *testing.T) (*Key, []fixtureProof) {
	t.Helper()
	raw, err := os.ReadFile("testdata/testnet-forgeable.json")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile("../vault/testdata/proofs.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Steps   []struct{ Proof fixtureProof } `json:"steps"`
		Refused []struct{ Proof fixtureProof } `json:"refused"`
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	var out []fixtureProof
	for _, s := range append(fixtures.Steps, fixtures.Refused...) {
		out = append(out, s.Proof)
	}
	return key, out
}

func decode(t *testing.T, p fixtureProof) ([64]byte, [128]byte, [64]byte, [PublicInputs]fr.Element) {
	t.Helper()
	bytes := func(s string, n int) []byte {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != n {
			t.Fatalf("point %q", s)
		}
		return b
	}
	field := func(s string) fr.Element {
		e, err := fr.SetHex(strings.TrimPrefix(s, "0x"))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	inputs := [PublicInputs]fr.Element{
		field(p.Root), field(p.PublicAmount), field(p.ExtDataHash), field(p.Domain),
		field(p.Nullifiers[0]), field(p.Nullifiers[1]), field(p.Commitments[0]), field(p.Commitments[1]),
	}
	return [64]byte(bytes(p.A, 64)), [128]byte(bytes(p.B, 128)), [64]byte(bytes(p.C, 64)), inputs
}

func TestTheFixtureProofsVerify(t *testing.T) {
	key, proofs := load(t)
	if len(proofs) < 5 {
		t.Fatalf("%d fixture proofs", len(proofs))
	}
	verified := 0
	for i, p := range proofs {
		if p.A == "" || p.Domain == "" {
			continue
		}
		a, b, c, inputs := decode(t, p)
		verified++
		if !key.Verify(a, b, c, inputs) {
			t.Fatalf("fixture proof %d does not verify", i)
		}
	}
	if verified < 5 {
		t.Fatalf("only %d fixture proofs checked", verified)
	}
}

func TestAProofForOtherInputsOrPointsIsRefused(t *testing.T) {
	key, proofs := load(t)
	a, b, c, inputs := decode(t, proofs[0])
	other := inputs
	other[3] = fr.SetUint64(7)
	if key.Verify(a, b, c, other) {
		t.Fatal("a proof verified for another domain")
	}
	swapped := inputs
	swapped[4], swapped[5] = inputs[5], inputs[4]
	if key.Verify(a, b, c, swapped) {
		t.Fatal("a proof verified with its nullifiers swapped")
	}
	if key.Verify(c, b, a, inputs) {
		t.Fatal("a proof verified with A and C swapped")
	}
	var zero [64]byte
	if key.Verify(zero, b, c, inputs) {
		t.Fatal("A at infinity accepted")
	}
	var off [64]byte
	off[63] = 1
	if key.Verify(off, b, c, inputs) {
		t.Fatal("A off the curve accepted")
	}
	big := b
	for i := range 32 {
		big[i] = 0xff
	}
	if key.Verify(a, big, c, inputs) {
		t.Fatal("a non-canonical coordinate accepted")
	}
}

func TestOnlyATransactionCircuitKeyParses(t *testing.T) {
	raw, err := os.ReadFile("testdata/testnet-forgeable.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"nPublic": 8`, `"nPublic": 7`, 1),
		strings.Replace(string(raw), `"groth16"`, `"plonk"`, 1),
		`{}`,
	} {
		if _, err := ParseKey([]byte(bad)); err == nil {
			t.Fatalf("parsed %.40q", bad)
		}
	}
}
