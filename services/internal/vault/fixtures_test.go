package vault

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

const proofFixtures = "../../../contracts/vault/fixtures/proofs.json"

// The real proofs the vault's own tests run, from circuits/scripts/contract-fixtures.mjs.
type fixtureFile struct {
	NetworkID string `json:"network_id"`
	Vault     string `json:"vault"`
	EmptyRoot string `json:"empty_root"`
	Steps     []struct {
		Name   string `json:"name"`
		Call   string `json:"call"`
		Caller string `json:"caller"`
		Ext    struct {
			Vault       string `json:"vault"`
			NetworkID   string `json:"network_id"`
			Deadline    uint32 `json:"deadline"`
			ExtAmount   string `json:"ext_amount"`
			Fee         string `json:"fee"`
			Recipient   string `json:"recipient"`
			Relayer     string `json:"relayer"`
			Ciphertext0 string `json:"encrypted_output0"`
			Ciphertext1 string `json:"encrypted_output1"`
		} `json:"ext"`
		ExtXDR string `json:"ext_xdr"`
		Proof  struct {
			A            string   `json:"a"`
			B            string   `json:"b"`
			C            string   `json:"c"`
			Root         string   `json:"root"`
			PublicAmount string   `json:"public_amount"`
			ExtDataHash  string   `json:"ext_data_hash"`
			Nullifiers   []string `json:"input_nullifiers"`
			Commitments  []string `json:"output_commitments"`
		} `json:"proof"`
		RootAfter string `json:"root_after"`
	} `json:"steps"`
}

func loadFixtures(t *testing.T) fixtureFile {
	t.Helper()
	raw, err := os.ReadFile(proofFixtures)
	if err != nil {
		t.Fatal(err)
	}
	var f fixtureFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func mustField(t *testing.T, s string) fr.Element {
	t.Helper()
	e, err := fr.SetHex(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("field %q: %v", s, err)
	}
	return e
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("integer %q", s)
	}
	return n
}
