package poseidon2

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

const noteVectors = "../../../circuits/test/vectors/notes.json"

func field(t *testing.T, s string) fr.Element {
	t.Helper()
	e, err := fr.SetHex(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The same known answer the contract's Poseidon2 crate pins.
func TestCompressMatchesTheKnownAnswer(t *testing.T) {
	got := Compress(fr.SetUint64(7), fr.SetUint64(11))
	want := "0960972bcfa9d858be6a1cca2c850d2eb0e5df1ad309192beeb95f8be328945f"
	if got.Hex() != want {
		t.Fatalf("compress(7, 11) = %s, want %s", got.Hex(), want)
	}
}

func TestZeroSubtreeRootsMatchTheVectors(t *testing.T) {
	raw, err := os.ReadFile(noteVectors)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Merkle struct {
			Levels int      `json:"levels"`
			Zeros  []string `json:"zeros"`
		} `json:"merkle"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Merkle.Zeros) != v.Merkle.Levels+1 || v.Merkle.Levels != 32 {
		t.Fatalf("unexpected vector shape: %d zeros at %d levels", len(v.Merkle.Zeros), v.Merkle.Levels)
	}
	node := fr.Element{}
	for i, want := range v.Merkle.Zeros {
		if node != field(t, want) {
			t.Fatalf("zeros[%d] = %s, want %s", i, node.Hex(), want)
		}
		node = Compress(node, node)
	}
}

func TestCompressionOfTheLargestInputsIsReduced(t *testing.T) {
	max := field(t, "30644e72e131a029b85045b68181585d2833e84879b97091"+"43e1f593f0000000")
	for _, pair := range [][2]fr.Element{{max, max}, {max, {}}} {
		out := Compress(pair[0], pair[1])
		if out.Big().Cmp(fr.Modulus) >= 0 {
			t.Fatal("compression is not reduced")
		}
	}
}

func BenchmarkCompress(b *testing.B) {
	l, r := fr.SetUint64(7), fr.SetUint64(11)
	for b.Loop() {
		l = Compress(l, r)
	}
}
