package tree

import (
	"encoding/json"
	"math/rand/v2"
	"os"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/poseidon2"
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

func vectors(t *testing.T) (zeros, leaves, roots []string) {
	t.Helper()
	raw, err := os.ReadFile(noteVectors)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Merkle struct {
			Zeros  []string `json:"zeros"`
			Leaves []string `json:"leaves"`
			Roots  []string `json:"roots_after_each_insert"`
		} `json:"merkle"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v.Merkle.Zeros, v.Merkle.Leaves, v.Merkle.Roots
}

// referenceRoot recomputes the root of a tree holding leaves from index 0, level by level.
func referenceRoot(leaves []fr.Element) fr.Element {
	level := append([]fr.Element(nil), leaves...)
	zero := fr.Element{}
	for range Depth {
		if len(level)%2 == 1 {
			level = append(level, zero)
		}
		next := make([]fr.Element, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next = append(next, poseidon2.Compress(level[i], level[i+1]))
		}
		level = next
		zero = poseidon2.Compress(zero, zero)
	}
	if len(level) == 0 {
		return zero
	}
	return level[0]
}

func TestAnEmptyTreeHasTheReferenceRoot(t *testing.T) {
	zeros, _, _ := vectors(t)
	var tr Tree
	if tr.Root() != field(t, zeros[Depth]) {
		t.Fatalf("empty root %s, want %s", tr.Root().Hex(), zeros[Depth])
	}
	// The empty root the vault fixtures prove shields against.
	if tr.Root().Hex() != "2dab419ddd63b813b7a156068546ace406b72a8a6207dbf388e6fe1c8174246c" {
		t.Fatalf("empty root %s", tr.Root().Hex())
	}
	for i, z := range zeros {
		if Zero(i) != field(t, z) {
			t.Fatalf("zero %d differs", i)
		}
	}
}

func TestPairInsertionMatchesTheReferenceVectors(t *testing.T) {
	_, leaves, roots := vectors(t)
	var tr Tree
	index, err := tr.AppendPair(field(t, leaves[0]), field(t, leaves[1]))
	if err != nil || index != 0 {
		t.Fatalf("first pair at %d: %v", index, err)
	}
	if tr.Root() != field(t, roots[1]) {
		t.Fatalf("root after one pair %s, want %s", tr.Root().Hex(), roots[1])
	}
	index, err = tr.AppendPair(field(t, leaves[2]), field(t, leaves[3]))
	if err != nil || index != 2 {
		t.Fatalf("second pair at %d: %v", index, err)
	}
	if tr.Root() != field(t, roots[3]) {
		t.Fatalf("root after two pairs %s, want %s", tr.Root().Hex(), roots[3])
	}
	if tr.Len() != 4 {
		t.Fatalf("len %d", tr.Len())
	}
}

func TestIncrementalRootsMatchAFullRecomputation(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	var tr Tree
	var leaves []fr.Element
	// 70 pairs cross every power-of-two boundary up to 128 leaves.
	for range 70 {
		l, rr := fr.SetUint64(r.Uint64()), fr.SetUint64(r.Uint64())
		leaves = append(leaves, l, rr)
		if _, err := tr.AppendPair(l, rr); err != nil {
			t.Fatal(err)
		}
		if tr.Root() != referenceRoot(leaves) {
			t.Fatalf("root differs after %d leaves", len(leaves))
		}
	}
}

func TestRepeatedCommitmentsAreSeparateLeaves(t *testing.T) {
	c := fr.SetUint64(42)
	var tr Tree
	for range 3 {
		if _, err := tr.AppendPair(c, c); err != nil {
			t.Fatal(err)
		}
	}
	want := referenceRoot([]fr.Element{c, c, c, c, c, c})
	if tr.Root() != want || tr.Len() != 6 {
		t.Fatal("repeated commitments were not kept as separate leaves")
	}
}

func TestStateRoundTrips(t *testing.T) {
	var tr Tree
	data, _ := tr.MarshalBinary()
	var empty Tree
	if err := empty.UnmarshalBinary(data); err != nil || empty.Root() != tr.Root() || empty.Len() != 0 {
		t.Fatalf("empty tree did not round trip: %v", err)
	}
	r := rand.New(rand.NewPCG(7, 8))
	for range 37 {
		if _, err := tr.AppendPair(fr.SetUint64(r.Uint64()), fr.SetUint64(r.Uint64())); err != nil {
			t.Fatal(err)
		}
	}
	data, _ = tr.MarshalBinary()
	var restored Tree
	if err := restored.UnmarshalBinary(data); err != nil {
		t.Fatal(err)
	}
	if restored.Root() != tr.Root() || restored.Len() != tr.Len() {
		t.Fatal("restored tree differs")
	}
	l, rr := fr.SetUint64(1), fr.SetUint64(2)
	if _, err := tr.AppendPair(l, rr); err != nil {
		t.Fatal(err)
	}
	if _, err := restored.AppendPair(l, rr); err != nil {
		t.Fatal(err)
	}
	if restored.Root() != tr.Root() {
		t.Fatal("restored tree diverges on the next insertion")
	}
	for _, bad := range [][]byte{nil, data[:len(data)-1], append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, data[8:]...)} {
		if err := restored.UnmarshalBinary(bad); err != ErrBadState {
			t.Fatalf("bad state accepted: %v", err)
		}
	}
}

func TestAFullTreeRefusesAnotherPair(t *testing.T) {
	tr := Tree{next: Capacity - 2}
	if _, err := tr.AppendPair(fr.Element{}, fr.Element{}); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.AppendPair(fr.Element{}, fr.Element{}); err != ErrFull {
		t.Fatalf("full tree accepted a pair: %v", err)
	}
}
