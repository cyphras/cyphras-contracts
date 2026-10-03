// Package poseidon2 implements the t = 2 Poseidon2 permutation over BN254 and the Merkle
// compression the vault computes with the CAP-0075 host function.
package poseidon2

import (
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

var (
	full    [8][2]fr.Element
	partial [56]fr.Element
)

func init() {
	for r, row := range fullRoundConstants {
		for i, c := range row {
			full[r][i] = mustHex(c)
		}
	}
	for r, c := range partialRoundConstants {
		partial[r] = mustHex(c)
	}
}

func mustHex(s string) fr.Element {
	e, err := fr.SetHex(s)
	if err != nil {
		panic(err)
	}
	return e
}

func sbox(x fr.Element) fr.Element {
	x2 := fr.Mul(x, x)
	x4 := fr.Mul(x2, x2)
	return fr.Mul(x4, x)
}

// external applies circ(2, 1).
func external(s0, s1 fr.Element) (fr.Element, fr.Element) {
	sum := fr.Add(s0, s1)
	return fr.Add(sum, s0), fr.Add(sum, s1)
}

// Permute applies 8 full and 56 partial rounds. The internal matrix is [[2, 1], [1, 3]], whose
// diagonal minus one is (1, 2).
func Permute(s0, s1 fr.Element) (fr.Element, fr.Element) {
	s0, s1 = external(s0, s1)
	for r := range 4 {
		s0, s1 = external(sbox(fr.Add(s0, full[r][0])), sbox(fr.Add(s1, full[r][1])))
	}
	for r := range 56 {
		x0 := sbox(fr.Add(s0, partial[r]))
		sum := fr.Add(x0, s1)
		s0, s1 = fr.Add(sum, x0), fr.Add(sum, fr.Add(s1, s1))
	}
	for r := 4; r < 8; r++ {
		s0, s1 = external(sbox(fr.Add(s0, full[r][0])), sbox(fr.Add(s1, full[r][1])))
	}
	return s0, s1
}

// Compress is the Merkle node hash (P(l, r) + (l, r))[0].
func Compress(l, r fr.Element) fr.Element {
	s0, _ := Permute(l, r)
	return fr.Add(s0, l)
}
