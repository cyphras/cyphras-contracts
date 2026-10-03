// Package groth16 verifies the vault's Groth16 proofs off chain with the same key and checks as its
// verifier contract, so a relayer can refuse a forged or garbled proof before it costs a
// simulation, a screening lookup or a held slot.
package groth16

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	bnfp "github.com/consensys/gnark-crypto/ecc/bn254/fp"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// PublicInputs is the number of public inputs of the transaction circuit: root, public amount, ext
// data hash, domain, two nullifiers and two output commitments.
const PublicInputs = 8

// Key is a verifying key.
type Key struct {
	alpha              bn254.G1Affine
	beta, gamma, delta bn254.G2Affine
	ic                 [PublicInputs + 1]bn254.G1Affine
}

type keyJSON struct {
	Protocol string       `json:"protocol"`
	Curve    string       `json:"curve"`
	NPublic  int          `json:"nPublic"`
	Alpha    [3]string    `json:"vk_alpha_1"`
	Beta     [3][2]string `json:"vk_beta_2"`
	Gamma    [3][2]string `json:"vk_gamma_2"`
	Delta    [3][2]string `json:"vk_delta_2"`
	IC       [][3]string  `json:"IC"`
}

func decimal(s string) (bnfp.Element, error) {
	var e bnfp.Element
	if _, err := e.SetString(s); err != nil {
		return e, err
	}
	return e, nil
}

func keyG1(p [3]string) (bn254.G1Affine, error) {
	var out bn254.G1Affine
	if p[2] != "1" {
		return out, errors.New("groth16: key point not in affine form")
	}
	var err error
	if out.X, err = decimal(p[0]); err != nil {
		return out, err
	}
	if out.Y, err = decimal(p[1]); err != nil {
		return out, err
	}
	if !out.IsOnCurve() {
		return out, errors.New("groth16: key point not on the curve")
	}
	return out, nil
}

// keyG2 reads a snarkjs point, whose coordinates list c0 then c1.
func keyG2(p [3][2]string) (bn254.G2Affine, error) {
	var out bn254.G2Affine
	if p[2] != [2]string{"1", "0"} {
		return out, errors.New("groth16: key point not in affine form")
	}
	coords := []*bnfp.Element{&out.X.A0, &out.X.A1, &out.Y.A0, &out.Y.A1}
	for i, s := range []string{p[0][0], p[0][1], p[1][0], p[1][1]} {
		e, err := decimal(s)
		if err != nil {
			return out, err
		}
		*coords[i] = e
	}
	if !out.IsOnCurve() || !out.IsInSubGroup() {
		return out, errors.New("groth16: key point not in G2")
	}
	return out, nil
}

// ParseKey reads a verification_key.json as snarkjs exports it.
func ParseKey(raw []byte) (*Key, error) {
	var j keyJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, fmt.Errorf("groth16: %w", err)
	}
	if j.Protocol != "groth16" || j.Curve != "bn128" || j.NPublic != PublicInputs || len(j.IC) != PublicInputs+1 {
		return nil, errors.New("groth16: not a key for the transaction circuit")
	}
	var k Key
	var err error
	if k.alpha, err = keyG1(j.Alpha); err != nil {
		return nil, err
	}
	for _, g := range []struct {
		dst *bn254.G2Affine
		src [3][2]string
	}{{&k.beta, j.Beta}, {&k.gamma, j.Gamma}, {&k.delta, j.Delta}} {
		if *g.dst, err = keyG2(g.src); err != nil {
			return nil, err
		}
	}
	for i, p := range j.IC {
		if k.ic[i], err = keyG1(p); err != nil {
			return nil, err
		}
	}
	return &k, nil
}

// coordinate reads one big-endian base-field element, refusing a non-canonical one.
func coordinate(b []byte) (bnfp.Element, error) {
	var e bnfp.Element
	err := e.SetBytesCanonical(b)
	return e, err
}

// proofG1 reads a point in the host encoding X || Y.
func proofG1(b [64]byte) (bn254.G1Affine, error) {
	var p bn254.G1Affine
	var err error
	if p.X, err = coordinate(b[:32]); err != nil {
		return p, err
	}
	if p.Y, err = coordinate(b[32:]); err != nil {
		return p, err
	}
	return p, nil
}

// proofG2 reads a point in the host encoding, which orders each coordinate c1 || c0.
func proofG2(b [128]byte) (bn254.G2Affine, error) {
	var p bn254.G2Affine
	coords := []*bnfp.Element{&p.X.A1, &p.X.A0, &p.Y.A1, &p.Y.A0}
	for i, c := range coords {
		e, err := coordinate(b[32*i : 32*(i+1)])
		if err != nil {
			return p, err
		}
		*c = e
	}
	return p, nil
}

// Verify reports whether the proof, in the host encoding, is valid for the inputs in the
// circuit's order. Like the verifier contract it refuses A or C off the curve or at infinity and
// B at infinity, and the pairing check refuses B outside G2.
func (k *Key) Verify(a [64]byte, b [128]byte, c [64]byte, inputs [PublicInputs]fr.Element) bool {
	pa, errA := proofG1(a)
	pb, errB := proofG2(b)
	pc, errC := proofG1(c)
	if errA != nil || errB != nil || errC != nil {
		return false
	}
	if pa.IsInfinity() || pc.IsInfinity() || pb.IsInfinity() || !pa.IsOnCurve() || !pc.IsOnCurve() || !pb.IsOnCurve() || !pb.IsInSubGroup() {
		return false
	}
	vkx := k.ic[0]
	for i, in := range inputs {
		var term bn254.G1Affine
		term.ScalarMultiplication(&k.ic[i+1], in.Big())
		vkx.Add(&vkx, &term)
	}
	var negA bn254.G1Affine
	negA.Neg(&pa)
	ok, err := bn254.PairingCheck([]bn254.G1Affine{negA, k.alpha, vkx, pc}, []bn254.G2Affine{pb, k.beta, k.gamma, k.delta})
	return err == nil && ok
}
