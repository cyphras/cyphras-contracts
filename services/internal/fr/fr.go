// Package fr implements arithmetic in the BN254 scalar field, the field of every commitment,
// nullifier and Merkle node of the vault.
package fr

import (
	"encoding/hex"
	"errors"
	"math/big"
	"math/bits"
)

// Element is a field element in Montgomery form, as four little-endian 64-bit limbs.
type Element [4]uint64

// Modulus is the field order p.
var Modulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

var (
	q = Element{0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029}
	// qInvNeg is -q^-1 mod 2^64.
	qInvNeg uint64
	// rSquare is R^2 mod q with R = 2^256, which moves a value into Montgomery form.
	rSquare Element
)

// ErrNonCanonical reports an encoding of a value at or above the modulus.
var ErrNonCanonical = errors.New("fr: value is not below the field modulus")

func init() {
	inv := uint64(1)
	for range 6 {
		inv *= 2 - q[0]*inv
	}
	qInvNeg = -inv
	r2 := new(big.Int).Lsh(big.NewInt(1), 512)
	r2.Mod(r2, Modulus)
	rSquare = fromBigRaw(r2)
}

func fromBigRaw(v *big.Int) Element {
	var buf [32]byte
	v.FillBytes(buf[:])
	var e Element
	for i := range 4 {
		for j := range 8 {
			e[i] |= uint64(buf[31-8*i-j]) << (8 * j)
		}
	}
	return e
}

// SetBytes decodes a canonical 32-byte big-endian value.
func SetBytes(b [32]byte) (Element, error) {
	var e Element
	for i := range 4 {
		for j := range 8 {
			e[i] |= uint64(b[31-8*i-j]) << (8 * j)
		}
	}
	if !lessThanQ(&e) {
		return Element{}, ErrNonCanonical
	}
	mul(&e, &e, &rSquare)
	return e, nil
}

// SetHex decodes 64 hex digits, big-endian, with no prefix.
func SetHex(s string) (Element, error) {
	var b [32]byte
	if len(s) != 64 {
		return Element{}, errors.New("fr: hex value must be 64 digits")
	}
	if _, err := hex.Decode(b[:], []byte(s)); err != nil {
		return Element{}, err
	}
	return SetBytes(b)
}

// SetUint64 returns the element v.
func SetUint64(v uint64) Element {
	e := Element{v}
	mul(&e, &e, &rSquare)
	return e
}

// Bytes encodes the element as 32 big-endian bytes.
func (e Element) Bytes() [32]byte {
	one := Element{1}
	mul(&e, &e, &one)
	var b [32]byte
	for i := range 4 {
		for j := range 8 {
			b[31-8*i-j] = byte(e[i] >> (8 * j))
		}
	}
	return b
}

// Hex encodes the element as 64 lowercase hex digits.
func (e Element) Hex() string {
	b := e.Bytes()
	return hex.EncodeToString(b[:])
}

// Big returns the canonical integer value of the element.
func (e Element) Big() *big.Int {
	b := e.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// IsZero reports whether the element is zero.
func (e Element) IsZero() bool {
	return e == Element{}
}

// Add returns x + y.
func Add(x, y Element) Element {
	var z Element
	var c uint64
	z[0], c = bits.Add64(x[0], y[0], 0)
	z[1], c = bits.Add64(x[1], y[1], c)
	z[2], c = bits.Add64(x[2], y[2], c)
	z[3], _ = bits.Add64(x[3], y[3], c)
	// Both inputs are below q < 2^254, so the sum cannot carry out of 256 bits.
	if !lessThanQ(&z) {
		subQ(&z)
	}
	return z
}

// Mul returns x * y.
func Mul(x, y Element) Element {
	var z Element
	mul(&z, &x, &y)
	return z
}

func lessThanQ(z *Element) bool {
	for i := 3; i >= 0; i-- {
		if z[i] != q[i] {
			return z[i] < q[i]
		}
	}
	return false
}

func subQ(z *Element) {
	var b uint64
	z[0], b = bits.Sub64(z[0], q[0], 0)
	z[1], b = bits.Sub64(z[1], q[1], b)
	z[2], b = bits.Sub64(z[2], q[2], b)
	z[3], _ = bits.Sub64(z[3], q[3], b)
}

// mul sets z = x * y * R^-1 mod q with the coarsely integrated operand scanning method.
func mul(z, x, y *Element) {
	var t [6]uint64
	for i := range 4 {
		var c uint64
		for j := range 4 {
			c, t[j] = madd(x[j], y[i], t[j], c)
		}
		var carry uint64
		t[4], carry = bits.Add64(t[4], c, 0)
		t[5] = carry

		m := t[0] * qInvNeg
		c, _ = madd(m, q[0], t[0], 0)
		for j := 1; j < 4; j++ {
			c, t[j-1] = madd(m, q[j], t[j], c)
		}
		t[3], carry = bits.Add64(t[4], c, 0)
		t[4] = t[5] + carry
	}
	r := Element{t[0], t[1], t[2], t[3]}
	if t[4] != 0 || !lessThanQ(&r) {
		subQ(&r)
	}
	*z = r
}

// madd returns hi, lo of a*b + c + d.
func madd(a, b, c, d uint64) (uint64, uint64) {
	hi, lo := bits.Mul64(a, b)
	var carry uint64
	lo, carry = bits.Add64(lo, c, 0)
	hi += carry
	lo, carry = bits.Add64(lo, d, 0)
	hi += carry
	return hi, lo
}
