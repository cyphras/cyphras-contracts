package fr

import (
	"math/big"
	"math/rand/v2"
	"testing"
)

func randomBig(r *rand.Rand) *big.Int {
	var buf [32]byte
	for i := range buf {
		buf[i] = byte(r.Uint32())
	}
	v := new(big.Int).SetBytes(buf[:])
	return v.Mod(v, Modulus)
}

func fromBig(t *testing.T, v *big.Int) Element {
	t.Helper()
	var b [32]byte
	v.FillBytes(b[:])
	e, err := SetBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func edgeValues() []*big.Int {
	pm1 := new(big.Int).Sub(Modulus, big.NewInt(1))
	half := new(big.Int).Rsh(Modulus, 1)
	return []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), pm1, half, new(big.Int).Lsh(big.NewInt(1), 253)}
}

func TestArithmeticMatchesBigIntegers(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	values := edgeValues()
	for range 2000 {
		values = append(values, randomBig(r))
	}
	for i := range values {
		x := values[i]
		y := values[(i*7+3)%len(values)]
		ex, ey := fromBig(t, x), fromBig(t, y)

		wantSum := new(big.Int).Add(x, y)
		wantSum.Mod(wantSum, Modulus)
		if got := Add(ex, ey).Big(); got.Cmp(wantSum) != 0 {
			t.Fatalf("%v + %v = %v, want %v", x, y, got, wantSum)
		}
		wantProduct := new(big.Int).Mul(x, y)
		wantProduct.Mod(wantProduct, Modulus)
		if got := Mul(ex, ey).Big(); got.Cmp(wantProduct) != 0 {
			t.Fatalf("%v * %v = %v, want %v", x, y, got, wantProduct)
		}
	}
}

func TestEncodingRoundTrips(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 200 {
		v := randomBig(r)
		e := fromBig(t, v)
		if e.Big().Cmp(v) != 0 {
			t.Fatalf("round trip of %v gave %v", v, e.Big())
		}
		back, err := SetHex(e.Hex())
		if err != nil || back != e {
			t.Fatalf("hex round trip of %v failed: %v", v, err)
		}
	}
	if SetUint64(7).Big().Int64() != 7 {
		t.Fatal("SetUint64(7)")
	}
	if !SetUint64(0).IsZero() {
		t.Fatal("zero is not zero")
	}
}

func TestNonCanonicalValuesAreRefused(t *testing.T) {
	for _, v := range []*big.Int{Modulus, new(big.Int).Add(Modulus, big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))} {
		var b [32]byte
		v.FillBytes(b[:])
		if _, err := SetBytes(b); err != ErrNonCanonical {
			t.Fatalf("%v accepted: %v", v, err)
		}
	}
	for _, s := range []string{"", "00", "zz" + string(make([]byte, 62))} {
		if _, err := SetHex(s); err == nil {
			t.Fatalf("hex %q accepted", s)
		}
	}
}
