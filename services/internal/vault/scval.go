package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// ErrMalformed reports a value that does not have the shape the vault gives it.
var ErrMalformed = errors.New("vault: malformed value")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

var (
	i128Min = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	i128Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
)

// Symbol encodes a symbol.
func Symbol(s string) xdr.ScVal {
	v := xdr.ScSymbol(s)
	return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &v}
}

// U32 encodes a u32.
func U32(n uint32) xdr.ScVal {
	v := xdr.Uint32(n)
	return xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &v}
}

// U64 encodes a u64.
func U64(n uint64) xdr.ScVal {
	v := xdr.Uint64(n)
	return xdr.ScVal{Type: xdr.ScValTypeScvU64, U64: &v}
}

// Bool encodes a bool.
func Bool(b bool) xdr.ScVal {
	return xdr.ScVal{Type: xdr.ScValTypeScvBool, B: &b}
}

// Bytes encodes a byte string.
func Bytes(b []byte) xdr.ScVal {
	v := xdr.ScBytes(slices.Clone(b))
	return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &v}
}

// U256 encodes a 32-byte big-endian value.
func U256(b [32]byte) xdr.ScVal {
	p := xdr.UInt256Parts{
		HiHi: xdr.Uint64(binary.BigEndian.Uint64(b[0:8])),
		HiLo: xdr.Uint64(binary.BigEndian.Uint64(b[8:16])),
		LoHi: xdr.Uint64(binary.BigEndian.Uint64(b[16:24])),
		LoLo: xdr.Uint64(binary.BigEndian.Uint64(b[24:32])),
	}
	return xdr.ScVal{Type: xdr.ScValTypeScvU256, U256: &p}
}

// I128 encodes a value in [-2^127, 2^127).
func I128(n *big.Int) (xdr.ScVal, error) {
	if n.Cmp(i128Min) < 0 || n.Cmp(i128Max) > 0 {
		return xdr.ScVal{}, malformed("%v is out of i128 range", n)
	}
	t := new(big.Int).Set(n)
	if n.Sign() < 0 {
		t.Add(t, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	var buf [16]byte
	t.FillBytes(buf[:])
	p := xdr.Int128Parts{
		Hi: xdr.Int64(binary.BigEndian.Uint64(buf[0:8])),
		Lo: xdr.Uint64(binary.BigEndian.Uint64(buf[8:16])),
	}
	return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &p}, nil
}

// Vec encodes a vector.
func Vec(items ...xdr.ScVal) xdr.ScVal {
	v := xdr.ScVec(items)
	p := &v
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &p}
}

// Field is one entry of a contracttype struct.
type Field struct {
	Name  string
	Value xdr.ScVal
}

// Struct encodes a contracttype struct, a map keyed by field name in sorted order.
func Struct(fields ...Field) xdr.ScVal {
	sorted := slices.Clone(fields)
	slices.SortFunc(sorted, func(a, b Field) int {
		switch {
		case a.Name < b.Name:
			return -1
		case a.Name > b.Name:
			return 1
		}
		return 0
	})
	entries := make(xdr.ScMap, 0, len(sorted))
	for _, f := range sorted {
		entries = append(entries, xdr.ScMapEntry{Key: Symbol(f.Name), Val: f.Value})
	}
	p := &entries
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &p}
}

// Address encodes a G, M or C strkey.
func Address(s string) (xdr.ScVal, error) {
	a, err := ScAddress(s)
	if err != nil {
		return xdr.ScVal{}, err
	}
	return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &a}, nil
}

// ScAddress decodes a G, M or C strkey.
func ScAddress(s string) (xdr.ScAddress, error) {
	if len(s) == 0 {
		return xdr.ScAddress{}, malformed("empty address")
	}
	switch s[0] {
	case 'G':
		raw, err := strkey.Decode(strkey.VersionByteAccountID, s)
		if err != nil {
			return xdr.ScAddress{}, malformed("account %q", s)
		}
		var key xdr.Uint256
		copy(key[:], raw)
		id := xdr.AccountId{Type: xdr.PublicKeyTypePublicKeyTypeEd25519, Ed25519: &key}
		return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &id}, nil
	case 'C':
		raw, err := strkey.Decode(strkey.VersionByteContract, s)
		if err != nil {
			return xdr.ScAddress{}, malformed("contract %q", s)
		}
		var id xdr.ContractId
		copy(id[:], raw)
		return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &id}, nil
	case 'M':
		var m xdr.MuxedAccount
		if err := m.SetAddress(s); err != nil || m.Med25519 == nil {
			return xdr.ScAddress{}, malformed("muxed account %q", s)
		}
		mux := xdr.MuxedEd25519Account{Id: m.Med25519.Id, Ed25519: m.Med25519.Ed25519}
		return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeMuxedAccount, MuxedAccount: &mux}, nil
	}
	return xdr.ScAddress{}, malformed("address %q", s)
}

// AccountOf returns the G account behind a G or M address, and the address unchanged otherwise.
func AccountOf(s string) (string, error) {
	a, err := ScAddress(s)
	if err != nil {
		return "", err
	}
	if a.Type != xdr.ScAddressTypeScAddressTypeMuxedAccount {
		return s, nil
	}
	key := a.MuxedAccount.Ed25519
	return strkey.Encode(strkey.VersionByteAccountID, key[:])
}

func symbolOf(v xdr.ScVal) (string, bool) {
	s, ok := v.GetSym()
	return string(s), ok
}

func u32Of(v xdr.ScVal) (uint32, error) {
	n, ok := v.GetU32()
	if !ok {
		return 0, malformed("want u32, got %v", v.Type)
	}
	return uint32(n), nil
}

func u64Of(v xdr.ScVal) (uint64, error) {
	n, ok := v.GetU64()
	if !ok {
		return 0, malformed("want u64, got %v", v.Type)
	}
	return uint64(n), nil
}

func boolOf(v xdr.ScVal) (bool, error) {
	b, ok := v.GetB()
	if !ok {
		return false, malformed("want bool, got %v", v.Type)
	}
	return b, nil
}

func bytesOf(v xdr.ScVal) ([]byte, error) {
	b, ok := v.GetBytes()
	if !ok {
		return nil, malformed("want bytes, got %v", v.Type)
	}
	return []byte(b), nil
}

func u256Of(v xdr.ScVal) ([32]byte, error) {
	p, ok := v.GetU256()
	if !ok {
		return [32]byte{}, malformed("want u256, got %v", v.Type)
	}
	var b [32]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(p.HiHi))
	binary.BigEndian.PutUint64(b[8:16], uint64(p.HiLo))
	binary.BigEndian.PutUint64(b[16:24], uint64(p.LoHi))
	binary.BigEndian.PutUint64(b[24:32], uint64(p.LoLo))
	return b, nil
}

// fieldOf decodes a U256 that must be a canonical field element.
func fieldOf(v xdr.ScVal) (fr.Element, error) {
	b, err := u256Of(v)
	if err != nil {
		return fr.Element{}, err
	}
	e, err := fr.SetBytes(b)
	if err != nil {
		return fr.Element{}, malformed("non-canonical field element")
	}
	return e, nil
}

func i128Of(v xdr.ScVal) (*big.Int, error) {
	p, ok := v.GetI128()
	if !ok {
		return nil, malformed("want i128, got %v", v.Type)
	}
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[0:8], uint64(p.Hi))
	binary.BigEndian.PutUint64(buf[8:16], uint64(p.Lo))
	n := new(big.Int).SetBytes(buf[:])
	if p.Hi < 0 {
		n.Sub(n, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return n, nil
}

// addressOf decodes an Address or MuxedAddress into its strkey.
func addressOf(v xdr.ScVal) (string, error) {
	a, ok := v.GetAddress()
	if !ok {
		return "", malformed("want address, got %v", v.Type)
	}
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount, xdr.ScAddressTypeScAddressTypeContract, xdr.ScAddressTypeScAddressTypeMuxedAccount:
	default:
		return "", malformed("unexpected address type %v", a.Type)
	}
	s, err := a.String()
	if err != nil {
		return "", malformed("address: %v", err)
	}
	return s, nil
}

func vecOf(v xdr.ScVal) ([]xdr.ScVal, error) {
	p, ok := v.GetVec()
	if !ok || p == nil {
		return nil, malformed("want vec, got %v", v.Type)
	}
	return *p, nil
}

// structOf decodes a contracttype struct, which must have exactly the named fields.
func structOf(v xdr.ScVal, names ...string) (map[string]xdr.ScVal, error) {
	p, ok := v.GetMap()
	if !ok || p == nil {
		return nil, malformed("want map, got %v", v.Type)
	}
	if len(*p) != len(names) {
		return nil, malformed("want %d fields, got %d", len(names), len(*p))
	}
	out := make(map[string]xdr.ScVal, len(names))
	for _, e := range *p {
		name, ok := symbolOf(e.Key)
		if !ok || !slices.Contains(names, name) {
			return nil, malformed("unexpected field %v", e.Key)
		}
		if _, dup := out[name]; dup {
			return nil, malformed("repeated field %q", name)
		}
		out[name] = e.Val
	}
	return out, nil
}

// optionOf decodes an Option<u32>, which the SDK encodes as void or the value.
func optionU32Of(v xdr.ScVal) (*uint32, error) {
	if v.Type == xdr.ScValTypeScvVoid {
		return nil, nil
	}
	n, err := u32Of(v)
	if err != nil {
		return nil, err
	}
	return &n, nil
}
