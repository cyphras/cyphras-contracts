package vault

import (
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"
	"golang.org/x/crypto/sha3"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// CiphertextLen is the only output ciphertext length the vault accepts.
const CiphertextLen = 181

// ExtData is the external data a proof binds through its ext_data_hash.
type ExtData struct {
	Vault       string
	NetworkID   [32]byte
	Deadline    uint32
	ExtAmount   *big.Int
	Fee         *big.Int
	Recipient   string
	Relayer     string
	Ciphertext0 []byte
	Ciphertext1 []byte
}

// ScVal encodes the ExtData as the vault's contracttype does.
func (e ExtData) ScVal() (xdr.ScVal, error) {
	vault, err := Address(e.Vault)
	if err != nil {
		return xdr.ScVal{}, err
	}
	recipient, err := Address(e.Recipient)
	if err != nil {
		return xdr.ScVal{}, err
	}
	relayer, err := Address(e.Relayer)
	if err != nil {
		return xdr.ScVal{}, err
	}
	extAmount, err := I128(e.ExtAmount)
	if err != nil {
		return xdr.ScVal{}, err
	}
	fee, err := I128(e.Fee)
	if err != nil {
		return xdr.ScVal{}, err
	}
	return Struct(
		Field{"vault", vault},
		Field{"network_id", Bytes(e.NetworkID[:])},
		Field{"deadline", U32(e.Deadline)},
		Field{"ext_amount", extAmount},
		Field{"fee", fee},
		Field{"recipient", recipient},
		Field{"relayer", relayer},
		Field{"encrypted_output0", Bytes(e.Ciphertext0)},
		Field{"encrypted_output1", Bytes(e.Ciphertext1)},
	), nil
}

// Hash is keccak256(XDR(ScVal(ext))) mod p, the value the proof commits to.
func (e ExtData) Hash() (fr.Element, error) {
	v, err := e.ScVal()
	if err != nil {
		return fr.Element{}, err
	}
	raw, err := v.MarshalBinary()
	if err != nil {
		return fr.Element{}, err
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(raw)
	digest := new(big.Int).SetBytes(h.Sum(nil))
	return fromBig(digest.Mod(digest, fr.Modulus)), nil
}

// PublicAmount is (ext_amount - fee) mod p.
func PublicAmount(extAmount, fee *big.Int) fr.Element {
	n := new(big.Int).Sub(extAmount, fee)
	return fromBig(n.Mod(n, fr.Modulus))
}

func fromBig(n *big.Int) fr.Element {
	var b [32]byte
	n.FillBytes(b[:])
	e, err := fr.SetBytes(b)
	if err != nil {
		panic("reduced value is not canonical")
	}
	return e
}

// Proof is a Groth16 proof with the public inputs the client supplies, the vault's TxProof.
type Proof struct {
	A            [64]byte
	B            [128]byte
	C            [64]byte
	Root         fr.Element
	PublicAmount fr.Element
	ExtDataHash  fr.Element
	Nullifiers   [2]fr.Element
	Commitments  [2]fr.Element
}

func fieldVal(e fr.Element) xdr.ScVal {
	return U256(e.Bytes())
}

// ScVal encodes the proof as the vault's contracttype does.
func (p Proof) ScVal() xdr.ScVal {
	return Struct(
		Field{"proof", Struct(
			Field{"a", Bytes(p.A[:])},
			Field{"b", Bytes(p.B[:])},
			Field{"c", Bytes(p.C[:])},
		)},
		Field{"root", fieldVal(p.Root)},
		Field{"public_amount", fieldVal(p.PublicAmount)},
		Field{"ext_data_hash", fieldVal(p.ExtDataHash)},
		Field{"input_nullifiers", Vec(fieldVal(p.Nullifiers[0]), fieldVal(p.Nullifiers[1]))},
		Field{"output_commitments", Vec(fieldVal(p.Commitments[0]), fieldVal(p.Commitments[1]))},
	)
}
