package relayer

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// SubmitBody is the request of POST /v1/submit. Binary values are lowercase hex of exact length,
// amounts are decimal strings and not_before is a Unix time.
type SubmitBody struct {
	Proof struct {
		A            string   `json:"a"`
		B            string   `json:"b"`
		C            string   `json:"c"`
		Root         string   `json:"root"`
		PublicAmount string   `json:"public_amount"`
		ExtDataHash  string   `json:"ext_data_hash"`
		Nullifiers   []string `json:"input_nullifiers"`
		Commitments  []string `json:"output_commitments"`
	} `json:"proof"`
	Ext struct {
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
	NotBefore *int64 `json:"not_before,omitempty"`
}

var errBadRequest = errors.New("bad_request")

func lowerHex(s string, n int) ([]byte, error) {
	if len(s) != 2*n {
		return nil, errBadRequest
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, errBadRequest
		}
	}
	return hex.DecodeString(s)
}

func field(s string) (fr.Element, error) {
	b, err := lowerHex(s, 32)
	if err != nil {
		return fr.Element{}, err
	}
	e, err := fr.SetBytes([32]byte(b))
	if err != nil {
		return fr.Element{}, errBadRequest
	}
	return e, nil
}

// amount parses a canonical decimal integer: no sign on zero, no leading zeros, no plus sign.
func amount(s string) (*big.Int, error) {
	if s == "" || len(s) > 40 {
		return nil, errBadRequest
	}
	n, ok := new(big.Int).SetString(s, 10)
	if !ok || n.String() != s {
		return nil, errBadRequest
	}
	if _, err := vault.I128(n); err != nil {
		return nil, errBadRequest
	}
	return n, nil
}

// Request is a parsed submission.
type Request struct {
	Proof     vault.Proof
	Ext       vault.ExtData
	NotBefore *int64
}

// Parse checks every field's form; it does not compare with the relayer's own values.
func (b *SubmitBody) Parse() (Request, error) {
	var r Request
	p := b.Proof
	a, err := lowerHex(p.A, 64)
	if err != nil {
		return r, err
	}
	bb, err := lowerHex(p.B, 128)
	if err != nil {
		return r, err
	}
	c, err := lowerHex(p.C, 64)
	if err != nil {
		return r, err
	}
	r.Proof.A, r.Proof.B, r.Proof.C = [64]byte(a), [128]byte(bb), [64]byte(c)
	if r.Proof.Root, err = field(p.Root); err != nil {
		return r, err
	}
	if r.Proof.PublicAmount, err = field(p.PublicAmount); err != nil {
		return r, err
	}
	if r.Proof.ExtDataHash, err = field(p.ExtDataHash); err != nil {
		return r, err
	}
	if len(p.Nullifiers) != 2 || len(p.Commitments) != 2 {
		return r, errBadRequest
	}
	for i := range 2 {
		if r.Proof.Nullifiers[i], err = field(p.Nullifiers[i]); err != nil {
			return r, err
		}
		if r.Proof.Commitments[i], err = field(p.Commitments[i]); err != nil {
			return r, err
		}
	}
	if r.Proof.Nullifiers[0] == r.Proof.Nullifiers[1] || r.Proof.Commitments[0] == r.Proof.Commitments[1] {
		return r, errBadRequest
	}

	e := b.Ext
	network, err := lowerHex(e.NetworkID, 32)
	if err != nil {
		return r, err
	}
	r.Ext.NetworkID = [32]byte(network)
	r.Ext.Vault, r.Ext.Deadline, r.Ext.Recipient, r.Ext.Relayer = e.Vault, e.Deadline, e.Recipient, e.Relayer
	if r.Ext.ExtAmount, err = amount(e.ExtAmount); err != nil {
		return r, err
	}
	if r.Ext.Fee, err = amount(e.Fee); err != nil || r.Ext.Fee.Sign() < 0 {
		return r, errBadRequest
	}
	if r.Ext.Ciphertext0, err = lowerHex(e.Ciphertext0, vault.CiphertextLen); err != nil {
		return r, err
	}
	if r.Ext.Ciphertext1, err = lowerHex(e.Ciphertext1, vault.CiphertextLen); err != nil {
		return r, err
	}
	for _, addr := range []string{r.Ext.Vault, r.Ext.Recipient, r.Ext.Relayer} {
		if _, err := vault.ScAddress(addr); err != nil {
			return r, errBadRequest
		}
	}
	if r.Ext.Vault[0] != 'C' || r.Ext.Relayer[0] != 'G' {
		return r, errBadRequest
	}
	r.NotBefore = b.NotBefore
	return r, nil
}
