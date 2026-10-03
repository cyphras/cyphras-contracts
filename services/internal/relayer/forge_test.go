package relayer

import (
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/groth16"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// A verifying key built from known scalars, as the vault's own trapdoor tests build theirs, so a
// test can make a valid proof for any request.
var (
	tdAlpha, tdBeta, tdGamma, tdDelta = int64(3), int64(5), int64(7), int64(11)
	tdIC                              = []int64{13, 17, 19, 23, 29, 31, 37, 41, 43}
)

func trapdoorKey(t *testing.T) *groth16.Key {
	t.Helper()
	_, _, g1, g2 := bn254.Generators()
	p1 := func(s int64) [3]string {
		var p bn254.G1Affine
		p.ScalarMultiplication(&g1, big.NewInt(s))
		return [3]string{p.X.String(), p.Y.String(), "1"}
	}
	p2 := func(s int64) [3][2]string {
		var p bn254.G2Affine
		p.ScalarMultiplication(&g2, big.NewInt(s))
		return [3][2]string{{p.X.A0.String(), p.X.A1.String()}, {p.Y.A0.String(), p.Y.A1.String()}, {"1", "0"}}
	}
	var ic [][3]string
	for _, s := range tdIC {
		ic = append(ic, p1(s))
	}
	raw, _ := json.Marshal(map[string]any{
		"protocol": "groth16", "curve": "bn128", "nPublic": 8,
		"vk_alpha_1": p1(tdAlpha), "vk_beta_2": p2(tdBeta), "vk_gamma_2": p2(tdGamma), "vk_delta_2": p2(tdDelta), "IC": ic,
	})
	k, err := groth16.ParseKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// forge makes a proof the trapdoor key accepts for the given public inputs.
func forge(inputs [8]fr.Element) (a [64]byte, b [128]byte, c [64]byte) {
	r := ecc.BN254.ScalarField()
	vkx := big.NewInt(tdIC[0])
	for i, in := range inputs {
		vkx.Add(vkx, new(big.Int).Mul(big.NewInt(tdIC[i+1]), in.Big()))
	}
	s := new(big.Int).Mul(big.NewInt(tdAlpha), big.NewInt(tdBeta))
	s.Add(s, new(big.Int).Mul(vkx, big.NewInt(tdGamma)))
	s.Add(s, big.NewInt(tdDelta))
	s.Mod(s, r)
	_, _, g1, g2 := bn254.Generators()
	var pa bn254.G1Affine
	pa.ScalarMultiplication(&g1, s)
	ax, ay := pa.X.Bytes(), pa.Y.Bytes()
	copy(a[:32], ax[:])
	copy(a[32:], ay[:])
	for i, e := range [][32]byte{g2.X.A1.Bytes(), g2.X.A0.Bytes(), g2.Y.A1.Bytes(), g2.Y.A0.Bytes()} {
		copy(b[32*i:], e[:])
	}
	cx, cy := g1.X.Bytes(), g1.Y.Bytes()
	copy(c[:32], cx[:])
	copy(c[32:], cy[:])
	return
}

func randomField(t *testing.T) fr.Element {
	t.Helper()
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	raw[0] = 0
	e, err := fr.SetBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// forged builds a request with fresh notes paying extAmount to recipient and fee to the fee
// address, with a proof the trapdoor key accepts.
func (h *harness) forged(t *testing.T, recipient string, extAmount, fee int64) Request {
	t.Helper()
	return h.forgedUntil(t, recipient, extAmount, fee, 5000)
}

// forgedUntil is forged with the given deadline.
func (h *harness) forgedUntil(t *testing.T, recipient string, extAmount, fee int64, deadline uint32) Request {
	t.Helper()
	_, roots := fixtureChain(t)
	e := vault.ExtData{
		Vault: vaulttest.Vault, NetworkID: h.r.cfg.NetworkID, Deadline: deadline,
		ExtAmount: big.NewInt(extAmount), Fee: big.NewInt(fee), Recipient: recipient, Relayer: feeAddress,
		Ciphertext0: make([]byte, vault.CiphertextLen), Ciphertext1: make([]byte, vault.CiphertextLen),
	}
	hash, err := e.Hash()
	if err != nil {
		t.Fatal(err)
	}
	p := vault.Proof{Root: roots[len(roots)-1], PublicAmount: vault.PublicAmount(e.ExtAmount, e.Fee), ExtDataHash: hash,
		Nullifiers: [2]fr.Element{randomField(t), randomField(t)}, Commitments: [2]fr.Element{randomField(t), randomField(t)}}
	p.A, p.B, p.C = forge([8]fr.Element{p.Root, p.PublicAmount, p.ExtDataHash, h.domain, p.Nullifiers[0], p.Nullifiers[1], p.Commitments[0], p.Commitments[1]})
	return Request{Proof: p, Ext: e}
}

func muxed(t *testing.T, base string, id uint64) string {
	t.Helper()
	m, err := xdr.MuxedAccountFromAccountId(base, id)
	if err != nil {
		t.Fatal(err)
	}
	return m.Address()
}

func (h *harness) sends() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sent
}
