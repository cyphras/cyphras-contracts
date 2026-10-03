// Package vaulttest builds vault events the way #[contractevent] encodes them, for tests of the
// services that consume them.
package vaulttest

import (
	"fmt"
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Vault is the contract the events come from.
const Vault = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"

// Depositor and Relayer are funded test accounts.
const (
	Depositor = "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH"
	Relayer   = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
)

// Chain hands out events with consistent positions and keeps the leaf and deposit counters the
// vault would.
type Chain struct {
	Ledger   uint32
	ClosedAt int64
	tx       uint32
	hash     string
	index    uint32
	NextLeaf uint64
	NextID   uint64
	Events   []vault.RawEvent
	nf       uint64
}

// New starts a chain at the given ledger.
func New(ledger uint32, closedAt int64) *Chain {
	return &Chain{Ledger: ledger, ClosedAt: closedAt, NextID: 1}
}

// NextLedger moves to the next ledger, seconds later.
func (c *Chain) NextLedger(seconds int64) *Chain {
	c.Ledger++
	c.ClosedAt += seconds
	c.tx = 0
	return c
}

// Tx starts a new transaction in the current ledger.
func (c *Chain) Tx() *Chain {
	c.tx++
	c.index = 0
	c.hash = fmt.Sprintf("%08x%08x%048x", c.Ledger, c.tx, 0)
	return c
}

func b64(v xdr.ScVal) string {
	s, err := xdr.MarshalBase64(v)
	if err != nil {
		panic(err)
	}
	return s
}

func addr(s string) xdr.ScVal {
	v, err := vault.Address(s)
	if err != nil {
		panic(err)
	}
	return v
}

func i128(n *big.Int) xdr.ScVal {
	v, err := vault.I128(n)
	if err != nil {
		panic(err)
	}
	return v
}

// Field encodes a field element.
func Field(e fr.Element) xdr.ScVal {
	return vault.U256(e.Bytes())
}

// Emit appends an event with the given topic and fields.
func (c *Chain) Emit(name string, fields ...vault.Field) *Chain {
	c.Events = append(c.Events, vault.RawEvent{
		Ledger: c.Ledger, ClosedAt: c.ClosedAt, TxHash: c.hash, Tx: c.tx, Op: 0, Index: c.index,
		Contract: Vault, Topics: []string{b64(vault.Symbol(name))}, Value: b64(vault.Struct(fields...)),
	})
	c.index++
	return c
}

func (c *Chain) nullifiers() {
	for range 2 {
		c.nf++
		c.Emit("new_nullifier", vault.Field{Name: "nullifier", Value: Field(fr.SetUint64(1_000_000 + c.nf))})
	}
}

// Commitment is the deterministic commitment a test deposit or output gets.
func Commitment(n uint64) fr.Element {
	return fr.SetUint64(5_000_000 + n)
}

// Shield emits a shield of amount by depositor and returns the deposit ID.
func (c *Chain) Shield(depositor string, amount int64) uint64 {
	c.Tx()
	c.nullifiers()
	id := c.NextID
	c.NextID++
	c.Emit("deposit_pending",
		vault.Field{Name: "id", Value: vault.U64(id)},
		vault.Field{Name: "depositor", Value: addr(depositor)},
		vault.Field{Name: "amount", Value: i128(big.NewInt(amount))},
		vault.Field{Name: "commitment0", Value: Field(Commitment(2 * id))},
		vault.Field{Name: "commitment1", Value: Field(Commitment(2*id + 1))},
		vault.Field{Name: "created_at", Value: vault.U64(uint64(c.ClosedAt))},
	)
	return id
}

func (c *Chain) output(commitment fr.Element) {
	c.Emit("new_commitment",
		vault.Field{Name: "index", Value: vault.U64(c.NextLeaf)},
		vault.Field{Name: "commitment", Value: Field(commitment)},
		vault.Field{Name: "encrypted_output", Value: vault.Bytes(make([]byte, vault.CiphertextLen))},
	)
	c.NextLeaf++
}

// Admit emits the admission of deposits, which must be pending, attested and unflagged.
func (c *Chain) Admit(ids ...uint64) {
	c.Tx()
	for _, id := range ids {
		leaf := c.NextLeaf
		c.output(Commitment(2 * id))
		c.output(Commitment(2*id + 1))
		c.Emit("deposit_admitted",
			vault.Field{Name: "id", Value: vault.U64(id)},
			vault.Field{Name: "leaf_index0", Value: vault.U64(leaf)},
			vault.Field{Name: "leaf_index1", Value: vault.U64(leaf + 1)},
		)
	}
}

// Transact emits a transact that pays -extAmount to recipient and fee to the relayer.
func (c *Chain) Transact(extAmount, fee int64, recipient string) {
	c.Tx()
	c.nullifiers()
	c.output(fr.SetUint64(9_000_000 + c.NextLeaf))
	c.output(fr.SetUint64(9_000_000 + c.NextLeaf))
	c.Emit("settled",
		vault.Field{Name: "ext_amount", Value: i128(big.NewInt(extAmount))},
		vault.Field{Name: "fee", Value: i128(big.NewInt(fee))},
		vault.Field{Name: "recipient", Value: addr(recipient)},
		vault.Field{Name: "relayer", Value: addr(Relayer)},
	)
}

// Attest emits attested.
func (c *Chain) Attest(upTo uint64) {
	c.Tx().Emit("attested", vault.Field{Name: "up_to", Value: vault.U64(upTo)})
}

// Flag emits deposit_flagged.
func (c *Chain) Flag(id uint64, reason uint32) {
	c.Tx().Emit("deposit_flagged", vault.Field{Name: "id", Value: vault.U64(id)}, vault.Field{Name: "reason", Value: vault.U32(reason)})
}

// Unflag emits deposit_unflagged.
func (c *Chain) Unflag(id uint64, reason uint32) {
	c.Tx().Emit("deposit_unflagged", vault.Field{Name: "id", Value: vault.U64(id)}, vault.Field{Name: "reason", Value: vault.U32(reason)})
}

// Refund emits deposit_refunded; reason 0 is a cancellation.
func (c *Chain) Refund(id uint64, reason uint32) {
	c.Tx().Emit("deposit_refunded", vault.Field{Name: "id", Value: vault.U64(id)}, vault.Field{Name: "reason", Value: vault.U32(reason)})
}

// Limits encodes a Limits value with every field set to n stroops, the threshold to large.
func Limits(n, large int64) xdr.ScVal {
	v := i128(big.NewInt(n))
	return vault.Struct(
		vault.Field{Name: "min_deposit", Value: i128(big.NewInt(1))},
		vault.Field{Name: "max_deposit", Value: v},
		vault.Field{Name: "max_daily_per_depositor", Value: v},
		vault.Field{Name: "tvl_cap", Value: v},
		vault.Field{Name: "max_daily_outflow", Value: v},
		vault.Field{Name: "max_fee", Value: v},
		vault.Field{Name: "large_deposit_threshold", Value: i128(big.NewInt(large))},
	)
}

// Governance emits a single governance event.
func (c *Chain) Governance(name string, fields ...vault.Field) {
	c.Tx().Emit(name, fields...)
}
