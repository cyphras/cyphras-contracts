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

// Transact emits a transact that pays -extAmount to recipient and fee to the relayer at once.
func (c *Chain) Transact(extAmount, fee int64, recipient string) {
	c.Tx()
	c.nullifiers()
	c.output(fr.SetUint64(9_000_000 + c.NextLeaf))
	c.output(fr.SetUint64(9_000_000 + c.NextLeaf))
	c.settled(extAmount, fee, recipient, nil)
}

func (c *Chain) settled(extAmount, fee int64, recipient string, exit *uint64) {
	exitID := xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	if exit != nil {
		exitID = vault.U64(*exit)
	}
	c.Emit("settled",
		vault.Field{Name: "ext_amount", Value: i128(big.NewInt(extAmount))},
		vault.Field{Name: "fee", Value: i128(big.NewInt(fee))},
		vault.Field{Name: "recipient", Value: addr(recipient)},
		vault.Field{Name: "relayer", Value: addr(Relayer)},
		vault.Field{Name: "exit_id", Value: exitID},
	)
}

// Exit is an exit the chain queued, kept so a release can pay it back.
type Exit struct {
	ID             uint64
	ExtAmount, Fee int64
	Recipient      string
}

// QueueExit emits a transact whose payment joins the exit queue as exit id.
func (c *Chain) QueueExit(id uint64, extAmount, fee int64, recipient string) Exit {
	c.Tx()
	c.nullifiers()
	c.output(fr.SetUint64(9_000_000 + c.NextLeaf))
	c.output(fr.SetUint64(9_000_000 + c.NextLeaf))
	c.Emit("exit_queued",
		vault.Field{Name: "id", Value: vault.U64(id)},
		vault.Field{Name: "ext_amount", Value: i128(big.NewInt(extAmount))},
		vault.Field{Name: "fee", Value: i128(big.NewInt(fee))},
		vault.Field{Name: "recipient", Value: addr(recipient)},
		vault.Field{Name: "relayer", Value: addr(Relayer)},
	)
	return Exit{ID: id, ExtAmount: extAmount, Fee: fee, Recipient: recipient}
}

// Release emits a release that pays the exits in order.
func (c *Chain) Release(exits ...Exit) {
	c.Tx()
	for _, e := range exits {
		id := e.ID
		c.settled(e.ExtAmount, e.Fee, e.Recipient, &id)
	}
}

// PayPart emits a release that pays part of the exit at the head and leaves the rest.
func (c *Chain) PayPart(e Exit, payoutPaid, feePaid, payoutLeft, feeLeft int64) {
	c.Tx().Emit("exit_paid",
		vault.Field{Name: "id", Value: vault.U64(e.ID)},
		vault.Field{Name: "payout_paid", Value: i128(big.NewInt(payoutPaid))},
		vault.Field{Name: "fee_paid", Value: i128(big.NewInt(feePaid))},
		vault.Field{Name: "payout_left", Value: i128(big.NewInt(payoutLeft))},
		vault.Field{Name: "fee_left", Value: i128(big.NewInt(feeLeft))},
	)
}

// Strand emits a release of one exit whose unpaid parts the asset contract refused.
func (c *Chain) Strand(e Exit, unpaidPayout, unpaidFee int64) {
	c.Tx().Emit("exit_stranded",
		vault.Field{Name: "id", Value: vault.U64(e.ID)},
		vault.Field{Name: "payout", Value: i128(big.NewInt(unpaidPayout))},
		vault.Field{Name: "fee", Value: i128(big.NewInt(unpaidFee))},
	)
}

// Requeue emits a claim that moves parts of a stranded exit back into the queue as the exit newID,
// and returns that exit.
func (c *Chain) Requeue(e Exit, newID uint64, payout, fee int64) Exit {
	c.Tx().Emit("exit_requeued",
		vault.Field{Name: "id", Value: vault.U64(e.ID)},
		vault.Field{Name: "new_id", Value: vault.U64(newID)},
		vault.Field{Name: "payout", Value: i128(big.NewInt(payout))},
		vault.Field{Name: "fee", Value: i128(big.NewInt(fee))},
	)
	return Exit{ID: newID, ExtAmount: -payout, Fee: fee, Recipient: e.Recipient}
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

// Asp and Guardian are the vault's privileged accounts in tests.
const (
	Asp      = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
	Guardian = "GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO"
	Token    = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"
)

// InstanceOptions describes the vault's instance storage.
type InstanceOptions struct {
	DelaySmall, DelayLarge uint64
	Limit, Large           int64
	Status                 vault.Status
	Queued                 *xdr.ScVal
	WasmHash               [32]byte
	// Domain is the vault's domain, 5 when zero.
	Domain fr.Element
}

// Instance encodes the vault's contract instance entry value.
func Instance(o InstanceOptions) xdr.ScVal {
	domain := o.Domain
	if domain.IsZero() {
		domain = fr.SetUint64(5)
	}
	cfg := vault.Struct(
		vault.Field{Name: "token", Value: addr(Token)},
		vault.Field{Name: "domain", Value: Field(domain)},
		vault.Field{Name: "guardian", Value: addr(Guardian)},
		vault.Field{Name: "asp", Value: addr(Asp)},
		vault.Field{Name: "delay_small", Value: vault.U64(o.DelaySmall)},
		vault.Field{Name: "delay_large", Value: vault.U64(o.DelayLarge)},
	)
	s := o.Status
	zero := big.NewInt(0)
	or := func(n *big.Int) *big.Int {
		if n == nil {
			return zero
		}
		return n
	}
	status := vault.Struct(
		vault.Field{Name: "deposits_paused", Value: vault.Bool(s.DepositsPaused)},
		vault.Field{Name: "transfers_paused", Value: vault.Bool(s.TransfersPaused)},
		vault.Field{Name: "halted_until", Value: vault.U64(s.HaltedUntil)},
		vault.Field{Name: "next_halt_at", Value: vault.U64(s.NextHaltAt)},
		vault.Field{Name: "next_deposit_id", Value: vault.U64(max(s.NextDepositID, 1))},
		vault.Field{Name: "attested_up_to", Value: vault.U64(s.AttestedUpTo)},
		vault.Field{Name: "tvl", Value: i128(or(s.Tvl))},
		vault.Field{Name: "pending_total", Value: i128(or(s.PendingTotal))},
		vault.Field{Name: "queued_total", Value: i128(or(s.QueuedTotal))},
		vault.Field{Name: "exit_head", Value: vault.U64(max(s.ExitHead, 1))},
		vault.Field{Name: "exit_tail", Value: vault.U64(max(s.ExitTail, 1))},
		vault.Field{Name: "outflow_day", Value: vault.U64(s.OutflowDay)},
		vault.Field{Name: "outflow", Value: i128(or(s.Outflow))},
	)
	storage := xdr.ScMap{
		{Key: vault.Vec(vault.Symbol("Config")), Val: cfg},
		{Key: vault.Vec(vault.Symbol("Limits")), Val: Limits(o.Limit, o.Large)},
		{Key: vault.Vec(vault.Symbol("Status")), Val: status},
	}
	if o.Queued != nil {
		storage = append(storage, xdr.ScMapEntry{Key: vault.Vec(vault.Symbol("QueuedLimits")), Val: *o.Queued})
	}
	hash := xdr.Hash(o.WasmHash)
	inst := xdr.ScContractInstance{
		Executable: xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableWasm, WasmHash: &hash},
		Storage:    &storage,
	}
	return xdr.ScVal{Type: xdr.ScValTypeScvContractInstance, Instance: &inst}
}

// RootRing encodes a root ring whose newest root is root.
func RootRing(root fr.Element, newest uint32) xdr.ScVal {
	roots := make([]xdr.ScVal, vault.RootHistory)
	for i := range roots {
		roots[i] = Field(fr.Element{})
	}
	roots[newest] = Field(root)
	return vault.Struct(vault.Field{Name: "roots", Value: vault.Vec(roots...)}, vault.Field{Name: "newest", Value: vault.U32(newest)})
}

// Pending encodes a Pending(id) entry of a deposit made by Shield.
func Pending(id uint64, depositor string, amount int64, createdAt, delay uint64, flag *uint32, flaggedAt uint64) xdr.ScVal {
	flagVal := xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	if flag != nil {
		flagVal = vault.U32(*flag)
	}
	return vault.Struct(
		vault.Field{Name: "depositor", Value: addr(depositor)},
		vault.Field{Name: "amount", Value: i128(big.NewInt(amount))},
		vault.Field{Name: "commitment0", Value: Field(Commitment(2 * id))},
		vault.Field{Name: "commitment1", Value: Field(Commitment(2*id + 1))},
		vault.Field{Name: "encrypted_output0", Value: vault.Bytes(make([]byte, vault.CiphertextLen))},
		vault.Field{Name: "encrypted_output1", Value: vault.Bytes(make([]byte, vault.CiphertextLen))},
		vault.Field{Name: "created_at", Value: vault.U64(createdAt)},
		vault.Field{Name: "delay", Value: vault.U64(delay)},
		vault.Field{Name: "flag", Value: flagVal},
		vault.Field{Name: "flagged_at", Value: vault.U64(flaggedAt)},
	)
}

// ExitEntry encodes the value of an Exit(id) or Stranded(id) entry.
func ExitEntry(recipient string, payout, fee int64, queuedAt uint64) xdr.ScVal {
	return vault.Struct(
		vault.Field{Name: "recipient", Value: addr(recipient)},
		vault.Field{Name: "payout", Value: i128(big.NewInt(payout))},
		vault.Field{Name: "relayer", Value: addr(Relayer)},
		vault.Field{Name: "fee", Value: i128(big.NewInt(fee))},
		vault.Field{Name: "queued_at", Value: vault.U64(queuedAt)},
	)
}

// Balance encodes a balance entry of the asset contract.
func Balance(amount *big.Int, authorized bool) xdr.ScVal {
	return vault.Struct(
		vault.Field{Name: "amount", Value: i128(amount)},
		vault.Field{Name: "authorized", Value: vault.Bool(authorized)},
		vault.Field{Name: "clawback", Value: vault.Bool(false)},
	)
}

// Transfer emits the asset contract's transfer of amount from the vault to an address, in the
// current transaction, as the Stellar Asset Contract reports it.
func (c *Chain) Transfer(to string, amount int64) {
	account, err := vault.AccountOf(to)
	if err != nil {
		panic(err)
	}
	asset := xdr.ScString("native")
	data := i128(big.NewInt(amount))
	if account != to {
		a, _ := vault.ScAddress(to)
		data = vault.Struct(vault.Field{Name: "amount", Value: data}, vault.Field{Name: "to_muxed_id", Value: vault.U64(uint64(a.MuxedAccount.Id))})
	}
	c.Events = append(c.Events, vault.RawEvent{
		Ledger: c.Ledger, ClosedAt: c.ClosedAt, TxHash: c.hash, Tx: c.tx, Op: 0, Index: c.index, Contract: Token,
		Topics: []string{b64(vault.Symbol("transfer")), b64(addr(Vault)), b64(addr(account)), b64(xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &asset})},
		Value:  b64(data),
	})
	c.index++
}

// Burn emits the Stellar Asset Contract's burn of amount from the vault, as a payment to the
// issuer of asset, CODE:ISSUER, reports it.
func (c *Chain) Burn(asset string, amount int64) {
	str := xdr.ScString(asset)
	c.Events = append(c.Events, vault.RawEvent{
		Ledger: c.Ledger, ClosedAt: c.ClosedAt, TxHash: c.hash, Tx: c.tx, Op: 0, Index: c.index, Contract: Token,
		Topics: []string{b64(vault.Symbol("burn")), b64(addr(Vault)), b64(xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &str})},
		Value:  b64(i128(big.NewInt(amount))),
	})
	c.index++
}

// Roots encodes a root ring holding the given roots, the last of them current.
func Roots(roots ...fr.Element) xdr.ScVal {
	ring := make([]xdr.ScVal, vault.RootHistory)
	for i := range ring {
		ring[i] = Field(fr.Element{})
	}
	for i, r := range roots {
		ring[i] = Field(r)
	}
	return vault.Struct(vault.Field{Name: "roots", Value: vault.Vec(ring...)}, vault.Field{Name: "newest", Value: vault.U32(uint32(len(roots) - 1))})
}
