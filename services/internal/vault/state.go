package vault

import (
	"math"
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// RootHistory is the number of roots the vault keeps.
const RootHistory = 256

// Config is fixed at construction.
type Config struct {
	Token      string
	Domain     fr.Element
	Guardian   string
	ASP        string
	DelaySmall uint64
	DelayLarge uint64
}

// Limits are in the asset's smallest unit.
type Limits struct {
	MinDeposit            *big.Int
	MaxDeposit            *big.Int
	MaxDailyPerDepositor  *big.Int
	TvlCap                *big.Int
	MaxDailyOutflow       *big.Int
	MaxFee                *big.Int
	LargeDepositThreshold *big.Int
}

// QueuedLimits is a loosening that applies once ReadyAt has passed.
type QueuedLimits struct {
	Limits  Limits
	ReadyAt uint64
}

// Status is the vault's mutable instance state.
type Status struct {
	DepositsPaused  bool
	TransfersPaused bool
	HaltedUntil     uint64
	NextHaltAt      uint64
	NextDepositID   uint64
	AttestedUpTo    uint64
	Tvl             *big.Int
	PendingTotal    *big.Int
	QueuedTotal     *big.Int
	// ExitHead is the oldest queued exit and ExitTail the ID the next one takes; the exit queue
	// is empty when they are equal.
	ExitHead   uint64
	ExitTail   uint64
	OutflowDay uint64
	Outflow    *big.Int
}

// OutflowOn is what the window of the given day has paid so far.
func (s Status) OutflowOn(day uint64) *big.Int {
	if s.OutflowDay == day {
		return new(big.Int).Set(s.Outflow)
	}
	return new(big.Int)
}

// Halted reports whether the vault is halted at the given ledger time.
func (s Status) Halted(now uint64) bool {
	return now < s.HaltedUntil
}

// PendingDeposit is a deposit waiting in the entry queue.
type PendingDeposit struct {
	Depositor   string
	Amount      *big.Int
	Commitment0 fr.Element
	Commitment1 fr.Element
	Ciphertext0 []byte
	Ciphertext1 []byte
	CreatedAt   uint64
	// Delay is the waiting time that applied when the deposit was made.
	Delay uint64
	// Flag is the reason code of a refusal, nil when the deposit is not flagged.
	Flag *uint32
	// FlaggedAt is the time of the first flag, 0 while not flagged.
	FlaggedAt uint64
}

// EligibleAt is the earliest time admit accepts the deposit, which waits for the longer of the
// delay at shield time and the delay the current configuration gives its amount.
func (d PendingDeposit) EligibleAt(cfg Config, limits Limits) uint64 {
	delay := max(d.Delay, DelayFor(d.Amount, cfg, limits))
	if d.CreatedAt > math.MaxUint64-delay {
		return math.MaxUint64
	}
	return d.CreatedAt + delay
}

// DelayFor is the delay the configuration gives a deposit of this amount.
func DelayFor(amount *big.Int, cfg Config, limits Limits) uint64 {
	if amount.Cmp(limits.LargeDepositThreshold) >= 0 {
		return cfg.DelayLarge
	}
	return cfg.DelaySmall
}

// RootRing holds the last RootHistory roots; Newest indexes the current one.
type RootRing struct {
	Roots  []fr.Element
	Newest uint32
}

// Current returns the newest root.
func (r RootRing) Current() fr.Element {
	return r.Roots[r.Newest]
}

var (
	configFields  = []string{"token", "domain", "guardian", "asp", "delay_small", "delay_large"}
	limitsFields  = []string{"min_deposit", "max_deposit", "max_daily_per_depositor", "tvl_cap", "max_daily_outflow", "max_fee", "large_deposit_threshold"}
	queuedFields  = []string{"limits", "ready_at"}
	statusFields  = []string{"deposits_paused", "transfers_paused", "halted_until", "next_halt_at", "next_deposit_id", "attested_up_to", "tvl", "pending_total", "queued_total", "exit_head", "exit_tail", "outflow_day", "outflow"}
	exitFields    = []string{"recipient", "payout", "relayer", "fee", "queued_at"}
	pendingFields = []string{"depositor", "amount", "commitment0", "commitment1", "encrypted_output0", "encrypted_output1", "created_at", "delay", "flag", "flagged_at"}
	ringFields    = []string{"roots", "newest"}
)

// decoder accumulates the first error of a sequence of field decodes.
type decoder struct {
	fields map[string]xdr.ScVal
	err    error
}

func (d *decoder) keep(err error) {
	if d.err == nil && err != nil {
		d.err = err
	}
}

func (d *decoder) address(name string) string {
	s, err := addressOf(d.fields[name])
	d.keep(err)
	return s
}

func (d *decoder) u64(name string) uint64 {
	n, err := u64Of(d.fields[name])
	d.keep(err)
	return n
}

func (d *decoder) u32(name string) uint32 {
	n, err := u32Of(d.fields[name])
	d.keep(err)
	return n
}

func (d *decoder) bool(name string) bool {
	b, err := boolOf(d.fields[name])
	d.keep(err)
	return b
}

func (d *decoder) i128(name string) *big.Int {
	n, err := i128Of(d.fields[name])
	d.keep(err)
	return n
}

func (d *decoder) field(name string) fr.Element {
	e, err := fieldOf(d.fields[name])
	d.keep(err)
	return e
}

func (d *decoder) bytes(name string) []byte {
	b, err := bytesOf(d.fields[name])
	d.keep(err)
	return b
}

func newDecoder(v xdr.ScVal, names []string) *decoder {
	fields, err := structOf(v, names...)
	return &decoder{fields: fields, err: err}
}

// DecodeConfig decodes the Config instance entry.
func DecodeConfig(v xdr.ScVal) (Config, error) {
	d := newDecoder(v, configFields)
	if d.err != nil {
		return Config{}, d.err
	}
	c := Config{
		Token:      d.address("token"),
		Domain:     d.field("domain"),
		Guardian:   d.address("guardian"),
		ASP:        d.address("asp"),
		DelaySmall: d.u64("delay_small"),
		DelayLarge: d.u64("delay_large"),
	}
	return c, d.err
}

// DecodeLimits decodes a Limits value.
func DecodeLimits(v xdr.ScVal) (Limits, error) {
	d := newDecoder(v, limitsFields)
	if d.err != nil {
		return Limits{}, d.err
	}
	l := Limits{
		MinDeposit:            d.i128("min_deposit"),
		MaxDeposit:            d.i128("max_deposit"),
		MaxDailyPerDepositor:  d.i128("max_daily_per_depositor"),
		TvlCap:                d.i128("tvl_cap"),
		MaxDailyOutflow:       d.i128("max_daily_outflow"),
		MaxFee:                d.i128("max_fee"),
		LargeDepositThreshold: d.i128("large_deposit_threshold"),
	}
	return l, d.err
}

// DecodeQueuedLimits decodes a QueuedLimits value.
func DecodeQueuedLimits(v xdr.ScVal) (QueuedLimits, error) {
	d := newDecoder(v, queuedFields)
	if d.err != nil {
		return QueuedLimits{}, d.err
	}
	limits, err := DecodeLimits(d.fields["limits"])
	if err != nil {
		return QueuedLimits{}, err
	}
	q := QueuedLimits{Limits: limits, ReadyAt: d.u64("ready_at")}
	return q, d.err
}

// DecodeStatus decodes the Status instance entry.
func DecodeStatus(v xdr.ScVal) (Status, error) {
	d := newDecoder(v, statusFields)
	if d.err != nil {
		return Status{}, d.err
	}
	s := Status{
		DepositsPaused:  d.bool("deposits_paused"),
		TransfersPaused: d.bool("transfers_paused"),
		HaltedUntil:     d.u64("halted_until"),
		NextHaltAt:      d.u64("next_halt_at"),
		NextDepositID:   d.u64("next_deposit_id"),
		AttestedUpTo:    d.u64("attested_up_to"),
		Tvl:             d.i128("tvl"),
		PendingTotal:    d.i128("pending_total"),
		QueuedTotal:     d.i128("queued_total"),
		ExitHead:        d.u64("exit_head"),
		ExitTail:        d.u64("exit_tail"),
		OutflowDay:      d.u64("outflow_day"),
		Outflow:         d.i128("outflow"),
	}
	return s, d.err
}

// Exit is a payment the vault owes: one waiting in the exit queue, or the unpaid parts of a
// stranded one.
type Exit struct {
	Recipient string
	Payout    *big.Int
	Relayer   string
	Fee       *big.Int
	QueuedAt  uint64
}

// DecodeExit decodes an Exit(id) or Stranded(id) entry.
func DecodeExit(v xdr.ScVal) (Exit, error) {
	d := newDecoder(v, exitFields)
	if d.err != nil {
		return Exit{}, d.err
	}
	e := Exit{
		Recipient: d.address("recipient"),
		Payout:    d.i128("payout"),
		Relayer:   d.address("relayer"),
		Fee:       d.i128("fee"),
		QueuedAt:  d.u64("queued_at"),
	}
	return e, d.err
}

// DecodePendingDeposit decodes a Pending(id) entry.
func DecodePendingDeposit(v xdr.ScVal) (PendingDeposit, error) {
	d := newDecoder(v, pendingFields)
	if d.err != nil {
		return PendingDeposit{}, d.err
	}
	flag, err := optionU32Of(d.fields["flag"])
	d.keep(err)
	p := PendingDeposit{
		Depositor:   d.address("depositor"),
		Amount:      d.i128("amount"),
		Commitment0: d.field("commitment0"),
		Commitment1: d.field("commitment1"),
		Ciphertext0: d.bytes("encrypted_output0"),
		Ciphertext1: d.bytes("encrypted_output1"),
		CreatedAt:   d.u64("created_at"),
		Delay:       d.u64("delay"),
		Flag:        flag,
		FlaggedAt:   d.u64("flagged_at"),
	}
	return p, d.err
}

// DecodeRootRing decodes the Roots entry.
func DecodeRootRing(v xdr.ScVal) (RootRing, error) {
	d := newDecoder(v, ringFields)
	if d.err != nil {
		return RootRing{}, d.err
	}
	items, err := vecOf(d.fields["roots"])
	if err != nil {
		return RootRing{}, err
	}
	if len(items) != RootHistory {
		return RootRing{}, malformed("root ring of %d entries", len(items))
	}
	ring := RootRing{Roots: make([]fr.Element, len(items)), Newest: d.u32("newest")}
	for i, item := range items {
		ring.Roots[i], err = fieldOf(item)
		if err != nil {
			return RootRing{}, err
		}
	}
	if d.err == nil && ring.Newest >= RootHistory {
		return RootRing{}, malformed("newest root index %d", ring.Newest)
	}
	return ring, d.err
}

// Instance is the vault's instance storage.
type Instance struct {
	Config       Config
	Limits       Limits
	QueuedLimits *QueuedLimits
	Status       Status
	WasmHash     [32]byte
}

// DecodeInstance decodes the vault's contract instance entry value.
func DecodeInstance(v xdr.ScVal) (Instance, error) {
	inst, ok := v.GetInstance()
	if !ok {
		return Instance{}, malformed("want contract instance, got %v", v.Type)
	}
	var out Instance
	if inst.Executable.Type != xdr.ContractExecutableTypeContractExecutableWasm || inst.Executable.WasmHash == nil {
		return Instance{}, malformed("vault executable is not wasm")
	}
	out.WasmHash = *inst.Executable.WasmHash
	if inst.Storage == nil {
		return Instance{}, malformed("empty instance storage")
	}
	var seen int
	for _, e := range *inst.Storage {
		name, err := enumName(e.Key)
		if err != nil {
			return Instance{}, err
		}
		switch name {
		case "Config":
			out.Config, err = DecodeConfig(e.Val)
			seen |= 1
		case "Limits":
			out.Limits, err = DecodeLimits(e.Val)
			seen |= 2
		case "Status":
			out.Status, err = DecodeStatus(e.Val)
			seen |= 4
		case "QueuedLimits":
			var q QueuedLimits
			q, err = DecodeQueuedLimits(e.Val)
			out.QueuedLimits = &q
		default:
			err = malformed("unexpected instance key %q", name)
		}
		if err != nil {
			return Instance{}, err
		}
	}
	if seen != 7 {
		return Instance{}, malformed("instance storage lacks config, limits or status")
	}
	return out, nil
}

// enumName returns the variant name of a unit contracttype enum value.
func enumName(v xdr.ScVal) (string, error) {
	items, err := vecOf(v)
	if err != nil || len(items) != 1 {
		return "", malformed("want a unit enum key")
	}
	name, ok := symbolOf(items[0])
	if !ok {
		return "", malformed("enum key is not a symbol")
	}
	return name, nil
}
