// Package submit sends Soroban transactions with one transaction in flight per source account and
// reports a transaction only once its outcome on chain is known.
package submit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Account is a source account and the key that signs for it. Its sequence number is cached and
// only used under its lock.
type Account struct {
	ID     string
	Signer *keypair.Full

	mu    sync.Mutex
	seq   int64
	known bool
}

// NewAccount returns an account whose sequence is read from the chain before first use.
func NewAccount(id string, signer *keypair.Full) *Account {
	return &Account{ID: id, Signer: signer}
}

// Lock takes the account for one transaction.
func (a *Account) Lock() { a.mu.Lock() }

// Unlock releases the account.
func (a *Account) Unlock() { a.mu.Unlock() }

var (
	// ErrSimulation reports a simulation that failed; the transaction was not sent.
	ErrSimulation = errors.New("submit: simulation failed")
	// ErrFeeCap reports a simulation whose resource fee is above the cap. It is an ErrSimulation.
	ErrFeeCap = fmt.Errorf("%w: the resource fee is above the cap", ErrSimulation)
	// ErrRejected reports a transaction the network refused without including it.
	ErrRejected = errors.New("submit: transaction rejected")
	// ErrExpired reports a transaction whose time bound passed before it was included.
	ErrExpired = errors.New("submit: transaction expired unconfirmed")
)

// Engine prepares, signs, sends and tracks transactions.
type Engine struct {
	RPC        rpc.Client
	Passphrase string
	// MaxInclusionFee caps the per-operation inclusion fee read from getFeeStats.
	MaxInclusionFee int64
	// ResourceMarginPct pads the simulated resource fee; the unused refundable part is refunded.
	ResourceMarginPct int64
	// MaxResourceFee refuses a simulation that asks for more, so a lying RPC cannot drain the
	// source's float.
	MaxResourceFee int64
	// MaxTTLFee, when set, takes the place of MaxResourceFee for footprint extensions and
	// restorations, whose fee is mostly the rent of the entries they keep alive.
	MaxTTLFee int64
	// Validity is how long a signed transaction may wait for inclusion.
	Validity time.Duration
	// Poll is the interval between getTransaction calls.
	Poll time.Duration
	Now  func() time.Time
	Log  *slog.Logger

	costMu sync.Mutex
	costs  ledgerCosts
}

// ledgerCosts are the network's Soroban fees and limits, read with the time they were read. Fees
// are in stroops: per 10,000 instructions, per entry and per 1 KiB.
type ledgerCosts struct {
	at                                    time.Time
	instruction, readEntry, writeEntry    int64
	read1KB, write1KB, historical1KB      int64
	txSize1KB, events1KB, rent1KB         int64
	rentDenominator                       int64
	minPersistentTTL, maxInstructions     uint32
	maxReadEntries, maxWriteEntries       uint32
	maxFootprint, maxReadBytes, maxWrites uint32
}

// classicPad is the room added to the bytes a call may read and write for each classic entry it
// touches, an account or a trustline: anyone can grow their own account, by signers or
// sponsorships, between a simulation and the ledger the call lands in, and the call would then run
// out of the bytes the simulation measured. An account entry holds at most about 2 KB.
const classicPad = 2048

// ledgerCosts reads the network's Soroban fees and limits, at most once an hour.
func (e *Engine) ledgerCosts(ctx context.Context) (ledgerCosts, error) {
	e.costMu.Lock()
	defer e.costMu.Unlock()
	if !e.costs.at.IsZero() && e.now().Sub(e.costs.at) < time.Hour {
		return e.costs, nil
	}
	ids := []xdr.ConfigSettingId{
		xdr.ConfigSettingIdConfigSettingContractComputeV0, xdr.ConfigSettingIdConfigSettingContractLedgerCostV0,
		xdr.ConfigSettingIdConfigSettingContractLedgerCostExtV0, xdr.ConfigSettingIdConfigSettingContractHistoricalDataV0,
		xdr.ConfigSettingIdConfigSettingContractEventsV0, xdr.ConfigSettingIdConfigSettingContractBandwidthV0,
		xdr.ConfigSettingIdConfigSettingStateArchival, xdr.ConfigSettingIdConfigSettingLiveSorobanStateSizeWindow,
	}
	keys := make([]xdr.LedgerKey, len(ids))
	for i, id := range ids {
		keys[i] = vault.ConfigSettingKey(id)
	}
	entries, _, err := rpc.Entries(ctx, e.RPC, keys)
	if err != nil {
		return ledgerCosts{}, fmt.Errorf("ledger costs: %w", err)
	}
	s := map[xdr.ConfigSettingId]*xdr.ConfigSettingEntry{}
	for _, k := range keys {
		if c := entries[mustKeyString(k)].Data.ConfigSetting; c != nil {
			s[c.ConfigSettingId] = c
		}
	}
	compute, cost, ext := s[ids[0]], s[ids[1]], s[ids[2]]
	historical, events, bandwidth, archival, state := s[ids[3]], s[ids[4]], s[ids[5]], s[ids[6]], s[ids[7]]
	if compute == nil || compute.ContractCompute == nil || cost == nil || cost.ContractLedgerCost == nil || ext == nil || ext.ContractLedgerCostExt == nil ||
		historical == nil || historical.ContractHistoricalData == nil || events == nil || events.ContractEvents == nil ||
		bandwidth == nil || bandwidth.ContractBandwidth == nil || archival == nil || archival.StateArchivalSettings == nil ||
		state == nil || state.LiveSorobanStateSizeWindow == nil || len(*state.LiveSorobanStateSizeWindow) == 0 {
		return ledgerCosts{}, errors.New("ledger costs: the network's settings are missing")
	}
	c, a := cost.ContractLedgerCost, archival.StateArchivalSettings
	var size uint64
	for _, n := range *state.LiveSorobanStateSizeWindow {
		size += uint64(n)
	}
	size /= uint64(len(*state.LiveSorobanStateSizeWindow))
	e.costs = ledgerCosts{
		at: e.now(), instruction: int64(compute.ContractCompute.FeeRatePerInstructionsIncrement),
		readEntry: int64(c.FeeDiskReadLedgerEntry), writeEntry: int64(c.FeeWriteLedgerEntry),
		read1KB: int64(c.FeeDiskRead1Kb), write1KB: int64(ext.ContractLedgerCostExt.FeeWrite1Kb),
		historical1KB: int64(historical.ContractHistoricalData.FeeHistorical1Kb), txSize1KB: int64(bandwidth.ContractBandwidth.FeeTxSize1Kb),
		events1KB:       int64(events.ContractEvents.FeeContractEvents1Kb),
		rent1KB:         rentPerKB(int64(size), int64(c.RentFee1KbSorobanStateSizeLow), int64(c.RentFee1KbSorobanStateSizeHigh), int64(c.SorobanStateTargetSizeBytes), int64(c.SorobanStateRentFeeGrowthFactor)),
		rentDenominator: int64(a.PersistentRentRateDenominator), minPersistentTTL: uint32(a.MinPersistentTtl),
		maxInstructions: uint32(compute.ContractCompute.TxMaxInstructions),
		maxReadEntries:  uint32(c.TxMaxDiskReadEntries), maxWriteEntries: uint32(c.TxMaxWriteLedgerEntries),
		maxFootprint: uint32(ext.ContractLedgerCostExt.TxMaxFootprintEntries),
		maxReadBytes: uint32(c.TxMaxDiskReadBytes), maxWrites: uint32(c.TxMaxWriteBytes),
	}
	return e.costs, nil
}

// rentPerKB is the network's rent for 1 KiB of persistent state over a rent period, which grows
// with the size of the Soroban state as the host computes it.
func rentPerKB(size, low, high, target, growth int64) int64 {
	target = max(target, 1)
	var fee int64
	if size < target {
		fee = ceilDiv((high-low)*size, target) + low
	} else {
		fee = high + ceilDiv((high-low)*(size-target)*growth, target)
	}
	return max(fee, 1000)
}

func ceilDiv(a, b int64) int64 {
	return (a + b - 1) / b
}

func mustKeyString(k xdr.LedgerKey) string {
	s, err := rpc.KeyString(k)
	if err != nil {
		panic(err)
	}
	return s
}

// padClassic adds classicPad to the bytes the call may read for each classic entry in its
// footprint, and to the bytes it may write for each it writes, within the network's limits, and
// returns the fee those bytes add.
func (e *Engine) padClassic(ctx context.Context, res *xdr.SorobanResources) (int64, error) {
	classic := func(keys []xdr.LedgerKey) uint64 {
		n := uint64(0)
		for _, k := range keys {
			if k.Type == xdr.LedgerEntryTypeAccount || k.Type == xdr.LedgerEntryTypeTrustline {
				n++
			}
		}
		return n
	}
	writes := classic(res.Footprint.ReadWrite)
	reads := writes + classic(res.Footprint.ReadOnly)
	if reads == 0 {
		return 0, nil
	}
	c, err := e.ledgerCosts(ctx)
	if err != nil {
		return 0, err
	}
	read := min(uint64(res.DiskReadBytes)+reads*classicPad, max(uint64(c.maxReadBytes), uint64(res.DiskReadBytes)))
	write := min(uint64(res.WriteBytes)+writes*classicPad, max(uint64(c.maxWrites), uint64(res.WriteBytes)))
	fee := perKB(read-uint64(res.DiskReadBytes), c.read1KB) + perKB(write-uint64(res.WriteBytes), c.write1KB)
	res.DiskReadBytes, res.WriteBytes = xdr.Uint32(read), xdr.Uint32(write)
	return fee, nil
}

// perKB is the fee of a number of bytes at a rate per 1024 of them, rounded up as the network
// rounds it.
func perKB(bytes uint64, rate int64) int64 {
	return int64((bytes*uint64(rate) + 1023) / 1024)
}

// Extra is what a call may need beyond its simulation, when the ledger it lands in can lead it
// down another path than the state it was simulated against did: the entries that path writes,
// and the instructions, written bytes, new persistent bytes and event bytes it may add.
type Extra struct {
	// ReadWrite are entries added to the footprint as read-write, or moved there from read-only,
	// in their order, as many as the network's limits allow.
	ReadWrite    []xdr.LedgerKey
	Instructions uint32
	WriteBytes   uint32
	// NewBytes is the size of persistent entries the other path may create, whose rent is set
	// aside for RentLedgers ledgers, or the network's least for a new entry if that is longer.
	NewBytes    uint32
	RentLedgers uint32
	EventBytes  uint32
}

// Extend computes a call's Extra from the footprint its simulation found.
type Extend func(ctx context.Context, footprint xdr.LedgerFootprint) (Extra, error)

// ttlEntryBytes is the size of the TTL entry the network writes with a persistent entry's rent.
const ttlEntryBytes = 48

// addExtra adds x to the simulated transaction data and returns the fee it adds: the network's fee
// for the entries, instructions, written bytes and transaction size it adds, all non-refundable,
// and the rent and event fee the other path may need, which is refunded when it goes unused.
func (e *Engine) addExtra(ctx context.Context, data *xdr.SorobanTransactionData, x Extra) (int64, error) {
	c, err := e.ledgerCosts(ctx)
	if err != nil {
		return 0, err
	}
	before, err := data.MarshalBinary()
	if err != nil {
		return 0, err
	}
	fp := &data.Resources.Footprint
	keyOf := func(k xdr.LedgerKey) string {
		b, _ := k.MarshalBinary()
		return string(b)
	}
	written := map[string]bool{}
	for _, k := range fp.ReadWrite {
		written[keyOf(k)] = true
	}
	read := map[string]int{}
	for i, k := range fp.ReadOnly {
		read[keyOf(k)] = i
	}
	reads := uint32(0)
	for _, k := range append(slices.Clone(fp.ReadOnly), fp.ReadWrite...) {
		if classic(k) {
			reads++
		}
	}
	var promoted []int
	writes, newReads, asked := int64(0), int64(0), 0
	for _, k := range x.ReadWrite {
		name := keyOf(k)
		if written[name] {
			continue
		}
		written[name] = true
		asked++
		if uint32(len(fp.ReadWrite)+len(promoted)) >= c.maxWriteEntries {
			continue
		}
		if i, ok := read[name]; ok {
			promoted = append(promoted, i)
		} else {
			if uint32(len(fp.ReadOnly)+len(fp.ReadWrite)) >= c.maxFootprint || (classic(k) && reads >= c.maxReadEntries) {
				continue
			}
			fp.ReadWrite = append(fp.ReadWrite, k)
			if classic(k) {
				reads++
				newReads++
			}
		}
		writes++
	}
	if left := asked - int(writes); left > 0 && e.Log != nil {
		// The call still goes, with less room than its other path may need.
		e.Log.Warn("the network's limits left entries out of a call's footprint", "asked", asked, "left_out", left)
	}
	slices.Sort(promoted)
	for j, i := range promoted {
		fp.ReadWrite = append(fp.ReadWrite, fp.ReadOnly[i-j])
		fp.ReadOnly = slices.Delete(fp.ReadOnly, i-j, i-j+1)
	}
	res := &data.Resources
	instructions := min(uint64(res.Instructions)+uint64(x.Instructions), uint64(max(c.maxInstructions, uint32(res.Instructions))))
	writeBytes := min(uint64(res.WriteBytes)+uint64(x.WriteBytes), uint64(max(c.maxWrites, uint32(res.WriteBytes))))
	fee := writes*c.writeEntry + newReads*c.readEntry +
		ceilDiv(int64(instructions)*c.instruction, 10_000) - ceilDiv(int64(res.Instructions)*c.instruction, 10_000) +
		perKB(writeBytes, c.write1KB) - perKB(uint64(res.WriteBytes), c.write1KB)
	res.Instructions, res.WriteBytes = xdr.Uint32(instructions), xdr.Uint32(writeBytes)
	after, err := data.MarshalBinary()
	if err != nil {
		return 0, err
	}
	grown := uint64(len(after) - len(before))
	fee += perKB(grown, c.txSize1KB) + perKB(grown, c.historical1KB)
	if x.NewBytes > 0 {
		ledgers := int64(max(x.RentLedgers, c.minPersistentTTL))
		fee += ceilDiv(int64(x.NewBytes)*c.rent1KB*ledgers, 1024*max(c.rentDenominator, 1)) + c.writeEntry + perKB(ttlEntryBytes, c.write1KB)
	}
	fee += perKB(uint64(x.EventBytes), c.events1KB)
	return fee, nil
}

// classic reports an entry of an account or a trustline, which the network reads from disk.
func classic(k xdr.LedgerKey) bool {
	return k.Type == xdr.LedgerEntryTypeAccount || k.Type == xdr.LedgerEntryTypeTrustline
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// minInclusionFee is the network's minimum fee per operation, in stroops.
const minInclusionFee = 100

// InclusionFee returns the p90 Soroban inclusion fee of recent ledgers, never below the network
// minimum and never above the cap.
func (e *Engine) InclusionFee(ctx context.Context) (int64, error) {
	stats, err := e.RPC.GetFeeStats(ctx)
	if err != nil {
		return 0, fmt.Errorf("fee stats: %w", err)
	}
	fee := max(int64(stats.SorobanInclusionFee.P90), minInclusionFee)
	if e.MaxInclusionFee > 0 {
		fee = min(fee, e.MaxInclusionFee)
	}
	return fee, nil
}

// Prepared is a simulated transaction ready to sign. Its account must stay locked until the
// transaction is final.
type Prepared struct {
	Account      *Account
	Tx           *txnbuild.Transaction
	Seq          int64
	InclusionFee int64
	ResourceFee  int64
	MaxTime      int64
	// MaxLedger, when set, is the first ledger that may no longer include the transaction.
	MaxLedger uint32
	// Return is the simulated return value of the call.
	Return *xdr.ScVal
	// SimulatedAt is the ledger the simulation read the chain at.
	SimulatedAt uint32
}

func (e *Engine) loadSequence(ctx context.Context, a *Account) error {
	key, err := vault.AccountKey(a.ID)
	if err != nil {
		return err
	}
	entry, _, err := rpc.One(ctx, e.RPC, key)
	if err != nil {
		return fmt.Errorf("load account %s: %w", a.ID, err)
	}
	if entry.Data.Account == nil {
		return fmt.Errorf("load account %s: not an account", a.ID)
	}
	a.seq = int64(entry.Data.Account.SeqNum)
	a.known = true
	return nil
}

// sorobanOp is an operation whose transaction carries Soroban data.
type sorobanOp interface {
	txnbuild.Operation
	setExt(xdr.TransactionExt)
}

type invokeOp struct{ *txnbuild.InvokeHostFunction }

func (o invokeOp) setExt(ext xdr.TransactionExt) { o.Ext = ext }

type extendOp struct{ *txnbuild.ExtendFootprintTtl }

func (o extendOp) setExt(ext xdr.TransactionExt) { o.Ext = ext }

type restoreOp struct{ *txnbuild.RestoreFootprint }

func (o restoreOp) setExt(ext xdr.TransactionExt) { o.Ext = ext }

// Prepare simulates op from the account and returns the assembled transaction. The account must
// be locked by the caller.
func (e *Engine) Prepare(ctx context.Context, a *Account, op txnbuild.Operation) (*Prepared, error) {
	return e.PrepareUntil(ctx, a, op, 0, nil)
}

// PrepareUntil is Prepare for a transaction the network may include only in a ledger below
// maxLedger, such as a call that stops being valid at a ledger: past that ledger the network
// drops it for free instead of including it to fail. A maxLedger of 0 sets no bound. A non-nil
// extend adds what the call may need beyond its simulation.
func (e *Engine) PrepareUntil(ctx context.Context, a *Account, op txnbuild.Operation, maxLedger uint32, extend Extend) (*Prepared, error) {
	var sop sorobanOp
	switch o := op.(type) {
	case *txnbuild.InvokeHostFunction:
		// The simulation decides the footprint and the authorization of an invocation.
		o.Auth, o.Ext = nil, xdr.TransactionExt{}
		sop = invokeOp{o}
	case *txnbuild.ExtendFootprintTtl:
		// The caller sets the footprint of the entries to extend or restore.
		sop = extendOp{o}
	case *txnbuild.RestoreFootprint:
		sop = restoreOp{o}
	default:
		return nil, fmt.Errorf("submit: %T is not a Soroban operation", op)
	}
	if !a.known {
		if err := e.loadSequence(ctx, a); err != nil {
			return nil, err
		}
	}
	inclusion, err := e.InclusionFee(ctx)
	if err != nil {
		return nil, err
	}
	maxTime := e.now().Add(e.Validity).Unix()
	pre := txnbuild.Preconditions{TimeBounds: txnbuild.NewTimebounds(0, maxTime)}
	if maxLedger > 0 {
		pre.LedgerBounds = &txnbuild.LedgerBounds{MaxLedger: maxLedger}
	}
	build := func(fee int64) (*txnbuild.Transaction, error) {
		return txnbuild.NewTransaction(txnbuild.TransactionParams{
			SourceAccount:        &txnbuild.SimpleAccount{AccountID: a.ID, Sequence: a.seq},
			IncrementSequenceNum: true,
			Operations:           []txnbuild.Operation{sop},
			BaseFee:              fee,
			Preconditions:        pre,
		})
	}
	draft, err := build(inclusion)
	if err != nil {
		return nil, err
	}
	encoded, err := draft.Base64()
	if err != nil {
		return nil, err
	}
	sim, err := e.RPC.SimulateTransaction(ctx, protocol.SimulateTransactionRequest{Transaction: encoded})
	if err != nil {
		return nil, fmt.Errorf("simulate: %w", err)
	}
	if sim.Error != "" {
		return nil, fmt.Errorf("%w: %s", ErrSimulation, sim.Error)
	}
	if sim.RestorePreamble != nil {
		return nil, fmt.Errorf("%w: archived entries need a separate restore", ErrSimulation)
	}
	var data xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionDataXDR, &data); err != nil {
		return nil, fmt.Errorf("simulation data: %w", err)
	}
	var extra int64
	if extend != nil {
		x, err := extend(ctx, data.Resources.Footprint)
		if err != nil {
			return nil, err
		}
		if extra, err = e.addExtra(ctx, &data, x); err != nil {
			return nil, err
		}
	}
	padding, err := e.padClassic(ctx, &data.Resources)
	if err != nil {
		return nil, err
	}
	resource := sim.MinResourceFee + sim.MinResourceFee*e.ResourceMarginPct/100 + padding + extra
	limit := e.MaxResourceFee
	if _, invoke := sop.(invokeOp); !invoke && e.MaxTTLFee > 0 {
		limit = e.MaxTTLFee
	}
	// The padding's fees come from the network's settings as the RPC reports them, so the cap
	// bounds the whole fee.
	if limit > 0 && resource > limit {
		return nil, fmt.Errorf("%w: %d stroops, the cap is %d", ErrFeeCap, resource, limit)
	}
	data.ResourceFee = xdr.Int64(resource)
	sop.setExt(xdr.TransactionExt{V: 1, SorobanData: &data})
	var ret *xdr.ScVal
	if invoke, ok := sop.(invokeOp); ok && len(sim.Results) > 0 {
		r := sim.Results[0]
		if r.AuthXDR != nil {
			for _, s := range *r.AuthXDR {
				var entry xdr.SorobanAuthorizationEntry
				if err := xdr.SafeUnmarshalBase64(s, &entry); err != nil {
					return nil, fmt.Errorf("simulated auth: %w", err)
				}
				if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
					return nil, fmt.Errorf("%w: the call needs a signature other than the source's", ErrSimulation)
				}
				invoke.Auth = append(invoke.Auth, entry)
			}
		}
		if r.ReturnValueXDR != nil {
			var v xdr.ScVal
			if err := xdr.SafeUnmarshalBase64(*r.ReturnValueXDR, &v); err == nil {
				ret = &v
			}
		}
	}
	tx, err := build(inclusion)
	if err != nil {
		return nil, err
	}
	return &Prepared{Account: a, Tx: tx, Seq: a.seq + 1, InclusionFee: inclusion, ResourceFee: resource, MaxTime: maxTime, MaxLedger: maxLedger, Return: ret,
		SimulatedAt: uint32(sim.LatestLedger)}, nil
}

// Signed is a transaction accepted for inclusion.
type Signed struct {
	*Prepared
	Hash string
}

// Send signs and submits the transaction and returns once the network holds it. A
// TRY_AGAIN_LATER resends the same envelope until the time bound passes. When an earlier attempt
// may have reached the network unanswered, a refusal or an expiry is checked against the
// envelope's own hash before it is believed, since the first copy may already be applied.
func (e *Engine) Send(ctx context.Context, p *Prepared) (*Signed, error) {
	signed, err := p.Tx.Sign(e.Passphrase, p.Account.Signer)
	if err != nil {
		return nil, err
	}
	envelope, err := signed.Base64()
	if err != nil {
		return nil, err
	}
	hash, err := signed.HashHex(e.Passphrase)
	if err != nil {
		return nil, err
	}
	s := &Signed{Prepared: p, Hash: hash}
	backoff := e.poll()
	ambiguous := false
	closed := e.now().Unix()
	var ledger uint32
	for {
		resp, err := e.RPC.SendTransaction(ctx, protocol.SendTransactionRequest{Transaction: envelope})
		switch {
		case err != nil:
			ambiguous = true
		case resp.Status == "PENDING" || resp.Status == "DUPLICATE":
			return s, nil
		case resp.Status == "ERROR":
			if ambiguous {
				return e.resolve(ctx, s)
			}
			// Any refusal may leave the cached sequence wrong, so it is read again next time.
			p.Account.known = false
			return nil, fmt.Errorf("%w: %s", ErrRejected, resultCode(resp.ErrorResultXDR))
		default:
			closed = max(closed, resp.LatestLedgerCloseTime)
			ledger = max(ledger, resp.LatestLedger)
		}
		if closed > p.MaxTime || p.pastLedger(ledger) {
			if ambiguous {
				return e.resolve(ctx, s)
			}
			p.Account.known = false
			return nil, ErrExpired
		}
		if err := wait(ctx, backoff); err != nil {
			p.Account.known = false
			return nil, err
		}
		backoff = min(backoff*2, 10*time.Second)
		closed = max(closed, e.now().Unix())
	}
}

// resolve asks for the envelope's own hash until it is known whether the network applied it.
func (e *Engine) resolve(ctx context.Context, s *Signed) (*Signed, error) {
	for {
		resp, err := e.RPC.GetTransaction(ctx, protocol.GetTransactionRequest{Hash: s.Hash})
		if err == nil {
			switch resp.Status {
			case protocol.TransactionStatusSuccess, protocol.TransactionStatusFailed:
				return s, nil
			case protocol.TransactionStatusNotFound:
				if resp.LatestLedgerCloseTime > s.MaxTime || s.pastLedger(resp.LatestLedger) {
					s.Account.known = false
					return nil, ErrExpired
				}
			}
		}
		if err := wait(ctx, e.poll()); err != nil {
			s.Account.known = false
			return nil, err
		}
	}
}

// pastLedger reports whether the network has closed the ledger at which the transaction stopped
// being includable.
func (p *Prepared) pastLedger(latest uint32) bool {
	return p.MaxLedger > 0 && latest >= p.MaxLedger
}

// poll is the polling interval, never zero.
func (e *Engine) poll() time.Duration {
	return max(e.Poll, 50*time.Millisecond)
}

func resultCode(b64 string) string {
	var r xdr.TransactionResult
	if err := xdr.SafeUnmarshalBase64(b64, &r); err != nil {
		return "unknown"
	}
	return r.Result.Code.String()
}

// Outcome is how a sent transaction ended.
type Outcome string

// The outcomes of a sent transaction.
const (
	Success Outcome = "success"
	Failed  Outcome = "failed"
	Expired Outcome = "expired"
)

// Result is the final state of a sent transaction.
type Result struct {
	Hash    string
	Outcome Outcome
	Ledger  uint32
	// FeeCharged is the total fee the source paid.
	FeeCharged int64
	// ResourceFeeCharged is the resource part of it, refundable and non-refundable.
	ResourceFeeCharged int64
	Code               string
	Return             *xdr.ScVal
	// Events are the contract events of a successful transaction.
	Events []xdr.ContractEvent
	// InvokeCode is the result code of a failed contract call, when the transaction got that far.
	InvokeCode *xdr.InvokeHostFunctionResultCode
	// ContractError is the first contract error the diagnostic events of a failed call name, when
	// the RPC returns them.
	ContractError *ContractError
	// Diagnosed is set when the RPC returned diagnostic events for the transaction; one that does
	// not keeps the cause of a failure from being told.
	Diagnosed bool
	// Conflict is set when the call failed on the host's storage, as when it touched an entry its
	// footprint does not hold: the chain moved under it between its simulation and its ledger,
	// and a new simulation sees where it moved.
	Conflict bool
}

// ContractError is an error a contract raised: the contract and its code.
type ContractError struct {
	Contract string
	Code     uint32
}

// Track polls until the transaction succeeded, failed or can no longer be included, and keeps the
// account's sequence consistent with that.
func (e *Engine) Track(ctx context.Context, s *Signed) (Result, error) {
	for {
		resp, err := e.RPC.GetTransaction(ctx, protocol.GetTransactionRequest{Hash: s.Hash})
		if err == nil {
			switch resp.Status {
			case protocol.TransactionStatusSuccess, protocol.TransactionStatusFailed:
				s.Account.seq = s.Seq
				s.Account.known = true
				return e.result(s, resp), nil
			case protocol.TransactionStatusNotFound:
				if resp.LatestLedgerCloseTime > s.MaxTime || s.pastLedger(resp.LatestLedger) {
					s.Account.known = false
					return Result{Hash: s.Hash, Outcome: Expired}, nil
				}
			}
		}
		if err := wait(ctx, e.poll()); err != nil {
			s.Account.known = false
			return Result{}, err
		}
	}
}

// Lookup follows a transaction known only by its hash, such as one sent before a restart, until it
// succeeded or failed, or until it has been unknown for longer than its time bound allows.
func (e *Engine) Lookup(ctx context.Context, hash string) (Result, error) {
	giveUp := e.now().Add(e.Validity + time.Minute)
	for {
		resp, err := e.RPC.GetTransaction(ctx, protocol.GetTransactionRequest{Hash: hash})
		if err == nil {
			switch resp.Status {
			case protocol.TransactionStatusSuccess, protocol.TransactionStatusFailed:
				return e.result(&Signed{Hash: hash}, resp), nil
			case protocol.TransactionStatusNotFound:
				if e.now().After(giveUp) {
					return Result{Hash: hash, Outcome: Expired}, nil
				}
			}
		}
		if err := wait(ctx, e.poll()); err != nil {
			return Result{}, err
		}
	}
}

func (e *Engine) result(s *Signed, resp protocol.GetTransactionResponse) Result {
	r := Result{Hash: s.Hash, Outcome: Success, Ledger: resp.Ledger}
	var tr xdr.TransactionResult
	if err := xdr.SafeUnmarshalBase64(resp.ResultXDR, &tr); err == nil {
		r.FeeCharged = int64(tr.FeeCharged)
		r.Code = tr.Result.Code.String()
		if results, ok := tr.Result.GetResults(); ok && len(results) > 0 {
			if inner, ok := results[0].GetTr(); ok && inner.InvokeHostFunctionResult != nil {
				code := inner.InvokeHostFunctionResult.Code
				r.InvokeCode = &code
			}
		}
	}
	if resp.Status == protocol.TransactionStatusFailed {
		r.Outcome = Failed
	}
	var diagnostics []xdr.DiagnosticEvent
	for _, raw := range resp.DiagnosticEventsXDR {
		var d xdr.DiagnosticEvent
		if xdr.SafeUnmarshalBase64(raw, &d) == nil {
			diagnostics = append(diagnostics, d)
		}
	}
	var meta xdr.TransactionMeta
	if err := xdr.SafeUnmarshalBase64(resp.ResultMetaXDR, &meta); err == nil {
		var ext xdr.SorobanTransactionMetaExt
		switch meta.V {
		case 3:
			if sm := meta.MustV3().SorobanMeta; sm != nil {
				ext = sm.Ext
				v := sm.ReturnValue
				r.Return = &v
				r.Events = sm.Events
				diagnostics = append(diagnostics, sm.DiagnosticEvents...)
			}
		case 4:
			v4 := meta.MustV4()
			if sm := v4.SorobanMeta; sm != nil {
				ext = sm.Ext
				r.Return = sm.ReturnValue
			}
			for _, op := range v4.Operations {
				r.Events = append(r.Events, op.Events...)
			}
			diagnostics = append(diagnostics, v4.DiagnosticEvents...)
		}
		if ext.V1 != nil {
			r.ResourceFeeCharged = int64(ext.V1.TotalNonRefundableResourceFeeCharged + ext.V1.TotalRefundableResourceFeeCharged)
		}
	}
	if r.Outcome == Failed {
		r.ContractError = contractError(diagnostics)
		r.Conflict = storageError(diagnostics)
	}
	r.Diagnosed = len(diagnostics) > 0
	return r
}

// storageError reports whether diagnostic events name an error of the host's storage.
func storageError(events []xdr.DiagnosticEvent) bool {
	for _, d := range events {
		body, ok := d.Event.Body.GetV0()
		if !ok {
			continue
		}
		for _, t := range body.Topics {
			if e, ok := t.GetError(); ok && e.Type == xdr.ScErrorTypeSceStorage {
				return true
			}
		}
	}
	return false
}

// contractError finds the first contract error in diagnostic events: the one closest to the cause,
// since a call that fails passes its callee's error up unchanged.
func contractError(events []xdr.DiagnosticEvent) *ContractError {
	for _, d := range events {
		body, ok := d.Event.Body.GetV0()
		if !ok {
			continue
		}
		for _, t := range body.Topics {
			e, ok := t.GetError()
			if !ok || e.Type != xdr.ScErrorTypeSceContract || e.ContractCode == nil {
				continue
			}
			out := &ContractError{Code: uint32(*e.ContractCode)}
			if d.Event.ContractId != nil {
				out.Contract = strkey.MustEncode(strkey.VersionByteContract, d.Event.ContractId[:])
			}
			return out
		}
	}
	return nil
}

// ErrNotWorth reports a call whose simulation showed it would achieve nothing, so it was not sent.
var ErrNotWorth = errors.New("submit: the call would achieve nothing")

// Do runs one call on the account from simulation to its final outcome, sending it again with
// backoff while it is refused or expires, and stops at the first failed simulation.
func (e *Engine) Do(ctx context.Context, a *Account, build func() (txnbuild.Operation, error), attempts int) (Result, error) {
	return e.DoWorth(ctx, a, build, attempts, nil)
}

// DoWorth is Do for a call that is sent only when worth accepts its simulated return value.
func (e *Engine) DoWorth(ctx context.Context, a *Account, build func() (txnbuild.Operation, error), attempts int, worth func(*xdr.ScVal) bool) (Result, error) {
	return e.DoExtended(ctx, a, build, attempts, worth, nil)
}

// ErrConflict reports calls that kept failing on the host's storage as the chain moved under them.
var ErrConflict = errors.New("submit: the chain kept moving under the call")

// DoExtended is DoWorth for a call that may need extend beyond its simulation. A call that fails
// for a conflict is simulated and sent again, as one that expired is.
func (e *Engine) DoExtended(ctx context.Context, a *Account, build func() (txnbuild.Operation, error), attempts int, worth func(*xdr.ScVal) bool, extend Extend) (Result, error) {
	a.Lock()
	defer a.Unlock()
	backoff := time.Second
	var last error
	for range max(attempts, 1) {
		op, err := build()
		if err != nil {
			return Result{}, err
		}
		p, err := e.PrepareUntil(ctx, a, op, 0, extend)
		if err == nil && worth != nil && !worth(p.Return) {
			return Result{}, ErrNotWorth
		}
		if err != nil {
			if errors.Is(err, ErrSimulation) {
				return Result{}, err
			}
			last = err
		} else if s, err := e.Send(ctx, p); err != nil {
			last = err
		} else {
			res, err := e.Track(ctx, s)
			if err != nil {
				return Result{}, err
			}
			switch {
			case res.Outcome == Failed && res.Conflict:
				last = fmt.Errorf("%w: %s", ErrConflict, res.Hash)
			case res.Outcome != Expired:
				return res, nil
			default:
				last = ErrExpired
			}
		}
		if err := wait(ctx, backoff); err != nil {
			return Result{}, err
		}
		backoff = min(backoff*2, 3*time.Minute)
	}
	return Result{}, last
}

func wait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
