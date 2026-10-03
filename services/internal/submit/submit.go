// Package submit sends Soroban transactions with one transaction in flight per source account and
// reports a transaction only once its outcome on chain is known.
package submit

import (
	"context"
	"errors"
	"fmt"
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
	// Validity is how long a signed transaction may wait for inclusion.
	Validity time.Duration
	// Poll is the interval between getTransaction calls.
	Poll time.Duration
	Now  func() time.Time

	costMu sync.Mutex
	costs  ledgerCosts
}

// ledgerCosts are the network's fees and limits for the bytes a call reads and writes, read with
// the time they were read.
type ledgerCosts struct {
	at                      time.Time
	read1KB, write1KB       int64
	maxReadBytes, maxWrites uint32
}

// classicPad is the room added to the bytes a call may read and write for each classic entry it
// touches, an account or a trustline: anyone can grow their own account, by signers or
// sponsorships, between a simulation and the ledger the call lands in, and the call would then run
// out of the bytes the simulation measured. An account entry holds at most about 2 KB.
const classicPad = 2048

// ledgerCosts reads the network's fees for read and written bytes, at most once an hour.
func (e *Engine) ledgerCosts(ctx context.Context) (ledgerCosts, error) {
	e.costMu.Lock()
	defer e.costMu.Unlock()
	if !e.costs.at.IsZero() && e.now().Sub(e.costs.at) < time.Hour {
		return e.costs, nil
	}
	base, ext := vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingContractLedgerCostV0), vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingContractLedgerCostExtV0)
	entries, _, err := rpc.Entries(ctx, e.RPC, []xdr.LedgerKey{base, ext})
	if err != nil {
		return ledgerCosts{}, fmt.Errorf("ledger costs: %w", err)
	}
	b, x := entries[mustKeyString(base)].Data.ConfigSetting, entries[mustKeyString(ext)].Data.ConfigSetting
	if b == nil || b.ContractLedgerCost == nil || x == nil || x.ContractLedgerCostExt == nil {
		return ledgerCosts{}, errors.New("ledger costs: the network's settings are missing")
	}
	e.costs = ledgerCosts{
		at: e.now(), read1KB: int64(b.ContractLedgerCost.FeeDiskRead1Kb), write1KB: int64(x.ContractLedgerCostExt.FeeWrite1Kb),
		maxReadBytes: uint32(b.ContractLedgerCost.TxMaxDiskReadBytes), maxWrites: uint32(b.ContractLedgerCost.TxMaxWriteBytes),
	}
	return e.costs, nil
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
	return e.PrepareUntil(ctx, a, op, 0)
}

// PrepareUntil is Prepare for a transaction the network may include only in a ledger below
// maxLedger, such as a call that stops being valid at a ledger: past that ledger the network
// drops it for free instead of including it to fail. A maxLedger of 0 sets no bound.
func (e *Engine) PrepareUntil(ctx context.Context, a *Account, op txnbuild.Operation, maxLedger uint32) (*Prepared, error) {
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
	if e.MaxResourceFee > 0 && sim.MinResourceFee > e.MaxResourceFee {
		return nil, fmt.Errorf("%w: a resource fee of %d stroops is above the cap", ErrSimulation, sim.MinResourceFee)
	}
	padding, err := e.padClassic(ctx, &data.Resources)
	if err != nil {
		return nil, err
	}
	resource := sim.MinResourceFee + sim.MinResourceFee*e.ResourceMarginPct/100 + padding
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
	}
	return r
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
	a.Lock()
	defer a.Unlock()
	backoff := time.Second
	var last error
	for range max(attempts, 1) {
		op, err := build()
		if err != nil {
			return Result{}, err
		}
		p, err := e.Prepare(ctx, a, op)
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
			if res.Outcome != Expired {
				return res, nil
			}
			last = ErrExpired
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
