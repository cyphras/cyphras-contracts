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
	// Validity is how long a signed transaction may wait for inclusion.
	Validity time.Duration
	// Poll is the interval between getTransaction calls.
	Poll time.Duration
	Now  func() time.Time
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
	// Return is the simulated return value of the call.
	Return *xdr.ScVal
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

// Prepare simulates op from the account and returns the assembled transaction. The account must
// be locked by the caller.
func (e *Engine) Prepare(ctx context.Context, a *Account, op txnbuild.Operation) (*Prepared, error) {
	var sop sorobanOp
	switch o := op.(type) {
	case *txnbuild.InvokeHostFunction:
		// The simulation decides the footprint and the authorization of an invocation.
		o.Auth, o.Ext = nil, xdr.TransactionExt{}
		sop = invokeOp{o}
	case *txnbuild.ExtendFootprintTtl:
		// The caller sets the footprint of the entries to extend.
		sop = extendOp{o}
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
	build := func(fee int64) (*txnbuild.Transaction, error) {
		return txnbuild.NewTransaction(txnbuild.TransactionParams{
			SourceAccount:        &txnbuild.SimpleAccount{AccountID: a.ID, Sequence: a.seq},
			IncrementSequenceNum: true,
			Operations:           []txnbuild.Operation{sop},
			BaseFee:              fee,
			Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewTimebounds(0, maxTime)},
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
	resource := sim.MinResourceFee + sim.MinResourceFee*e.ResourceMarginPct/100
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
	return &Prepared{Account: a, Tx: tx, Seq: a.seq + 1, InclusionFee: inclusion, ResourceFee: resource, MaxTime: maxTime, Return: ret}, nil
}

// Signed is a transaction accepted for inclusion.
type Signed struct {
	*Prepared
	Hash string
}

// Send signs and submits the transaction and returns once the network holds it. A
// TRY_AGAIN_LATER resends the same envelope until the time bound passes.
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
	backoff := e.Poll
	for {
		resp, err := e.RPC.SendTransaction(ctx, protocol.SendTransactionRequest{Transaction: envelope})
		switch {
		case err != nil:
			// The RPC may or may not have the envelope; resending the same one is safe.
		case resp.Status == "PENDING" || resp.Status == "DUPLICATE":
			return &Signed{Prepared: p, Hash: hash}, nil
		case resp.Status == "ERROR":
			code := resultCode(resp.ErrorResultXDR)
			// Any refusal may leave the cached sequence wrong, so it is read again next time.
			p.Account.known = false
			return nil, fmt.Errorf("%w: %s", ErrRejected, code)
		}
		if e.now().Unix() > p.MaxTime {
			p.Account.known = false
			return nil, ErrExpired
		}
		if err := wait(ctx, backoff); err != nil {
			p.Account.known = false
			return nil, err
		}
		backoff = min(backoff*2, 10*time.Second)
	}
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
				if resp.LatestLedgerCloseTime > s.MaxTime {
					s.Account.known = false
					return Result{Hash: s.Hash, Outcome: Expired}, nil
				}
			}
		}
		if err := wait(ctx, e.Poll); err != nil {
			s.Account.known = false
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
	}
	if resp.Status == protocol.TransactionStatusFailed {
		r.Outcome = Failed
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
			}
		case 4:
			if sm := meta.MustV4().SorobanMeta; sm != nil {
				ext = sm.Ext
				r.Return = sm.ReturnValue
			}
		}
		if ext.V1 != nil {
			r.ResourceFeeCharged = int64(ext.V1.TotalNonRefundableResourceFeeCharged + ext.V1.TotalRefundableResourceFeeCharged)
		}
	}
	return r
}

// Do runs one call on the account from simulation to its final outcome, sending it again with
// backoff while it is refused or expires, and stops at the first failed simulation.
func (e *Engine) Do(ctx context.Context, a *Account, build func() (txnbuild.Operation, error), attempts int) (Result, error) {
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
