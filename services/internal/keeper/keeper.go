// Package keeper keeps the vault's entries alive, admits eligible deposits, refunds deposits that
// stayed flagged, pays the exit queue as the outflow window allows and queues stranded exits again
// once they can be paid. Every call it makes is permissionless, so its key only risks its float.
package keeper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const ledgersPerDay = 17_280

// Config sets the vault and the keeper's bounds.
type Config struct {
	Vault        string
	DeployLedger uint32
	// Asset is the vault's asset as its asset contract names it: native, or CODE:ISSUER.
	Asset string
	// MaxAdmissions is the most deposits one admit call carries. The event size limit of a
	// transaction allows 17; one fewer keeps a margin should an event grow.
	MaxAdmissions int
	// MaxExtensions is the most entries one footprint extension carries.
	MaxExtensions int
	// MaxReleases is the most exits one release call handles; the vault measures fifteen as what
	// fits every transaction limit in the worst case.
	MaxReleases int
	// RefundDelay is how long a deposit must stay flagged before anyone may refund it.
	RefundDelay time.Duration
	// HoldReasons are flag reasons the keeper never refunds, such as a written order from an
	// authority; the depositor can still claim those refunds.
	HoldReasons map[uint32]bool
	// BalanceFloor is the keeper account's balance, in stroops, below which it alerts.
	BalanceFloor int64
	// ExitKeys is how many exits queued, or released, ahead of a claim or release in the ledger it
	// lands in still leave its footprint room; 4 when unset.
	ExitKeys uint32
	// Unflags, when set, names the deposits an operator's queued unflag waits to correct, each
	// with when its final window ends: the keeper does not refund one before then.
	Unflags func(ctx context.Context) (map[uint64]uint64, error)
}

// Keeper follows the vault and runs the upkeep.
type Keeper struct {
	cfg     Config
	rpc     rpc.Client
	chain   *chainstate.Store
	engine  *submit.Engine
	account *submit.Account
	alerts  *alert.Alerter
	log     *slog.Logger
	now     func() time.Time

	mu        sync.RWMutex
	state     *chainstate.State
	cursor    uint32
	lastCycle time.Time
	claims    map[uint64]claimTry
	idle      *releaseIdle

	// charged is what the current TTL cycle's transactions were charged; only the cycle uses it.
	charged int64
}

// New loads the stored chain state.
func New(ctx context.Context, cfg Config, client rpc.Client, chain *chainstate.Store, engine *submit.Engine, account *submit.Account, alerts *alert.Alerter, log *slog.Logger) (*Keeper, error) {
	state, cursor, err := chain.Load(ctx, cfg.Vault, cfg.DeployLedger)
	if err != nil {
		return nil, err
	}
	if cfg.ExitKeys == 0 {
		cfg.ExitKeys = 4
	}
	return &Keeper{
		cfg: cfg, rpc: client, chain: chain, engine: engine, account: account, alerts: alerts, log: log, now: time.Now,
		state: state, cursor: cursor, claims: map[uint64]claimTry{},
	}, nil
}

// Cursor implements follow.Sink.
func (k *Keeper) Cursor() uint32 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.cursor
}

// Apply implements follow.Sink.
func (k *Keeper) Apply(ctx context.Context, b follow.Batch) error {
	k.mu.RLock()
	next := k.state.Clone()
	k.mu.RUnlock()
	delta, err := next.Apply(b.Txs)
	if err != nil {
		return fmt.Errorf("%w: %w", follow.ErrFault, err)
	}
	if err := k.chain.Commit(ctx, b.From, b.To, next, delta, nil); err != nil {
		if errors.Is(err, chainstate.ErrInconsistent) {
			return fmt.Errorf("%w: %w", follow.ErrFault, err)
		}
		return err
	}
	k.mu.Lock()
	k.state, k.cursor = next, b.To
	k.mu.Unlock()
	return nil
}

func (k *Keeper) pendingIDs() []uint64 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	ids := make([]uint64, 0, len(k.state.Pending))
	for id := range k.state.Pending {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (k *Keeper) invoke(fn string, args ...xdr.ScVal) (txnbuild.Operation, error) {
	addr, err := vault.ScAddress(k.cfg.Vault)
	if err != nil {
		return nil, err
	}
	return &txnbuild.InvokeHostFunction{HostFunction: xdr.HostFunction{
		Type:           xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
		InvokeContract: &xdr.InvokeContractArgs{ContractAddress: addr, FunctionName: xdr.ScSymbol(fn), Args: args},
	}}, nil
}

// call runs one keeper transaction to its outcome and alerts when it still fails after retries.
func (k *Keeper) call(ctx context.Context, what string, build func() (txnbuild.Operation, error)) (submit.Result, error) {
	return k.callWorth(ctx, what, build, nil, nil)
}

// callWorth is call for a transaction sent only when worth accepts its simulated return value,
// given what extend adds beyond its simulation.
func (k *Keeper) callWorth(ctx context.Context, what string, build func() (txnbuild.Operation, error), worth func(*xdr.ScVal) bool, extend submit.Extend) (submit.Result, error) {
	res, err := k.attempt(ctx, what, build, worth, extend)
	if err != nil && !errors.Is(err, submit.ErrSimulation) && !errors.Is(err, submit.ErrNotWorth) {
		k.alerts.Raise(ctx, alert.Critical, "call_failed", "%s failed after retries: %v", what, err)
	}
	return res, err
}

// attempt is callWorth without the alert, for a caller that judges a failure itself.
func (k *Keeper) attempt(ctx context.Context, what string, build func() (txnbuild.Operation, error), worth func(*xdr.ScVal) bool, extend submit.Extend) (submit.Result, error) {
	res, err := k.engine.DoExtended(ctx, k.account, build, 5, worth, extend)
	if err == nil && res.Outcome != submit.Success {
		err = fmt.Errorf("%s %s: %s", what, res.Outcome, res.Code)
	}
	if err == nil {
		k.log.Info("submitted", "call", what, "tx", res.Hash, "ledger", res.Ledger, "fee", res.FeeCharged)
	}
	return res, err
}

// chainTime is the close time of the latest ledger, the clock the vault's checks use.
func (k *Keeper) chainTime(ctx context.Context) (uint64, uint32, error) {
	h, err := k.rpc.GetHealth(ctx)
	if err != nil {
		return 0, 0, err
	}
	return uint64(h.LatestLedgerCloseTime), h.LatestLedger, nil
}

type pendingEntry struct {
	id      uint64
	deposit vault.PendingDeposit
}

// readPending reads the queue from the chain; deposits whose entry is missing are skipped.
func (k *Keeper) readPending(ctx context.Context, ids []uint64) ([]pendingEntry, error) {
	keys := make([]xdr.LedgerKey, len(ids))
	for i, id := range ids {
		key, err := vault.PendingKey(k.cfg.Vault, id)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	entries, _, err := rpc.Entries(ctx, k.rpc, keys)
	if err != nil {
		return nil, err
	}
	var out []pendingEntry
	for i, id := range ids {
		s, _ := rpc.KeyString(keys[i])
		e, ok := entries[s]
		if !ok {
			continue
		}
		v, err := rpc.ContractValue(e)
		if err != nil {
			return nil, err
		}
		d, err := vault.DecodePendingDeposit(v)
		if err != nil {
			return nil, err
		}
		out = append(out, pendingEntry{id: id, deposit: d})
	}
	return out, nil
}

// Admit admits every eligible deposit in ascending order, in batches that fit a transaction.
func (k *Keeper) Admit(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return err
	}
	now, _, err := k.chainTime(ctx)
	if err != nil {
		return err
	}
	if inst.Status.Halted(now) {
		return nil
	}
	var candidates []uint64
	for _, id := range k.pendingIDs() {
		if id <= inst.Status.AttestedUpTo {
			candidates = append(candidates, id)
		}
	}
	pending, err := k.readPending(ctx, candidates)
	if err != nil {
		return err
	}
	var eligible []uint64
	for _, p := range pending {
		at := p.deposit.EligibleAt(inst.Config, inst.Limits)
		if p.deposit.Flag != nil || now < at {
			continue
		}
		eligible = append(eligible, p.id)
		if now >= at+600 {
			k.alerts.Raise(ctx, alert.Warning, "admission_late", "deposit %d has been eligible for %d seconds", p.id, now-at)
		}
	}
	batch := max(k.cfg.MaxAdmissions, 1)
	for len(eligible) > 0 {
		n := min(batch, len(eligible))
		ids := make([]xdr.ScVal, n)
		for i, id := range eligible[:n] {
			ids[i] = vault.U64(id)
		}
		_, err := k.callWorth(ctx, fmt.Sprintf("admit of %d deposits", n), func() (txnbuild.Operation, error) {
			return k.invoke("admit", vault.Vec(ids...))
		}, admittedAny, nil)
		if errors.Is(err, submit.ErrSimulation) && n > 1 {
			// A batch over the transaction's limits fails in simulation; try a smaller one.
			batch = n / 2
			continue
		}
		if err != nil && !errors.Is(err, submit.ErrNotWorth) {
			return err
		}
		eligible = eligible[n:]
	}
	k.alerts.Clear(ctx, "admission_late", "every eligible deposit is admitted")
	return nil
}

// admittedAny reports whether a simulated admit admitted at least one deposit.
func admittedAny(ret *xdr.ScVal) bool {
	if ret == nil {
		return true
	}
	v, ok := ret.GetVec()
	return !ok || v == nil || len(*v) > 0
}

// Refund returns deposits that stayed flagged past the correction window, except those held and
// those an operator's queued unflag waits to correct, until it is carried out or the deposit's
// final window ends. A refund that fails because the deposit left the queue first, as when its
// depositor cancels it, does not page.
func (k *Keeper) Refund(ctx context.Context) error {
	now, _, err := k.chainTime(ctx)
	if err != nil {
		return err
	}
	pending, err := k.readPending(ctx, k.pendingIDs())
	if err != nil {
		return err
	}
	var unflags map[uint64]uint64
	if k.cfg.Unflags != nil {
		// Without the list no refund goes, as one could preempt an operator's correction.
		if unflags, err = k.cfg.Unflags(ctx); err != nil {
			k.alerts.Raise(ctx, alert.Warning, "refunds_wait", "refunds wait: the deposits with an unflag queued cannot be read from the screening service: %v", err)
			return err
		}
		k.alerts.Clear(ctx, "refunds_wait", "refunds go again")
	}
	for _, p := range pending {
		d := p.deposit
		if d.Flag == nil || k.cfg.HoldReasons[*d.Flag] || now < d.FlaggedAt+uint64(k.cfg.RefundDelay.Seconds()) {
			continue
		}
		if until, queued := unflags[p.id]; queued && now < until {
			continue
		}
		id := p.id
		what := fmt.Sprintf("refund of deposit %d", id)
		res, err := k.attempt(ctx, what, func() (txnbuild.Operation, error) {
			return k.invoke("refund", vault.U64(id))
		}, nil, nil)
		switch {
		case err == nil:
		case errors.Is(err, submit.ErrSimulation):
			k.log.Info("refund not sent", "deposit", id, "error", err.Error())
		case res.Outcome == submit.Failed && k.pendingGone(ctx, id):
			k.log.Info("refund came after the deposit left the queue", "deposit", id, "tx", res.Hash)
		default:
			k.alerts.Raise(ctx, alert.Critical, "call_failed", "%s failed after retries: %v", what, err)
		}
	}
	return nil
}

// pendingGone reports whether a deposit's pending entry is gone, as after its cancellation.
func (k *Keeper) pendingGone(ctx context.Context, id uint64) bool {
	key, err := vault.PendingKey(k.cfg.Vault, id)
	if err != nil {
		return false
	}
	_, _, err = rpc.One(ctx, k.rpc, key)
	return errors.Is(err, rpc.ErrMissing)
}

// CheckBalance alerts when the keeper's own account runs low.
func (k *Keeper) CheckBalance(ctx context.Context) error {
	key, err := vault.AccountKey(k.account.ID)
	if err != nil {
		return err
	}
	e, _, err := rpc.One(ctx, k.rpc, key)
	if err != nil {
		return err
	}
	if balance := int64(e.Data.Account.Balance); balance < k.cfg.BalanceFloor {
		k.alerts.Raise(ctx, alert.Warning, "balance_low", "the keeper account holds %d stroops", balance)
	} else {
		k.alerts.Clear(ctx, "balance_low", "the keeper account is funded")
	}
	return nil
}

// Run follows the vault and runs each job on its schedule until ctx ends.
func (k *Keeper) Run(ctx context.Context, f *follow.Follower, poll time.Duration) {
	go f.Run(ctx, poll, func(err error) {
		if errors.Is(err, follow.ErrFault) {
			k.alerts.Raise(ctx, alert.Critical, "ingest_fault", "keeper ingest stopped: %v", err)
		} else {
			k.log.Warn("ingest retry", "error", err.Error())
		}
	})
	jobs := []struct {
		name  string
		every time.Duration
		run   func(context.Context) error
		next  func(time.Time, time.Duration) time.Duration
	}{
		{"admission", 30 * time.Second, k.Admit, nil},
		{"releases", 30 * time.Second, k.Release, untilRelease},
		{"claims", 10 * time.Minute, k.Claims, nil},
		{"refunds", 5 * time.Minute, k.Refund, nil},
		{"ttl", time.Hour, k.TTLCycle, nil},
		{"balance", 10 * time.Minute, k.CheckBalance, nil},
		{"watch", time.Minute, func(ctx context.Context) error { k.Watch(ctx); return nil }, nil},
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Go(func() {
			for ctx.Err() == nil {
				if err := j.run(ctx); err != nil && ctx.Err() == nil {
					k.log.Warn("job incomplete", "job", j.name, "error", err.Error())
				}
				wait := j.every
				if j.next != nil {
					wait = j.next(k.now(), j.every)
				}
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
				case <-t.C:
				}
			}
		})
	}
	wg.Wait()
}
