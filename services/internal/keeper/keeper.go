// Package keeper keeps the vault's entries alive, admits eligible deposits and refunds deposits
// that stayed flagged. Every call it makes is permissionless, so its key only risks its float.
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
	// MaxAdmissions is the most deposits one admit call carries; the event size limit of a
	// transaction allows 17.
	MaxAdmissions int
	// MaxExtensions is the most entries one footprint extension carries.
	MaxExtensions int
	// RefundDelay is how long a deposit must stay flagged before anyone may refund it.
	RefundDelay time.Duration
	// HoldReasons are flag reasons the keeper never refunds, such as a written order from an
	// authority; the depositor can still claim those refunds.
	HoldReasons map[uint32]bool
	// BalanceFloor is the keeper account's balance, in stroops, below which it alerts.
	BalanceFloor int64
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
}

// New loads the stored chain state.
func New(ctx context.Context, cfg Config, client rpc.Client, chain *chainstate.Store, engine *submit.Engine, account *submit.Account, alerts *alert.Alerter, log *slog.Logger) (*Keeper, error) {
	state, cursor, err := chain.Load(ctx, cfg.Vault, cfg.DeployLedger)
	if err != nil {
		return nil, err
	}
	return &Keeper{cfg: cfg, rpc: client, chain: chain, engine: engine, account: account, alerts: alerts, log: log, now: time.Now, state: state, cursor: cursor}, nil
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
	res, err := k.engine.Do(ctx, k.account, build, 5)
	if err == nil && res.Outcome != submit.Success {
		err = fmt.Errorf("%s %s: %s", what, res.Outcome, res.Code)
	}
	if err != nil {
		if !errors.Is(err, submit.ErrSimulation) {
			k.alerts.Raise(ctx, alert.Critical, "call_failed", "%s failed after retries: %v", what, err)
		}
		return res, err
	}
	k.log.Info("submitted", "call", what, "tx", res.Hash, "ledger", res.Ledger, "fee", res.FeeCharged)
	return res, nil
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
		_, err := k.call(ctx, fmt.Sprintf("admit of %d deposits", n), func() (txnbuild.Operation, error) {
			return k.invoke("admit", vault.Vec(ids...))
		})
		if errors.Is(err, submit.ErrSimulation) && n > 1 {
			// A batch over the transaction's limits fails in simulation; try a smaller one.
			batch = n / 2
			continue
		}
		if err != nil {
			return err
		}
		eligible = eligible[n:]
	}
	k.alerts.Clear(ctx, "admission_late", "every eligible deposit is admitted")
	return nil
}

// Refund returns deposits that stayed flagged past the correction window, except those held.
func (k *Keeper) Refund(ctx context.Context) error {
	now, _, err := k.chainTime(ctx)
	if err != nil {
		return err
	}
	pending, err := k.readPending(ctx, k.pendingIDs())
	if err != nil {
		return err
	}
	for _, p := range pending {
		d := p.deposit
		if d.Flag == nil || k.cfg.HoldReasons[*d.Flag] || now < d.FlaggedAt+uint64(k.cfg.RefundDelay.Seconds()) {
			continue
		}
		id := p.id
		if _, err := k.call(ctx, fmt.Sprintf("refund of deposit %d", id), func() (txnbuild.Operation, error) {
			return k.invoke("refund", vault.U64(id))
		}); err != nil {
			k.log.Warn("refund failed", "deposit", id, "error", err.Error())
		}
	}
	return nil
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
	}{
		{"admission", 30 * time.Second, k.Admit},
		{"refunds", 5 * time.Minute, k.Refund},
		{"ttl", time.Hour, k.TTLCycle},
		{"balance", 10 * time.Minute, k.CheckBalance},
		{"watch", time.Minute, func(ctx context.Context) error { k.Watch(ctx); return nil }},
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Go(func() {
			for ctx.Err() == nil {
				if err := j.run(ctx); err != nil && ctx.Err() == nil {
					k.log.Warn("job incomplete", "job", j.name, "error", err.Error())
				}
				t := time.NewTimer(j.every)
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
