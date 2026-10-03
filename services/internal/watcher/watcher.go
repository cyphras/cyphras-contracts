// Package watcher checks a vault from outside and pages a person. It holds no keys. It rebuilds
// the vault from events with its own follower, compares the result with the chain as two
// independent RPC providers report it and with the indexer, and evaluates every ledger it
// ingests.
package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const (
	secondsPerDay = 86_400
	ledgersPerDay = 17_280
	// tipLedgers is how close to the chain tip a window must end for its alerts about activity, so
	// a rebuild does not page about the past.
	tipLedgers = 12
)

// HotAccount is an account that should only pay its own transaction fees.
type HotAccount struct {
	Name    string
	Address string
	// Floor is the balance in stroops below which the watcher alerts; 0 checks none.
	Floor int64
}

// Config sets what the watcher watches and its thresholds.
type Config struct {
	Vault        string
	DeployLedger uint32
	// IndexerURL is the base URL of the indexer's API, whose root is compared with the watcher's.
	IndexerURL string
	// HealthURLs are health endpoints that must answer 200.
	HealthURLs  []string
	HotAccounts []HotAccount
	// ServiceAccounts are checked against CAP-77 freezes, with the vault, its code and its asset.
	ServiceAccounts []string
	// BurstMultiple and BurstFloor bound transact calls within 10 minutes: alert above the
	// multiple of the trailing daily rate, but never below the floor.
	BurstMultiple float64
	BurstFloor    int64
	// QueueLength and QueueAge bound the exit queue.
	QueueLength uint64
	QueueAge    time.Duration
	// RoundTrips is how many payouts within 7 days may share a funding source with earlier
	// deposits before the watcher alerts; IgnoreFunders are sources, such as exchanges, that fund
	// too many accounts to mean anything.
	RoundTrips    int
	IgnoreFunders map[string]bool
	// EarlyWindow and EarlyShare define an early saturation: that share, in percent, of the day's
	// outflow window used within that long after midnight UTC.
	EarlyWindow time.Duration
	EarlyShare  int64
}

// Watcher follows one vault and runs the checks.
type Watcher struct {
	cfg     Config
	rpc     rpc.Client
	second  rpc.Client
	chain   *chainstate.Store
	db      store
	horizon *horizon.Client
	http    *http.Client
	alerts  *alert.Alerter
	public  *alert.Alerter
	log     *slog.Logger
	now     func() time.Time

	mu     sync.RWMutex
	state  *chainstate.State
	cursor uint32
	latest uint32
	// roots holds the tree's recent roots by leaf count, as the vault's root ring does.
	roots     map[uint64]fr.Element
	rootOrder []uint64
	// snapshots are the replayed status at the end of recent windows, so a read of the vault's
	// status made at a later ledger than the cursor is compared once the watcher gets there.
	snapshots []snapshot
	reads     []statusRead
	inst      *vault.Instance
	// pendingCross holds windows the second RPC had not reached when they were applied.
	pendingCross []follow.Batch
	// rpcFails counts each provider's failures of each method in a row.
	rpcFails    map[string]int
	healthFails map[string]int
	// authorized is whether the issuer let the vault hold the asset at the last read.
	authorized *bool
	// faulted is set while ingest is stopped by a fault.
	faulted bool
	// beat, when set, is pinged after each healthy reconciliation.
	beat func(context.Context) error
}

// SetHeartbeat makes the watcher ping beat after each reconciliation that ran while ingest was
// healthy, so a monitor elsewhere notices when the watcher stops or goes blind.
func (w *Watcher) SetHeartbeat(beat func(context.Context) error) {
	w.beat = beat
}

// New loads the stored chain state.
func New(ctx context.Context, cfg Config, primary, second rpc.Client, chain *chainstate.Store, hz *horizon.Client, alerts, public *alert.Alerter, log *slog.Logger) (*Watcher, error) {
	state, cursor, err := chain.Load(ctx, cfg.Vault, cfg.DeployLedger)
	if err != nil {
		return nil, err
	}
	w := &Watcher{
		cfg: cfg, rpc: primary, second: second, chain: chain, db: store{chain.Pool}, horizon: hz,
		http: &http.Client{Timeout: 10 * time.Second}, alerts: alerts, public: public, log: log, now: time.Now,
		state: state, cursor: cursor, roots: map[uint64]fr.Element{}, healthFails: map[string]int{}, rpcFails: map[string]int{},
		snapshots: []snapshot{snapshotOf(cursor, state)},
	}
	w.keepRoot(chainstate.RootAt{LeafCount: state.Tree.Len(), Root: state.Tree.Root()})
	return w, nil
}

// snapshot is the replayed status at the end of a window: only what a status read is compared
// with, rather than a whole state with every pending deposit and exit.
type snapshot struct {
	ledger uint32
	status vault.Status
	limits *vault.Limits
}

func snapshotOf(ledger uint32, s *chainstate.State) snapshot {
	out := snapshot{ledger: ledger, status: s.Status()}
	if s.Limits != nil {
		l := *s.Limits
		out.limits = &l
	}
	return out
}

// statusRead is a read of the vault's instance: valid from the ledger that last modified it to
// the ledger the read was made at.
type statusRead struct {
	inst     vault.Instance
	from, to uint32
	now      uint64
}

const (
	rootHistory     = 1024
	snapshotHistory = 64
)

func (w *Watcher) keepRoot(r chainstate.RootAt) {
	if _, ok := w.roots[r.LeafCount]; ok {
		return
	}
	w.roots[r.LeafCount] = r.Root
	w.rootOrder = append(w.rootOrder, r.LeafCount)
	if len(w.rootOrder) > rootHistory {
		delete(w.roots, w.rootOrder[0])
		w.rootOrder = w.rootOrder[1:]
	}
}

// Cursor implements follow.Sink.
func (w *Watcher) Cursor() uint32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cursor
}

// Apply implements follow.Sink: replay the window under the vault's rules, cross-check its events
// and the asset transfers out of the vault, store it, then run the checks its events trigger.
func (w *Watcher) Apply(ctx context.Context, b follow.Batch) error {
	w.mu.RLock()
	next := w.state.Clone()
	w.mu.RUnlock()
	delta, err := next.Apply(b.Txs)
	if err != nil {
		w.alerts.Raise(ctx, alert.Critical, "invariant", "ledgers %d to %d break the vault's rules: %v", b.From, b.To, err)
		return fmt.Errorf("%w: %w", follow.ErrFault, err)
	}
	live := b.To+tipLedgers >= b.Latest
	recent := b.To+ledgersPerDay >= b.Latest
	if err := w.loadInstance(ctx); err != nil {
		return err
	}
	if err := w.checkTransfers(ctx, b, delta); err != nil {
		return err
	}
	err = w.chain.Commit(ctx, b.From, b.To, next, delta, func(tx pgx.Tx) error {
		if err := w.recordActivity(ctx, tx, b); err != nil {
			return err
		}
		// An attestation's timing is judged after the window is stored; until it is, the check
		// stays in the database, so neither a failed read nor a restart loses it.
		for _, n := range delta.Notices {
			if n.Name == "attested" && n.ClosedAt+secondsPerDay >= b.LatestCloseTime {
				if err := w.db.addAttestCheck(ctx, tx, n.Body.(vault.Attested).UpTo, n.Ledger, n.ClosedAt); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if errors.Is(err, chainstate.ErrInconsistent) {
		w.alerts.Raise(ctx, alert.Critical, "invariant", "ledgers %d to %d break the vault's rules: %v", b.From, b.To, err)
		return fmt.Errorf("%w: %w", follow.ErrFault, err)
	}
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.state, w.cursor, w.faulted = next, b.To, false
	w.latest = max(w.latest, b.Latest)
	for _, r := range delta.Roots {
		w.keepRoot(r)
	}
	w.snapshots = append(w.snapshots, snapshotOf(b.To, next))
	if len(w.snapshots) > snapshotHistory {
		w.snapshots = w.snapshots[1:]
	}
	if recent {
		w.pendingCross = append(w.pendingCross, b)
		if len(w.pendingCross) > 1000 {
			w.pendingCross = w.pendingCross[1:]
		}
	}
	w.mu.Unlock()
	w.notices(ctx, delta.Notices, b.LatestCloseTime)
	if live {
		w.activityChecks(ctx, b, next, delta)
	}
	return nil
}

func (w *Watcher) recordActivity(ctx context.Context, tx pgx.Tx, b follow.Batch) error {
	counts := map[uint32]int{}
	closed := map[uint32]int64{}
	for _, t := range b.Txs {
		for _, c := range t.Calls {
			if _, ok := c.(vault.Transact); ok {
				counts[t.Ledger]++
				closed[t.Ledger] = t.ClosedAt
			}
		}
	}
	for _, ledger := range slices.Sorted(maps.Keys(counts)) {
		if err := w.db.recordActivity(ctx, tx, ledger, closed[ledger], counts[ledger]); err != nil {
			return err
		}
	}
	return nil
}

// Fault records an ingest failure from the follower. A fault, such as an event that does not
// decode, stops the watcher at that ledger, so it pages at once whatever its cause.
func (w *Watcher) Fault(ctx context.Context, err error) {
	if errors.Is(err, follow.ErrFault) {
		w.mu.Lock()
		w.faulted = true
		w.mu.Unlock()
		w.alerts.Raise(ctx, alert.Critical, "ingest_fault", "the watcher stopped at ledger %d: %v", w.Cursor(), err)
		return
	}
	w.log.Warn("ingest retry", "error", err.Error())
}

// loadInstance reads the vault's instance once, so the first windows at the tip are checked
// before the first reconciliation.
func (w *Watcher) loadInstance(ctx context.Context) error {
	w.mu.RLock()
	loaded := w.inst != nil
	w.mu.RUnlock()
	if loaded {
		return nil
	}
	inst, _, _, err := rpc.VaultInstance(ctx, w.rpc, w.cfg.Vault)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.inst = &inst
	w.mu.Unlock()
	return nil
}

// limits returns the vault's limits as the latest instance read shows them, or as the events do.
func (w *Watcher) limits() *vault.Limits {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.inst != nil {
		l := w.inst.Limits
		return &l
	}
	return w.state.Limits
}

var governance = map[string]bool{
	"limits_queued": true, "limits_applied": true, "limits_cancelled": true, "paused": true, "halted": true, "resumed": true,
}

// notices reports governance events to the operator and the public channel, flags and requeued
// exits as information, stranded exits, and checks every attestation against the screening
// policy's timing. Events older than a day, met while rebuilding, are not reported again.
func (w *Watcher) notices(ctx context.Context, notices []chainstate.Notice, latestClose int64) {
	for _, n := range notices {
		if n.ClosedAt+secondsPerDay < latestClose {
			continue
		}
		at := time.Unix(n.ClosedAt, 0).UTC().Format(time.RFC3339)
		switch {
		case governance[n.Name]:
			msg := fmt.Sprintf("%s at ledger %d (%s): %s", n.Name, n.Ledger, at, describe(n.Body))
			severity := alert.Warning
			if n.Name == "halted" {
				severity = alert.Critical
			}
			// Each event has its own code, so two in one ledger are both reported.
			code := fmt.Sprintf("governance_%s_%.16s_%d", n.Name, n.TxHash, n.Index)
			w.alerts.Raise(ctx, severity, code, "%s", msg)
			w.public.Raise(ctx, alert.Info, code, "%s", msg)
		case n.Name == "deposit_flagged" || n.Name == "deposit_unflagged":
			w.alerts.Raise(ctx, alert.Info, fmt.Sprintf("%s_%.16s_%d", n.Name, n.TxHash, n.Index), "%s at ledger %d: %s", n.Name, n.Ledger, describe(n.Body))
		case n.Name == "exit_stranded":
			s := n.Body.(vault.ExitStranded)
			w.alerts.Raise(ctx, alert.Warning, fmt.Sprintf("exit_stranded_%d", s.ID), "exit %d was released with %v of its payout and %v of its fee unpaid; claim queues them again once the parties can receive", s.ID, s.Payout, s.Fee)
		case n.Name == "exit_requeued":
			r := n.Body.(vault.ExitRequeued)
			w.alerts.Raise(ctx, alert.Info, fmt.Sprintf("exit_requeued_%d", r.NewID), "%v of the payout and %v of the fee of stranded exit %d were queued again as exit %d", r.Payout, r.Fee, r.ID, r.NewID)
		case n.Name == "attested":
			if err := w.judgeAttestation(ctx, attestCheck{upTo: n.Body.(vault.Attested).UpTo, ledger: n.Ledger, closedAt: n.ClosedAt}); err != nil {
				w.log.Warn("attestation check deferred", "ledger", n.Ledger, "error", err.Error())
			}
		}
	}
}

func describe(body any) string {
	switch b := body.(type) {
	case vault.LimitsQueued:
		return fmt.Sprintf("limits %s ready at %s", limitsText(b.Limits), time.Unix(int64(b.ReadyAt), 0).UTC().Format(time.RFC3339))
	case vault.LimitsApplied:
		return "limits now " + limitsText(b.Limits)
	case vault.LimitsCancelled:
		return "the queued limits " + limitsText(b.Limits) + " were dropped"
	case vault.Paused:
		return fmt.Sprintf("deposits paused %t, transfers paused %t", b.Deposits, b.Transfers)
	case vault.Halted:
		return "halted until " + time.Unix(int64(b.Until), 0).UTC().Format(time.RFC3339)
	case vault.Resumed:
		return "resumed; the next halt is possible from " + time.Unix(int64(b.NextHaltAt), 0).UTC().Format(time.RFC3339)
	case vault.DepositFlagged:
		return fmt.Sprintf("deposit %d, reason %d", b.ID, b.Reason)
	case vault.DepositUnflagged:
		return fmt.Sprintf("deposit %d, reason %d cleared", b.ID, b.Reason)
	}
	return fmt.Sprintf("%+v", body)
}

func limitsText(l vault.Limits) string {
	return fmt.Sprintf("min_deposit %v, max_deposit %v, max_daily_per_depositor %v, tvl_cap %v, max_daily_outflow %v, max_fee %v, large_deposit_threshold %v",
		l.MinDeposit, l.MaxDeposit, l.MaxDailyPerDepositor, l.TvlCap, l.MaxDailyOutflow, l.MaxFee, l.LargeDepositThreshold)
}

// attestSlack allows for ledger close times around the screening service's ten-minute window.
const attestSlack = 2 * 60

// attestCheck is an attestation whose timing is still to be judged.
type attestCheck struct {
	upTo     uint64
	ledger   uint32
	closedAt int64
}

// errNotYet reports a check that cannot run before the vault's instance has been read.
var errNotYet = errors.New("the vault's instance is not read yet")

// judgeAttestation pages when an attestation covers a deposit more than ten minutes before that
// deposit can be admitted: the screening service attests only after the final check, which runs
// in the last ten minutes, so an earlier one can mean a stolen asp key. Once judged, the check is
// forgotten; one that cannot be judged now stays for RetryAttestations.
func (w *Watcher) judgeAttestation(ctx context.Context, c attestCheck) error {
	w.mu.RLock()
	inst := w.inst
	w.mu.RUnlock()
	if inst == nil {
		return errNotYet
	}
	amount, createdAt, found, err := w.db.deposit(ctx, c.upTo)
	if err != nil {
		return err
	}
	if found {
		delay, ok, err := w.delayOf(ctx, c.upTo)
		if err != nil {
			return err
		}
		if !ok {
			delay = vault.DelayFor(amount, inst.Config, inst.Limits)
		}
		eligible := vault.PendingDeposit{Amount: amount, CreatedAt: createdAt, Delay: delay}.EligibleAt(inst.Config, inst.Limits)
		if uint64(c.closedAt)+600+attestSlack < eligible {
			w.alerts.Raise(ctx, alert.Critical, fmt.Sprintf("early_attestation_%d", c.upTo),
				"attestation up to deposit %d at ledger %d came %d seconds before its final-check window; the asp key may be stolen",
				c.upTo, c.ledger, eligible-600-uint64(c.closedAt))
		}
	}
	return w.db.dropAttestCheck(ctx, c.upTo, c.ledger)
}

// RetryAttestations judges the attestations whose check could not run when they were seen.
func (w *Watcher) RetryAttestations(ctx context.Context) error {
	checks, err := w.db.attestChecks(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range checks {
		if err := w.judgeAttestation(ctx, c); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// delayOf returns the delay a deposit was made under, from the watcher's records or its entry.
func (w *Watcher) delayOf(ctx context.Context, id uint64) (uint64, bool, error) {
	if d, ok, err := w.db.delay(ctx, id); err != nil || ok {
		return d, ok, err
	}
	key, err := vault.PendingKey(w.cfg.Vault, id)
	if err != nil {
		return 0, false, err
	}
	e, _, err := rpc.One(ctx, w.rpc, key)
	if errors.Is(err, rpc.ErrMissing) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	v, err := rpc.ContractValue(e)
	if err != nil {
		return 0, false, err
	}
	p, err := vault.DecodePendingDeposit(v)
	if err != nil {
		return 0, false, err
	}
	return p.Delay, true, w.db.setDelay(ctx, id, p.Delay)
}

// activityChecks evaluate a window near the tip: today's outflow against its cap, an outflow spike
// over the last hour, single unshields above max_deposit and a burst of transact calls.
func (w *Watcher) activityChecks(ctx context.Context, b follow.Batch, s *chainstate.State, d chainstate.Delta) {
	limits := w.limits()
	if limits == nil {
		return
	}
	now := b.LatestCloseTime
	if today := s.OutflowOn(uint64(now) / secondsPerDay); today.Cmp(limits.MaxDailyOutflow) > 0 {
		w.alerts.Raise(ctx, alert.Critical, "outflow_over_cap", "today's outflow %v exceeds max_daily_outflow %v", today, limits.MaxDailyOutflow)
	}
	for i, st := range d.Settlements {
		if payout := new(big.Int).Neg(st.ExtAmount); payout.Cmp(limits.MaxDeposit) > 0 {
			w.alerts.Raise(ctx, alert.Warning, fmt.Sprintf("large_unshield_%.16s_%d", st.TxHash, i), "an unshield of %v in ledger %d exceeds max_deposit %v", payout, st.Ledger, limits.MaxDeposit)
		}
	}
	hour, err := w.db.outflowSince(ctx, now-3600)
	if err != nil {
		w.log.Warn("outflow check incomplete", "error", err.Error())
	} else if share := new(big.Int).Div(new(big.Int).Mul(limits.MaxDailyOutflow, big.NewInt(20)), big.NewInt(100)); hour.Cmp(share) > 0 {
		times, _ := new(big.Float).Quo(new(big.Float).SetInt(hour), new(big.Float).SetInt(share)).Float64()
		w.alerts.Raise(ctx, alert.Warning, "outflow_spike"+escalation(times), "%v left the vault within one hour, above 20 percent of max_daily_outflow %v", hour, limits.MaxDailyOutflow)
	}
	recent, day, err := w.db.transacts(ctx, now-600, now-secondsPerDay)
	if err != nil {
		w.log.Warn("burst check incomplete", "error", err.Error())
		return
	}
	bound := max(float64(w.cfg.BurstFloor), w.cfg.BurstMultiple*float64(day)/144)
	if float64(recent) > bound {
		w.alerts.Raise(ctx, alert.Warning, "nullifier_burst"+escalation(float64(recent)/bound), "%d transact calls within 10 minutes, above %.0f from a trailing day of %d", recent, bound, day)
	}
}

// escalation names how far a reading is past its bound, in doublings, so a reading twice as far
// past it raises an alert of its own rather than repeating one the cooldown holds back.
func escalation(times float64) string {
	n := 1
	for n < 1<<20 && float64(2*n) <= times {
		n *= 2
	}
	return fmt.Sprintf("_x%d", n)
}

// checkTransfers compares the asset transfers out of the vault in the window with the payments and
// refunds its events report. The vault's events name amounts, but only the asset contract's
// events show what actually left. Windows the RPC no longer holds are not checked.
func (w *Watcher) checkTransfers(ctx context.Context, b follow.Batch, d chainstate.Delta) error {
	w.mu.RLock()
	inst := w.inst
	w.mu.RUnlock()
	if inst == nil {
		return nil
	}
	want := map[string]*big.Int{}
	add := func(m map[string]*big.Int, address string, amount *big.Int) error {
		if amount.Sign() <= 0 {
			return nil
		}
		account, err := vault.AccountOf(address)
		if err != nil {
			return err
		}
		if m[account] == nil {
			m[account] = new(big.Int)
		}
		m[account].Add(m[account], amount)
		return nil
	}
	for _, s := range d.Settlements {
		if err := add(want, s.Recipient, new(big.Int).Neg(s.ExtAmount)); err != nil {
			return err
		}
		if err := add(want, s.Relayer, s.Fee); err != nil {
			return err
		}
	}
	for _, r := range d.Resolved {
		if r.Outcome != chainstate.Admitted {
			if err := add(want, r.Deposit.Depositor, r.Deposit.Amount); err != nil {
				return err
			}
		}
	}
	src := follow.RPCSource{Client: w.rpc, Contract: inst.Config.Token, Topics: transferFilters(w.cfg.Vault), PageLimit: 1000}
	events, err := src.Events(ctx, b.From, b.To)
	if errors.Is(err, follow.ErrRetention) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("asset transfers: %w", err)
	}
	got := map[string]*big.Int{}
	for _, e := range events {
		t, err := vault.DecodeTransfer(e)
		if err != nil {
			// A payment to the asset's issuer is a burn.
			t, err = vault.DecodeBurn(e)
		}
		if err != nil || t.From != w.cfg.Vault {
			continue
		}
		if err := add(got, t.To, t.Amount); err != nil {
			return err
		}
	}
	if !sameAmounts(want, got) {
		w.alerts.Raise(ctx, alert.Critical, fmt.Sprintf("outflow_mismatch_%d", b.To),
			"ledgers %d to %d: the asset contract moved %s out of the vault, its events report %s", b.From, b.To, amountsText(got), amountsText(want))
	}
	return nil
}

// transferFilters match an asset contract's transfer events sent by the vault, with three topics
// as SEP-41 has them or four as the Stellar Asset Contract has them, and the Stellar Asset
// Contract's burn events from the vault, which a payment to the asset's issuer emits.
func transferFilters(vaultID string) []protocol.TopicFilter {
	transfer, burn := xdr.ScSymbol("transfer"), xdr.ScSymbol("burn")
	name := xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &transfer}
	burned := xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &burn}
	from, _ := vault.Address(vaultID)
	one := protocol.WildCardExactOne
	return []protocol.TopicFilter{
		{{ScVal: &name}, {ScVal: &from}, {Wildcard: &one}},
		{{ScVal: &name}, {ScVal: &from}, {Wildcard: &one}, {Wildcard: &one}},
		{{ScVal: &burned}, {ScVal: &from}, {Wildcard: &one}},
	}
}

func sameAmounts(a, b map[string]*big.Int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] == nil || b[k].Cmp(v) != 0 {
			return false
		}
	}
	return true
}

func amountsText(m map[string]*big.Int) string {
	if len(m) == 0 {
		return "nothing"
	}
	var parts []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		parts = append(parts, fmt.Sprintf("%v to %s", m[k], k))
	}
	return strings.Join(parts, ", ")
}

var _ follow.Sink = (*Watcher)(nil)

// reconcileAndBeat reconciles, and pings the heartbeat when that succeeded with ingest healthy.
func (w *Watcher) reconcileAndBeat(ctx context.Context) error {
	if err := w.Reconcile(ctx); err != nil {
		return err
	}
	w.mu.RLock()
	healthy := !w.faulted && w.cursor+60 >= w.latest
	w.mu.RUnlock()
	if w.beat == nil || !healthy {
		return nil
	}
	if err := w.beat(ctx); err != nil {
		w.log.Warn("heartbeat failed", "error", err.Error())
	}
	return nil
}

// Run follows the vault and runs each periodic check on its schedule until ctx ends.
func (w *Watcher) Run(ctx context.Context, f *follow.Follower, poll time.Duration) {
	go f.Run(ctx, poll, func(err error) { w.Fault(ctx, err) })
	jobs := []struct {
		name  string
		every time.Duration
		run   func(context.Context) error
	}{
		{"reconcile", 15 * time.Second, w.reconcileAndBeat},
		{"indexer", time.Minute, w.CheckIndexer},
		{"health", time.Minute, w.CheckHealth},
		{"admissions", time.Minute, w.CheckAdmissions},
		{"attestations", time.Minute, w.RetryAttestations},
		{"exit queue", time.Minute, w.CheckExitQueue},
		{"hot accounts", time.Minute, w.CheckHotAccounts},
		{"governance accounts", time.Minute, w.CheckGovernanceAccounts},
		{"freezes", time.Minute, w.CheckFreezes},
		{"patterns", 5 * time.Minute, w.CheckPatterns},
		{"ttl", time.Hour, w.CheckTTL},
	}
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Go(func() {
			failures := 0
			for ctx.Err() == nil {
				if err := j.run(ctx); err != nil && ctx.Err() == nil {
					failures++
					w.log.Warn("check incomplete", "check", j.name, "error", err.Error())
					// A check that keeps failing is a blind spot, which is itself worth a page.
					if failures >= 5 {
						w.alerts.Raise(ctx, alert.Warning, "check_failing_"+j.name, "the %s check has failed %d times in a row: %v", j.name, failures, err)
					}
				} else if err == nil {
					if failures >= 5 {
						w.alerts.Clear(ctx, "check_failing_"+j.name, "the %s check runs again", j.name)
					}
					failures = 0
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
