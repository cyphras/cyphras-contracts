package screening

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Config sets the vault and the schedule of the screening policy.
type Config struct {
	Vault        string
	DeployLedger uint32
	NetworkID    [32]byte
	// Network is "mainnet" or "testnet", as the self-report message names it.
	Network       string
	PolicyVersion string
	// RecheckWindow is how long before eligibility the final check runs.
	RecheckWindow time.Duration
	// Cutoff is how long before eligibility a deposit whose checks keep failing, without a passed
	// re-check, is held rather than risk its admission unchecked.
	Cutoff time.Duration
	// FirstCheckWithin is the time the policy allows for a deposit's first check.
	FirstCheckWithin time.Duration
	// RequestLookups bounds the funder lookups per minute that relayed unshields may cause.
	RequestLookups int
	// ReviewSLA is how long a deposit may wait for a person before the oldest one waiting pages
	// as overdue; 2 hours when unset.
	ReviewSLA time.Duration
	// Workers bounds the checks that run at once. TickChecks and TickBudget bound the checks one
	// round starts and how long it starts them for; what does not fit waits for the next round,
	// the nearest deadline first. Unset, they are 4, 40 and 15 seconds.
	Workers    int
	TickChecks int
	TickBudget time.Duration
}

// Screener follows the vault's deposits and decides each one.
type Screener struct {
	cfg   Config
	rpc   rpc.Client
	chain *chainstate.Store
	db    store
	check *Checker
	// requestCheck screens the destinations requests ask about, on its own lookup budget.
	requestCheck *Checker
	reports      *ReportSource
	engine       *submit.Engine
	asp          *submit.Account
	alerts       *alert.Alerter
	log          *slog.Logger
	now          func() time.Time
	// lock is the asp account's lock, without which nothing is sent as the account.
	lock *Lock

	mu       sync.RWMutex
	state    *chainstate.State
	cursor   uint32
	latest   uint32
	fault    bool
	tickedAt time.Time
	// reviews is how many deposits wait for a person, and oldestReview how long the first of them
	// has waited, as the last round found.
	reviews      int
	oldestReview time.Duration
	// retries holds the deposits whose last check failed, with when to try each again.
	retries map[uint64]retry
}

type retry struct {
	attempts int
	next     time.Time
}

// New loads the stored chain state. The checker's sources must not include a report source; the
// screener adds its own.
func New(ctx context.Context, cfg Config, client rpc.Client, chain *chainstate.Store, check *Checker,
	engine *submit.Engine, asp *submit.Account, alerts *alert.Alerter, log *slog.Logger) (*Screener, error) {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	if cfg.TickChecks <= 0 {
		cfg.TickChecks = 40
	}
	if cfg.TickBudget <= 0 {
		cfg.TickBudget = 15 * time.Second
	}
	if cfg.ReviewSLA <= 0 {
		cfg.ReviewSLA = 2 * time.Hour
	}
	s := &Screener{cfg: cfg, rpc: client, chain: chain, db: store{chain.Pool}, check: check, engine: engine, asp: asp, alerts: alerts, log: log, now: time.Now,
		retries: map[uint64]retry{}}
	s.reports = &ReportSource{list: list{name: "self_reports", maxAge: 365 * 24 * time.Hour}, load: s.db.selfReports, now: s.clock}
	check.Sources = append(check.Sources, s.reports)
	lookups := max(cfg.RequestLookups, 1)
	s.requestCheck = &Checker{
		Sources: check.Sources, MaxFunders: check.MaxFunders, Dust: check.Dust, Exempt: check.Exempt, Now: check.Now,
		Inflows: BudgetedInflows{Inner: check.Inflows, Budget: httpapi.NewLimiter(lookups, lookups/3+1)},
	}
	state, cursor, err := chain.Load(ctx, cfg.Vault, cfg.DeployLedger)
	if err != nil {
		return nil, err
	}
	s.state, s.cursor = state, cursor
	guards, err := s.db.guards(ctx)
	if err != nil {
		return nil, err
	}
	for _, src := range check.Sources {
		if g, ok := src.(guarded); ok {
			if last, ok := guards[src.Name()]; ok {
				g.restore(last.size, last.canaries)
			}
		}
	}
	if err := s.reports.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Screener) clock() time.Time { return s.now() }

// UseLock sets the lock of the asp account; the screener sends nothing as the account without it.
func (s *Screener) UseLock(l *Lock) { s.lock = l }

// Cursor implements follow.Sink.
func (s *Screener) Cursor() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cursor
}

// Apply implements follow.Sink.
func (s *Screener) Apply(ctx context.Context, b follow.Batch) error {
	s.mu.RLock()
	next := s.state.Clone()
	s.mu.RUnlock()
	delta, err := next.Apply(b.Txs)
	if err != nil {
		return fmt.Errorf("%w: %w", follow.ErrFault, err)
	}
	if err := s.chain.Commit(ctx, b.From, b.To, next, delta, nil); err != nil {
		if errors.Is(err, chainstate.ErrInconsistent) {
			return fmt.Errorf("%w: %w", follow.ErrFault, err)
		}
		return err
	}
	s.mu.Lock()
	s.state, s.cursor = next, b.To
	s.latest, s.fault = max(s.latest, b.Latest), false
	s.mu.Unlock()
	for _, n := range delta.Notices {
		if n.Name == "attested" {
			s.log.Info("attestation on chain", "up_to", n.Body.(chainstate.Attestation).UpTo, "ledger", n.Ledger)
		}
	}
	return nil
}

// guarded is a source whose guard compares each update with the last good copy.
type guarded interface {
	lastGood() (int, []string, bool)
	restore(size int, canaries []string)
}

// RefreshSources fetches every source again; a failure leaves the old data, which then ages, and
// an update the source's guard refuses pages. What a guard compares the next update with is kept,
// so the first update after a restart is checked too.
func (s *Screener) RefreshSources(ctx context.Context) {
	for _, src := range s.check.Sources {
		err := src.Refresh(ctx)
		switch {
		case errors.Is(err, ErrSuspect):
			s.alerts.Raise(ctx, alert.Warning, "source_update_refused_"+src.Name(), "%v; the previous copy stays in use", err)
		case err != nil:
			s.log.Warn("source refresh failed", "source", src.Name(), "error", err.Error())
		default:
			s.alerts.Clear(ctx, "source_update_refused_"+src.Name(), "%s updated again", src.Name())
			if g, ok := src.(guarded); ok {
				if size, canaries, ok := g.lastGood(); ok {
					if err := s.db.saveGuard(ctx, src.Name(), guardState{size, canaries}); err != nil {
						s.log.Warn("source guard not saved", "source", src.Name(), "error", err.Error())
					}
				}
			}
		}
	}
	if err := s.check.Fresh(); err != nil {
		s.alerts.Raise(ctx, alert.Critical, "source_unavailable", "screening fails closed: %v", err)
	} else {
		s.alerts.Clear(ctx, "source_unavailable", "every source is fresh again")
	}
}

func (s *Screener) record(ctx context.Context, d Decision) {
	at := s.now()
	if d.Kind == "unshield" || d.Kind == "self_report" {
		// These follow a client request, whose time the policy does not keep.
		at = at.UTC().Truncate(24 * time.Hour)
	}
	if err := s.db.record(ctx, at, d); err != nil {
		s.log.Error("decision record failed", "kind", d.Kind, "error", err.Error())
		s.alerts.Raise(ctx, alert.Critical, "record_failed", "a decision could not be recorded: %v", err)
	}
}

func (s *Screener) invoke(fn string, args ...xdr.ScVal) (txnbuild.Operation, error) {
	addr, err := vault.ScAddress(s.cfg.Vault)
	if err != nil {
		return nil, err
	}
	return &txnbuild.InvokeHostFunction{HostFunction: xdr.HostFunction{
		Type:           xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
		InvokeContract: &xdr.InvokeContractArgs{ContractAddress: addr, FunctionName: xdr.ScSymbol(fn), Args: args},
	}}, nil
}

var errNoLock = errors.New("screening: sending as the asp account needs its lock")

func (s *Screener) send(ctx context.Context, fn string, args ...xdr.ScVal) (submit.Result, error) {
	if s.lock == nil {
		return submit.Result{}, errNoLock
	}
	if err := s.lock.Held(ctx); err != nil {
		return submit.Result{}, err
	}
	res, err := s.engine.Do(ctx, s.asp, func() (txnbuild.Operation, error) { return s.invoke(fn, args...) }, 4)
	if err != nil {
		return res, err
	}
	if res.Outcome != submit.Success {
		return res, fmt.Errorf("%s %s: %s", fn, res.Outcome, res.Code)
	}
	return res, nil
}

// Flag refuses a pending deposit on chain and records it. kind names the decision behind it.
func (s *Screener) Flag(ctx context.Context, id uint64, reason uint32, kind, detail string) error {
	res, err := s.send(ctx, "flag", vault.U64(id), vault.U32(reason))
	if err != nil {
		s.alerts.Raise(ctx, alert.Critical, "flag_failed", "deposit %d could not be flagged with reason %d: %v", id, reason, err)
		return err
	}
	if err := s.db.update(ctx, id, "flag_sent", int32(reason)); err != nil {
		return err
	}
	if err := s.db.update(ctx, id, "flag_kind", kind); err != nil {
		return err
	}
	r := reason
	s.record(ctx, Decision{Kind: kind, DepositID: &id, Outcome: "flag", Reason: &r, Detail: detail, TxHash: res.Hash})
	s.log.Info("flagged", "deposit", id, "reason", reason, "tx", res.Hash)
	return nil
}

// vaultView is what one tick needs from the chain.
type vaultView struct {
	inst vault.Instance
	now  uint64
}

// task is what a deposit needs next.
type task int

const (
	taskNone task = iota
	// taskFlag is a flag that must be sent, the most urgent work there is.
	taskFlag
	// taskLift lifts a hold once the deposit passed its own final check.
	taskLift
	taskRecheck
	taskFirst
)

type plan struct {
	r          *row
	task       task
	eligibleAt uint64
	reason     uint32
	kind       string
	detail     string
}

// plan decides what a deposit needs next from its stored state alone.
func (s *Screener) plan(v vaultView, r *row) plan {
	p := plan{r: r}
	if r.delay == nil {
		return p
	}
	cfg, limits := v.inst.Config, v.inst.Limits
	p.eligibleAt = vault.PendingDeposit{Amount: r.amountInt(), CreatedAt: r.createdAt, Delay: *r.delay}.EligibleAt(cfg, limits)
	flag := func(reason uint32, kind, detail string) plan {
		p.task, p.reason, p.kind, p.detail = taskFlag, reason, kind, detail
		return p
	}
	// A refusal stands; a hold waits for what it holds the deposit for.
	held := false
	if f := r.reason(); f != nil {
		if *f != ReasonHeld {
			return p
		}
		held = true
	}
	if h, ok := s.reports.Lookup(r.depositor); ok && !h.Refer {
		return flag(ReasonFraud, "self_report", "the depositor reported its key compromised")
	}
	refusal := uint32(ReasonOther)
	if r.refuseReason != nil {
		refusal = *r.refuseReason
	}
	inRecheck := v.now+uint64(s.cfg.RecheckWindow.Seconds()) >= p.eligibleAt
	attested := r.id <= v.inst.Status.AttestedUpTo
	passed := r.recheck == "pass" && (attested || s.fresh(v.now, r))
	switch {
	case r.firstCheck == "refuse":
		return flag(refusal, "first_check", "refused at the first check")
	case r.review == "refused":
		return flag(ReasonReview, "review", "refused by the reviewer")
	case r.recheck == "refuse":
		return flag(refusal, "recheck", "refused at the final check")
	case !held && !passed && v.now+uint64(s.cfg.Cutoff.Seconds()) >= p.eligibleAt && s.failing(r.id):
		// Its own checks keep failing: held, it is admitted on nothing and holds back no later
		// deposit, and the hold is lifted once its final check passes.
		return flag(ReasonHeld, "hold", "its checks could not run in time")
	case r.firstCheck == "":
		p.task = taskFirst
	case r.review == "needed":
		// The deposit must not become eligible unreviewed, and it would hold back every later
		// attestation while it waits; the hold is lifted once a review clears it.
		if inRecheck && !held {
			return flag(ReasonHeld, "hold", "the review was not finished before the final check")
		}
	case !inRecheck:
	case held && r.recheck == "pass" && s.fresh(v.now, r):
		p.task = taskLift
	case held:
		p.task = taskRecheck
	case passed:
	default:
		p.task = taskRecheck
	}
	return p
}

// fresh reports whether a deposit's passed final check is recent enough for an attestation to
// rest on: a deposit attested later than that, behind a slower one, is checked again first.
func (s *Screener) fresh(now uint64, r *row) bool {
	return r.recheckAt != nil && now <= *r.recheckAt+uint64(s.cfg.RecheckWindow.Seconds())
}

// failing reports a deposit whose last check failed and whose next try is not due yet.
func (s *Screener) failing(id uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.retries[id]
	return ok && s.now().Before(r.next)
}

// due reports whether a deposit whose checks failed may be tried again, at a backoff from 30
// seconds doubling to 10 minutes.
func (s *Screener) due(id uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.retries[id]
	return !ok || !s.now().Before(r.next)
}

func (s *Screener) failed(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.retries[id]
	r.attempts++
	wait := 30 * time.Second
	for range min(r.attempts-1, 5) {
		wait *= 2
	}
	r.next = s.now().Add(min(wait, 10*time.Minute))
	s.retries[id] = r
}

func (s *Screener) succeeded(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.retries, id)
}

// Tick runs one round of the schedule. Deadline work comes first: the flags that are due, then
// the operators' queued decisions, then the re-checks nearest their deadline, then first checks,
// within the round's budget and a bounded pool of workers. The attestation comes last.
func (s *Screener) Tick(ctx context.Context) error {
	start := s.now()
	inst, _, _, err := rpc.VaultInstance(ctx, s.rpc, s.cfg.Vault)
	if err != nil {
		return fmt.Errorf("read the vault: %w", err)
	}
	view := vaultView{inst: inst, now: uint64(start.Unix())}
	rows, err := s.db.pending(ctx)
	if err != nil {
		return err
	}
	if err := s.loadDelays(ctx, rows); err != nil {
		return err
	}
	if rows, err = s.db.pending(ctx); err != nil {
		return err
	}
	s.settle(ctx, view, rows, true, false)
	if err := s.runOps(ctx); err != nil {
		s.log.Warn("operator decisions incomplete", "error", err.Error())
	}
	if rows, err = s.db.pending(ctx); err != nil {
		return err
	}
	checks := s.settle(ctx, view, rows, false, true)
	slices.SortStableFunc(checks, func(a, b plan) int {
		if a.task != b.task {
			return int(a.task) - int(b.task)
		}
		if a.task == taskRecheck {
			return cmp.Compare(a.eligibleAt, b.eligibleAt)
		}
		return cmp.Compare(a.r.createdAt, b.r.createdAt)
	})
	s.runChecks(ctx, view, checks, start)
	// What the checks refused is flagged, and what they cleared lifted, in the same round, so it
	// holds up no attestation.
	if rows, err = s.db.pending(ctx); err != nil {
		return err
	}
	s.settle(ctx, view, rows, true, true)
	if err := s.attest(ctx, view, rows); err != nil {
		return err
	}
	s.remind(ctx, rows)
	s.mu.Lock()
	s.tickedAt = s.now()
	s.mu.Unlock()
	return nil
}

// settle sends the flags the deposits' state calls for and lifts the holds whose deposits passed
// their final check, as asked, and returns the checks that are due.
func (s *Screener) settle(ctx context.Context, v vaultView, rows []row, flags, lifts bool) []plan {
	var checks []plan
	for i := range rows {
		p := s.plan(v, &rows[i])
		switch {
		case p.task == taskFlag && flags:
			if err := s.Flag(ctx, p.r.id, p.reason, p.kind, p.detail); err != nil {
				p.r.needsFlag = true
				s.log.Warn("flag not sent", "deposit", p.r.id, "error", err.Error())
				continue
			}
			reason := p.reason
			p.r.flagSent, p.r.flagKind = &reason, p.kind
		case p.task == taskLift && lifts:
			if err := s.lift(ctx, p.r); err != nil {
				s.log.Warn("hold not lifted", "deposit", p.r.id, "error", err.Error())
			}
		case p.task == taskRecheck, p.task == taskFirst:
			if s.due(p.r.id) {
				checks = append(checks, p)
			}
		}
	}
	return checks
}

// remind pages while deposits wait for a person. A review not finished before a deposit's final
// check holds the deposit, and the keeper refunds it a day after the hold.
func (s *Screener) remind(ctx context.Context, rows []row) {
	var waiting []uint64
	var oldest uint64
	var since time.Duration
	for i := range rows {
		r := &rows[i]
		if !r.awaitsReview() {
			continue
		}
		waiting = append(waiting, r.id)
		at := r.createdAt
		if r.reviewAt != nil {
			at = *r.reviewAt
		}
		if waited := s.now().Sub(time.Unix(int64(at), 0)); waited > since {
			oldest, since = r.id, waited
		}
	}
	s.mu.Lock()
	s.reviews, s.oldestReview = len(waiting), since
	s.mu.Unlock()
	if since > s.cfg.ReviewSLA {
		s.alerts.Raise(ctx, alert.Critical, "review_overdue", "deposit %d has waited %s for a review, past the %s the policy allows", oldest, since.Round(time.Minute), s.cfg.ReviewSLA)
	} else {
		s.alerts.Clear(ctx, "review_overdue", "every review is within its time again")
	}
	if len(waiting) == 0 {
		s.alerts.Clear(ctx, "review_needed", "no deposit waits for a review")
		return
	}
	s.alerts.Raise(ctx, alert.Warning, "review_needed", "%d deposits wait for a review: %v", len(waiting), waiting[:min(len(waiting), 20)])
}

// runChecks runs the planned checks on a bounded pool of workers until the round's budget is
// spent. A check that fails is retried in a later round, at a growing backoff.
func (s *Screener) runChecks(ctx context.Context, v vaultView, checks []plan, start time.Time) {
	work := make(chan plan)
	var wg sync.WaitGroup
	for range s.cfg.Workers {
		wg.Go(func() {
			for p := range work {
				var err error
				if p.task == taskRecheck {
					err = s.recheck(ctx, v, p)
				} else {
					var outcome string
					outcome, err = s.firstCheck(ctx, v, p)
					// A first check that runs inside the final window is followed by the final
					// check at once, with the same current sources.
					if err == nil && outcome == "pass" && v.now+uint64(s.cfg.RecheckWindow.Seconds()) >= p.eligibleAt {
						p.r.firstCheck = outcome
						err = s.recheck(ctx, v, p)
					}
				}
				if err != nil {
					s.failed(p.r.id)
					s.log.Warn("deposit undecided", "deposit", p.r.id, "error", err.Error())
				} else {
					s.succeeded(p.r.id)
				}
			}
		})
	}
	for i, p := range checks {
		if i >= s.cfg.TickChecks || s.now().Sub(start) > s.cfg.TickBudget {
			break
		}
		work <- p
	}
	close(work)
	wg.Wait()
}

// loadDelays reads the delay snapshot of deposits that do not have one yet.
func (s *Screener) loadDelays(ctx context.Context, rows []row) error {
	var keys []xdr.LedgerKey
	var ids []uint64
	for _, r := range rows {
		if r.delay == nil {
			k, err := vault.PendingKey(s.cfg.Vault, r.id)
			if err != nil {
				return err
			}
			keys, ids = append(keys, k), append(ids, r.id)
		}
	}
	if len(keys) == 0 {
		return nil
	}
	entries, _, err := rpc.Entries(ctx, s.rpc, keys)
	if err != nil {
		return err
	}
	for i, k := range keys {
		ks, _ := rpc.KeyString(k)
		e, ok := entries[ks]
		if !ok {
			continue
		}
		v, err := rpc.ContractValue(e)
		if err != nil {
			return err
		}
		d, err := vault.DecodePendingDeposit(v)
		if err != nil {
			return err
		}
		if err := s.db.update(ctx, ids[i], "delay", int64(d.Delay)); err != nil {
			return err
		}
	}
	return nil
}

func (r row) amountInt() *big.Int {
	n, _ := new(big.Int).SetString(r.amount, 10)
	return n
}

func (s *Screener) hops(r row, limits vault.Limits) int {
	if r.amountInt().Cmp(limits.LargeDepositThreshold) >= 0 {
		return 2
	}
	return 1
}

// firstCheck runs a deposit's first check. A refusal is flagged in the next round's deadline work;
// anything a person must look at, a large deposit, a contract depositor, a funder's match or a
// history that could not be read in full, goes to review.
func (s *Screener) firstCheck(ctx context.Context, v vaultView, p plan) (string, error) {
	r, id := p.r, p.r.id
	since := time.Unix(int64(r.createdAt), 0).Add(-FunderWindow)
	verdict, err := s.check.Check(ctx, r.depositor, s.hops(*r, v.inst.Limits), since)
	if err != nil {
		if s.now().Sub(time.Unix(int64(r.createdAt), 0)) > s.cfg.FirstCheckWithin {
			s.alerts.Raise(ctx, alert.Warning, "first_check_late", "deposit %d has waited %s for its first check: %v", id, s.cfg.FirstCheckWithin, err)
		}
		return "", err
	}
	// A contract has no payment history to read its funders from, so a person reviews it.
	contract := strkey.IsValidContractAddress(r.depositor)
	large := r.amountInt().Cmp(v.inst.Limits.LargeDepositThreshold) >= 0
	if contract && verdict.Clear() {
		verdict.Detail = "a contract depositor, whose funders cannot be read"
	}
	outcome := "pass"
	switch {
	case verdict.Refused:
		outcome = "refuse"
	case !verdict.Clear() || large || contract:
		outcome = "refer"
	}
	var reason *uint32
	if verdict.Refused {
		reason = &verdict.Reason
	}
	s.record(ctx, Decision{Kind: "first_check", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: outcome, Reason: reason, Detail: verdict.Detail, Sources: verdict.Sources})
	if verdict.Refused {
		if err := s.db.update(ctx, id, "refuse_reason", int32(verdict.Reason)); err != nil {
			return "", err
		}
	}
	if err := s.db.update(ctx, id, "first_findings", strings.Join(verdict.Findings, "\n")); err != nil {
		return "", err
	}
	if outcome == "refer" {
		if err := s.sendToReview(ctx, id); err != nil {
			return "", err
		}
	}
	return outcome, s.db.update(ctx, id, "first_check", outcome)
}

// sendToReview marks a deposit for a person to decide, from now.
func (s *Screener) sendToReview(ctx context.Context, id uint64) error {
	if err := s.db.update(ctx, id, "review_at", s.now().Unix()); err != nil {
		return err
	}
	return s.db.update(ctx, id, "review", "needed")
}

// recheck runs a deposit's final check with current sources. A refusal is flagged; anything a
// person must look at goes to review, unless a review already cleared exactly what the check finds
// now, and the deposit is held until the review clears it.
func (s *Screener) recheck(ctx context.Context, v vaultView, p plan) error {
	r, id := p.r, p.r.id
	since := time.Unix(int64(r.createdAt), 0).Add(-FunderWindow)
	verdict, err := s.check.Check(ctx, r.depositor, s.hops(*r, v.inst.Limits), since)
	if err != nil {
		return err
	}
	outcome := "pass"
	var reason *uint32
	switch {
	case verdict.Refused:
		outcome, reason = "refuse", &verdict.Reason
	case !verdict.Clear() && !(r.review == "cleared" && subset(verdict.Findings, r.findings)):
		outcome = "refer"
	}
	s.record(ctx, Decision{Kind: "recheck", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: outcome, Reason: reason, Detail: verdict.Detail, Sources: verdict.Sources})
	if verdict.Refused {
		if err := s.db.update(ctx, id, "refuse_reason", int32(verdict.Reason)); err != nil {
			return err
		}
	}
	if outcome == "refer" {
		if err := s.db.update(ctx, id, "first_findings", strings.Join(verdict.Findings, "\n")); err != nil {
			return err
		}
		if err := s.sendToReview(ctx, id); err != nil {
			return err
		}
		r.findings, r.review = verdict.Findings, "needed"
	}
	if err := s.db.update(ctx, id, "recheck", outcome); err != nil {
		return err
	}
	at := uint64(s.now().Unix())
	if err := s.db.update(ctx, id, "recheck_at", int64(at)); err != nil {
		return err
	}
	r.recheck, r.recheckAt = outcome, &at
	return nil
}

func subset(found, cleared []string) bool {
	for _, f := range found {
		if !slices.Contains(cleared, f) {
			return false
		}
	}
	return true
}

// lift unflags a held deposit once its own final check passed, as recently as an attestation
// needs: a deposit inside the attested range is admitted on that check once it is eligible.
func (s *Screener) lift(ctx context.Context, r *row) error {
	res, err := s.send(ctx, "unflag", vault.U64(r.id))
	if err != nil {
		return err
	}
	// "lifted" stands for the flag until the follower sees the unflag land.
	if err := s.db.update(ctx, r.id, "flag_sent", nil); err != nil {
		return err
	}
	if err := s.db.update(ctx, r.id, "flag_kind", "lifted"); err != nil {
		return err
	}
	r.flagSent, r.flagKind = nil, "lifted"
	id, held := r.id, uint32(ReasonHeld)
	s.record(ctx, Decision{Kind: "unflag", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: "unflag", Reason: &held,
		Detail: "the hold ended: its final check passed", TxHash: res.Hash})
	return nil
}

// refundDelay is how long after a flag anyone may refund the deposit, the vault's REFUND_DELAY.
const refundDelay = 24 * 60 * 60

// attestCandidate is the end of the longest run of pending deposits after the attested ones in
// which each one passed its own final check lately or is flagged, with the deposits the run passes
// only once they are held: those that wait, as holdable reports, for a person or for their own
// final window. Any other deposit not re-checked, checked too long ago, or refused without its
// flag landed, ends the run: attest vouches for every unflagged deposit up to the ID, so none may
// be covered on the strength of an older check.
func attestCandidate(rows []row, attested, now, window uint64, holdable func(*row) bool) (uint64, []*row) {
	var best uint64
	var holds, waiting []*row
	for i := range rows {
		r := &rows[i]
		if r.id <= attested || r.reason() != nil {
			continue
		}
		if r.needsFlag || r.recheck != "pass" || r.recheckAt == nil || now > *r.recheckAt+window {
			if !r.needsFlag && holdable(r) {
				waiting = append(waiting, r)
				continue
			}
			break
		}
		best = r.id
		holds, waiting = append(holds, waiting...), nil
	}
	return best, holds
}

func (s *Screener) attest(ctx context.Context, v vaultView, rows []row) error {
	if err := s.check.Fresh(); err != nil {
		return nil
	}
	if v.inst.Status.Halted(v.now) {
		return nil
	}
	window := uint64(s.cfg.RecheckWindow.Seconds())
	// A deposit is held only when its hold can be lifted, before it is eligible, ahead of the
	// refund the hold allows a day later.
	holdable := func(r *row) bool {
		if r.delay == nil {
			return false
		}
		eligible := vault.PendingDeposit{Amount: r.amountInt(), CreatedAt: r.createdAt, Delay: *r.delay}.EligibleAt(v.inst.Config, v.inst.Limits)
		return eligible <= v.now+refundDelay && (r.review == "needed" || v.now+window < eligible)
	}
	upTo, holds := attestCandidate(rows, v.inst.Status.AttestedUpTo, v.now, window, holdable)
	if upTo == 0 || upTo >= v.inst.Status.NextDepositID {
		return nil
	}
	for _, r := range holds {
		detail := "it holds back later deposits while it waits for its own final check"
		if r.review == "needed" {
			detail = "it holds back later deposits while it waits for a review"
		}
		if err := s.Flag(ctx, r.id, ReasonHeld, "hold", detail); err != nil {
			return err
		}
		held := uint32(ReasonHeld)
		r.flagSent, r.flagKind = &held, "hold"
	}
	if err := s.chainAgrees(ctx, v.inst.Status.AttestedUpTo, upTo, v.now, rows); err != nil {
		s.alerts.Raise(ctx, alert.Critical, "attest_withheld", "attestation up to %d withheld: %v", upTo, err)
		return err
	}
	res, err := s.send(ctx, "attest", vault.U64(upTo))
	if err != nil {
		s.alerts.Raise(ctx, alert.Critical, "attest_failed", "attestation up to %d failed: %v", upTo, err)
		return err
	}
	s.record(ctx, Decision{Kind: "attest", DepositID: &upTo, Outcome: "attest", Detail: fmt.Sprintf("attested up to %d", upTo), Sources: s.check.Statuses(), TxHash: res.Hash})
	s.log.Info("attested", "up_to", upTo, "tx", res.Hash)
	return nil
}

// chainAgrees reads every deposit an attestation would cover from the chain, not from the replay
// the candidate came from: each one still pending must be flagged on chain or have passed its
// final check here. A replay that missed a deposit, or saw it resolved when it is not, would
// otherwise attest it unscreened.
func (s *Screener) chainAgrees(ctx context.Context, attested, upTo, now uint64, rows []row) error {
	passed := make(map[uint64]bool, len(rows))
	for i := range rows {
		if rows[i].recheck == "pass" && s.fresh(now, &rows[i]) {
			passed[rows[i].id] = true
		}
	}
	var ids []uint64
	var keys []xdr.LedgerKey
	for id := attested + 1; id <= upTo; id++ {
		k, err := vault.PendingKey(s.cfg.Vault, id)
		if err != nil {
			return err
		}
		ids, keys = append(ids, id), append(keys, k)
	}
	entries, _, err := rpc.Entries(ctx, s.rpc, keys)
	if err != nil {
		return err
	}
	for i, id := range ids {
		name, _ := rpc.KeyString(keys[i])
		e, ok := entries[name]
		if !ok {
			continue
		}
		v, err := rpc.ContractValue(e)
		if err != nil {
			return err
		}
		d, err := vault.DecodePendingDeposit(v)
		if err != nil {
			return err
		}
		if d.Flag == nil && !passed[id] {
			return fmt.Errorf("deposit %d is pending on chain without a passed final check here", id)
		}
	}
	return nil
}

// Run follows the vault and runs the schedule until ctx ends.
func (s *Screener) Run(ctx context.Context, f *follow.Follower, poll, tick, refresh time.Duration) {
	go f.Run(ctx, poll, func(err error) {
		if errors.Is(err, follow.ErrFault) {
			s.mu.Lock()
			s.fault = true
			s.mu.Unlock()
			s.alerts.Raise(ctx, alert.Critical, "ingest_fault", "screening ingest stopped: %v", err)
		} else {
			s.log.Warn("ingest retry", "error", err.Error())
		}
	})
	go func() {
		for ctx.Err() == nil {
			s.RefreshSources(ctx)
			sleep(ctx, refresh)
		}
	}()
	for ctx.Err() == nil {
		if err := s.Tick(ctx); err != nil {
			s.log.Warn("screening round incomplete", "error", err.Error())
		}
		sleep(ctx, tick)
	}
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// Health is the identity and readiness of the screening service. It is ready when every source is
// fresh, ingest is near the chain tip without a fault, and a screening round completed in the last
// two minutes; otherwise deposits wait, as the policy has them.
type Health struct {
	Ready          bool   `json:"ready"`
	Code           string `json:"code,omitempty"`
	Vault          string `json:"vault"`
	NetworkID      string `json:"network_id"`
	PolicyVersion  string `json:"policy_version"`
	LatestLedger   uint32 `json:"latest_ledger"`
	IngestedLedger uint32 `json:"ingested_ledger"`
	AttestedUpTo   uint64 `json:"attested_up_to"`
	// ReviewQueue is how many deposits wait for a person, and OldestReview how many seconds the
	// first of them has waited.
	ReviewQueue  int   `json:"review_queue"`
	OldestReview int64 `json:"oldest_review_seconds"`
}

// Not-ready codes of the health endpoint.
const (
	CodeSourcesStale = "sources_stale"
	CodeLagging      = "lagging"
	CodeFault        = "fault"
	CodeStalled      = "stalled"
)

// Health reports readiness.
func (s *Screener) Health() Health {
	stale := s.check.Fresh() != nil
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := Health{
		Vault: s.cfg.Vault, NetworkID: fmt.Sprintf("%x", s.cfg.NetworkID), PolicyVersion: s.cfg.PolicyVersion,
		LatestLedger: s.latest, IngestedLedger: s.cursor, AttestedUpTo: s.state.AttestedUpTo,
		ReviewQueue: s.reviews, OldestReview: int64(s.oldestReview.Seconds()),
	}
	switch {
	case s.fault:
		h.Code = CodeFault
	case stale:
		h.Code = CodeSourcesStale
	case s.latest > s.cursor+12:
		h.Code = CodeLagging
	case s.tickedAt.IsZero() || s.now().Sub(s.tickedAt) > 2*time.Minute:
		h.Code = CodeStalled
	default:
		h.Ready = true
	}
	return h
}
