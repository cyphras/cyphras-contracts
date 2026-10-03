package screening

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
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
	// Cutoff is how long before eligibility an attested deposit without a passed re-check is
	// refused rather than risk its admission unchecked.
	Cutoff time.Duration
	// FirstCheckWithin is the time the policy allows for a deposit's first check.
	FirstCheckWithin time.Duration
}

// Screener follows the vault's deposits and decides each one.
type Screener struct {
	cfg     Config
	rpc     rpc.Client
	chain   *chainstate.Store
	db      store
	check   *Checker
	reports *ReportSource
	engine  *submit.Engine
	asp     *submit.Account
	alerts  *alert.Alerter
	log     *slog.Logger
	now     func() time.Time

	mu       sync.RWMutex
	state    *chainstate.State
	cursor   uint32
	latest   uint32
	fault    bool
	tickedAt time.Time
}

// New loads the stored chain state. The checker's sources must not include a report source; the
// screener adds its own.
func New(ctx context.Context, cfg Config, client rpc.Client, chain *chainstate.Store, check *Checker,
	engine *submit.Engine, asp *submit.Account, alerts *alert.Alerter, log *slog.Logger) (*Screener, error) {
	s := &Screener{cfg: cfg, rpc: client, chain: chain, db: store{chain.Pool}, check: check, engine: engine, asp: asp, alerts: alerts, log: log, now: time.Now}
	s.reports = &ReportSource{list: list{name: "self_reports", maxAge: 365 * 24 * time.Hour}, load: s.db.selfReports, now: s.clock}
	check.Sources = append(check.Sources, s.reports)
	state, cursor, err := chain.Load(ctx, cfg.Vault, cfg.DeployLedger)
	if err != nil {
		return nil, err
	}
	s.state, s.cursor = state, cursor
	if err := s.reports.Refresh(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Screener) clock() time.Time { return s.now() }

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
			s.log.Info("attestation on chain", "up_to", n.Body.(vault.Attested).UpTo, "ledger", n.Ledger)
		}
	}
	return nil
}

// RefreshSources fetches every source again; a failure leaves the old data, which then ages.
func (s *Screener) RefreshSources(ctx context.Context) {
	for _, src := range s.check.Sources {
		if err := src.Refresh(ctx); err != nil {
			s.log.Warn("source refresh failed", "source", src.Name(), "error", err.Error())
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

func (s *Screener) send(ctx context.Context, fn string, args ...xdr.ScVal) (submit.Result, error) {
	res, err := s.engine.Do(ctx, s.asp, func() (txnbuild.Operation, error) { return s.invoke(fn, args...) }, 4)
	if err != nil {
		return res, err
	}
	if res.Outcome != submit.Success {
		return res, fmt.Errorf("%s %s: %s", fn, res.Outcome, res.Code)
	}
	return res, nil
}

// Flag refuses a pending deposit on chain and records it.
func (s *Screener) Flag(ctx context.Context, id uint64, reason uint32, kind, detail string) error {
	res, err := s.send(ctx, "flag", vault.U64(id), vault.U32(reason))
	if err != nil {
		s.alerts.Raise(ctx, alert.Critical, "flag_failed", "deposit %d could not be flagged with reason %d: %v", id, reason, err)
		return err
	}
	if err := s.db.update(ctx, id, "flag_sent", int32(reason)); err != nil {
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

// Tick runs one round of the schedule: first checks, review deadlines, re-checks, self-reports and
// the attestation.
func (s *Screener) Tick(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, s.rpc, s.cfg.Vault)
	if err != nil {
		return fmt.Errorf("read the vault: %w", err)
	}
	view := vaultView{inst: inst, now: uint64(s.now().Unix())}
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
	for i := range rows {
		if err := s.decide(ctx, view, &rows[i]); err != nil {
			s.log.Warn("deposit undecided", "deposit", rows[i].id, "error", err.Error())
		}
	}
	if err := s.attest(ctx, view, rows); err != nil {
		return err
	}
	s.mu.Lock()
	s.tickedAt = s.now()
	s.mu.Unlock()
	return nil
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

func (s *Screener) decide(ctx context.Context, v vaultView, r *row) error {
	if r.delay == nil {
		return errors.New("delay snapshot not read yet")
	}
	id := r.id
	cfg, limits := v.inst.Config, v.inst.Limits
	eligibleAt := vault.PendingDeposit{Amount: r.amountInt(), CreatedAt: r.createdAt, Delay: *r.delay}.EligibleAt(cfg, limits)
	since := time.Unix(int64(r.createdAt), 0).Add(-FunderWindow)
	large := r.amountInt().Cmp(limits.LargeDepositThreshold) >= 0
	flag := func(reason uint32, kind, detail string) error {
		if err := s.Flag(ctx, id, reason, kind, detail); err != nil {
			r.needsFlag = true
			return err
		}
		r.flagSent = &reason
		return nil
	}
	// A flag this service sent counts before the follower has seen it land.
	if r.flag != nil || r.flagSent != nil {
		return nil
	}
	if h, ok := s.reports.Lookup(r.depositor); ok && !h.Refer {
		return flag(ReasonFraud, "self_report", "the depositor reported its key compromised")
	}

	if r.firstCheck == "" {
		verdict, err := s.check.Check(ctx, r.depositor, s.hops(*r, limits), since)
		if err != nil {
			if s.now().Sub(time.Unix(int64(r.createdAt), 0)) > s.cfg.FirstCheckWithin {
				s.alerts.Raise(ctx, alert.Warning, "first_check_late", "deposit %d has waited %s for its first check: %v", id, s.cfg.FirstCheckWithin, err)
			}
			return err
		}
		outcome := "pass"
		switch {
		case verdict.Refused:
			outcome = "refuse"
		case verdict.Refer || large:
			outcome = "refer"
		}
		var reason *uint32
		if verdict.Refused {
			reason = &verdict.Reason
		}
		s.record(ctx, Decision{Kind: "first_check", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: outcome, Reason: reason, Detail: verdict.Detail, Sources: verdict.Sources})
		if err := s.db.update(ctx, id, "first_check", outcome); err != nil {
			return err
		}
		if verdict.Refused {
			if err := s.db.update(ctx, id, "refuse_reason", int32(verdict.Reason)); err != nil {
				return err
			}
			r.refuseReason = &verdict.Reason
		}
		r.firstCheck = outcome
		if outcome == "refer" {
			if err := s.db.update(ctx, id, "review", "needed"); err != nil {
				return err
			}
			r.review = "needed"
		}
	}
	refusal := uint32(ReasonOther)
	if r.refuseReason != nil {
		refusal = *r.refuseReason
	}
	if r.firstCheck == "refuse" {
		return flag(refusal, "first_check", "refused at the first check")
	}

	inRecheck := v.now+uint64(s.cfg.RecheckWindow.Seconds()) >= eligibleAt
	switch {
	case r.review == "refused":
		return flag(ReasonReview, "review", "refused by the reviewer")
	case r.review == "needed" && inRecheck:
		return flag(ReasonReview, "review", "the review was not finished before the final check")
	case r.review == "needed":
		return nil
	case r.recheck == "refuse":
		return flag(refusal, "recheck", "refused at the final check")
	case !inRecheck || r.recheck == "pass":
		return nil
	}
	verdict, err := s.check.Check(ctx, r.depositor, s.hops(*r, limits), since)
	if err != nil {
		attested := id <= v.inst.Status.AttestedUpTo
		if attested && v.now+uint64(s.cfg.Cutoff.Seconds()) >= eligibleAt {
			s.log.Warn("re-check impossible before eligibility", "deposit", id)
			return flag(ReasonReview, "recheck", "the final check could not run in time: "+err.Error())
		}
		return err
	}
	outcome := "pass"
	var reason *uint32
	if verdict.Refused {
		outcome, reason = "refuse", &verdict.Reason
	}
	s.record(ctx, Decision{Kind: "recheck", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: outcome, Reason: reason, Detail: verdict.Detail, Sources: verdict.Sources})
	if verdict.Refused {
		if err := s.db.update(ctx, id, "refuse_reason", int32(verdict.Reason)); err != nil {
			return err
		}
	}
	if err := s.db.update(ctx, id, "recheck", outcome); err != nil {
		return err
	}
	r.recheck = outcome
	if verdict.Refused {
		return flag(verdict.Reason, "recheck", verdict.Detail)
	}
	return nil
}

// attestCandidate is the highest deposit whose re-check passed, provided every pending deposit
// below it passed its first check or is flagged. A refusal whose flag has not landed blocks the
// attestation, since attest vouches for every unflagged deposit up to the ID.
func attestCandidate(rows []row, attested uint64) uint64 {
	var best uint64
	for _, r := range rows {
		if r.id <= attested {
			continue
		}
		flagged := r.flag != nil || r.flagSent != nil
		refused := r.needsFlag || r.firstCheck == "refuse" || r.recheck == "refuse" || r.review == "refused"
		if !flagged && (refused || (r.firstCheck != "pass" && r.firstCheck != "refer")) {
			break
		}
		if !flagged && r.recheck == "pass" {
			best = r.id
		}
	}
	return best
}

func (s *Screener) attest(ctx context.Context, v vaultView, rows []row) error {
	if err := s.check.Fresh(); err != nil {
		return nil
	}
	if v.inst.Status.Halted(v.now) {
		return nil
	}
	upTo := attestCandidate(rows, v.inst.Status.AttestedUpTo)
	if upTo == 0 || upTo >= v.inst.Status.NextDepositID {
		return nil
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
