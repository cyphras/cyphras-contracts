package screening

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Review is a deposit waiting for a person's decision.
type Review struct {
	ID        uint64
	Depositor string
	Amount    string
	CreatedAt uint64
}

// Reviews lists the deposits a person must review, the held ones included: a review that clears
// one of them lifts its hold after its final check.
func (s *Screener) Reviews(ctx context.Context) ([]Review, error) {
	rows, err := s.db.pending(ctx)
	if err != nil {
		return nil, err
	}
	var out []Review
	for i := range rows {
		if r := &rows[i]; r.awaitsReview() {
			out = append(out, Review{ID: r.id, Depositor: r.depositor, Amount: r.amount, CreatedAt: r.createdAt})
		}
	}
	return out, nil
}

// ErrNotPending reports a deposit that is not waiting for the decision asked of it.
var ErrNotPending = errors.New("screening: the deposit is not waiting for that decision")

func (s *Screener) pendingRow(ctx context.Context, id uint64) (row, error) {
	rows, err := s.db.pending(ctx)
	if err != nil {
		return row{}, err
	}
	for _, r := range rows {
		if r.id == id {
			return r, nil
		}
	}
	return row{}, ErrNotPending
}

// DecideReview records a reviewer's decision; a refusal is flagged at the next round.
func (s *Screener) DecideReview(ctx context.Context, id uint64, reviewer string, clear bool) error {
	r, err := s.pendingRow(ctx, id)
	if err != nil {
		return err
	}
	if r.review != "needed" {
		return ErrNotPending
	}
	outcome := "refused"
	if clear {
		outcome = "cleared"
	}
	if err := s.db.update(ctx, id, "review", outcome); err != nil {
		return err
	}
	s.record(ctx, Decision{Kind: "review", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: outcome, Detail: "reviewer: " + reviewer})
	return nil
}

// manualReason reports the reasons a person may flag with: a fraud report (4), another reason the
// record explains (99), and a written order from an authority (100).
func manualReason(r uint32) bool {
	return r == ReasonFraud || r == ReasonOther || r == ReasonCourtOrder
}

// FlagManually refuses a pending deposit with a reason only a person decides.
func (s *Screener) FlagManually(ctx context.Context, id uint64, reason uint32, reviewer, note string) error {
	if !manualReason(reason) {
		return fmt.Errorf("screening: manual flags use reason %d, %d or %d", ReasonFraud, ReasonOther, ReasonCourtOrder)
	}
	if _, err := s.pendingRow(ctx, id); err != nil {
		return err
	}
	return s.Flag(ctx, id, reason, "manual", fmt.Sprintf("reviewer: %s; %s", reviewer, note))
}

// QueueFlag leaves a manual flag for the process that writes as the asp account, and returns its
// queue number.
func (s *Screener) QueueFlag(ctx context.Context, id uint64, reason uint32, reviewer, note string) (int64, error) {
	if !manualReason(reason) {
		return 0, fmt.Errorf("screening: manual flags use reason %d, %d or %d", ReasonFraud, ReasonOther, ReasonCourtOrder)
	}
	return s.db.queueOp(ctx, op{kind: "flag", deposit: id, reason: &reason, reviewer: reviewer, note: note}, s.now())
}

// QueueUnflag leaves an unflag for the process that writes as the asp account.
func (s *Screener) QueueUnflag(ctx context.Context, id uint64, reviewer, note string) (int64, error) {
	return s.db.queueOp(ctx, op{kind: "unflag", deposit: id, reviewer: reviewer, note: note}, s.now())
}

// runOps carries out the operators' queued decisions and records each result.
func (s *Screener) runOps(ctx context.Context) error {
	ops, err := s.db.queuedOps(ctx)
	if err != nil {
		return err
	}
	for _, o := range ops {
		var err error
		switch o.kind {
		case "flag":
			err = s.FlagManually(ctx, o.deposit, *o.reason, o.reviewer, o.note)
		case "unflag":
			err = s.Unflag(ctx, o.deposit, o.reviewer, o.note)
		default:
			err = fmt.Errorf("unknown operation %q", o.kind)
		}
		result := "done"
		if err != nil {
			result = "failed: " + err.Error()
			s.alerts.Raise(ctx, alert.Warning, fmt.Sprintf("operator_op_failed_%d", o.id), "the queued %s of deposit %d failed: %v", o.kind, o.deposit, err)
		}
		if err := s.db.finishOp(ctx, o.id, result, s.now()); err != nil {
			return err
		}
	}
	return nil
}

// Unflag corrects a mistaken flag while the deposit is pending, after the automated checks run
// again; it is refused when they refuse the deposit. A deposit inside the attested range is
// admitted as soon as the flag is gone, so its unflag is its final check: it waits for the
// deposit's final window, and the checks must find nothing at all. Earlier, the attestation would
// cover the deposit before its final window, which only a stolen asp key does, and which the
// watcher pages for. A hold is lifted the same way wherever the deposit stands, and only once any
// review it waits for has cleared it.
func (s *Screener) Unflag(ctx context.Context, id uint64, reviewer, note string) error {
	r, err := s.pendingRow(ctx, id)
	if err != nil {
		return err
	}
	if r.flag == nil {
		return ErrNotPending
	}
	inst, _, _, err := rpc.VaultInstance(ctx, s.rpc, s.cfg.Vault)
	if err != nil {
		return err
	}
	now := s.now()
	held := *r.flag == ReasonHeld
	if held && r.review == "needed" {
		return fmt.Errorf("screening: deposit %d is held for a review; the review decides it first", id)
	}
	final := held || id <= inst.Status.AttestedUpTo
	if final {
		if r.delay == nil {
			return fmt.Errorf("screening: deposit %d has no delay read yet", id)
		}
		eligible := vault.PendingDeposit{Amount: r.amountInt(), CreatedAt: r.createdAt, Delay: *r.delay}.EligibleAt(inst.Config, inst.Limits)
		if uint64(now.Add(s.cfg.RecheckWindow).Unix()) < eligible {
			return fmt.Errorf("screening: deposit %d keeps its flag until its final window, which opens %s before it is eligible", id, s.cfg.RecheckWindow)
		}
	}
	since := time.Unix(int64(r.createdAt), 0).Add(-FunderWindow)
	verdict, err := s.check.Check(ctx, r.depositor, s.hops(r, inst.Limits), since)
	if err != nil {
		return err
	}
	if verdict.Refused {
		return fmt.Errorf("screening: the checks refuse deposit %d now: %s", id, verdict.Detail)
	}
	if final && !verdict.Clear() {
		return fmt.Errorf("screening: the checks do not clear deposit %d now: %s", id, verdict.Detail)
	}
	res, err := s.send(ctx, "unflag", vault.U64(id))
	if err != nil {
		return err
	}
	reset := map[string]any{"first_check": "pass", "review": "cleared", "recheck": nil, "recheck_at": nil, "flag_sent": nil, "refuse_reason": nil, "flag_kind": nil}
	if final {
		reset["recheck"], reset["recheck_at"] = "pass", now.Unix()
		s.record(ctx, Decision{Kind: "recheck", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: "pass", Detail: verdict.Detail, Sources: verdict.Sources})
	}
	if held {
		reset["flag_kind"] = "lifted"
	}
	for column, value := range reset {
		if err := s.db.update(ctx, id, column, value); err != nil {
			return err
		}
	}
	s.record(ctx, Decision{Kind: "unflag", DepositID: &id, Address: r.depositor, Amount: r.amount, Outcome: "unflag", Reason: r.flag, Detail: fmt.Sprintf("reviewer: %s; %s", reviewer, note), TxHash: res.Hash})
	return nil
}

// Register records a fraud report or a law-enforcement request for the statistics.
func (s *Screener) Register(ctx context.Context, kind, note string) error {
	if kind != "fraud_report" && kind != "legal_request" {
		return fmt.Errorf("screening: unknown register %q", kind)
	}
	return s.db.register(ctx, kind, note, s.now())
}
