package screening

import (
	"context"
	"errors"
	"fmt"
	"time"

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

// Reviews lists the deposits a person must review.
func (s *Screener) Reviews(ctx context.Context) ([]Review, error) {
	rows, err := s.db.pending(ctx)
	if err != nil {
		return nil, err
	}
	var out []Review
	for _, r := range rows {
		if r.review == "needed" && r.flag == nil && r.flagSent == nil {
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

// FlagManually refuses a pending deposit for a fraud report (reason 4) or a written order from an
// authority (reason 99).
func (s *Screener) FlagManually(ctx context.Context, id uint64, reason uint32, reviewer, note string) error {
	if reason != ReasonFraud && reason != ReasonOther {
		return fmt.Errorf("screening: manual flags use reason %d or %d", ReasonFraud, ReasonOther)
	}
	if _, err := s.pendingRow(ctx, id); err != nil {
		return err
	}
	return s.Flag(ctx, id, reason, "manual", fmt.Sprintf("reviewer: %s; %s", reviewer, note))
}

// Unflag corrects a mistaken flag while the deposit is pending. A deposit inside the attested
// range is admitted as soon as the flag is gone, so the automated checks run again first, and the
// unflag is refused unless they pass.
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
	since := time.Unix(int64(r.createdAt), 0).Add(-FunderWindow)
	verdict, err := s.check.Check(ctx, r.depositor, s.hops(r, inst.Limits), since)
	if err != nil {
		return err
	}
	if verdict.Refused {
		return fmt.Errorf("screening: the checks refuse deposit %d now: %s", id, verdict.Detail)
	}
	res, err := s.send(ctx, "unflag", vault.U64(id))
	if err != nil {
		return err
	}
	for column, value := range map[string]any{"first_check": "pass", "review": "cleared", "recheck": nil, "flag_sent": nil, "refuse_reason": nil} {
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
