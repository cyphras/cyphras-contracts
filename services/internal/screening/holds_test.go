package screening

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// spammed answers for its accounts a history longer than a check reads, whose funders it reads
// are clean, as a history flooded with small payments is.
type spammed map[string]bool

func (s spammed) Inflows(_ context.Context, account string, _ time.Time) ([]Inflow, Gap, error) {
	if !s[account] {
		return nil, 0, nil
	}
	return []Inflow{{From: funder, Asset: "native", Amount: big.NewInt(1_000_000_000)}}, GapVolume, nil
}

func (h *harness) paged(code string) bool {
	for _, p := range h.pages {
		if p.Code == code {
			return true
		}
	}
	return false
}

func TestHistorySpamHoldsADepositForAPersonAndNeverRefusesIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	victim := keypair.MustRandom().Address()
	h.s.check.Inflows = spammed{victim: true}
	h.s.requestCheck.Inflows = spammed{victim: true}
	id := h.shield(victim, 10_000_000)
	h.tick()
	// The deposit goes to a person, who is paged.
	if reviews, _ := h.s.Reviews(ctx); len(reviews) != 1 || reviews[0].ID != id {
		t.Fatalf("reviews %v", reviews)
	}
	if !h.paged("review_needed") {
		t.Fatalf("pages %+v", h.pages)
	}
	// Unreviewed at its final check, it is held with reason 6, never refused with reason 5.
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6"}) {
		t.Fatalf("at the final check: %v", got)
	}
	// An unshield to the account stays withheld; its owner can still send it without the relayer.
	api := h.s.Internal(sha256.Sum256([]byte("token")), sha256.Sum256([]byte("keeper")))
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/screen", strings.NewReader(`{"address":"`+victim+`"}`))
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	api.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"withheld"`) {
		t.Fatalf("an unshield to a spammed account: %s", rec.Body.String())
	}
	// A reviewer clears it, and its hold is lifted once its final check finds nothing new.
	if err := h.s.DecideReview(ctx, id, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1", "attest 1"}) {
		t.Fatalf("after the review: %v", got)
	}
	if !h.paged("review_needed_resolved") {
		t.Fatalf("the review page stayed open: %+v", h.pages)
	}
}

func TestOnlyVolumeIsToldApartFromOtherGaps(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	listed := keypair.MustRandom().Address()
	src := static("exploits", now, map[string]Hit{listed: {Source: "exploits", Reason: ReasonExploit}})
	clean := []Inflow{{From: funder, Asset: "native", Amount: big.NewInt(1_000_000_000)}}
	many := make([]Inflow, 0, 26)
	for range 26 {
		many = append(many, Inflow{From: keypair.MustRandom().Address(), Asset: "native", Amount: big.NewInt(1_000_000_000)})
	}
	for name, c := range map[string]struct {
		inflows []Inflow
		gap     Gap
		volume  bool
	}{
		"a long history":            {clean, GapVolume, true},
		"too many funders":          {many, 0, true},
		"a sender without a name":   {clean, GapUnnamed, false},
		"both":                      {clean, GapVolume | GapUnnamed, false},
		"a listed funder in a long": {[]Inflow{{From: listed, Asset: "native", Amount: big.NewInt(1_000_000_000)}}, GapVolume, false},
		"nothing missing":           {clean, 0, false},
	} {
		chk := &Checker{Sources: []Source{src}, Inflows: inflowList{c.inflows, c.gap}, MaxFunders: 25, Now: func() time.Time { return now }}
		v, err := chk.Check(context.Background(), keypair.MustRandom().Address(), 1, now.Add(-FunderWindow))
		if err != nil || v.OnlyVolume() != c.volume {
			t.Fatalf("%s: %+v %v", name, v, err)
		}
	}
}

// delayed gives a deposit, before its first round, another delay than its amount's.
func (h *harness) delayed(id uint64, delay uint64) {
	d := h.deposits[id]
	d.delay = delay
	h.deposits[id] = d
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, d.depositor, d.amount, d.createdAt, delay, nil, 0), h.chain.Ledger, nil)
}

func TestAClearedLargeDepositIsHeldUntilItsOwnFinalCheck(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	if err := h.s.DecideReview(ctx, big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	last := h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	// The small deposits pass their final checks a day before the large one's.
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "attest " + itoa(int64(last))}) {
		t.Fatalf("in the small deposits' final window: %v", got)
	}
	// Cleared and held, it still waits for its own final window.
	h.now = h.now.Add(time.Hour)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a day before its final window: %v", got)
	}
	// The hold is lifted once the large deposit passes its own final check, before it is eligible.
	h.now = time.Unix(int64(h.deposits[big].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1"}) {
		t.Fatalf("in the large deposit's final window: %v", got)
	}
	if h.deposits[big].flaggedAt != 0 {
		t.Fatal("still flagged")
	}
}

func TestADepositEligibleMoreThanADayAwayIsNotHeld(t *testing.T) {
	h := newHarness(t)
	big := h.shield(clean, 6_000_000_000)
	// A hold could be refunded a day after it, before the deposit's own final check.
	h.delayed(big, 3*86400)
	h.tick()
	if err := h.s.DecideReview(context.Background(), big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a hold that could end in a refund: %v", got)
	}
	// Half an hour more than a day before eligibility, a hold could still end in a refund.
	eligible := time.Unix(int64(h.deposits[big].createdAt), 0).Add(3 * 24 * time.Hour)
	h.now = eligible.Add(-24*time.Hour - 30*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a hold that could end in a refund: %v", got)
	}
	// Within a day of eligibility, it is held.
	h.now = eligible.Add(-23 * time.Hour)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "3", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "attest 2"}) {
		t.Fatalf("a day before eligibility: %v", got)
	}
}

func TestADepositWhoseChecksKeepFailingIsHeldAtItsCutoff(t *testing.T) {
	h := newHarness(t)
	first := h.shield(clean, 10_000_000)
	h.tick()
	h.now = h.now.Add(2 * time.Minute)
	h.chain.ClosedAt = h.now.Unix()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	// The first deposit's final window opens and its check fails: it is tried again, not held.
	h.s.check.Inflows = failing{clean}
	h.now = h.now.Add(49 * time.Minute)
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("held before its cutoff: %v", got)
	}
	if r := h.s.retries[first]; r.attempts == 0 {
		t.Fatal("the first deposit was not checked")
	}
	// At its cutoff its check still fails: it is held, and the deposit behind it is attested on time.
	h.now = h.now.Add(3 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "attest 2"}) {
		t.Fatalf("at the cutoff: %v", got)
	}
}

func TestADepositWhoseFirstCheckNeverRunsHoldsBackNothing(t *testing.T) {
	h := newHarness(t)
	bad := keypair.MustRandom().Address()
	h.s.check.Inflows = failing{bad}
	h.shield(bad, 10_000_000)
	h.tick()
	h.now = h.now.Add(5 * time.Minute)
	h.chain.ClosedAt = h.now.Unix()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	var all []string
	for _, step := range []time.Duration{45 * time.Minute, 5 * time.Minute, 5 * time.Minute} {
		h.now = h.now.Add(step)
		h.tick()
		all = append(all, h.sent()...)
	}
	if !equal(all, []string{"flag 1 6", "attest 2"}) {
		t.Fatalf("sent %v", all)
	}
}

// failing fails the lookups of its account and answers the others with no inflows.
type failing struct{ account string }

func (f failing) Inflows(_ context.Context, account string, _ time.Time) ([]Inflow, Gap, error) {
	if account == f.account {
		return nil, 0, errUnreachable
	}
	return nil, 0, nil
}

var errUnreachable = errors.New("horizon down")

func TestALiftThatWaitedPastItsCheckChecksAgain(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	h.now = time.Unix(int64(h.deposits[big].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6"}) {
		t.Fatalf("at the review deadline: %v", got)
	}
	if err := h.s.DecideReview(ctx, big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	// The unflag cannot go through for a while, longer than a final check vouches for a deposit.
	simulate := h.fake.Simulate
	h.fake.Simulate = func(req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		var env xdr.TransactionEnvelope
		if err := xdr.SafeUnmarshalBase64(req.Transaction, &env); err != nil {
			return protocol.SimulateTransactionResponse{}, err
		}
		if env.V1.Tx.Operations[0].Body.InvokeHostFunctionOp.HostFunction.InvokeContract.FunctionName == "unflag" {
			return protocol.SimulateTransactionResponse{Error: "the RPC is down"}, nil
		}
		return simulate(req)
	}
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("during the outage: %v", got)
	}
	h.now = h.now.Add(11 * time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "3", h.now)
	h.fake.Simulate = simulate
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1", "attest 1"}) {
		t.Fatalf("after the outage: %v", got)
	}
	rechecks := 0
	for _, d := range h.decisions() {
		if d == "recheck pass -" {
			rechecks++
		}
	}
	if rechecks != 2 {
		t.Fatalf("lifted on a final check %d minutes old: %v", 11, h.decisions())
	}
}

func TestALiftedHoldIsNotLiftedAgainBeforeTheChainShowsIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	h.now = time.Unix(int64(h.deposits[big].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if err := h.s.DecideReview(ctx, big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "unflag 1", "attest 1"}) {
		t.Fatalf("sent %v", got)
	}
	// The next round runs before the follower has seen the unflag land.
	h.setVault(h.attest)
	if err := h.s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a lifted hold was lifted again: %v", got)
	}
}

// gapped reads one account's history only in part, as a flood of tiny payments makes Horizon.
type gapped struct {
	inner   Inflows
	account string
}

func (g gapped) Inflows(ctx context.Context, account string, since time.Time) ([]Inflow, Gap, error) {
	out, gap, err := g.inner.Inflows(ctx, account, since)
	if account == g.account {
		gap |= GapVolume
	}
	return out, gap, err
}

func TestTheReviewQueueIsMeasuredAndPagedPastItsTime(t *testing.T) {
	// The review time is the default, 2 hours.
	h := newHarness(t)
	victim := keypair.MustRandom().Address()
	h.s.check.Inflows = gapped{inner: h.s.check.Inflows, account: victim}
	big := h.shield(victim, 6_000_000_000)
	h.tick()
	if hl := h.s.Health(); hl.ReviewQueue != 1 || hl.OldestReview != 0 {
		t.Fatalf("after the first check: %+v", hl)
	}
	h.now = h.now.Add(time.Hour)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if hl := h.s.Health(); hl.OldestReview != 3600 || h.paged("review_overdue") {
		t.Fatalf("an hour in: %+v", hl)
	}
	h.now = h.now.Add(61 * time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "3", h.now)
	h.tick()
	var overdue bool
	for _, p := range h.pages {
		overdue = overdue || (p.Code == "review_overdue" && p.Severity == alert.Critical)
	}
	if !overdue {
		t.Fatalf("pages %+v", h.pages)
	}
	if err := h.s.DecideReview(context.Background(), big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if hl := h.s.Health(); hl.ReviewQueue != 0 || !h.paged("review_overdue_resolved") {
		t.Fatalf("after the review: %+v", hl)
	}
}

func TestAnOperatorLiftsAHoldOnlyAsItsFinalCheckWould(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "attest 2"}) {
		t.Fatalf("sent %v", got)
	}
	h.tick()
	// Held for a review, it is the review's to decide, even in its final window.
	final := time.Unix(int64(h.deposits[big].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	for _, at := range []time.Time{h.now, final} {
		h.now = at
		h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
		if err := h.s.Unflag(ctx, big, "operator", "meant another deposit"); err == nil || !strings.Contains(err.Error(), "review decides") {
			t.Fatalf("an unflag of a hold waiting for its review: %v", err)
		}
	}
	h.now = time.Unix(int64(h.deposits[big].createdAt), 0).Add(time.Hour)
	if err := h.s.DecideReview(ctx, big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	// A day before its final window, the hold stays whatever the checks say.
	if err := h.s.Unflag(ctx, big, "reviewer", "looked fine"); err == nil || !strings.Contains(err.Error(), "final window") {
		t.Fatalf("an early unflag: %v", err)
	}
	// In its final window a referral is not clear enough.
	h.now = time.Unix(int64(h.deposits[big].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	h.funders[clean] = []string{funder}
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}, funder: {Source: "exploits", Refer: true}}, "2", h.now)
	if err := h.s.Unflag(ctx, big, "reviewer", "looked fine"); err == nil || !strings.Contains(err.Error(), "do not clear") {
		t.Fatalf("an unflag on a referral: %v", err)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
	// A clear check then counts as the final check: the deposit is not checked again before it is
	// admitted, and the lifted flag is not lifted twice.
	delete(h.funders, clean)
	if err := h.s.Unflag(ctx, big, "reviewer", "looked fine"); err != nil {
		t.Fatal(err)
	}
	lifted := h.now
	h.now = h.now.Add(time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1"}) {
		t.Fatalf("sent %v", got)
	}
	rows, err := h.s.db.pending(ctx)
	if err != nil || rows[0].recheck != "pass" || rows[0].recheckAt == nil || *rows[0].recheckAt != uint64(lifted.Unix()) {
		t.Fatalf("rows %+v %v", rows, err)
	}
}

func TestACorrectionInsideTheAttestedRangeWaitsForTheFinalWindow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dirty := h.shield(thief, 6_000_000_000)
	h.tick()
	h.land()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	// The attestation of the later deposit passes over the flagged one.
	if got := h.sent(); !equal(got, []string{"flag 1 2", "attest 2"}) {
		t.Fatalf("sent %v", got)
	}
	// A deposit no attestation has passed yet is corrected at once: its own attestation comes in
	// its final window.
	later := h.shield(thief, 6_000_000_000)
	h.tick()
	h.setVault(h.attest)
	h.sync()
	h.sources.set(map[string]Hit{}, "2", h.now)
	if err := h.s.Unflag(ctx, later, "reviewer", "false positive"); err != nil {
		t.Fatal(err)
	}
	if got := h.sent(); !equal(got, []string{"flag 3 2", "unflag 3"}) {
		t.Fatalf("sent %v", got)
	}
	// The flag was a mistake: the list drops the account. Unflagged now, the deposit would come
	// under the attestation a day before its final check, as only a stolen key would put it.
	h.now = h.now.Add(2 * time.Hour)
	h.setVault(h.attest)
	h.sources.set(map[string]Hit{}, "3", h.now)
	if err := h.s.Unflag(ctx, dirty, "reviewer", "false positive"); err == nil || !strings.Contains(err.Error(), "final window") {
		t.Fatalf("an early correction: %v", err)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
	// In its final window the correction is its final check: a referral is not clear enough.
	h.now = time.Unix(int64(h.deposits[dirty].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	h.funders[thief] = []string{funder}
	h.sources.set(map[string]Hit{funder: {Source: "exploits", Refer: true}}, "4", h.now)
	if err := h.s.Unflag(ctx, dirty, "reviewer", "false positive"); err == nil || !strings.Contains(err.Error(), "do not clear") {
		t.Fatalf("a correction on a referral: %v", err)
	}
	delete(h.funders, thief)
	h.sources.set(map[string]Hit{}, "5", h.now)
	if err := h.s.Unflag(ctx, dirty, "reviewer", "false positive"); err != nil {
		t.Fatal(err)
	}
	if got := h.sent(); !equal(got, []string{"unflag 1"}) {
		t.Fatalf("sent %v", got)
	}
	rows, err := h.s.db.pending(ctx)
	if err != nil || rows[0].recheck != "pass" || rows[0].recheckAt == nil || *rows[0].recheckAt != uint64(h.now.Unix()) {
		t.Fatalf("rows %+v %v", rows, err)
	}
}

func TestAQueuedCorrectionWaitsForTheFinalWindow(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dirty := h.shield(thief, 6_000_000_000)
	h.tick()
	h.land()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 2", "attest 2"}) {
		t.Fatalf("sent %v", got)
	}
	// The flag was a mistake. Queued a day early, the correction waits.
	h.now = h.now.Add(2 * time.Hour)
	h.sources.set(map[string]Hit{}, "2", h.now)
	id, err := h.s.QueueUnflag(ctx, dirty, "reviewer", "false positive")
	if err != nil {
		t.Fatal(err)
	}
	h.tick()
	var done *int64
	if err := h.s.db.pool.QueryRow(ctx, `SELECT done_at FROM operator_ops WHERE id = $1`, id).Scan(&done); err != nil || done != nil || h.paged("operator_op_failed") {
		t.Fatalf("a correction waiting for the window was finished: %v, pages %+v", err, h.pages)
	}
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("sent %v", got)
	}
	// Once the window opens, the service carries it out.
	h.now = time.Unix(int64(h.deposits[dirty].createdAt), 0).Add(24*time.Hour - 9*time.Minute)
	h.sources.set(map[string]Hit{}, "3", h.now)
	h.tick()
	var result string
	if err := h.s.db.pool.QueryRow(ctx, `SELECT result FROM operator_ops WHERE id = $1`, id).Scan(&result); err != nil || result != "done" {
		t.Fatalf("result %q, %v", result, err)
	}
	if got := h.sent(); !slices.Contains(got, "unflag 1") {
		t.Fatalf("sent %v", got)
	}
}

func TestTheKeeperLearnsWhichDepositsAQueuedUnflagWaitsFor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	dirty := h.shield(thief, 6_000_000_000)
	h.tick()
	h.land()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	api := h.s.Internal(sha256.Sum256([]byte("relayer")), sha256.Sum256([]byte("keeper")))
	ask := func(token string) (int, []PendingUnflag) {
		req := httptest.NewRequest(http.MethodGet, "/internal/v1/unflags", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		var body struct {
			Deposits []PendingUnflag `json:"deposits"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Deposits
	}
	if code, got := ask("keeper"); code != http.StatusOK || len(got) != 0 {
		t.Fatalf("with nothing queued: %d %v", code, got)
	}
	if _, err := h.s.QueueUnflag(ctx, dirty, "reviewer", "false positive"); err != nil {
		t.Fatal(err)
	}
	eligible := h.deposits[dirty].createdAt + 86_400
	if code, got := ask("keeper"); code != http.StatusOK || len(got) != 1 || got[0].ID != dirty || got[0].Until != eligible {
		t.Fatalf("with an unflag queued: %d %v", code, got)
	}
	// Only the keeper's token reads it.
	if code, _ := ask("relayer"); code != http.StatusUnauthorized {
		t.Fatalf("the relayer's token: %d", code)
	}
}
