package screening

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

func TestAttestationNeverCoversADepositUnderReview(t *testing.T) {
	at := uint64(1_728_000_000)
	rows := []row{
		{id: 1, firstCheck: "refer", review: "needed"},
		{id: 2, firstCheck: "pass", recheck: "pass", recheckAt: &at},
	}
	if got, _ := attestCandidate(rows, 0, at, 600, func(*row) bool { return false }); got != 0 {
		t.Fatalf("attest(%d) would cover a deposit still under review", got)
	}
	// Only a deposit that is held first is passed.
	if got, holds := attestCandidate(rows, 0, at, 600, func(*row) bool { return true }); got != 2 || len(holds) != 1 || holds[0].id != 1 {
		t.Fatalf("attest(%d) holding %v", got, holds)
	}
}

func TestADepositUnderReviewIsHeldSoLaterOnesAreAdmittedOnTime(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 6_000_000_000)
	h.shield(clean, 10_000_000)
	h.tick()
	// The small deposit passes its final check while the large one before it is still under
	// review: the large one is held, and the small one attested on time.
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "attest 2"}) {
		t.Fatalf("in the small deposit's final window: %v", got)
	}
	if reviews, _ := h.s.Reviews(context.Background()); len(reviews) != 1 || reviews[0].ID != 1 {
		t.Fatalf("the held deposit left the review list: %v", reviews)
	}
	if err := h.s.DecideReview(context.Background(), 1, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	// Cleared, the large deposit waits for its own final check, and its hold is lifted once that
	// passes, before it is eligible.
	h.now = h.now.Add(24*time.Hour - 64*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1"}) {
		t.Fatalf("in the large deposit's final window: %v, decisions %v", got, h.decisions())
	}
	want := []string{"first_check refer -", "first_check pass -", "recheck pass -", "hold flag 6", "attest attest -", "review cleared -", "recheck pass -", "unflag unflag 6"}
	if got := h.decisions(); !equal(got, want) {
		t.Fatalf("decisions %v", got)
	}
}

func TestALateReviewFlagIsLiftedOnceTheReviewClearsIt(t *testing.T) {
	h := newHarness(t)
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	// The final window opens with the review unfinished: the deposit is held with reason 6 so it
	// cannot be admitted unreviewed.
	h.now = h.now.Add(24*time.Hour - 9*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6"}) {
		t.Fatalf("at the review deadline: %v", got)
	}
	if reviews, _ := h.s.Reviews(context.Background()); len(reviews) != 1 || reviews[0].ID != big {
		t.Fatalf("the flagged deposit left the review list: %v", reviews)
	}
	if err := h.s.DecideReview(context.Background(), big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	// Its final check runs, the hold is lifted, and the attestation covers it on that check.
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1", "attest 1"}) {
		rows, _ := h.s.db.pending(context.Background())
		t.Fatalf("after the review cleared it: %v, decisions %v, rows %+v", got, h.decisions(), rows)
	}
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a lifted hold was lifted again: %v", got)
	}
}

func TestAReferralAtTheFinalCheckHoldsTheDepositForAPerson(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 10_000_000)
	h.funders[clean] = []string{funder}
	h.tick()
	// Before the final check, the funder is tagged unsafe: the deposit is held, not refused, until
	// a person decides.
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}, funder: {Source: "exploits", Refer: true}}, "2", h.now.Add(55*time.Minute))
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6"}) {
		t.Fatalf("a referral at the final check: %v", got)
	}
	if reviews, _ := h.s.Reviews(context.Background()); len(reviews) != 1 {
		t.Fatalf("not sent to review: %v", reviews)
	}
	// It waits for a person from the referral, not from the deposit.
	if hl := h.s.Health(); hl.ReviewQueue != 1 || hl.OldestReview != 0 {
		t.Fatalf("health %+v", hl)
	}
	if err := h.s.DecideReview(context.Background(), 1, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1", "attest 1"}) {
		t.Fatalf("after the review cleared it: %v", got)
	}
}

func TestAReviewTheReviewerRefusesReplacesTheHold(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 6_000_000_000)
	h.tick()
	h.now = h.now.Add(24*time.Hour - 9*time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6"}) {
		t.Fatalf("at the review deadline: %v", got)
	}
	heldAt := uint64(h.now.Unix())
	if err := h.s.DecideReview(context.Background(), 1, "reviewer", false); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Hour)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 5"}) {
		t.Fatalf("a refused review: %v", got)
	}
	if h.deposits[1].flaggedAt != heldAt {
		t.Fatal("the refusal moved the time of the first flag")
	}
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a refusal was acted on again: %v", got)
	}
}

func TestDeadlineWorkComesFirstAndAFailingCheckBacksOff(t *testing.T) {
	h := newHarness(t)
	h.s.cfg.TickChecks = 1
	first := h.shield(clean, 10_000_000)
	h.tick()
	// A second deposit arrives as the first one's final window opens; one check fits a round, and
	// it goes to the nearest deadline.
	h.now = h.now.Add(52 * time.Minute)
	second := h.shield(clean, 10_000_000)
	h.tick()
	got := h.decisions()
	if last := got[len(got)-1]; last != "attest attest -" || len(got) != 3 {
		t.Fatalf("decisions %v", got)
	}
	if got := h.sent(); !equal(got, []string{"attest 1"}) {
		t.Fatalf("sent %v", got)
	}
	// The second deposit's lookups fail: it is tried again only after its backoff.
	h.s.check.Inflows = funderMap{clean: nil}
	h.funders["unreachable"] = nil
	h.s.check.Inflows = unreachable{}
	h.s.cfg.TickChecks = 10
	h.tick()
	h.tick()
	if r := h.s.retries[second]; r.attempts != 1 {
		t.Fatalf("%d attempts within the backoff", r.attempts)
	}
	h.now = h.now.Add(31 * time.Second)
	h.tick()
	if r := h.s.retries[second]; r.attempts != 2 {
		t.Fatalf("%d attempts after the backoff", r.attempts)
	}
	_ = first
}

type unreachable struct{}

func (unreachable) Inflows(context.Context, string, time.Time) ([]Inflow, Gap, error) {
	return nil, 0, errors.New("horizon down")
}

func TestQueuedOperatorDecisionsAreCarriedOutByTheService(t *testing.T) {
	h := newHarness(t)
	id := h.shield(clean, 10_000_000)
	h.tick()
	if _, err := h.s.QueueFlag(context.Background(), id, ReasonFraud, "reviewer", "victim report 12"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.QueueFlag(context.Background(), id, ReasonReview, "reviewer", "not a manual reason"); err == nil {
		t.Fatal("reason 5 queued by hand")
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 4"}) {
		t.Fatalf("queued flag: %v", got)
	}
	var result string
	_ = h.s.db.pool.QueryRow(context.Background(), `SELECT result FROM operator_ops`).Scan(&result)
	if result != "done" {
		t.Fatalf("op result %q", result)
	}
	court := h.shield(clean, 10_000_000)
	h.tick()
	if err := h.s.FlagManually(context.Background(), court, ReasonCourtOrder, "reviewer", "order 7"); err != nil {
		t.Fatal(err)
	}
	if got := h.sent(); !equal(got, []string{"flag 2 100"}) {
		t.Fatalf("court order: %v", got)
	}
}

func TestOnlyOneProcessWritesAsTheASPAccount(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	lock, err := LockWriter(ctx, h.s.db.pool, "GASP")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockWriter(ctx, h.s.db.pool, "GASP"); !errors.Is(err, ErrWriterRunning) {
		t.Fatalf("a second writer: %v", err)
	}
	if other, err := LockWriter(ctx, h.s.db.pool, "GOTHER"); err != nil {
		t.Fatalf("another account: %v", err)
	} else {
		other.Release()
	}
	lock.Release()
	again, err := LockWriter(ctx, h.s.db.pool, "GASP")
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	again.Release()
}

func TestAnUnclearDestinationIsWithheldWithoutAPublicReason(t *testing.T) {
	h := newHarness(t)
	token := "relayer-token"
	api := h.s.Internal(sha256.Sum256([]byte(token)), sha256.Sum256([]byte("keeper")))
	screen := func(address string) string {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/screen", strings.NewReader(`{"address":"`+address+`"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	h.funders[clean] = []string{thief}
	if body := screen(clean); !strings.Contains(body, `"withheld"`) || strings.Contains(body, "reason") {
		t.Fatalf("a destination funded by a listed account: %s", body)
	}
	var outcome, detail string
	_ = h.s.db.pool.QueryRow(context.Background(), `SELECT outcome, detail FROM decisions WHERE kind = 'unshield'`).Scan(&outcome, &detail)
	if outcome != "withhold" || !strings.Contains(detail, thief) {
		t.Fatalf("record %q %q", outcome, detail)
	}
}

func TestPublicBudgetsAreSpentOnlyPastTheFreeChecks(t *testing.T) {
	h := newHarness(t)
	reports, checks := httpapi.NewLimiter(1, 1), httpapi.NewLimiter(1, 1)
	api := h.s.Public(reports, checks)
	post := func(body []byte) int {
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/self-report", bytes.NewReader(body)))
		return rec.Code
	}
	get := func(q string) int {
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/check?address="+q, nil))
		return rec.Code
	}
	for range 20 {
		post([]byte(`{"junk":1}`))
		forged, _ := json.Marshal(map[string]string{"address": clean, "date": h.now.UTC().Format(time.DateOnly), "signature": "AAAA"})
		post(forged)
		get("not-an-address")
	}
	kp := keypair.MustRandom()
	day := h.now.UTC().Format(time.DateOnly)
	sig, _ := kp.Sign(sep53Digest(SelfReportMessage("testnet", kp.Address(), day)))
	body, _ := json.Marshal(map[string]string{"address": kp.Address(), "date": day, "signature": encodeB64(sig)})
	if code := post(body); code != http.StatusAccepted {
		t.Fatalf("an honest report after garbage answered %d", code)
	}
	if code := get(clean); code != http.StatusOK {
		t.Fatalf("an honest check after garbage answered %d", code)
	}
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func TestALiftWaitsForAReviewOfWhatTheCheckFoundSince(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	h.now = h.now.Add(23*time.Hour + 30*time.Minute)
	h.chain.ClosedAt = h.now.Unix()
	small := h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	// The large deposit's final window opens with its review unfinished: it is held with reason 6.
	h.now = h.now.Add(21 * time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6"}) {
		t.Fatalf("at the review deadline: %v", got)
	}
	// The small deposit is attested past the held large one.
	h.now = h.now.Add(45 * time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "3", h.now)
	h.tick()
	if h.attest < small {
		t.Fatalf("attested up to %d, sent %v", h.attest, h.sent())
	}
	h.sent()
	// A funder of the large deposit's depositor is listed since, a finding the review never saw.
	h.funders[clean] = []string{funder}
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}, funder: {Source: "exploits", Reason: ReasonSanctions}}, "4", h.now)
	if err := h.s.DecideReview(ctx, big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("a new finding lifted the flag: %v", got)
	}
	reviews, err := h.s.Reviews(ctx)
	if err != nil || len(reviews) != 1 || reviews[0].ID != big {
		t.Fatalf("not back for review: %v, %v", reviews, err)
	}
	// A review that clears what was found lifts it.
	if err := h.s.DecideReview(ctx, big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1"}) {
		t.Fatalf("after the second review: %v", got)
	}
}

func TestAttestationIsWithheldWhenACoveredFinalCheckIsStale(t *testing.T) {
	h := newHarness(t)
	id := h.shield(clean, 10_000_000)
	now := uint64(h.now.Unix())
	stale, recent := now-11*60, now-60
	rows := []row{{id: id, firstCheck: "pass", recheck: "pass", recheckAt: &stale}}
	if err := h.s.chainAgrees(context.Background(), 0, id, now, rows); err == nil {
		t.Fatal("a final check older than its window vouched for an unflagged deposit")
	}
	rows[0].recheckAt = &recent
	if err := h.s.chainAgrees(context.Background(), 0, id, now, rows); err != nil {
		t.Fatal(err)
	}
}
