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
	if got := attestCandidate(rows, 0, at, 600); got != 0 {
		t.Fatalf("attest(%d) would cover a deposit still under review", got)
	}
}

func TestADepositUnderReviewHoldsBackLaterOnes(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 6_000_000_000)
	h.shield(clean, 10_000_000)
	h.tick()
	// The small deposit passes its final check, but the large one before it is still under review.
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("attested past a deposit under review: %v", got)
	}
	if err := h.s.DecideReview(context.Background(), 1, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	// Cleared, the large deposit still waits for its own final check; the small one's check is
	// done again then, since the one from a day before no longer vouches for it.
	h.now = h.now.Add(24*time.Hour - 64*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"attest 2"}) {
		t.Fatalf("in the large deposit's final window: %v, decisions %v", got, h.decisions())
	}
	got := h.decisions()
	rechecks := 0
	for _, d := range got {
		if strings.HasPrefix(d, "recheck pass") {
			rechecks++
		}
	}
	if rechecks != 3 {
		t.Fatalf("decisions %v", got)
	}
}

func TestALateReviewFlagIsLiftedOnceTheReviewClearsIt(t *testing.T) {
	h := newHarness(t)
	big := h.shield(clean, 6_000_000_000)
	h.tick()
	// The final window opens with the review unfinished: the deposit is flagged with reason 5 so it
	// cannot be admitted unreviewed.
	h.now = h.now.Add(24*time.Hour - 9*time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 5"}) {
		t.Fatalf("at the review deadline: %v", got)
	}
	if reviews, _ := h.s.Reviews(context.Background()); len(reviews) != 1 || reviews[0].ID != big {
		t.Fatalf("the flagged deposit left the review list: %v", reviews)
	}
	if err := h.s.DecideReview(context.Background(), big, "reviewer", true); err != nil {
		t.Fatal(err)
	}
	h.tick()
	if got := h.sent(); !equal(got, []string{"unflag 1"}) {
		rows, _ := h.s.db.pending(context.Background())
		t.Fatalf("after the review cleared it: %v, decisions %v, rows %+v", got, h.decisions(), rows)
	}
	// Unflagged, it is checked again before an attestation covers it.
	h.tick()
	if got := h.sent(); !equal(got, []string{"attest 1"}) {
		t.Fatalf("after its final check: %v", got)
	}
}

func TestAReferralAtTheFinalCheckIsReasonFive(t *testing.T) {
	h := newHarness(t)
	h.shield(clean, 10_000_000)
	h.funders[clean] = []string{funder}
	h.tick()
	// Before the final check, the funder is tagged unsafe: no review fits in the time left.
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}, funder: {Source: "exploits", Refer: true}}, "2", h.now.Add(55*time.Minute))
	h.now = h.now.Add(55 * time.Minute)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 5"}) {
		t.Fatalf("a referral at the final check: %v", got)
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

func (unreachable) Inflows(context.Context, string, time.Time) ([]Inflow, bool, error) {
	return nil, false, errors.New("horizon down")
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
	release, err := LockWriter(ctx, h.s.db.pool, "GASP")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockWriter(ctx, h.s.db.pool, "GASP"); !errors.Is(err, ErrWriterRunning) {
		t.Fatalf("a second writer: %v", err)
	}
	if other, err := LockWriter(ctx, h.s.db.pool, "GOTHER"); err != nil {
		t.Fatalf("another account: %v", err)
	} else {
		other()
	}
	release()
	again, err := LockWriter(ctx, h.s.db.pool, "GASP")
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	again()
}

func TestAnUnclearDestinationIsWithheldWithoutAPublicReason(t *testing.T) {
	h := newHarness(t)
	token := "relayer-token"
	api := h.s.Internal(sha256.Sum256([]byte(token)))
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
