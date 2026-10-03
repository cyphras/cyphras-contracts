package screening

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

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
	api := h.s.Internal(sha256.Sum256([]byte("token")))
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
	// Within a day of eligibility, it is held.
	h.now = h.now.Add(2*24*time.Hour + time.Minute)
	h.sources.set(map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}}, "2", h.now)
	h.tick()
	if got := h.sent(); !equal(got, []string{"flag 1 6", "attest 2"}) {
		t.Fatalf("a day before eligibility: %v", got)
	}
}

func TestADepositInItsFinalWindowIsNeverHeldPastAnother(t *testing.T) {
	h := newHarness(t)
	first := h.shield(clean, 10_000_000)
	h.tick()
	h.now = h.now.Add(2 * time.Minute)
	h.chain.ClosedAt = h.now.Unix()
	h.shield(keypair.MustRandom().Address(), 10_000_000)
	h.tick()
	// The first deposit's final check fails while the second one's passes: the first one ends the
	// run, since its own window is open and a hold would only stand for a check that is due.
	h.now = h.now.Add(56 * time.Minute)
	h.s.check.Inflows = failing{clean}
	h.tick()
	if got := h.sent(); len(got) != 0 {
		t.Fatalf("held a deposit whose final check is due: %v", got)
	}
	if r := h.s.retries[first]; r.attempts == 0 {
		t.Fatal("the first deposit was not checked")
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
