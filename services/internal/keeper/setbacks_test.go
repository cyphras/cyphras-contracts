package keeper

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

func (h *harness) has(code string) bool {
	for _, a := range h.pages {
		if a.Code == code {
			return true
		}
	}
	return false
}

// claims takes what was sent and keeps the claims of one exit.
func (h *harness) claims(id uint64) int {
	n := 0
	for _, d := range h.take() {
		if d == fmt.Sprintf("claim %d", id) {
			n++
		}
	}
	return n
}

// at moves the clock, and the chain's with it.
func (h *harness) at(t time.Time) {
	h.now = t
	if gap := t.Unix() - h.chain.ClosedAt; gap > 0 {
		h.chain.NextLedger(gap)
	}
	h.sync()
}

func TestAReleaseThatHandlesNoExitWaitsForANewDayOrNewRoom(t *testing.T) {
	h := newHarness(t)
	h.limit, h.partial = 100_000_000, true
	h.status.ExitHead, h.status.ExitTail = 1, 1
	// A 2 XLM payout to an account that does not exist yet, with 0.5 XLM of today's window left.
	h.queueExits(20_000_000)
	h.creates = map[uint64]bool{1: true}
	h.status.OutflowDay, h.status.Outflow = uint64(h.now.Unix())/secondsPerDay, big.NewInt(95_000_000)
	h.sentHook = func(d string) {
		var n uint64
		if _, err := fmt.Sscanf(d, "release %d", &n); err == nil {
			h.release(n)
		}
	}
	h.sync()
	release := func(times int) {
		for range times {
			if err := h.k.Release(context.Background()); err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(30 * time.Second)
			h.fake.CloseTime = h.now.Unix()
		}
	}
	simulations := func() int { return h.fake.CallCount("simulateTransaction") }
	release(3)
	if got := h.take(); len(got) != 0 || simulations() != 1 {
		t.Fatalf("sent %v after %d simulations", got, simulations())
	}
	// More room, still less than 1 XLM: one more try, and again nothing.
	h.limit = 104_000_000
	h.setInstance()
	release(3)
	if got := h.take(); len(got) != 0 || simulations() != 2 {
		t.Fatalf("sent %v after %d simulations", got, simulations())
	}
	// The next day's window pays the payout whole.
	h.now = h.now.Add(24 * time.Hour)
	h.sync()
	release(1)
	if got := h.take(); !equal(got, []string{"release 1"}) || h.status.ExitHead != 2 {
		t.Fatalf("on the next day: %v, head %d", got, h.status.ExitHead)
	}
}

// strand queues an exit, strands it and publishes its stranded entry.
func (h *harness) strand(id uint64, payout int64, recipient string) vaulttest.Exit {
	e := h.chain.QueueExit(id, -payout, 0, recipient)
	h.chain.NextLedger(5)
	h.chain.Strand(e, payout, 0)
	h.chain.NextLedger(5)
	h.storeStranded(id, payout, recipient)
	return e
}

func (h *harness) storeStranded(id uint64, payout int64, recipient string) {
	h.fake.SetContractData(mustKey(vault.StrandedKey(vaulttest.Vault, id)), vaulttest.ExitEntry(recipient, payout, 0, 1), h.chain.Ledger, h.live(500_000))
}

func TestClaimsThatCreateAnAccountWaitWhileTheBaseReserveIsHigh(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 50_000_000)
	h.chain.Attest(1)
	h.chain.Admit(1)
	// Exit 1 pays 2 XLM to an account that does not exist; exit 2 pays too little to create one.
	h.strand(1, 20_000_000, vaulttest.Depositor)
	h.strand(2, 300, vaulttest.Relayer)
	h.status.ExitHead, h.status.ExitTail = 3, 3
	h.sync()
	h.fake.BaseReserve = 6_000_000
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"claim 2"}) || !h.has("creating_claims_wait") {
		t.Fatalf("with a base reserve of 0.6 XLM: %v, pages %+v", got, h.pages)
	}
	// Nor is it claimed while the reserve cannot be read.
	h.fake.Fail["getLatestLedger"] = errors.New("down")
	h.at(h.now.Add(2 * time.Hour))
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.claims(1); n != 0 {
		t.Fatal("claimed without knowing the base reserve")
	}
	delete(h.fake.Fail, "getLatestLedger")
	h.fake.BaseReserve = 5_000_000
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := h.claims(1); n != 1 || !h.has("creating_claims_wait_resolved") {
		t.Fatalf("at 0.5 XLM: %d claims, pages %+v", n, h.pages)
	}
}

func TestAnExitThatStrandsAgainRestsLongerEachTime(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 50_000)
	h.chain.Attest(1)
	h.chain.Admit(1)
	first := h.strand(1, 400, vaulttest.Depositor)
	second := h.chain.Requeue(first, 2, 400, 0)
	h.chain.NextLedger(5)
	h.chain.Strand(second, 400, 0)
	h.chain.NextLedger(5)
	h.storeStranded(2, 400, vaulttest.Depositor)
	h.status.ExitHead, h.status.ExitTail = 3, 3
	stranded := time.Unix(h.chain.ClosedAt, 0)
	h.at(stranded)
	claim := func(at time.Duration) int {
		h.at(stranded.Add(at))
		if err := h.k.Claims(context.Background()); err != nil {
			t.Fatal(err)
		}
		return h.claims(2)
	}
	// Stranded a second time, it rests an hour.
	if claim(0) != 0 || claim(59*time.Minute) != 0 || claim(61*time.Minute) != 1 {
		t.Fatal("claimed within the first rest")
	}
	// Stranded a third time, two hours.
	h.chain.NextLedger(5)
	third := h.chain.Requeue(second, 3, 400, 0)
	h.chain.NextLedger(5)
	h.chain.Strand(third, 400, 0)
	h.chain.NextLedger(5)
	h.storeStranded(3, 400, vaulttest.Depositor)
	h.status.ExitHead, h.status.ExitTail = 4, 4
	stranded = time.Unix(h.chain.ClosedAt, 0)
	h.at(stranded)
	claim3 := func(at time.Duration) int {
		h.at(stranded.Add(at))
		if err := h.k.Claims(context.Background()); err != nil {
			t.Fatal(err)
		}
		return h.claims(3)
	}
	if claim3(0) != 0 || claim3(119*time.Minute) != 0 || claim3(121*time.Minute) != 1 {
		t.Fatal("claimed within the second rest")
	}
	if rest(1) != time.Hour || rest(3) != 4*time.Hour || rest(6) != 24*time.Hour || rest(60) != 24*time.Hour {
		t.Fatalf("rests %s %s %s %s", rest(1), rest(3), rest(6), rest(60))
	}
}

func TestAClaimThatFailsOnChainRestsItsExitAndTheOthersGoAhead(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.chain.Attest(1)
	h.chain.Admit(1)
	h.strand(1, 400, vaulttest.Depositor)
	h.strand(2, 300, vaulttest.Relayer)
	h.status.ExitHead, h.status.ExitTail = 3, 3
	h.sync()
	h.chainFail = func(d string) bool { return d == "claim 1" }
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"claim 1", "claim 2"}) || !h.has("claim_failed") || h.has("call_failed") {
		t.Fatalf("sent %v, pages %+v", got, h.pages)
	}
	// The depositor's account changes, but exit 1 rests an hour after its failure.
	key := mustKey(vault.AccountKey(vaulttest.Depositor))
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, SeqNum: 1, Balance: 10_000_000}}, h.chain.Ledger, nil)
	start := h.now
	try := func(at time.Duration) int {
		h.at(start.Add(at))
		if err := h.k.Claims(context.Background()); err != nil {
			t.Fatal(err)
		}
		return h.claims(1)
	}
	if try(time.Minute) != 0 || try(61*time.Minute) != 1 {
		t.Fatal("not rested an hour")
	}
	// It fails again and rests two hours.
	if try(3*time.Hour) != 0 || try(3*time.Hour+2*time.Minute) != 1 {
		t.Fatal("not rested two hours")
	}
}

func TestAnAdmitThatWouldAdmitNothingIsNotSent(t *testing.T) {
	h := newHarness(t)
	h.shield(10, nil, 0)
	h.shield(10, nil, 0)
	h.status.AttestedUpTo = 2
	h.now = h.now.Add(time.Hour + time.Minute)
	h.sync()
	// Both deposits leave the queue between the keeper's read and its simulation.
	h.skipped = map[uint64]bool{1: true, 2: true}
	if err := h.k.Admit(context.Background()); err != nil || len(h.take()) != 0 || len(h.pages) != 0 {
		t.Fatalf("an admit of nothing: %v, pages %+v", err, h.pages)
	}
	h.skipped = map[uint64]bool{1: true}
	if err := h.k.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"admit [1,2]"}) {
		t.Fatalf("admissions %v", got)
	}
}

func TestARefundThatLosesARaceWithACancellationDoesNotPage(t *testing.T) {
	h := newHarness(t)
	four := uint32(4)
	flaggedAt := uint64(h.now.Unix())
	h.shield(10, &four, flaggedAt)
	h.shield(10, &four, flaggedAt)
	h.now = h.now.Add(25 * time.Hour)
	h.sync()
	// The depositor of 1 cancels while its refund is on the way; the refund of 2 fails for another
	// reason.
	h.chainFail = func(d string) bool { return d == "refund 1" || d == "refund 2" }
	h.sentHook = func(d string) {
		if d == "refund 1" {
			h.fake.DeleteEntry(mustKey(vault.PendingKey(vaulttest.Vault, 1)))
		}
	}
	if err := h.k.Refund(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"refund 1", "refund 2"}) {
		t.Fatalf("refunds %v", got)
	}
	if len(h.pages) != 1 || h.pages[0].Code != "call_failed" || !strings.Contains(h.pages[0].Message, "deposit 2") {
		t.Fatalf("pages %+v", h.pages)
	}
}
