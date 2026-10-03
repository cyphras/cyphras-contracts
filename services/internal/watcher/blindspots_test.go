package watcher

import (
	"context"
	"errors"
	"strings"
	"testing"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

func mustB64(v xdr.ScVal) string {
	s, err := xdr.MarshalBase64(v)
	if err != nil {
		panic(err)
	}
	return s
}

func TestTwoGovernanceEventsInOneLedgerAreBothReported(t *testing.T) {
	h := newHarness(t)
	c := h.chain
	ready := vault.U64(uint64(c.ClosedAt + 7*86400))
	c.Governance("limits_queued", vault.Field{Name: "limits", Value: vaulttest.Limits(1_000, 500)}, vault.Field{Name: "ready_at", Value: ready})
	c.Governance("limits_queued", vault.Field{Name: "limits", Value: vaulttest.Limits(777_777_777, 500)}, vault.Field{Name: "ready_at", Value: ready})
	c.NextLedger(5)
	h.sync()
	operator, public, second := 0, 0, false
	for _, a := range h.pages.alerts {
		if strings.HasPrefix(a.Code, "governance_limits_queued") {
			operator++
			second = second || strings.Contains(a.Message, "777777777")
		}
	}
	for _, a := range h.public.alerts {
		if strings.HasPrefix(a.Code, "governance_limits_queued") {
			public++
		}
	}
	if operator != 2 || public != 2 || !second {
		t.Fatalf("operator %d, public %d, second seen %v", operator, public, second)
	}
}

func TestAFollowerFaultPages(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.publish()
	bad := vault.RawEvent{Ledger: h.chain.Ledger, ClosedAt: h.chain.ClosedAt, TxHash: strings.Repeat("ab", 32), Tx: 1, Contract: vaulttest.Vault,
		Topics: []string{mustB64(vault.Symbol("not_a_vault_event"))}, Value: mustB64(vault.Struct(vault.Field{Name: "x", Value: vault.U64(1)}))}
	h.primary.AddEvent(rpctest.EventInfo(bad))
	h.chain.NextLedger(5)
	h.primary.SetLatest(h.chain.Ledger)
	var err error
	for range 10 {
		var progressed bool
		if progressed, err = h.f.Step(context.Background()); err != nil {
			h.w.Fault(context.Background(), err)
			break
		}
		if !progressed {
			break
		}
	}
	if !errors.Is(err, follow.ErrFault) || !h.pages.has("ingest_fault") {
		t.Fatalf("fault %v, pages %v", err, h.pages.codes())
	}
	for _, a := range h.pages.alerts {
		if a.Code == "ingest_fault" && a.Severity != alert.Critical {
			t.Fatalf("an ingest fault paged as %s", a.Severity)
		}
	}
	beats := 0
	h.w.SetHeartbeat(func(context.Context) error { beats++; return nil })
	if err := h.w.reconcileAndBeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if beats != 0 {
		t.Fatal("a faulted watcher reported itself healthy")
	}
}

func TestAHealthyReconciliationBeatsTheHeartbeat(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	beats := 0
	h.w.SetHeartbeat(func(context.Context) error { beats++; return nil })
	if err := h.w.reconcileAndBeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.primary.Fail["getLedgerEntries"] = errors.New("down")
	_ = h.w.reconcileAndBeat(context.Background())
	if beats != 1 {
		t.Fatalf("%d beats", beats)
	}
}

// racing changes the chain between two entry reads of one reconciliation.
type racing struct {
	*rpctest.Fake
	calls   int
	between func()
}

func (r *racing) GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error) {
	resp, err := r.Fake.GetLedgerEntries(ctx, req)
	r.calls++
	if r.calls == 1 && r.between != nil {
		r.between()
	}
	return resp, err
}

func TestAPaymentBetweenTwoReadsRaisesNoFalseAlarm(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	c := h.chain
	h.w.rpc = &racing{Fake: h.primary, between: func() {
		c.NextLedger(5)
		c.Transact(-1_000_000, 0, vaulttest.Relayer)
		c.Transfer(vaulttest.Relayer, 1_000_000)
		c.NextLedger(5)
		h.publish()
	}}
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if progressed, err := h.f.Step(context.Background()); err != nil || !progressed {
			break
		}
	}
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.pages.has("balance_below_tvl") || h.pages.has("state_mismatch") {
		t.Fatalf("a false alarm: %v", h.pages.codes())
	}
}

func TestASecondRPCFailingOneMethodPages(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	h.second.Fail["getEvents"] = errors.New("method not allowed")
	h.chain.NextLedger(5)
	h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.publish()
	for range 10 {
		if progressed, err := h.f.Step(context.Background()); err != nil || !progressed {
			break
		}
	}
	for range 5 {
		if err := h.w.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !h.pages.has("rpc_failing_second_getEvents") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestAPrimaryFarBehindTheSecondPages(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	h.second.SetLatest(h.chain.Ledger + 10_000)
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("primary_rpc_lagging") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestProvidersAtTheSameLedgerMustAgree(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	// The primary shows the tree as it was some ledgers ago, at the second's latest ledger.
	key := mustKey(vault.NextLeafKey(vaulttest.Vault))
	h.primary.SetContractData(key, vault.U64(2), h.chain.Ledger-2, nil)
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("rpc_disagreement") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestAMissingHotAccountPagesAndTheOthersAreStillChecked(t *testing.T) {
	const (
		gone = "GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO"
		low  = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
	)
	h := newHarness(t, func(c *Config) {
		c.HotAccounts = []HotAccount{{Name: "channel-1", Address: gone, Floor: 100}, {Name: "keeper", Address: low, Floor: 100}}
	})
	key := mustKey(vault.AccountKey(low))
	h.primary.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, Balance: 50}}, 1, nil)
	if err := h.w.CheckHotAccounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("hot_account_missing_"+gone) || !h.pages.has("hot_balance_low_"+low) {
		t.Fatalf("pages %v", h.pages.codes())
	}
	for _, a := range h.pages.alerts {
		if a.Code == "hot_account_missing_"+gone && a.Severity != "critical" {
			t.Fatalf("severity %s", a.Severity)
		}
	}
}

// failingPending fails reads of a deposit's pending entry, as an RPC that is down would.
type failingPending struct {
	*rpctest.Fake
	key  string
	fail bool
}

func (f *failingPending) GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error) {
	for _, k := range req.Keys {
		if f.fail && k == f.key {
			return protocol.GetLedgerEntriesResponse{}, errors.New("rpc down")
		}
	}
	return f.Fake.GetLedgerEntries(ctx, req)
}

func TestAnAttestationCheckOutlivesAFailedReadAndARestart(t *testing.T) {
	h := newHarness(t)
	id := h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.sync()
	key := mustKey(vault.PendingKey(vaulttest.Vault, id))
	keyString := mustKeyString(key)
	failing := &failingPending{Fake: h.primary, key: keyString, fail: true}
	h.w.rpc = failing
	// Attested a minute after the deposit, while the deposit's entry cannot be read.
	h.chain.NextLedger(60)
	h.chain.Attest(id)
	h.chain.NextLedger(5)
	h.sync()
	if h.pages.has("early_attestation") {
		t.Fatal("judged without the delay")
	}
	checks, err := h.w.db.attestChecks(context.Background())
	if err != nil || len(checks) != 1 {
		t.Fatalf("pending checks %v %v", checks, err)
	}
	// After a restart, with the RPC back, the retry judges it.
	again, err := New(context.Background(), h.w.cfg, h.primary, h.second, h.w.chain, nil, h.w.alerts, h.w.public, h.w.log)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.primary.SetContractData(key, vaulttest.Pending(id, vaulttest.Depositor, 10_000_000, uint64(h.chain.ClosedAt-70), 3600, nil, 0), h.chain.Ledger, nil)
	if err := again.RetryAttestations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("early_attestation_1") {
		t.Fatalf("pages %v", h.pages.codes())
	}
	if checks, _ := again.db.attestChecks(context.Background()); len(checks) != 0 {
		t.Fatalf("a judged check stayed: %v", checks)
	}
}

func TestAnUnflagSharingItsAttestationsLedgerOutlivesAFailedRead(t *testing.T) {
	h := newHarness(t)
	c := h.chain
	large := c.Shield(vaulttest.Depositor, 6_000_000_000)
	c.NextLedger(5)
	h.sync()
	created := uint64(c.ClosedAt - 5)
	key := mustKey(vault.PendingKey(vaulttest.Vault, large))
	h.primary.SetContractData(key, vaulttest.Pending(large, vaulttest.Depositor, 6_000_000_000, created, 86400, nil, 0), c.Ledger, nil)
	failing := &failingPending{Fake: h.primary, key: mustKeyString(key), fail: true}
	h.w.rpc = failing
	// Flagged, attested past and unflagged in one ledger, a day early, while the deposit's entry
	// cannot be read: the attestation itself covers nothing and is judged at once.
	c.NextLedger(120)
	c.Flag(large, 6)
	c.Attest(large)
	c.Unflag(large, 6)
	c.NextLedger(5)
	h.sync()
	if h.pages.has("early_attestation") {
		t.Fatal("judged without the delay")
	}
	failing.fail = false
	if err := h.w.RetryAttestations(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("early_attestation_1") {
		t.Fatalf("pages %v", h.pages.codes())
	}
	if checks, _ := h.w.db.attestChecks(context.Background()); len(checks) != 0 {
		t.Fatalf("a judged check stayed: %v", checks)
	}
}

func TestALargerSpikeWithinTheCooldownStillPages(t *testing.T) {
	h := newHarness(t)
	h.limit = 100_000_000
	c := h.chain
	c.Shield(vaulttest.Depositor, 90_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	pay := func(n int) {
		for range n {
			c.NextLedger(5)
			c.Transact(-7_000_000, 0, vaulttest.Relayer)
			c.Transfer(vaulttest.Relayer, 7_000_000)
		}
		h.sync()
	}
	// 21 of a window of 100 within an hour is a spike; 42 is twice as far past the bound.
	pay(3)
	pay(3)
	if !h.pages.has("outflow_spike_x1") || !h.pages.has("outflow_spike_x2") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestTwoFlagsInOneLedgerAreBothReported(t *testing.T) {
	h := newHarness(t)
	c := h.chain
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.NextLedger(5)
	c.Flag(1, 4)
	c.Flag(2, 4)
	c.NextLedger(5)
	h.sync()
	flags := 0
	for _, a := range h.pages.alerts {
		if strings.HasPrefix(a.Code, "deposit_flagged") {
			flags++
		}
	}
	if flags != 2 {
		t.Fatalf("%d flags reported: %v", flags, h.pages.codes())
	}
}

func TestAPaymentToTheAssetsIssuerIsNoMismatch(t *testing.T) {
	const issuer = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
	h := newHarness(t)
	c := h.chain
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	c.Transact(-4_000_000, 100_000, issuer)
	// The asset contract reports a payment to its issuer as a burn.
	c.Burn("USDC:"+issuer, 4_000_000)
	c.Transfer(vaulttest.Relayer, 100_000)
	c.NextLedger(5)
	h.sync()
	if h.pages.has("outflow_mismatch") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestAnAttestationIsJudgedForEveryDepositItCovers(t *testing.T) {
	for _, held := range []bool{false, true} {
		h := newHarness(t)
		c := h.chain
		large := c.Shield(vaulttest.Depositor, 6_000_000_000)
		small := c.Shield(vaulttest.Depositor, 10_000_000)
		c.NextLedger(5)
		h.sync()
		created := uint64(c.ClosedAt - 5)
		h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, large)), vaulttest.Pending(large, vaulttest.Depositor, 6_000_000_000, created, 86400, nil, 0), c.Ledger, nil)
		h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, small)), vaulttest.Pending(small, vaulttest.Depositor, 10_000_000, created, 3600, nil, 0), c.Ledger, nil)
		// Inside the small deposit's final ten minutes, 23 hours before the large one's: the
		// attestation vouches for the large one too, unless it is held.
		c.NextLedger(3600 - 5*60)
		if held {
			c.Flag(large, 6)
		}
		c.Attest(small)
		c.NextLedger(5)
		h.sync()
		if got := h.pages.has("early_attestation_1"); got == held || h.pages.has("early_attestation_2") {
			t.Fatalf("held %v: pages %v", held, h.pages.codes())
		}
	}
}

func TestAStalledPrimaryStopsTheHeartbeat(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.activity()
	h.sync()
	h.second.Fail["getLedgerEntries"] = errors.New("down")
	h.second.Fail["getHealth"] = errors.New("down")
	beats := 0
	h.w.SetHeartbeat(func(context.Context) error { beats++; return nil })
	if err := h.w.reconcileAndBeat(ctx); err != nil || beats != 1 {
		t.Fatalf("a fresh primary: %d beats, %v", beats, err)
	}
	// The primary stops at its last ledger while time goes on.
	h.chain.NextLedger(3 * 60)
	for range 5 {
		if err := h.w.reconcileAndBeat(ctx); err != nil {
			t.Fatal(err)
		}
	}
	critical := false
	for _, a := range h.pages.alerts {
		critical = critical || (a.Code == "rpc_stale" && a.Severity == alert.Critical)
	}
	if beats != 1 || !critical {
		t.Fatalf("a stalled primary: %d beats, pages %v", beats, h.pages.codes())
	}
}

// refusing refuses every alert, as a webhook that is down does.
type refusing struct{}

func (refusing) Send(context.Context, alert.Alert) error { return errors.New("webhook down") }

func TestAnAlertChannelThatRefusesEverythingStopsTheHeartbeat(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.activity()
	h.sync()
	q := &alert.Queue{Name: "operator", Channels: []alert.Channel{refusing{}}, Now: h.w.now}
	h.w.alerts.Queue = q
	beats := 0
	h.w.SetHeartbeat(func(context.Context) error { beats++; return nil })
	h.w.alerts.Raise(ctx, alert.Critical, "balance_below_tvl", "test")
	q.Flush(ctx)
	if err := h.w.reconcileAndBeat(ctx); err != nil || beats != 1 {
		t.Fatalf("a channel failing for a moment: %d beats, %v", beats, err)
	}
	h.chain.NextLedger(11 * 60)
	h.sync()
	q.Flush(ctx)
	if err := h.w.reconcileAndBeat(ctx); err != nil || beats != 1 {
		t.Fatalf("a channel failing for 11 minutes: %d beats, %v", beats, err)
	}
}

func TestADepositNotAttestedPastItsEligibilityPages(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	id := h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.sync()
	h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10_000_000, uint64(h.chain.ClosedAt-5), 3600, nil, 0), h.chain.Ledger, nil)
	h.primary.CloseTime = h.chain.ClosedAt + 3600 + 11*60
	if err := h.w.CheckAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("attestation_late") || h.pages.has("admission_late") {
		t.Fatalf("pages %v", h.pages.codes())
	}
	// A flagged deposit waits for nothing.
	h.chain.NextLedger(5)
	h.chain.Flag(id, 6)
	h.chain.NextLedger(5)
	h.sync()
	h.primary.CloseTime = h.chain.ClosedAt + 3600 + 11*60
	if err := h.w.CheckAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	resolved := false
	for _, a := range h.pages.alerts {
		resolved = resolved || a.Code == "attestation_late_resolved"
	}
	if !resolved {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestAnUnflagInsideTheAttestedRangeIsJudgedAsAnAttestation(t *testing.T) {
	for _, early := range []bool{true, false} {
		h := newHarness(t)
		c := h.chain
		large := c.Shield(vaulttest.Depositor, 6_000_000_000)
		c.NextLedger(5)
		h.sync()
		created := uint64(c.ClosedAt - 5)
		h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, large)), vaulttest.Pending(large, vaulttest.Depositor, 6_000_000_000, created, 86400, nil, 0), c.Ledger, nil)
		// A stolen asp key flags the deposit, attests past it and unflags it, all a day early. A
		// hold lifted in the deposit's own final window is what the screening service does.
		c.NextLedger(120)
		c.Flag(large, 6)
		c.Attest(large)
		if !early {
			c.NextLedger(86400 - 120 - 5*60)
		}
		c.Unflag(large, 6)
		c.NextLedger(5)
		h.sync()
		if got := h.pages.has("early_attestation_1"); got != early {
			t.Fatalf("early %v: pages %v", early, h.pages.codes())
		}
	}
}

// largeDeposits makes n large deposits in one ledger, with the entries the vault keeps for them.
func (h *harness) largeDeposits(n int) []uint64 {
	h.t.Helper()
	c := h.chain
	var ids []uint64
	for range n {
		ids = append(ids, c.Shield(vaulttest.Depositor, 6_000_000_000))
	}
	c.NextLedger(5)
	h.sync()
	created := uint64(c.ClosedAt - 5)
	for _, id := range ids {
		h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 6_000_000_000, created, 86400, nil, 0), c.Ledger, nil)
	}
	return ids
}

func (h *harness) waitingChecks() int {
	h.t.Helper()
	checks, err := h.w.db.attestChecks(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	return len(checks)
}

func TestEveryEarlyUnflagOfALedgerIsJudged(t *testing.T) {
	for name, play := range map[string]func(h *harness, x, y uint64){
		// Two unflags under an attestation that covers neither, in one ledger.
		"two unflags": func(h *harness, x, y uint64) {
			h.chain.Flag(x, 6)
			h.chain.Flag(y, 6)
			h.chain.Attest(y)
			h.chain.Unflag(x, 6)
			h.chain.Unflag(y, 6)
		},
		// Flagged again and unflagged again in the ledger of the first unflag.
		"an unflag, a flag and an unflag": func(h *harness, x, y uint64) {
			h.chain.Flag(x, 6)
			h.chain.Flag(y, 6)
			h.chain.Attest(y)
			h.chain.NextLedger(60)
			h.chain.Unflag(x, 6)
			h.chain.Flag(x, 7)
			h.chain.Unflag(x, 7)
			h.chain.Unflag(y, 6)
		},
	} {
		for _, readFails := range []bool{false, true} {
			h := newHarness(t)
			ids := h.largeDeposits(2)
			x, y := ids[0], ids[1]
			failing := &failingPending{Fake: h.primary, key: mustKeyString(mustKey(vault.PendingKey(vaulttest.Vault, x))), fail: readFails}
			h.w.rpc = failing
			h.chain.NextLedger(120)
			play(h, x, y)
			h.chain.NextLedger(5)
			h.sync()
			failing.fail = false
			if err := h.w.RetryAttestations(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !h.pages.has("early_attestation_1") || !h.pages.has("early_attestation_2") || h.waitingChecks() != 0 {
				t.Fatalf("%s, read failing %v: pages %v, %d checks wait", name, readFails, h.pages.codes(), h.waitingChecks())
			}
		}
	}
}

func TestAnUnflagInTheTransactionOfItsAttestationIsJudged(t *testing.T) {
	h := newHarness(t)
	x := h.largeDeposits(1)[0]
	h.chain.NextLedger(120)
	h.chain.Tx().
		Emit("deposit_flagged", vault.Field{Name: "id", Value: vault.U64(x)}, vault.Field{Name: "reason", Value: vault.U32(6)}).
		Emit("attested", vault.Field{Name: "up_to", Value: vault.U64(x)}).
		Emit("deposit_unflagged", vault.Field{Name: "id", Value: vault.U64(x)}, vault.Field{Name: "reason", Value: vault.U32(6)})
	h.chain.NextLedger(5)
	h.sync()
	if !h.pages.has("early_attestation_1") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestAnUnflagWaitingForItsJudgmentOutlivesARestart(t *testing.T) {
	h := newHarness(t)
	ids := h.largeDeposits(2)
	x, y := ids[0], ids[1]
	h.w.rpc = &failingPending{Fake: h.primary, key: mustKeyString(mustKey(vault.PendingKey(vaulttest.Vault, x))), fail: true}
	h.chain.NextLedger(120)
	h.chain.Flag(x, 6)
	h.chain.Attest(y)
	h.chain.Unflag(x, 6)
	h.chain.NextLedger(5)
	h.sync()
	pages := &recorder{}
	alerts := &alert.Alerter{Service: "watcher", Channels: []alert.Channel{pages}}
	again, err := New(context.Background(), h.w.cfg, h.primary, h.second, h.w.chain, nil, alerts, h.w.public, h.w.log)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := again.RetryAttestations(context.Background()); err != nil {
		t.Fatal(err)
	}
	checks, _ := again.db.attestChecks(context.Background())
	if !pages.has("early_attestation_1") || len(checks) != 0 {
		t.Fatalf("after a restart: pages %v, %d checks wait", pages.codes(), len(checks))
	}
}
