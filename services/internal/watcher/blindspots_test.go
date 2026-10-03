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
