package watcher

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const passphrase = "Test SDF Network ; September 2015"

type recorder struct {
	mu     sync.Mutex
	alerts []alert.Alert
}

func (r *recorder) Send(_ context.Context, a alert.Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.alerts = append(r.alerts, a)
	return nil
}

// codes lists the codes raised, with any per-event suffix kept.
func (r *recorder) codes() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, a := range r.alerts {
		if !strings.HasSuffix(a.Code, "_resolved") {
			out = append(out, a.Code)
		}
	}
	return out
}

func (r *recorder) has(prefix string) bool {
	for _, c := range r.codes() {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

type harness struct {
	t       *testing.T
	primary *rpctest.Fake
	second  *rpctest.Fake
	chain   *vaulttest.Chain
	w       *Watcher
	f       *follow.Follower
	pages   *recorder
	public  *recorder
	limit   int64
	// tamper changes what the primary RPC reports after the honest state is computed.
	tamper func(*vault.Status, *big.Int)
	// deauthorized makes the issuer refuse to let the vault hold the asset.
	deauthorized bool
}

func newHarness(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	h := &harness{
		t: t, primary: rpctest.New(passphrase, 9), second: rpctest.New(passphrase, 9),
		chain: vaulttest.New(10, 1_728_000_000), pages: &recorder{}, public: &recorder{}, limit: 1_000_000_000_000,
	}
	pool, err := chainstate.Open(context.Background(), testdb.URL(t), Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	cfg := Config{
		Vault: vaulttest.Vault, DeployLedger: 10, BurstMultiple: 5, BurstFloor: 3, QueueLength: 3, QueueAge: 48 * time.Hour,
		RoundTrips: 2, IgnoreFunders: map[string]bool{}, EarlyWindow: 2 * time.Hour, EarlyShare: 80,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	alerts := &alert.Alerter{Service: "watcher", Channels: []alert.Channel{h.pages}, Cooldown: time.Hour}
	public := &alert.Alerter{Service: "watcher", Channels: []alert.Channel{h.public}, Cooldown: time.Hour}
	w, err := New(context.Background(), cfg, h.primary, h.second, &chainstate.Store{Pool: pool}, nil, alerts, public, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h.w = w
	h.f = &follow.Follower{RPC: h.primary, Live: follow.RPCSource{Client: h.primary, Contract: vaulttest.Vault, PageLimit: 50}, Window: 100, Sink: w}
	return h
}

func mustKey[T any](k T, err error) T {
	if err != nil {
		panic(err)
	}
	return k
}

// honest replays the chain's vault events the way the vault applied them.
func (h *harness) honest() *chainstate.State {
	h.t.Helper()
	var events []vault.Event
	for _, raw := range h.chain.Events {
		if raw.Contract != vaulttest.Vault {
			continue
		}
		e, err := vault.Decode(raw)
		if err != nil {
			h.t.Fatal(err)
		}
		events = append(events, e)
	}
	txs, err := vault.ParseTxs(events)
	if err != nil {
		h.t.Fatal(err)
	}
	s := chainstate.New()
	if _, err := s.Apply(txs); err != nil {
		h.t.Fatal(err)
	}
	return s
}

// publish puts the chain into both RPCs with the entries an honest vault would hold.
func (h *harness) publish() {
	h.t.Helper()
	s := h.honest()
	status := vault.Status{
		DepositsPaused: s.DepositsPaused, TransfersPaused: s.TransfersPaused, HaltedUntil: s.HaltedUntil, NextHaltAt: s.NextHaltAt,
		NextDepositID: s.NextDepositID, AttestedUpTo: s.AttestedUpTo, Tvl: s.Tvl, PendingTotal: s.PendingTotal,
		QueuedTotal: s.QueuedTotal, ExitHead: s.ExitHead, ExitTail: s.ExitTail, OutflowDay: s.OutflowDay, Outflow: s.Outflow,
	}
	for i, fake := range []*rpctest.Fake{h.primary, h.second} {
		st, balance := status, new(big.Int).Set(s.Tvl)
		if i == 0 && h.tamper != nil {
			h.tamper(&st, balance)
		}
		fake.Events = nil
		for _, e := range h.chain.Events {
			fake.AddEvent(rpctest.EventInfo(e))
		}
		fake.SetLatest(h.chain.Ledger)
		fake.CloseTime = h.chain.ClosedAt
		fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
			DelaySmall: 3600, DelayLarge: 86400, Limit: h.limit, Large: 5_000_000_000, Status: st, WasmHash: [32]byte{9},
		}), h.chain.Ledger, nil)
		var tr tree.Tree
		var leaves []vault.NewCommitment
		for _, raw := range h.chain.Events {
			if e, err := vault.Decode(raw); err == nil {
				if c, ok := e.Body.(vault.NewCommitment); ok {
					leaves = append(leaves, c)
				}
			}
		}
		for j := 0; j+1 < len(leaves); j += 2 {
			if _, err := tr.AppendPair(leaves[j].Commitment, leaves[j+1].Commitment); err != nil {
				h.t.Fatal(err)
			}
		}
		fake.SetContractData(mustKey(vault.NextLeafKey(vaulttest.Vault)), vault.U64(tr.Len()), h.chain.Ledger, nil)
		fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.RootRing(tr.Root(), uint32(tr.Len()/2)%vault.RootHistory), h.chain.Ledger, nil)
		amount, _ := vault.I128(balance)
		fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vault.Struct(
			vault.Field{Name: "amount", Value: amount}, vault.Field{Name: "authorized", Value: vault.Bool(!h.deauthorized)}, vault.Field{Name: "clawback", Value: vault.Bool(false)},
		), h.chain.Ledger, nil)
	}
}

// sync publishes, lets the watcher ingest everything and reconcile.
func (h *harness) sync() {
	h.t.Helper()
	h.publish()
	for range 100 {
		progressed, err := h.f.Step(context.Background())
		if err != nil {
			h.w.Fault(context.Background(), err)
			break
		}
		if !progressed {
			break
		}
	}
	if err := h.w.Reconcile(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

// activity is an honest day: three deposits, one admitted, an unshield and a transfer.
func (h *harness) activity() {
	c := h.chain
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.Shield(vaulttest.Depositor, 20_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	c.Transact(-4_000_000, 100_000, vaulttest.Relayer)
	c.Transfer(vaulttest.Relayer, 4_000_000)
	c.Transfer(vaulttest.Relayer, 100_000)
	c.NextLedger(5)
}

func TestAnHonestVaultRaisesNothing(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	if codes := h.pages.codes(); len(codes) != 0 {
		t.Fatalf("pages %v", codes)
	}
	if h.w.Cursor() != h.chain.Ledger {
		t.Fatalf("cursor %d", h.w.Cursor())
	}
}

func TestATransferTheEventsDoNotReportPages(t *testing.T) {
	h := newHarness(t)
	c := h.chain
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	c.Transact(-4_000_000, 100_000, vaulttest.Relayer)
	// The asset moved more to the relayer than the vault's events say.
	c.Transfer(vaulttest.Relayer, 5_000_000)
	c.Transfer(vaulttest.Relayer, 100_000)
	c.NextLedger(5)
	h.sync()
	if !h.pages.has("outflow_mismatch") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestStateAndBalanceMismatchesPage(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.tamper = func(st *vault.Status, balance *big.Int) {
		st.Tvl = new(big.Int).Add(st.Tvl, big.NewInt(1))
		balance.Sub(balance, big.NewInt(10))
	}
	h.sync()
	for _, want := range []string{"state_mismatch", "balance_below_tvl", "rpc_disagreement"} {
		if !h.pages.has(want) {
			t.Fatalf("missing %s in %v", want, h.pages.codes())
		}
	}
}

func TestTheSecondRPCIsComparedEventByEvent(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.publish()
	// The second provider reports a different settlement.
	h.second.Events[len(h.second.Events)-3].ValueXDR = h.second.Events[0].ValueXDR
	for range 10 {
		if progressed, err := h.f.Step(context.Background()); err != nil || !progressed {
			break
		}
	}
	h.w.crossCheckEvents(context.Background())
	if !h.pages.has("rpc_disagreement_") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestGovernanceEventsArePublic(t *testing.T) {
	h := newHarness(t)
	h.chain.Governance("halted", vault.Field{Name: "until", Value: vault.U64(uint64(h.chain.ClosedAt + 72*3600))})
	h.chain.NextLedger(5)
	h.sync()
	if !h.pages.has("governance_halted") || !h.public.has("governance_halted") {
		t.Fatalf("pages %v, public %v", h.pages.codes(), h.public.codes())
	}
}

func TestAnEarlyAttestationPages(t *testing.T) {
	h := newHarness(t)
	id := h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.sync()
	h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10_000_000, uint64(h.chain.ClosedAt-5), 3600, nil, 0), h.chain.Ledger, nil)
	// Attested a minute after the deposit, which needs an hour.
	h.chain.NextLedger(60)
	h.chain.Attest(id)
	h.chain.NextLedger(5)
	h.sync()
	if !h.pages.has("early_attestation_1") {
		t.Fatalf("pages %v", h.pages.codes())
	}

	// An attestation inside the last ten minutes is what the policy does.
	h2 := newHarness(t)
	id = h2.chain.Shield(vaulttest.Depositor, 10_000_000)
	h2.chain.NextLedger(5)
	h2.sync()
	h2.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10_000_000, uint64(h2.chain.ClosedAt-5), 3600, nil, 0), h2.chain.Ledger, nil)
	h2.chain.NextLedger(3600 - 5*60)
	h2.chain.Attest(id)
	h2.chain.NextLedger(5)
	h2.sync()
	if h2.pages.has("early_attestation") {
		t.Fatalf("pages %v", h2.pages.codes())
	}
}

func TestBurstsSpikesAndLargeUnshieldsPage(t *testing.T) {
	h := newHarness(t)
	h.limit = 100_000_000
	c := h.chain
	c.Shield(vaulttest.Depositor, 90_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	for range 4 {
		c.Transact(-6_000_000, 0, vaulttest.Relayer)
		c.Transfer(vaulttest.Relayer, 6_000_000)
		c.NextLedger(5)
	}
	h.sync()
	// Four transacts within ten minutes pass a floor of three, and 24 of a window of 100 within an
	// hour is a spike.
	for _, want := range []string{"nullifier_burst", "outflow_spike"} {
		if !h.pages.has(want) {
			t.Fatalf("missing %s in %v", want, h.pages.codes())
		}
	}
}

func TestTheExitQueueIsWatched(t *testing.T) {
	h := newHarness(t)
	c := h.chain
	c.Shield(vaulttest.Depositor, 90_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	first := c.QueueExit(1, -1_000, 0, vaulttest.Depositor)
	second := c.QueueExit(2, -1_000, 0, vaulttest.Depositor)
	for id := uint64(3); id <= 5; id++ {
		c.QueueExit(id, -1_000, 0, vaulttest.Depositor)
	}
	c.NextLedger(5)
	c.Strand(first, 1_000, 0)
	c.PayPart(second, 400, 0, 600, 0)
	c.NextLedger(5)
	h.sync()
	h.primary.CloseTime = h.chain.ClosedAt + 49*3600
	if err := h.w.CheckExitQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.pages.has("exit_stranded_old") {
		t.Fatalf("a stranded exit paged before seven days: %v", h.pages.codes())
	}
	h.primary.CloseTime = h.chain.ClosedAt + 8*24*3600
	if err := h.w.CheckExitQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"exit_stranded_1", "exit_queue_long", "exit_queue_old", "exit_part_paid_old", "exit_stranded_old"} {
		if !h.pages.has(want) {
			t.Fatalf("missing %s in %v", want, h.pages.codes())
		}
	}
	// A claim queues the stranded exit again, at the tail.
	c.NextLedger(8 * 24 * 3600)
	c.Requeue(first, 6, 1_000, 0)
	c.NextLedger(5)
	h.sync()
	if err := h.w.CheckExitQueue(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("exit_requeued_6") || h.w.alerts.Open("exit_stranded_old") {
		t.Fatalf("after the claim %v", h.pages.codes())
	}
}

func TestLateAdmissionsAndExpiringEntriesPage(t *testing.T) {
	h := newHarness(t)
	id := h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.chain.Attest(id)
	h.chain.NextLedger(5)
	h.sync()
	soon := h.chain.Ledger + 100
	h.primary.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10_000_000, uint64(h.chain.ClosedAt-10), 3600, nil, 0), h.chain.Ledger, &soon)
	h.primary.CloseTime = h.chain.ClosedAt + 3600 + 11*60
	if err := h.w.CheckAdmissions(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.w.CheckTTL(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"admission_late", "entry_expiring"} {
		if !h.pages.has(want) {
			t.Fatalf("missing %s in %v", want, h.pages.codes())
		}
	}
}

func TestFreezesAndGovernanceAccountChangesPage(t *testing.T) {
	h := newHarness(t)
	h.sync()
	guardian := mustKey(vault.AccountKey(vaulttest.Guardian))
	account := func(weight uint32) xdr.LedgerEntryData {
		return xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{
			AccountId: guardian.MustAccount().AccountId, Thresholds: xdr.Thresholds{1, 1, byte(weight), 1},
		}}
	}
	asp := mustKey(vault.AccountKey(vaulttest.Asp))
	h.primary.SetEntry(asp, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: asp.MustAccount().AccountId, Thresholds: xdr.Thresholds{1, 1, 1, 1}}}, 1, nil)
	h.primary.SetEntry(guardian, account(2), 1, nil)
	if err := h.w.CheckGovernanceAccounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.primary.SetEntry(guardian, account(1), 2, nil)
	if err := h.w.CheckGovernanceAccounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("governance_account_guardian") || !h.public.has("governance_account_guardian") {
		t.Fatalf("pages %v, public %v", h.pages.codes(), h.public.codes())
	}

	raw, _ := mustKey(vault.InstanceKey(vaulttest.Vault)).MarshalBinary()
	h.primary.SetEntry(vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingFrozenLedgerKeys), xdr.LedgerEntryData{
		Type: xdr.LedgerEntryTypeConfigSetting,
		ConfigSetting: &xdr.ConfigSettingEntry{
			ConfigSettingId:  xdr.ConfigSettingIdConfigSettingFrozenLedgerKeys,
			FrozenLedgerKeys: &xdr.FrozenLedgerKeys{Keys: []xdr.EncodedLedgerKey{raw}},
		},
	}, 1, nil)
	if err := h.w.CheckFreezes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("frozen") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestTheIndexerAndHealthEndpointsAreChecked(t *testing.T) {
	var root string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken/v1/health" {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"leaf_count": 4, "root": root})
	}))
	defer srv.Close()
	h := newHarness(t, func(c *Config) {
		c.IndexerURL = srv.URL
		c.HealthURLs = []string{srv.URL + "/v1/health", srv.URL + "/broken/v1/health"}
	})
	h.activity()
	h.sync()
	root = h.w.state.Tree.Root().Hex()
	if err := h.w.CheckIndexer(context.Background()); err != nil || h.pages.has("indexer_root_mismatch") {
		t.Fatalf("the same root paged: %v %v", h.pages.codes(), err)
	}
	root = strings.Repeat("0", 64)
	if err := h.w.CheckIndexer(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("indexer_root_mismatch") {
		t.Fatalf("pages %v", h.pages.codes())
	}
	for range 2 {
		if err := h.w.CheckHealth(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !h.pages.has("health_failing_1") || h.pages.has("health_failing_0") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestHotAccountsAndCyclingCapitalAreWatched(t *testing.T) {
	const (
		hot    = "GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO"
		source = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
	)
	var effects []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/effects"):
			_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": effects}})
		case strings.HasSuffix(r.URL.Path, "/payments"):
			records := []map[string]any{{"type": "payment", "created_at": time.Unix(1_728_000_000, 0), "from": source, "to": strings.Split(r.URL.Path, "/")[2]}}
			_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": records}})
		}
	}))
	defer srv.Close()
	h := newHarness(t, func(c *Config) {
		c.HotAccounts = []HotAccount{{Name: "keeper", Address: hot, Floor: 100}}
	})
	h.w.horizon = &horizon.Client{URL: srv.URL, HTTP: srv.Client(), MaxPages: 2}
	key := mustKey(vault.AccountKey(hot))
	h.primary.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, Balance: 50}}, 1, nil)
	effects = []map[string]any{{"id": "1-1", "paging_token": "1", "type": "account_credited"}}
	if err := h.w.CheckHotAccounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	effects = []map[string]any{{"id": "2-1", "paging_token": "2", "type": "account_debited", "amount": "9.0000000"}}
	if err := h.w.CheckHotAccounts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("hot_balance_low_"+hot) || !h.pages.has("hot_account_outflow_2-1") {
		t.Fatalf("pages %v", h.pages.codes())
	}

	// Two payouts to recipients funded by the same source as earlier depositors, which also fill
	// the day's window minutes after midnight.
	h.limit = 2_000_000
	c := h.chain
	c.Shield(vaulttest.Depositor, 50_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	for range 2 {
		c.Transact(-1_000_000, 0, vaulttest.Relayer)
		c.Transfer(vaulttest.Relayer, 1_000_000)
		c.NextLedger(5)
	}
	h.sync()
	h.primary.CloseTime = h.chain.ClosedAt
	if err := h.w.CheckPatterns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("round_trip_"+source) || !h.pages.has("window_saturated_early_20000") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestHotAccountLinesParse(t *testing.T) {
	got, err := ParseHotAccounts([]byte("# channels\nchannel-1 GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO 100000000\n\nkeeper GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3 0\n"))
	if err != nil || len(got) != 2 || got[0].Floor != 100_000_000 || got[1].Name != "keeper" {
		t.Fatalf("parsed %+v, %v", got, err)
	}
	for _, bad := range []string{"x GXX 1", "x GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO -1", "x y"} {
		if _, err := ParseHotAccounts([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestAStatusReadAheadOfTheReplayWaitsForIt(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.tamper = func(st *vault.Status, _ *big.Int) { st.AttestedUpTo = 2 }
	h.publish()
	// The read is of the last ledger, which the watcher has not replayed yet.
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.pages.has("state_mismatch") {
		t.Fatalf("compared before the replay got there: %v", h.pages.codes())
	}
	for range 10 {
		if progressed, err := h.f.Step(context.Background()); err != nil || !progressed {
			break
		}
	}
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !h.pages.has("state_mismatch") {
		t.Fatalf("pages %v", h.pages.codes())
	}
}

func TestARebuildDoesNotReportOldGovernanceAgain(t *testing.T) {
	h := newHarness(t)
	h.chain.Governance("paused", vault.Field{Name: "deposits", Value: vault.Bool(false)}, vault.Field{Name: "transfers", Value: vault.Bool(true)})
	// Two days of quiet ledgers follow, so the event is old when the watcher first reads it.
	h.chain.NextLedger(2 * 86_400)
	h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.f.Window = 1
	h.publish()
	h.primary.CloseTime = h.chain.ClosedAt
	for range 100 {
		progressed, err := h.f.Step(context.Background())
		if err != nil || !progressed {
			break
		}
	}
	if h.pages.has("governance_paused") || h.public.has("governance_paused") {
		t.Fatalf("an old governance event was reported again: %v %v", h.pages.codes(), h.public.codes())
	}
}

func TestAVaultTheIssuerDeauthorizesPages(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.sync()
	h.deauthorized = true
	h.publish()
	if err := h.w.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vault_deauthorized", "vault_authorization_false"} {
		if !h.pages.has(want) {
			t.Fatalf("missing %s in %v", want, h.pages.codes())
		}
	}
}
