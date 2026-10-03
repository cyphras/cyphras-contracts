package indexer

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const passphrase = "Test SDF Network ; September 2015"

type recorder struct{ alerts []alert.Alert }

func (r *recorder) Send(_ context.Context, a alert.Alert) error {
	r.alerts = append(r.alerts, a)
	return nil
}

type harness struct {
	t      *testing.T
	fake   *rpctest.Fake
	chain  *vaulttest.Chain
	ix     *Indexer
	f      *follow.Follower
	store  *chainstate.Store
	pages  *recorder
	now    time.Time
	url    string
	cfg    Config
	logger *slog.Logger
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	url := testdb.URL(t)
	h := &harness{t: t, fake: rpctest.New(passphrase, 9), chain: vaulttest.New(10, 1_728_000_000), pages: &recorder{}, now: time.Unix(1_728_000_000, 0), url: url}
	h.cfg = Config{Vault: vaulttest.Vault, NetworkID: rpc.NetworkID(passphrase), DeployLedger: 10, ArchiveDir: t.TempDir(), MaxLag: 12, ProbeMaxAge: 30 * time.Second}
	h.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	h.open()
	h.setInstance(vault.Status{NextDepositID: 1, ExitHead: 1, ExitTail: 1}, 10)
	return h
}

func (h *harness) open() {
	h.t.Helper()
	pool, err := chainstate.Open(context.Background(), h.url, Schema)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(pool.Close)
	h.store = &chainstate.Store{Pool: pool, KeepLeaves: true}
	alerts := &alert.Alerter{Service: "indexer", Channels: []alert.Channel{h.pages}, Cooldown: time.Hour}
	ix, err := New(context.Background(), h.cfg, h.fake, h.store, alerts, h.logger)
	if err != nil {
		h.t.Fatal(err)
	}
	ix.now = func() time.Time { return h.now }
	h.ix = ix
	h.f = &follow.Follower{RPC: h.fake, Live: follow.RPCSource{Client: h.fake, Contract: vaulttest.Vault, PageLimit: 10}, Window: 5, Sink: ix}
}

func (h *harness) setInstance(status vault.Status, modified uint32) {
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000, Status: status,
	}), modified, nil)
}

// replayStatus is the vault's status after the chain's events, up to the first ledger whose events
// the vault could not have emitted, and the last ledger applied.
func (h *harness) replayStatus() (vault.Status, uint32) {
	s, last := chainstate.New(), uint32(10)
	var ledgers []uint32
	byLedger := map[uint32][]vault.Event{}
	for _, raw := range h.chain.Events {
		e, err := vault.Decode(raw)
		if err != nil {
			byLedger[raw.Ledger] = nil
			ledgers = append(ledgers, raw.Ledger)
			break
		}
		if _, ok := byLedger[raw.Ledger]; !ok {
			ledgers = append(ledgers, raw.Ledger)
		}
		byLedger[raw.Ledger] = append(byLedger[raw.Ledger], e)
	}
	for _, l := range ledgers {
		txs, err := vault.ParseTxs(byLedger[l])
		if err != nil || len(byLedger[l]) == 0 {
			break
		}
		next := s.Clone()
		if _, err := next.Apply(txs); err != nil {
			break
		}
		s, last = next, l
	}
	return s.Status(), last
}

func mustKey[T any](k T, err error) T {
	if err != nil {
		panic(err)
	}
	return k
}

// publish puts the chain's events into the RPC and sets the tree entries the vault would hold.
func (h *harness) publish() {
	h.t.Helper()
	h.fake.Events = nil
	for _, e := range h.chain.Events {
		h.fake.AddEvent(rpctest.EventInfo(e))
	}
	h.fake.SetLatest(h.chain.Ledger)
	h.fake.CloseTime = h.chain.ClosedAt
	var tr tree.Tree
	modified := uint32(10)
	for _, e := range h.chain.Events {
		ev, err := vault.Decode(e)
		if err != nil {
			continue
		}
		if c, ok := ev.Body.(vault.NewCommitment); ok && c.Index%2 == 1 {
			// The right leaf of a pair; its left one came just before.
			modified = e.Ledger
		}
	}
	leaves := h.leafValues()
	for i := 0; i+1 < len(leaves); i += 2 {
		if _, err := tr.AppendPair(leaves[i], leaves[i+1]); err != nil {
			h.t.Fatal(err)
		}
	}
	h.fake.SetContractData(mustKey(vault.NextLeafKey(vaulttest.Vault)), vault.U64(tr.Len()), modified, nil)
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.RootRing(tr.Root(), uint32(tr.Len()/2)%vault.RootHistory), modified, nil)
	h.setInstance(h.replayStatus())
}

func (h *harness) leafValues() []fr.Element {
	var out []fr.Element
	for _, e := range h.chain.Events {
		ev, _ := vault.Decode(e)
		if c, ok := ev.Body.(vault.NewCommitment); ok {
			out = append(out, c.Commitment)
		}
	}
	return out
}

func (h *harness) drain() {
	h.t.Helper()
	for range 200 {
		progressed, err := h.f.Step(context.Background())
		if err != nil {
			h.ix.Fault(context.Background(), err)
			return
		}
		if !progressed {
			return
		}
	}
	h.t.Fatal("never caught up")
}

func (h *harness) get(path string) (int, map[string]any) {
	h.t.Helper()
	rec := httptest.NewRecorder()
	h.ix.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		h.t.Fatalf("%s: %v (%s)", path, err, rec.Body.String())
	}
	return rec.Code, body
}

func (h *harness) activity() {
	c := h.chain
	for range 3 {
		c.Shield(vaulttest.Depositor, 10_000_000)
		c.NextLedger(5)
	}
	c.Shield(vaulttest.Relayer, 6_000_000_000)
	c.NextLedger(5)
	c.Attest(2)
	c.Flag(3, 4)
	c.NextLedger(5)
	c.Admit(1, 2)
	c.NextLedger(5)
	c.Transact(-1_000_000, 100_000, vaulttest.Relayer)
	c.Transact(0, 100_000, vaulttest.Relayer)
	c.NextLedger(5)
}

func TestTheIndexerServesWhatItReconciled(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.publish()
	h.ix.Probe(context.Background())
	if code, body := h.get("/v1/leaves?page=0"); code != http.StatusServiceUnavailable || body["error"] != CodeLagging {
		t.Fatalf("before ingesting: %d %v", code, body)
	}
	h.drain()
	h.ix.Probe(context.Background())
	code, body := h.get("/v1/health")
	if code != http.StatusOK || body["ready"] != true || body["leaf_count"].(float64) != 8 || body["nullifier_count"].(float64) != 12 {
		t.Fatalf("health %d %v", code, body)
	}
	if body["network_id"] != "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472" || body["vault"] != vaulttest.Vault {
		t.Fatal("identity")
	}

	code, body = h.get("/v1/leaves?page=0")
	leaves := body["leaves"].([]any)
	if code != http.StatusOK || len(leaves) != 8 || body["complete"] != false {
		t.Fatalf("leaves %d %v", code, body)
	}
	first := leaves[0].(map[string]any)
	if first["commitment"] != vaulttest.Commitment(2).Hex() || len(first["ciphertext"].(string)) != 2*vault.CiphertextLen {
		t.Fatalf("first leaf %v", first)
	}
	if _, body = h.get("/v1/leaves?page=1"); len(body["leaves"].([]any)) != 0 {
		t.Fatal("page past the end")
	}
	for _, bad := range []string{"-1", "x", "01", "4194304"} {
		if code, _ := h.get("/v1/leaves?page=" + bad); code != http.StatusBadRequest {
			t.Fatalf("page %q answered %d", bad, code)
		}
	}

	_, body = h.get("/v1/nullifiers?since_ledger=0")
	if len(body["nullifiers"].([]any)) != 12 || body["next_cursor"] != nil || body["complete_to"].(float64) != float64(h.chain.Ledger) {
		t.Fatalf("nullifiers %v", body)
	}
	_, body = h.get("/v1/nullifiers?since_ledger=" + itoa(h.chain.Ledger-1))
	if len(body["nullifiers"].([]any)) != 4 {
		t.Fatalf("recent nullifiers %v", body)
	}

	if err := h.ix.RefreshPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, body = h.get("/v1/deposits")
	pending := body["pending"].([]any)
	resolved := body["resolved"].([]any)
	if len(pending) != 2 || len(resolved) != 2 {
		t.Fatalf("deposits %v", body)
	}
	flagged := pending[0].(map[string]any)
	if flagged["id"].(float64) != 3 || flagged["flag_reason"].(float64) != 4 || flagged["attested"] != false {
		t.Fatalf("flagged deposit %v", flagged)
	}
	admitted := resolved[1].(map[string]any)
	if admitted["outcome"] != "admitted" || admitted["leaf_index0"].(float64) != 2 {
		t.Fatalf("admitted deposit %v", admitted)
	}

	_, body = h.get("/v1/stats")
	if body["admitted_deposits"].(float64) != 2 || body["distinct_depositors"].(float64) != 1 || body["pending_deposits"].(float64) != 2 || body["leaf_count"].(float64) != 8 {
		t.Fatalf("stats %v", body)
	}

	// Every raw event reached the archive.
	got, err := archive.Reader{Dir: h.cfg.ArchiveDir, Vault: vaulttest.Vault}.Events(context.Background(), 10, h.chain.Ledger)
	if err != nil || len(got) != len(h.chain.Events) {
		t.Fatalf("archive holds %d of %d events: %v", len(got), len(h.chain.Events), err)
	}
}

func itoa(n uint32) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestAMismatchStopsServingUntilARebuild(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	if !h.ix.Health().Ready {
		t.Fatal("not ready after ingesting")
	}
	// The chain's root differs from the indexer's.
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.RootRing(fr.SetUint64(1), 4), h.chain.Ledger, nil)
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, body := h.get("/v1/nullifiers"); code != http.StatusServiceUnavailable || body["error"] != CodeMismatch {
		t.Fatalf("after a mismatch: %d %v", code, body)
	}
	if len(h.pages.alerts) == 0 || h.pages.alerts[0].Code != "reconcile_mismatch" {
		t.Fatalf("alerts %+v", h.pages.alerts)
	}
	// The chain agreeing again does not clear it either.
	h.publish()
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/leaves?page=0", "/v1/nullifiers", "/v1/deposits"} {
		if code, _ := h.get(path); code != http.StatusServiceUnavailable {
			t.Fatalf("%s served after a mismatch: %d", path, code)
		}
	}
	// It keeps ingesting, and a restart does not clear the mismatch.
	h.chain.Shield(vaulttest.Depositor, 1)
	h.publish()
	h.drain()
	h.open()
	h.ix.Probe(context.Background())
	if h.ix.Health().Code != CodeMismatch {
		t.Fatal("a restart cleared the mismatch")
	}
	if err := Rebuild(context.Background(), h.store); err != nil {
		t.Fatal(err)
	}
	h.open()
	h.drain()
	h.ix.Probe(context.Background())
	if hl := h.ix.Health(); !hl.Ready || hl.LeafCount != 8 {
		t.Fatalf("after a rebuild: %+v", hl)
	}
}

func TestAFaultAndAFailedProbeAreNotReady(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.chain.Tx().Emit("mint", vault.Field{Name: "amount", Value: vault.U32(1)})
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	if hl := h.ix.Health(); hl.Code != CodeFault || hl.Ready {
		t.Fatalf("after an unknown topic: %+v", hl)
	}

	h2 := newHarness(t)
	h2.activity()
	h2.publish()
	h2.drain()
	h2.ix.Probe(context.Background())
	h2.fake.Fail["getHealth"] = io.ErrUnexpectedEOF
	h2.now = h2.now.Add(31 * time.Second)
	h2.ix.Probe(context.Background())
	if hl := h2.ix.Health(); hl.Code != CodeProbeFailed {
		t.Fatalf("after a failed probe: %+v", hl)
	}
	h2.fake.Fail = map[string]error{}
	h2.ix.Probe(context.Background())
	h2.fake.SetLatest(h2.chain.Ledger + 13)
	h2.ix.Probe(context.Background())
	if hl := h2.ix.Health(); hl.Code != CodeLagging {
		t.Fatalf("13 ledgers behind: %+v", hl)
	}
}

func TestNullifierPagesFollowTheCursor(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	rows := make([][]any, 5000)
	for i := range rows {
		rows[i] = []any{int64(i), fr.SetUint64(uint64(i) + 1).Bytes(), int64(100 + i/100), "h"}
	}
	for i := range rows {
		b := rows[i][1].([32]byte)
		rows[i][1] = b[:]
	}
	if _, err := h.store.Pool.CopyFrom(ctx, pgx.Identifier{"nullifiers"}, []string{"seq", "nullifier", "ledger", "tx_hash"}, pgx.CopyFromRows(rows)); err != nil {
		t.Fatal(err)
	}
	db := store{h.store.Pool}
	first, next, err := db.nullifiers(ctx, 0, 1000, 0)
	if err != nil || len(first) != MaxNullifiers || next != "4096" {
		t.Fatalf("first page %d %q %v", len(first), next, err)
	}
	second, next, err := db.nullifiers(ctx, 0, 1000, 4096)
	if err != nil || len(second) != 5000-MaxNullifiers || next != "" {
		t.Fatalf("second page %d %q %v", len(second), next, err)
	}
	recent, _, _ := db.nullifiers(ctx, 149, 1000, 0)
	if len(recent) != 100 {
		t.Fatalf("since ledger 149: %d", len(recent))
	}
	cut, _, _ := db.nullifiers(ctx, 149, 148, 0)
	if len(cut) != 0 {
		t.Fatalf("up to ledger 148 from 149: %d", len(cut))
	}
}

func TestTheStreamWakesSubscribers(t *testing.T) {
	h := newHarness(t)
	srv := httptest.NewServer(h.ix.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal("content type")
	}
	reader := bufio.NewReader(resp.Body)
	if line, _ := reader.ReadString('\n'); !strings.HasPrefix(line, "retry:") {
		t.Fatalf("first line %q", line)
	}
	h.chain.Shield(vaulttest.Depositor, 5)
	h.publish()
	h.drain()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data: ") {
			var w Wake
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &w); err != nil || w.NullifierCount != 2 {
				t.Fatalf("wake %q", line)
			}
			return
		}
	}
}

func TestExitsArePaidByTheBoundTheWindowSets(t *testing.T) {
	const day = 20_000 * secondsPerDay
	n := func(v int64) *big.Int { return big.NewInt(v) }
	endOf := func(d uint64) uint64 { return day + (d+1)*secondsPerDay - 1 }
	got := paidBy([]*big.Int{n(300), n(500), n(1000), n(1)}, day+100, 0, n(1000))
	// 300 and the 500 behind it need one more window, the 1000 and the 1 two.
	want := []uint64{endOf(1), endOf(1), endOf(2), endOf(2)}
	for i := range want {
		if got[i] == nil || *got[i] != want[i] {
			t.Fatalf("exit %d paid by %v, want %d", i, got[i], want[i])
		}
	}
	// A halt that ends tomorrow counts the windows from there.
	if got = paidBy([]*big.Int{n(900)}, day+100, day+secondsPerDay+50, n(1000)); *got[0] != endOf(2) {
		t.Fatalf("after a halt %d", *got[0])
	}
	if got = paidBy([]*big.Int{n(1)}, day, 0, n(0)); got[0] != nil {
		t.Fatal("a bound without a window")
	}
}

func TestAFirstPayoutToANewAccountMayWaitForTheNextWindow(t *testing.T) {
	n := func(v int64) *big.Int { return big.NewInt(v) }
	exit := func(left, queued int64, recipient string) *chainstate.Exit {
		return &chainstate.Exit{Payout: n(left), Fee: n(0), QueuedPayout: n(queued), QueuedFee: n(0), Recipient: recipient}
	}
	native, issued := &Indexer{cfg: Config{Native: true}}, &Indexer{}
	slack := int64(vault.MinNewAccountPayout - 1)
	for name, c := range map[string]struct {
		ix   *Indexer
		e    *chainstate.Exit
		want int64
	}{
		"nothing paid yet":   {native, exit(300_000_000, 300_000_000, vaulttest.Depositor), 300_000_000 + slack},
		"paid in part":       {native, exit(200_000_000, 300_000_000, vaulttest.Depositor), 200_000_000},
		"a contract":         {native, exit(300_000_000, 300_000_000, vaulttest.Vault), 300_000_000},
		"an issued asset":    {issued, exit(300_000_000, 300_000_000, vaulttest.Depositor), 300_000_000},
		"a fee only is left": {native, exit(0, 0, vaulttest.Depositor), 0},
	} {
		if got := c.ix.takes(c.e); got.Int64() != c.want {
			t.Fatalf("%s takes %v, want %d", name, got, c.want)
		}
	}
	// Three such exits that would fill one window of 100 XLM between them may need a second.
	const day = 20_000 * secondsPerDay
	owed := []*big.Int{}
	for range 3 {
		owed = append(owed, native.takes(exit(333_000_000, 333_000_000, vaulttest.Depositor)))
	}
	if got := paidBy(owed, day, 0, n(1_000_000_000)); *got[2] != day+3*secondsPerDay-1 {
		t.Fatalf("the third is paid by %d", *got[2])
	}
}

func TestTheExitQueueIsServedWithReleaseTimes(t *testing.T) {
	h := newHarness(t)
	c := h.chain
	c.Shield(vaulttest.Depositor, 9_000_000_000)
	c.NextLedger(5)
	c.Attest(1)
	c.Admit(1)
	c.NextLedger(5)
	first := c.QueueExit(1, -2_000_000_000, 1_000, vaulttest.Depositor)
	second := c.QueueExit(2, -1_000_000_000, 0, vaulttest.Relayer)
	third := c.QueueExit(3, -500_000_000, 0, vaulttest.Relayer)
	c.NextLedger(5)
	c.Strand(first, 2_000_000_000, 0)
	c.Release(second)
	c.PayPart(third, 100_000_000, 0, 400_000_000, 0)
	c.NextLedger(5)
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	if err := h.ix.RefreshPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	h.now = time.Unix(c.ClosedAt, 0)
	code, body := h.get("/v1/exits")
	if code != http.StatusOK {
		t.Fatalf("exits %d %v", code, body)
	}
	if body["head"].(float64) != 3 || body["tail"].(float64) != 4 || body["queued_total"] != "2400000000" || body["window"].(map[string]any)["used"] != "1100001000" {
		t.Fatalf("exits %v", body)
	}
	exits := body["exits"].([]any)
	if len(exits) != 3 {
		t.Fatalf("exits %v", exits)
	}
	q := exits[0].(map[string]any)
	if q["id"].(float64) != 3 || q["state"] != ExitPaidInPart || q["position"].(float64) != 0 || q["payout"] != "500000000" || q["payout_paid"] != "100000000" ||
		q["payout_left"] != "400000000" || q["paid_by"] == nil || q["tx_hash"] == "" {
		t.Fatalf("queued exit %v", q)
	}
	st := exits[1].(map[string]any)
	if st["id"].(float64) != 1 || st["state"] != ExitStranded || st["payout_left"] != "2000000000" || st["fee_paid"] != "1000" || st["fee_left"] != "0" ||
		st["recipient"] != vaulttest.Depositor || st["stranded_tx"] == nil || st["stranded_tx"] == st["tx_hash"] || st["position"] != nil {
		t.Fatalf("stranded exit %v", st)
	}
	done := exits[2].(map[string]any)
	if done["id"].(float64) != 2 || done["state"] != ExitSettled || done["settled_tx"] == nil || done["payout_paid"] != "1000000000" || done["payout_left"] != "0" {
		t.Fatalf("settled exit %v", done)
	}

	// A claim moves the stranded payout back into the queue, at its tail, as exit 4.
	c.NextLedger(5)
	c.Requeue(first, 4, 2_000_000_000, 0)
	c.NextLedger(5)
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	h.now = time.Unix(c.ClosedAt, 0)
	_, body = h.get("/v1/exits")
	exits = body["exits"].([]any)
	if len(exits) != 4 || body["tail"].(float64) != 5 || body["queued_total"] != "2400000000" {
		t.Fatalf("after the claim %v", body)
	}
	moved := exits[1].(map[string]any)
	if moved["id"].(float64) != 4 || moved["state"] != ExitQueued || moved["position"].(float64) != 1 || moved["requeued_from"].(float64) != 1 ||
		moved["payout"] != "2000000000" || moved["paid_by"] == nil {
		t.Fatalf("requeued exit %v", moved)
	}
	old := exits[2].(map[string]any)
	if old["id"].(float64) != 1 || old["state"] != ExitRequeued || old["requeued_to"].([]any)[0].(float64) != 4 || old["payout_requeued"] != "2000000000" ||
		old["payout_paid"] != "0" || old["fee_paid"] != "1000" || old["payout_left"] != "0" || old["requeued_tx"] != moved["tx_hash"] || old["stranded_tx"] == nil {
		t.Fatalf("exit after its claim %v", old)
	}
}

func TestPagesStopAtTheLedgerTheyReport(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	_, body := h.get("/v1/nullifiers?since_ledger=0")
	before := len(body["nullifiers"].([]any))
	completeTo := body["complete_to"].(float64)
	// A window lands in the database while the indexer has not moved its cursor yet.
	next := h.ix.state.Clone()
	d, err := next.Apply([]vault.Tx{{Ledger: h.chain.Ledger + 1, ClosedAt: h.chain.ClosedAt + 5, Hash: "late", Calls: []any{
		vault.Shield{
			Nullifiers: [2]vault.NewNullifier{{Nullifier: fr.SetUint64(77)}, {Nullifier: fr.SetUint64(78)}},
			Deposit: vault.DepositPending{ID: next.NextDepositID, Depositor: vaulttest.Depositor, Amount: big.NewInt(5),
				Commitment0: fr.SetUint64(91), Commitment1: fr.SetUint64(92), CreatedAt: uint64(h.chain.ClosedAt + 5)},
		},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.Commit(context.Background(), h.chain.Ledger+1, h.chain.Ledger+1, next, d, nil); err != nil {
		t.Fatal(err)
	}
	_, body = h.get("/v1/nullifiers?since_ledger=0")
	if len(body["nullifiers"].([]any)) != before || body["complete_to"].(float64) != completeTo {
		t.Fatalf("a page reached past its complete_to: %v", body)
	}
	_, body = h.get("/v1/deposits")
	for _, p := range body["pending"].([]any) {
		if p.(map[string]any)["id"].(float64) == float64(next.NextDepositID-1) {
			t.Fatalf("a deposit past complete_to was served: %v", body)
		}
	}
}

func TestBulkResponsesAreServedFromMemoryForAFewSeconds(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.publish()
	h.drain()
	h.ix.Probe(context.Background())
	_, body := h.get("/v1/stats")
	pending := body["pending_deposits"].(float64)
	// A row the cached answer does not know about.
	if _, err := h.store.Pool.Exec(context.Background(), `INSERT INTO deposits (id, depositor, amount, commitment0, commitment1, created_at, created_ledger, created_tx)
		VALUES (999, $1, 1, '\x00', '\x00', 0, 10, 'x')`, vaulttest.Depositor); err != nil {
		t.Fatal(err)
	}
	if _, body = h.get("/v1/stats"); body["pending_deposits"].(float64) != pending {
		t.Fatalf("the second request read the database: %v", body)
	}
	h.now = h.now.Add(memoAge)
	h.ix.Probe(context.Background())
	if _, body = h.get("/v1/stats"); body["pending_deposits"].(float64) != pending+1 {
		t.Fatalf("a stale copy was served: %v", body)
	}
}

// lagging serves ledger entries as a node some ledgers behind the chain would.
type lagging struct {
	*rpctest.Fake
	by uint32
}

func (l *lagging) GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error) {
	resp, err := l.Fake.GetLedgerEntries(ctx, req)
	resp.LatestLedger -= l.by
	return resp, err
}

func TestOnlyAFullAndRecentReconciliationMakesTheIndexerReady(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.publish()
	leaves := h.leafValues()
	// A node behind the indexer reads the chain as it was when only the first pair was inserted: a
	// prefix the indexer agrees with, which says nothing about the leaves after it.
	var tr tree.Tree
	if _, err := tr.AppendPair(leaves[0], leaves[1]); err != nil {
		t.Fatal(err)
	}
	h.fake.SetContractData(mustKey(vault.NextLeafKey(vaulttest.Vault)), vault.U64(tr.Len()), 10, nil)
	h.fake.SetContractData(mustKey(vault.RootsKey(vaulttest.Vault)), vaulttest.RootRing(tr.Root(), 1), 10, nil)
	h.ix.rpc = &lagging{Fake: h.fake, by: 5}
	for range 50 {
		if progressed, err := h.f.Step(context.Background()); err != nil || !progressed {
			break
		}
	}
	h.ix.Probe(context.Background())
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.ix.Health(); got.Ready || got.Code != CodeLagging {
		t.Fatalf("ready on a prefix: %+v", got)
	}
	h.ix.rpc = h.fake
	h.publish()
	if err := h.ix.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.ix.Health(); !got.Ready {
		t.Fatalf("not ready after a full match: %+v", got)
	}
	h.now = h.now.Add(reconcileMaxAge + time.Second)
	h.ix.Probe(context.Background())
	if got := h.ix.Health(); got.Ready || got.Code != CodeLagging {
		t.Fatalf("still ready without reconciling: %+v", got)
	}
}

func TestTheArchiveKeepsCopyingWhileIngestIsStuck(t *testing.T) {
	h := newHarness(t)
	h.activity()
	h.chain.Tx().Emit("mint", vault.Field{Name: "amount", Value: vault.U32(1)})
	h.chain.NextLedger(5)
	stuckAt := h.chain.Ledger - 1
	h.chain.Shield(vaulttest.Depositor, 10_000_000)
	h.chain.NextLedger(5)
	h.publish()
	h.drain()
	if h.ix.Cursor() >= stuckAt {
		t.Fatalf("ingest passed the faulty ledger: %d", h.ix.Cursor())
	}
	src := follow.RPCSource{Client: h.fake, Contract: vaulttest.Vault, PageLimit: 10}
	for range 20 {
		copied, err := h.ix.ArchiveStep(context.Background(), src)
		if err != nil {
			t.Fatal(err)
		}
		if !copied {
			break
		}
	}
	got, err := archive.Reader{Dir: h.cfg.ArchiveDir, Vault: vaulttest.Vault}.Events(context.Background(), 10, h.chain.Ledger)
	if err != nil || len(got) != len(h.chain.Events) {
		t.Fatalf("archive holds %d of %d events: %v", len(got), len(h.chain.Events), err)
	}
}
