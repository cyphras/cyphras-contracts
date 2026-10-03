package indexer

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

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
	h.setInstance(0)
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
	h.f = &follow.Follower{RPC: h.fake, Live: follow.RPCSource{Client: h.fake, Vault: vaulttest.Vault, PageLimit: 10}, Window: 5, Sink: ix}
}

func (h *harness) setInstance(attested uint64) {
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000,
		Status: vault.Status{AttestedUpTo: attested},
	}), 10, nil)
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
	first, next, err := db.nullifiers(ctx, 0, 0)
	if err != nil || len(first) != MaxNullifiers || next != "4096" {
		t.Fatalf("first page %d %q %v", len(first), next, err)
	}
	second, next, err := db.nullifiers(ctx, 0, 4096)
	if err != nil || len(second) != 5000-MaxNullifiers || next != "" {
		t.Fatalf("second page %d %q %v", len(second), next, err)
	}
	recent, _, _ := db.nullifiers(ctx, 149, 0)
	if len(recent) != 100 {
		t.Fatalf("since ledger 149: %d", len(recent))
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
