//go:build integration

// Package integration runs the indexer and the watcher against a deployed vault on a real network,
// such as a local stellar/quickstart network the vault was deployed to:
//
//	INTEGRATION_RPC_URL=http://localhost:8000/rpc INTEGRATION_PASSPHRASE="Standalone Network ; February 2017" \
//	INTEGRATION_VAULT=C... INTEGRATION_DEPLOY_LEDGER=123 TEST_DATABASE_URL=postgres://... \
//	go test -tags integration ./internal/integration/
package integration

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/indexer"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/watcher"
)

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

func settings(t *testing.T) (rpc.Client, string, uint32, string) {
	t.Helper()
	url, vault, deploy, passphrase := os.Getenv("INTEGRATION_RPC_URL"), os.Getenv("INTEGRATION_VAULT"), os.Getenv("INTEGRATION_DEPLOY_LEDGER"), os.Getenv("INTEGRATION_PASSPHRASE")
	if url == "" || vault == "" || deploy == "" || passphrase == "" {
		t.Skip("INTEGRATION_RPC_URL, INTEGRATION_VAULT, INTEGRATION_DEPLOY_LEDGER and INTEGRATION_PASSPHRASE name the vault to test against")
	}
	ledger, err := strconv.ParseUint(deploy, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	client := rpc.Dial(url)
	if err := rpc.CheckNetwork(context.Background(), client, passphrase); err != nil {
		t.Fatal(err)
	}
	return client, vault, uint32(ledger), passphrase
}

func catchUp(t *testing.T, f *follow.Follower) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		progressed, err := f.Step(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !progressed {
			return
		}
	}
	t.Fatal("did not catch up within ten minutes")
}

func TestTheIndexerRebuildsAndReconcilesWithTheChain(t *testing.T) {
	client, vault, deploy, passphrase := settings(t)
	ctx := context.Background()
	pool, err := chainstate.Open(ctx, testdb.URL(t), indexer.Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	pages := &recorder{}
	ix, err := indexer.New(ctx, indexer.Config{
		Vault: vault, NetworkID: rpc.NetworkID(passphrase), DeployLedger: deploy, ArchiveDir: t.TempDir(),
		MaxLag: 12, ProbeMaxAge: time.Minute,
	}, client, &chainstate.Store{Pool: pool, KeepLeaves: true}, &alert.Alerter{Service: "indexer", Channels: []alert.Channel{pages}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	catchUp(t, &follow.Follower{RPC: client, Live: follow.RPCSource{Client: client, Contract: vault, PageLimit: 1000}, Window: 500, Sink: ix})
	ix.Probe(ctx)
	if err := ix.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if h := ix.Health(); !h.Ready {
		t.Fatalf("not ready after catching up: %+v, pages %+v", h, pages.alerts)
	}
}

func TestTheWatcherAgreesWithTheChain(t *testing.T) {
	client, vault, deploy, _ := settings(t)
	ctx := context.Background()
	pool, err := chainstate.Open(ctx, testdb.URL(t), watcher.Schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	pages := &recorder{}
	alerts := &alert.Alerter{Service: "watcher", Channels: []alert.Channel{pages}, Cooldown: time.Hour}
	w, err := watcher.New(ctx, watcher.Config{
		Vault: vault, DeployLedger: deploy, BurstMultiple: 5, BurstFloor: 1000, QueueLength: 1000, QueueAge: 30 * 24 * time.Hour,
		RoundTrips: 1000, IgnoreFunders: map[string]bool{}, EarlyWindow: time.Hour, EarlyShare: 100,
	}, client, client, &chainstate.Store{Pool: pool}, nil, alerts, alerts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	catchUp(t, &follow.Follower{RPC: client, Live: follow.RPCSource{Client: client, Contract: vault, PageLimit: 1000}, Window: 500, Sink: w})
	if err := w.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, a := range pages.alerts {
		if strings.HasPrefix(a.Code, "state_mismatch") || strings.HasPrefix(a.Code, "invariant") || strings.HasPrefix(a.Code, "balance_below_tvl") || strings.HasPrefix(a.Code, "outflow_mismatch") {
			t.Fatalf("the watcher disagrees with the chain: %+v", a)
		}
	}
}
