// Command indexer rebuilds one vault from its events and serves leaves, nullifiers and the entry
// queue. "indexer rebuild" deletes its state so the next start ingests again from the deploy
// ledger, out of its own event archive, the ledger-meta archive and RPC.
package main

import (
	"net/http"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/indexer"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
)

func main() {
	ctx, stop := service.Context()
	defer stop()
	base, err := service.Start(ctx, "indexer")
	if err != nil {
		service.Fatal(nil, "start", err)
	}
	log := base.Log
	dbURL, err := service.DatabaseURL()
	if err != nil {
		service.Fatal(log, "database url", err)
	}
	pool, err := chainstate.Open(ctx, dbURL, indexer.Schema)
	if err != nil {
		service.Fatal(log, "database", err)
	}
	defer pool.Close()
	chain := &chainstate.Store{Pool: pool, KeepLeaves: true}

	if service.Command("serve") == "rebuild" {
		if err := indexer.Rebuild(ctx, chain); err != nil {
			service.Fatal(log, "rebuild", err)
		}
		log.Info("state deleted; the next start ingests from the deploy ledger")
		return
	}

	archiveDir := config.Env("ARCHIVE_DIR", "")
	window, err := config.Int("WINDOW_LEDGERS", 500)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	poll, err := config.Duration("POLL", time.Second)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	ix, err := indexer.New(ctx, indexer.Config{
		Vault: base.Vault.Vault, NetworkID: base.NetworkID, DeployLedger: base.Vault.DeployLedger,
		ArchiveDir: archiveDir, MaxLag: 12, ProbeMaxAge: 30 * time.Second,
	}, base.RPC, chain, base.Alerts, log)
	if err != nil {
		service.Fatal(log, "load", err)
	}

	var history []follow.Source
	if archiveDir != "" {
		history = append(history, archive.Reader{Dir: archiveDir, Vault: base.Vault.Vault})
	}
	if url := config.Env("LEDGER_META_ARCHIVE_URL", ""); url != "" {
		history = append(history, &follow.LedgerArchive{
			BaseURL: url, Passphrase: base.Deployment.NetworkPassphrase, Vault: base.Vault.Vault,
			HTTP: &http.Client{Timeout: time.Minute}, Workers: 16,
		})
	}
	f := &follow.Follower{
		RPC: base.RPC, Live: follow.RPCSource{Client: base.RPC, Vault: base.Vault.Vault, PageLimit: 1000},
		History: history, Window: uint32(window), Sink: ix,
	}
	go ix.Run(ctx, f, poll)

	addr := config.Env("LISTEN_ADDR", "127.0.0.1:8080")
	log.Info("serving", "vault", base.Vault.Vault, "addr", addr)
	if err := httpapi.Serve(ctx, addr, ix.Handler()); err != nil && ctx.Err() == nil {
		service.Fatal(log, "serve", err)
	}
}
