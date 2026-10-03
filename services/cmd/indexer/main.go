// Command indexer rebuilds one vault from its events and serves leaves, nullifiers, the entry
// queue and the exit queue. "indexer rebuild" deletes its state so the next start ingests again
// from the deploy ledger, out of its own event archive, the ledger-meta archive and RPC.
package main

import (
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/indexer"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
)

func main() {
	ctx, stop := service.Context()
	defer stop()
	base, err := service.Start(ctx, "indexer")
	if err != nil {
		service.Fatal(service.Logger("indexer"), "start", err)
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
	if err := base.StartAlerts(ctx, pool); err != nil {
		service.Fatal(log, "alerts", err)
	}
	chain := &chainstate.Store{Pool: pool, KeepLeaves: true}

	if service.Command("serve") == "rebuild" {
		if err := indexer.Rebuild(ctx, chain); err != nil {
			service.Fatal(log, "rebuild", err)
		}
		log.Info("state deleted; the next start ingests from the deploy ledger")
		return
	}

	poll, err := config.Duration("POLL", time.Second)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	ix, err := indexer.New(ctx, indexer.Config{
		Vault: base.Vault.Vault, NetworkID: base.NetworkID, DeployLedger: base.Vault.DeployLedger,
		ArchiveDir: config.Env("ARCHIVE_DIR", ""), MaxLag: 12, ProbeMaxAge: 30 * time.Second, Native: base.Vault.Asset == "native",
	}, base.RPC, chain, base.Alerts, log)
	if err != nil {
		service.Fatal(log, "load", err)
	}
	f, err := base.Follower(ix)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	go ix.Run(ctx, f, poll)

	addr := config.Env("LISTEN_ADDR", "127.0.0.1:8080")
	log.Info("serving", "vault", base.Vault.Vault, "addr", addr)
	if err := httpapi.Serve(ctx, addr, ix.Handler()); err != nil && ctx.Err() == nil {
		service.Fatal(log, "serve", err)
	}
}
