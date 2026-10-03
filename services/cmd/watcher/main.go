// Command watcher checks one vault from outside and pages a person through at least two
// independent channels, and posts governance events to a public one. It holds no keys and serves
// no API, so anyone can run one.
package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
	"github.com/cyphras/cyphras-contracts/services/internal/watcher"
)

func main() {
	ctx, stop := service.Context()
	defer stop()
	base, err := service.Start(ctx, "watcher")
	if err != nil {
		service.Fatal(service.Logger("watcher"), "start", err)
	}
	log := base.Log
	if len(base.Alerts.Channels) < 2 {
		service.Fatal(log, "config", errors.New("the watcher pages through two independent channels; ALERT_WEBHOOKS_FILE must list at least two"))
	}
	public := &alert.Alerter{Service: "watcher", Log: log, Cooldown: time.Hour}
	if os.Getenv("PUBLIC_WEBHOOKS_FILE") != "" {
		data, err := config.Secret("PUBLIC_WEBHOOKS")
		if err != nil {
			service.Fatal(log, "config", err)
		}
		if public.Channels, err = alert.ParseWebhooks(data); err != nil {
			service.Fatal(log, "config", err)
		}
	}
	secondURL, err := config.Value("SECOND_RPC_URL")
	if err != nil {
		service.Fatal(log, "config", err)
	}
	second := rpc.Dial(secondURL)
	if err := rpc.CheckNetwork(ctx, second, base.Deployment.NetworkPassphrase); err != nil {
		service.Fatal(log, "second rpc", err)
	}
	var hz *horizon.Client
	if os.Getenv("HORIZON_URL") != "" || os.Getenv("HORIZON_URL_FILE") != "" {
		u, err := config.Value("HORIZON_URL")
		if err != nil {
			service.Fatal(log, "config", err)
		}
		hz = &horizon.Client{URL: u, HTTP: &http.Client{Timeout: 20 * time.Second}, MaxPages: 10}
	}
	cfg, err := settings(base)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	dbURL, err := service.DatabaseURL()
	if err != nil {
		service.Fatal(log, "database url", err)
	}
	pool, err := chainstate.Open(ctx, dbURL, watcher.Schema)
	if err != nil {
		service.Fatal(log, "database", err)
	}
	defer pool.Close()
	// A webhook that fails must never lose a page, so both queues keep what waits in the database.
	if err := base.StartAlerts(ctx, pool); err != nil {
		service.Fatal(log, "alerts", err)
	}
	if err := service.StartQueue(ctx, public, "public", pool, log); err != nil {
		service.Fatal(log, "alerts", err)
	}
	w, err := watcher.New(ctx, cfg, base.RPC, second, &chainstate.Store{Pool: pool}, hz, base.Alerts, public, log)
	if err != nil {
		service.Fatal(log, "load", err)
	}
	beat, err := service.LoadHeartbeat()
	if err != nil {
		service.Fatal(log, "config", err)
	}
	if beat != nil {
		w.SetHeartbeat(beat.Ping)
	}
	f, err := base.Follower(w)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	log.Info("watching", "vault", base.Vault.Vault, "hot_accounts", len(cfg.HotAccounts), "health_urls", len(cfg.HealthURLs))
	w.Run(ctx, f, time.Second)
}

func list(name string) []string {
	var out []string
	for _, s := range strings.Split(config.Env(name, ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// settings reads the watcher's thresholds and the accounts it watches.
func settings(base *service.Base) (watcher.Config, error) {
	cfg := watcher.Config{
		Vault: base.Vault.Vault, DeployLedger: base.Vault.DeployLedger,
		IndexerURL: config.Env("INDEXER_URL", ""), HealthURLs: list("HEALTH_URLS"),
		ServiceAccounts: list("SERVICE_ACCOUNTS"), IgnoreFunders: map[string]bool{},
	}
	for _, f := range list("ROUND_TRIP_IGNORE") {
		cfg.IgnoreFunders[f] = true
	}
	multiple, err := strconv.ParseFloat(config.Env("BURST_MULTIPLE", "5"), 64)
	if err != nil || multiple <= 0 {
		return cfg, fmt.Errorf("BURST_MULTIPLE must be a positive number")
	}
	cfg.BurstMultiple = multiple
	for _, s := range []struct {
		name string
		def  int64
		dst  func(int64)
	}{
		{"BURST_FLOOR", 20, func(v int64) { cfg.BurstFloor = v }},
		{"QUEUE_LENGTH", 50, func(v int64) { cfg.QueueLength = uint64(v) }},
		{"ROUND_TRIPS", 3, func(v int64) { cfg.RoundTrips = int(v) }},
		{"EARLY_SHARE", 80, func(v int64) { cfg.EarlyShare = v }},
	} {
		v, err := config.Int(s.name, s.def)
		if err != nil || v < 1 {
			return cfg, fmt.Errorf("%s must be a positive integer", s.name)
		}
		s.dst(v)
	}
	if cfg.QueueAge, err = config.Duration("QUEUE_AGE", 48*time.Hour); err != nil {
		return cfg, err
	}
	if cfg.EarlyWindow, err = config.Duration("EARLY_WINDOW", 2*time.Hour); err != nil {
		return cfg, err
	}
	if path := config.Env("HOT_ACCOUNTS_FILE", ""); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		if cfg.HotAccounts, err = watcher.ParseHotAccounts(data); err != nil {
			return cfg, err
		}
	}
	for _, h := range cfg.HotAccounts {
		cfg.ServiceAccounts = append(cfg.ServiceAccounts, h.Address)
	}
	return cfg, nil
}
