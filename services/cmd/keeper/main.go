// Command keeper keeps one vault's entries alive, admits eligible deposits, refunds deposits that
// stayed flagged and pays queued and stranded exits, from its own funded account. It serves no API.
package main

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/keeper"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
)

func main() {
	ctx, stop := service.Context()
	defer stop()
	base, err := service.Start(ctx, "keeper")
	if err != nil {
		service.Fatal(nil, "start", err)
	}
	log := base.Log
	key, err := config.Key("KEEPER_KEY")
	if err != nil {
		service.Fatal(log, "key", err)
	}
	dbURL, err := service.DatabaseURL()
	if err != nil {
		service.Fatal(log, "database url", err)
	}
	pool, err := chainstate.Open(ctx, dbURL, "")
	if err != nil {
		service.Fatal(log, "database", err)
	}
	defer pool.Close()
	engine, err := service.Engine(base.RPC, base.Deployment.NetworkPassphrase)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	hold := map[uint32]bool{}
	for _, r := range strings.Split(config.Env("HOLD_REASONS", "99"), ",") {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		n, err := strconv.ParseUint(r, 10, 32)
		if err != nil {
			service.Fatal(log, "config", err)
		}
		hold[uint32(n)] = true
	}
	floor, err := config.Int("BALANCE_FLOOR", 500_000_000)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	releases, err := config.Int("RELEASE_BATCH", 10)
	if err == nil && (releases < 1 || releases > 100) {
		err = errors.New("RELEASE_BATCH must be 1 to 100")
	}
	if err != nil {
		service.Fatal(log, "config", err)
	}
	k, err := keeper.New(ctx, keeper.Config{
		Vault: base.Vault.Vault, DeployLedger: base.Vault.DeployLedger, MaxAdmissions: 17, MaxExtensions: 50,
		MaxReleases: int(releases), RefundDelay: 24 * time.Hour, HoldReasons: hold, BalanceFloor: floor,
	}, base.RPC, &chainstate.Store{Pool: pool}, engine, submit.NewAccount(key.Address(), key), base.Alerts, log)
	if err != nil {
		service.Fatal(log, "load", err)
	}
	f, err := base.Follower(k)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	log.Info("running", "vault", base.Vault.Vault, "account", key.Address())
	k.Run(ctx, f, time.Second)
}
