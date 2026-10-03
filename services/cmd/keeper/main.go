// Command keeper keeps one vault's entries alive, admits eligible deposits, refunds deposits that
// stayed flagged, pays the exit queue and queues stranded exits again, from its own funded
// account. It serves no API.
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
		service.Fatal(service.Logger("keeper"), "start", err)
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
	if err := base.StartAlerts(ctx, pool); err != nil {
		service.Fatal(log, "alerts", err)
	}
	engine, err := service.Engine(base.RPC, base.Deployment.NetworkPassphrase, base.Log)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	hold, err := holdReasons()
	if err != nil {
		service.Fatal(log, "config", err)
	}
	floor, err := config.Int("BALANCE_FLOOR", 500_000_000)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	releases, err := config.Int("RELEASE_BATCH", 15)
	if err == nil && (releases < 1 || releases > 15) {
		err = errors.New("RELEASE_BATCH must be 1 to 15")
	}
	if err != nil {
		service.Fatal(log, "config", err)
	}
	exitKeys, err := service.ExitKeys()
	if err != nil {
		service.Fatal(log, "config", err)
	}
	k, err := keeper.New(ctx, keeper.Config{
		Vault: base.Vault.Vault, DeployLedger: base.Vault.DeployLedger, Asset: base.Vault.Asset, MaxAdmissions: 16, MaxExtensions: 50,
		MaxReleases: int(releases), RefundDelay: 24 * time.Hour, HoldReasons: hold, BalanceFloor: floor, ExitKeys: exitKeys,
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

// holdReasons reads HOLD_REASONS, the flag reasons the keeper never refunds: by default a written
// order from an authority only. A screening hold, reason 6, may not be one of them, since a hold
// is harmless only because its deposit goes back to the depositor once the refund delay passes.
func holdReasons() (map[uint32]bool, error) {
	hold := map[uint32]bool{}
	for _, r := range strings.Split(config.Env("HOLD_REASONS", "100"), ",") {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		n, err := strconv.ParseUint(r, 10, 32)
		if err != nil {
			return nil, err
		}
		if n == screeningHold {
			return nil, errors.New("HOLD_REASONS may not hold reason 6: a screening hold must be refunded once its delay passes")
		}
		hold[uint32(n)] = true
	}
	return hold, nil
}

// screeningHold is the reason of the screening service's holds.
const screeningHold = 6
