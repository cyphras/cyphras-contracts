// Command screening is the association set provider. It screens deposits and unshield
// destinations, attests and flags deposits with the asp account's hot signer, and records every
// decision. Operator commands:
//
//	screening review list
//	screening review clear|refuse <deposit> <reviewer>
//	screening flag <deposit> <4|99> <reviewer> <note>
//	screening unflag <deposit> <reviewer> <note>
//	screening register fraud_report|legal_request <note>
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/screening"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
)

func main() {
	ctx, stop := service.Context()
	defer stop()
	base, err := service.Start(ctx, "screening")
	if err != nil {
		service.Fatal(nil, "start", err)
	}
	log := base.Log
	s, err := build(ctx, base)
	if err != nil {
		service.Fatal(log, "start", err)
	}
	if cmd := service.Command("serve"); cmd != "serve" {
		if err := operate(ctx, s, os.Args[1:]); err != nil {
			service.Fatal(log, cmd, err)
		}
		return
	}

	tokenHash, err := hex.DecodeString(config.Env("SCREEN_TOKEN_SHA256", ""))
	if err != nil || len(tokenHash) != 32 {
		service.Fatal(log, "config", errors.New("SCREEN_TOKEN_SHA256 must be 64 hex digits"))
	}
	poll, err := config.Duration("POLL", time.Second)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	f, err := base.Follower(s)
	if err != nil {
		service.Fatal(log, "config", err)
	}
	go s.Run(ctx, f, poll, 20*time.Second, 5*time.Minute)
	go func() {
		addr := config.Env("INTERNAL_ADDR", "127.0.0.1:8091")
		if err := httpapi.Serve(ctx, addr, s.Internal([32]byte(tokenHash))); err != nil && ctx.Err() == nil {
			service.Fatal(log, "serve internal", err)
		}
	}()
	addr := config.Env("LISTEN_ADDR", "127.0.0.1:8090")
	log.Info("serving", "vault", base.Vault.Vault, "addr", addr)
	if err := httpapi.Serve(ctx, addr, s.Public(httpapi.NewLimiter(30, 10), httpapi.NewLimiter(60, 20))); err != nil && ctx.Err() == nil {
		service.Fatal(log, "serve", err)
	}
}

func build(ctx context.Context, base *service.Base) (*screening.Screener, error) {
	dbURL, err := service.DatabaseURL()
	if err != nil {
		return nil, err
	}
	pool, err := chainstate.Open(ctx, dbURL, screening.Schema)
	if err != nil {
		return nil, err
	}
	hot, err := config.Key("ASP_KEY")
	if err != nil {
		return nil, err
	}
	inst, _, _, err := rpc.VaultInstance(ctx, base.RPC, base.Vault.Vault)
	if err != nil {
		return nil, err
	}
	if err := service.CheckSigner(ctx, base.RPC, inst.Config.ASP, hot); err != nil {
		return nil, err
	}
	engine, err := service.Engine(base.RPC, base.Deployment.NetworkPassphrase)
	if err != nil {
		return nil, err
	}
	sources, err := sourcesFromEnv(base)
	if err != nil {
		return nil, err
	}
	maxFunders, err := config.Int("MAX_FUNDERS", 25)
	if err != nil {
		return nil, err
	}
	horizonURL, err := config.Value("HORIZON_URL")
	if err != nil {
		return nil, err
	}
	check := &screening.Checker{
		Sources:    sources,
		Funders:    horizon.Client{URL: horizonURL, HTTP: &http.Client{Timeout: 20 * time.Second}, MaxPages: 10},
		MaxFunders: int(maxFunders),
	}
	return screening.New(ctx, screening.Config{
		Vault: base.Vault.Vault, DeployLedger: base.Vault.DeployLedger, Network: base.Deployment.Network,
		PolicyVersion: config.Env("POLICY_VERSION", "1"),
		RecheckWindow: 10 * time.Minute, Cutoff: 2 * time.Minute, FirstCheckWithin: 10 * time.Minute,
	}, base.RPC, &chainstate.Store{Pool: pool}, check, engine, submit.NewAccount(inst.Config.ASP, hot), base.Alerts, base.Log)
}

func sourcesFromEnv(base *service.Base) ([]screening.Source, error) {
	frozenAge, err := config.Duration("FROZEN_MAX_AGE", 15*time.Minute)
	if err != nil {
		return nil, err
	}
	sources := []screening.Source{screening.NewFrozenSource(base.RPC, frozenAge)}
	if path := config.Env("EXPLOIT_LIST_FILE", ""); path != "" {
		age, err := config.Duration("EXPLOIT_LIST_MAX_AGE", 30*24*time.Hour)
		if err != nil {
			return nil, err
		}
		sources = append(sources, screening.NewFileSource("curated_list", path, age))
	}
	if url := config.Env("OFAC_URL", ""); url != "" {
		age, err := config.Duration("OFAC_MAX_AGE", 48*time.Hour)
		if err != nil {
			return nil, err
		}
		sources = append(sources, screening.NewOFACSource(url, age))
	}
	if url := config.Env("DIRECTORY_URL", ""); url != "" {
		age, err := config.Duration("DIRECTORY_MAX_AGE", 24*time.Hour)
		if err != nil {
			return nil, err
		}
		sources = append(sources, screening.NewDirectorySource(url, age))
	}
	return sources, nil
}

func operate(ctx context.Context, s *screening.Screener, args []string) error {
	id := func(i int) (uint64, error) {
		if len(args) <= i {
			return 0, errors.New("missing deposit id")
		}
		return strconv.ParseUint(args[i], 10, 64)
	}
	switch {
	case len(args) == 2 && args[0] == "review" && args[1] == "list":
		reviews, err := s.Reviews(ctx)
		if err != nil {
			return err
		}
		for _, r := range reviews {
			fmt.Printf("%d\t%s\t%s\t%s\n", r.ID, r.Depositor, r.Amount, time.Unix(int64(r.CreatedAt), 0).UTC().Format(time.RFC3339))
		}
		return nil
	case len(args) == 4 && args[0] == "review" && (args[1] == "clear" || args[1] == "refuse"):
		dep, err := id(2)
		if err != nil {
			return err
		}
		return s.DecideReview(ctx, dep, args[3], args[1] == "clear")
	case len(args) == 5 && args[0] == "flag":
		dep, err := id(1)
		if err != nil {
			return err
		}
		reason, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return err
		}
		return s.FlagManually(ctx, dep, uint32(reason), args[3], args[4])
	case len(args) == 4 && args[0] == "unflag":
		dep, err := id(1)
		if err != nil {
			return err
		}
		return s.Unflag(ctx, dep, args[2], args[3])
	case len(args) == 3 && args[0] == "register":
		return s.Register(ctx, args[1], args[2])
	}
	return errors.New("unknown command; see the package documentation")
}
