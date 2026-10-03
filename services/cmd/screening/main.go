// Command screening is the association set provider. It screens deposits and unshield
// destinations, attests and flags deposits with the asp account's hot signer, and records every
// decision. Operator commands:
//
//	screening review list
//	screening review clear|refuse <deposit> <reviewer>
//	screening flag <deposit> <4|99|100> <reviewer> <note>
//	screening unflag <deposit> <reviewer> <note>
//	screening register fraud_report|legal_request <note>
//
// Only one process sends as the asp account. A flag or unflag given while the service runs is
// queued, and the service carries it out in its next round.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stellar/go-stellar-sdk/strkey"

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
		service.Fatal(service.Logger("screening"), "start", err)
	}
	log := base.Log
	b, err := build(ctx, base)
	if err != nil {
		service.Fatal(log, "start", err)
	}
	s := b.screener
	if cmd := service.Command("serve"); cmd != "serve" {
		if err := operate(ctx, b, os.Args[1:]); err != nil {
			service.Fatal(log, cmd, err)
		}
		return
	}
	lock, err := screening.LockWriter(ctx, b.pool, b.asp)
	if err != nil {
		service.Fatal(log, "start", err)
	}
	defer lock.Release()
	s.UseLock(lock)
	go lock.Keep(ctx, 10*time.Second)
	go func() {
		select {
		case <-lock.Lost():
			if ctx.Err() == nil {
				service.Fatal(log, "writer lock", screening.ErrLockLost)
			}
		case <-ctx.Done():
		}
	}()

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
	if err := httpapi.Serve(ctx, addr, s.Public(httpapi.NewLimiter(300, 50), httpapi.NewLimiter(3000, 300))); err != nil && ctx.Err() == nil {
		service.Fatal(log, "serve", err)
	}
}

// built is the screener with what an operator command needs besides it.
type built struct {
	screener *screening.Screener
	pool     *pgxpool.Pool
	asp      string
}

func build(ctx context.Context, base *service.Base) (*built, error) {
	dbURL, err := service.DatabaseURL()
	if err != nil {
		return nil, err
	}
	pool, err := chainstate.Open(ctx, dbURL, screening.Schema)
	if err != nil {
		return nil, err
	}
	if err := base.StartAlerts(ctx, pool); err != nil {
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
	if err := service.CheckHotSigner(ctx, base.RPC, inst.Config.ASP, hot); err != nil {
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
	check, err := checker(sources)
	if err != nil {
		return nil, err
	}
	lookups, err := config.Int("REQUEST_LOOKUPS_PER_MINUTE", 30)
	if err != nil {
		return nil, err
	}
	workers, err := config.Int("SCREEN_WORKERS", 4)
	if err != nil {
		return nil, err
	}
	tickChecks, err := config.Int("SCREEN_TICK_CHECKS", 40)
	if err != nil {
		return nil, err
	}
	tickBudget, err := config.Duration("SCREEN_TICK_BUDGET", 15*time.Second)
	if err != nil {
		return nil, err
	}
	reviewSLA, err := config.Duration("REVIEW_SLA", 2*time.Hour)
	if err != nil {
		return nil, err
	}
	s, err := screening.New(ctx, screening.Config{
		Vault: base.Vault.Vault, DeployLedger: base.Vault.DeployLedger, NetworkID: base.NetworkID, Network: base.Deployment.Network,
		PolicyVersion: config.Env("POLICY_VERSION", "1"),
		RecheckWindow: 10 * time.Minute, Cutoff: 8 * time.Minute, FirstCheckWithin: 10 * time.Minute, RequestLookups: int(lookups),
		Workers: int(workers), TickChecks: int(tickChecks), TickBudget: tickBudget, ReviewSLA: reviewSLA,
	}, base.RPC, &chainstate.Store{Pool: pool}, check, engine, submit.NewAccount(inst.Config.ASP, hot), base.Alerts, base.Log)
	if err != nil {
		return nil, err
	}
	return &built{screener: s, pool: pool, asp: inst.Config.ASP}, nil
}

// checker builds the deposit checker from the funder settings, with conservative defaults: a
// funder counts unless it sent less than 1 percent of an address's inflows and less than 10 XLM.
func checker(sources []screening.Source) (*screening.Checker, error) {
	maxFunders, err := config.Int("MAX_FUNDERS", 25)
	if err != nil {
		return nil, err
	}
	maxPages, err := config.Int("FUNDER_MAX_PAGES", 50)
	if err != nil {
		return nil, err
	}
	shareBps, err := config.Int("FUNDER_DUST_SHARE_BPS", 100)
	if err != nil {
		return nil, err
	}
	if maxFunders < 1 || maxPages < 1 || shareBps < 0 || shareBps > 10_000 {
		return nil, errors.New("MAX_FUNDERS and FUNDER_MAX_PAGES must be positive, FUNDER_DUST_SHARE_BPS 0 to 10000")
	}
	floors := map[string]*big.Int{}
	for _, f := range list(config.Env("FUNDER_DUST_FLOORS", "native=100000000"), ",") {
		asset, amount, ok := strings.Cut(f, "=")
		n, valid := new(big.Int).SetString(amount, 10)
		if !ok || !valid || n.Sign() < 0 {
			return nil, fmt.Errorf("FUNDER_DUST_FLOORS entry %q is not asset=amount", f)
		}
		floors[asset] = n
	}
	exempt := map[string]bool{}
	for _, a := range list(config.Env("FUNDER_EXEMPT", ""), ",") {
		if !strkey.IsValidEd25519PublicKey(a) {
			return nil, fmt.Errorf("FUNDER_EXEMPT entry %q is not an account", a)
		}
		exempt[a] = true
	}
	horizonURL, err := config.Value("HORIZON_URL")
	if err != nil {
		return nil, err
	}
	return &screening.Checker{
		Sources: sources,
		Inflows: &screening.CachedInflows{
			Inner: horizon.Client{URL: horizonURL, HTTP: &http.Client{Timeout: 20 * time.Second}, MaxPages: int(maxPages), Floors: floors},
			TTL:   10 * time.Minute, Now: time.Now,
		},
		MaxFunders: int(maxFunders),
		Dust:       screening.Dust{ShareBps: shareBps, Floors: floors},
		Exempt:     exempt,
	}, nil
}

func list(s, sep string) []string {
	var out []string
	for _, v := range strings.Split(s, sep) {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// guard is a source's update guard: SOURCE_MAX_SHRINK_PCT, 20 unless set, and the canaries in the
// variable named, separated by "|", or else the defaults given.
func guard(canaries, defaults string) (*screening.Guard, error) {
	shrink, err := config.Int("SOURCE_MAX_SHRINK_PCT", 20)
	if err != nil {
		return nil, err
	}
	if shrink < 0 || shrink > 100 {
		return nil, errors.New("SOURCE_MAX_SHRINK_PCT must be 0 to 100")
	}
	return &screening.Guard{MaxShrinkPct: int(shrink), Canaries: list(config.Env(canaries, defaults), "|")}, nil
}

// ofacCanaries is text every good copy of the SDN list holds: two kinds of digital-currency
// address it has carried for years, and an entity listed since 2019.
const ofacCanaries = "Digital Currency Address - XBT|Digital Currency Address - ETH|LAZARUS GROUP"

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
		g, err := guard("EXPLOIT_LIST_CANARIES", "")
		if err != nil {
			return nil, err
		}
		src := screening.NewFileSource("curated_list", path, age)
		src.Guard(g)
		sources = append(sources, src)
	}
	if url := config.Env("OFAC_URL", ""); url != "" {
		age, err := config.Duration("OFAC_MAX_AGE", 48*time.Hour)
		if err != nil {
			return nil, err
		}
		g, err := guard("OFAC_CANARIES", ofacCanaries)
		if err != nil {
			return nil, err
		}
		src := screening.NewOFACSource(url, age)
		src.Guard(g)
		sources = append(sources, src)
	}
	if url := config.Env("DIRECTORY_URL", ""); url != "" {
		age, err := config.Duration("DIRECTORY_MAX_AGE", 24*time.Hour)
		if err != nil {
			return nil, err
		}
		g, err := guard("DIRECTORY_CANARIES", "")
		if err != nil {
			return nil, err
		}
		src := screening.NewDirectorySource(url, age)
		src.Guard(g)
		sources = append(sources, src)
	}
	return sources, nil
}

// writeOrQueue sends an operator's decision as the asp account when no other process does, and
// otherwise queues it for the running service.
func writeOrQueue(ctx context.Context, b *built, send func() error, queue func() (int64, error)) error {
	lock, err := screening.LockWriter(ctx, b.pool, b.asp)
	switch {
	case errors.Is(err, screening.ErrWriterRunning):
		id, err := queue()
		if err != nil {
			return err
		}
		fmt.Printf("queued as %d; the running service carries it out in its next round\n", id)
		return nil
	case err != nil:
		return err
	}
	defer lock.Release()
	b.screener.UseLock(lock)
	return send()
}

func operate(ctx context.Context, b *built, args []string) error {
	s := b.screener
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
		return writeOrQueue(ctx, b,
			func() error { return s.FlagManually(ctx, dep, uint32(reason), args[3], args[4]) },
			func() (int64, error) { return s.QueueFlag(ctx, dep, uint32(reason), args[3], args[4]) })
	case len(args) == 4 && args[0] == "unflag":
		dep, err := id(1)
		if err != nil {
			return err
		}
		return writeOrQueue(ctx, b,
			func() error { return s.Unflag(ctx, dep, args[2], args[3]) },
			func() (int64, error) { return s.QueueUnflag(ctx, dep, args[2], args[3]) })
	case len(args) == 3 && args[0] == "register":
		return s.Register(ctx, args[1], args[2])
	}
	return errors.New("unknown command; see the package documentation")
}
