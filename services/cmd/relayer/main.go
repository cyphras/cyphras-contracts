// Command relayer submits transfers and unshields for one vault from its channel accounts, for a
// fee that covers the cost and is paid in the pool asset to an address whose key is offline.
package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/groth16"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/relayer"
	"github.com/cyphras/cyphras-contracts/services/internal/service"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
)

// minChannels is the fewest channel accounts a relayer runs with.
const minChannels = 4

func main() {
	ctx, stop := service.Context()
	defer stop()
	base, err := service.Start(ctx, "relayer")
	if err != nil {
		service.Fatal(service.Logger("relayer"), "start", err)
	}
	log := base.Log
	r, err := build(ctx, base)
	if err != nil {
		service.Fatal(log, "start", err)
	}
	if err := r.Resume(); err != nil {
		service.Fatal(log, "resume", err)
	}
	go r.Run(10 * time.Second)
	addr := config.Env("LISTEN_ADDR", "127.0.0.1:8081")
	log.Info("serving", "vault", base.Vault.Vault, "addr", addr)
	if err := httpapi.Serve(ctx, addr, r.Handler()); err != nil && ctx.Err() == nil {
		service.Fatal(log, "serve", err)
	}
	r.Wait()
}

func build(ctx context.Context, base *service.Base) (*relayer.Relayer, error) {
	feeAddress, err := config.Required("FEE_ADDRESS")
	if err != nil {
		return nil, err
	}
	if !strkey.IsValidEd25519PublicKey(feeAddress) {
		return nil, errors.New("FEE_ADDRESS must be a G account")
	}
	keys, err := config.Keys("CHANNEL_KEYS")
	if err != nil {
		return nil, err
	}
	if len(keys) < minChannels {
		return nil, fmt.Errorf("at least %d channel accounts are needed", minChannels)
	}
	var channels []*submit.Account
	for _, k := range keys {
		if k.Address() == feeAddress {
			return nil, errors.New("the fee address must not be a channel; its key stays offline")
		}
		if err := service.CheckSigner(ctx, base.RPC, k.Address(), k); err != nil {
			return nil, err
		}
		channels = append(channels, submit.NewAccount(k.Address(), k))
	}
	tier, err := base.Vault.Tier()
	if err != nil {
		return nil, err
	}
	margin, err := config.Int("MARGIN_BPS", 500)
	if err != nil {
		return nil, err
	}
	pricing := relayer.Pricing{Native: base.Vault.Asset == "native", MarginBps: margin, Tier: tier}
	if !pricing.Native {
		num, den, ok := strings.Cut(config.Env("ASSET_PER_STROOP", ""), "/")
		n, ok1 := new(big.Int).SetString(num, 10)
		d, ok2 := new(big.Int).SetString(den, 10)
		if !ok || !ok1 || !ok2 {
			return nil, errors.New("ASSET_PER_STROOP must be a fraction such as 3/10")
		}
		pricing.PerStroopNum, pricing.PerStroopDen = n, d
	}
	bootstrap, err := config.Int("BOOTSTRAP_RESOURCE_FEE", 2_000_000)
	if err != nil {
		return nil, err
	}
	screenURL, err := config.Required("SCREENING_URL")
	if err != nil {
		return nil, err
	}
	token, err := config.SecretString("SCREEN_TOKEN")
	if err != nil {
		return nil, err
	}
	dbURL, err := service.DatabaseURL()
	if err != nil {
		return nil, err
	}
	pool, err := chainstate.Open(ctx, dbURL, relayer.Schema)
	if err != nil {
		return nil, err
	}
	if err := base.StartAlerts(ctx, pool); err != nil {
		return nil, err
	}
	engine, err := service.Engine(base.RPC, base.Deployment.NetworkPassphrase)
	if err != nil {
		return nil, err
	}
	keyPath, err := config.Required("VERIFICATION_KEY_FILE")
	if err != nil {
		return nil, err
	}
	rawKey, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := groth16.ParseKey(rawKey)
	if err != nil {
		return nil, err
	}
	r, err := relayer.New(ctx, relayer.Config{
		Vault: base.Vault.Vault, NetworkID: base.NetworkID, Asset: base.Vault.Asset, FeeAddress: feeAddress,
		Pricing: pricing, LedgerSeconds: 5, MaxHeld: 1000, Jitter: 10 * time.Minute, Key: key,
	}, base.RPC, engine, channels,
		relayer.ScreeningClient{URL: screenURL, Token: token, HTTP: &http.Client{Timeout: 5 * time.Second}},
		relayer.NewStore(pool), bootstrap, base.Alerts, base.Log)
	if err != nil {
		return nil, err
	}
	// Every relayed fee goes to the fee address, so the vault would refuse every relay if it could
	// not receive the asset. A fee is too small to create the account.
	ok, err := r.CanReceive(ctx, feeAddress, new(big.Int))
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("the fee address cannot receive the vault's asset: it needs an account and an authorized trustline")
	}
	return r, nil
}
