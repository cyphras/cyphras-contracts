// Package service holds the start-up steps every service binary shares.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
)

// Version is set at build time from the release tag.
var Version = "dev"

// Base is what every service starts with.
type Base struct {
	Name       string
	Log        *slog.Logger
	Alerts     *alert.Alerter
	Deployment config.Deployment
	Vault      config.DeployedVault
	RPC        rpc.Client
	NetworkID  [32]byte
}

// Context returns a context cancelled by SIGINT or SIGTERM.
func Context() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}

// Logger writes JSON lines to stdout; the container runtime rotates them.
func Logger(name string) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", name, "version", Version)
}

// Alerter pages through the webhooks in ALERT_WEBHOOKS_FILE, if that is set.
func Alerter(name string, log *slog.Logger) (*alert.Alerter, error) {
	a := &alert.Alerter{Service: name, Log: log, Cooldown: 15 * time.Minute}
	if os.Getenv("ALERT_WEBHOOKS_FILE") == "" {
		log.Warn("no alert webhooks configured; alerts go to the log only")
		return a, nil
	}
	data, err := config.Secret("ALERT_WEBHOOKS")
	if err != nil {
		return nil, err
	}
	channels, err := alert.ParseWebhooks(data)
	if err != nil {
		return nil, err
	}
	a.Channels = channels
	return a, nil
}

// Start loads the deployment and the vault named by VAULT, connects to RPC_URL (or the file named
// by RPC_URL_FILE) and refuses an RPC that serves another network.
func Start(ctx context.Context, name string) (*Base, error) {
	log := Logger(name)
	alerts, err := Alerter(name, log)
	if err != nil {
		return nil, err
	}
	path, err := config.Required("DEPLOYMENT_FILE")
	if err != nil {
		return nil, err
	}
	vaultID, err := config.Required("VAULT")
	if err != nil {
		return nil, err
	}
	deployment, v, err := config.LoadDeployment(path, vaultID)
	if err != nil {
		return nil, err
	}
	url, err := config.Value("RPC_URL")
	if err != nil {
		return nil, err
	}
	client := rpc.Dial(url)
	if err := rpc.CheckNetwork(ctx, client, deployment.NetworkPassphrase); err != nil {
		return nil, err
	}
	inst, _, _, err := rpc.VaultInstance(ctx, client, v.Vault)
	if err != nil {
		return nil, fmt.Errorf("read the vault: %w", err)
	}
	if inst.Config.Token != v.Token {
		return nil, fmt.Errorf("the vault holds %s, the deployment file names %s", inst.Config.Token, v.Token)
	}
	return &Base{
		Name: name, Log: log, Alerts: alerts, Deployment: deployment, Vault: v, RPC: client,
		NetworkID: rpc.NetworkID(deployment.NetworkPassphrase),
	}, nil
}

// DatabaseURL reads the connection string, which holds a password, from DATABASE_URL_FILE.
func DatabaseURL() (string, error) {
	return config.SecretString("DATABASE_URL")
}

// Command returns the subcommand, the first argument, or def when there is none.
func Command(def string) string {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		return os.Args[1]
	}
	return def
}

// Fatal logs the error and exits.
func Fatal(log *slog.Logger, msg string, err error) {
	if log == nil {
		log = Logger("unknown")
	}
	log.Error(msg, "error", err.Error())
	os.Exit(1)
}

// History returns the sources of ledgers older than the RPC keeps: the event archive in
// ARCHIVE_DIR, then the ledger metadata archive at LEDGER_META_ARCHIVE_URL.
func (b *Base) History() []follow.Source {
	var out []follow.Source
	if dir := config.Env("ARCHIVE_DIR", ""); dir != "" {
		out = append(out, archive.Reader{Dir: dir, Vault: b.Vault.Vault})
	}
	if url := config.Env("LEDGER_META_ARCHIVE_URL", ""); url != "" {
		out = append(out, &follow.LedgerArchive{
			BaseURL: url, Passphrase: b.Deployment.NetworkPassphrase, Vault: b.Vault.Vault, Workers: 16,
		})
	}
	return out
}

// Follower follows the vault into sink from the RPC, with History for older ledgers.
func (b *Base) Follower(sink follow.Sink) (*follow.Follower, error) {
	window, err := config.Int("WINDOW_LEDGERS", 500)
	if err != nil {
		return nil, err
	}
	if window < 1 || window > 10_000 {
		return nil, fmt.Errorf("WINDOW_LEDGERS %d is outside 1 to 10000", window)
	}
	return &follow.Follower{
		RPC: b.RPC, Live: follow.RPCSource{Client: b.RPC, Contract: b.Vault.Vault, PageLimit: 1000},
		History: b.History(), Window: uint32(window), Sink: sink,
	}, nil
}
