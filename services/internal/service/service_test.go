package service

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

func TestTheSubcommandIsTheFirstArgument(t *testing.T) {
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"indexer"}
	if Command("serve") != "serve" {
		t.Fatal("default command")
	}
	os.Args = []string{"indexer", "rebuild"}
	if Command("serve") != "rebuild" {
		t.Fatal("rebuild")
	}
	os.Args = []string{"indexer", "-v"}
	if Command("serve") != "serve" {
		t.Fatal("a flag is not a command")
	}
}

func TestAServicePagesThroughAtLeastTwoChannels(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := Alerter("keeper", log); err == nil {
		t.Fatal("started without webhooks")
	}
	dir := t.TempDir()
	hooks := func(lines string) {
		path := filepath.Join(dir, "hooks")
		_ = os.Remove(path)
		if err := os.WriteFile(path, []byte(lines), 0o400); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ALERT_WEBHOOKS_FILE", path)
	}
	hooks("# being rewritten\n")
	t.Setenv("ALERT_DEV", "1")
	if _, err := Alerter("keeper", log); err == nil {
		t.Fatal("started with no channel")
	}
	hooks("slack https://hooks.example/a\n")
	if a, err := Alerter("keeper", log); err != nil || len(a.Channels) != 1 {
		t.Fatalf("one channel for development: %v", err)
	}
	t.Setenv("ALERT_DEV", "")
	if _, err := Alerter("keeper", log); err == nil {
		t.Fatal("started with one channel")
	}
	hooks("slack https://hooks.example/a\ntext https://ntfy.example/b\n")
	if a, err := Alerter("keeper", log); err != nil || len(a.Channels) != 2 {
		t.Fatalf("with two channels: %v", err)
	}
}

func TestASignerMustMeetTheMediumThreshold(t *testing.T) {
	f := rpctest.New("Test SDF Network ; September 2015", 1)
	account := keypair.MustRandom()
	hot := keypair.MustRandom()
	key, _ := vault.AccountKey(account.Address())
	set := func(master, medium, hotWeight uint32) {
		var signers []xdr.Signer
		if hotWeight > 0 {
			sk, _ := xdr.AddressToAccountId(hot.Address())
			signers = append(signers, xdr.Signer{Key: xdr.SignerKey{Type: xdr.SignerKeyTypeSignerKeyTypeEd25519, Ed25519: sk.Ed25519}, Weight: xdr.Uint32(hotWeight)})
		}
		f.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{
			AccountId: key.MustAccount().AccountId, Thresholds: xdr.Thresholds{byte(master), 1, byte(medium), 3}, Signers: signers,
		}}, 1, nil)
	}
	ctx := context.Background()
	set(0, 2, 2)
	if err := CheckSigner(ctx, f, account.Address(), hot); err != nil {
		t.Fatal(err)
	}
	set(0, 2, 1)
	if err := CheckSigner(ctx, f, account.Address(), hot); err == nil {
		t.Fatal("a weak signer accepted")
	}
	set(2, 2, 0)
	if err := CheckSigner(ctx, f, account.Address(), account); err != nil {
		t.Fatal("the master key with enough weight")
	}
	if err := CheckSigner(ctx, f, account.Address(), hot); err == nil {
		t.Fatal("a key that is not a signer accepted")
	}
}

func TestAHotSignerIsNeitherTheMasterNorAtTheHighThreshold(t *testing.T) {
	f := rpctest.New("Test SDF Network ; September 2015", 1)
	account, hot := keypair.MustRandom(), keypair.MustRandom()
	key, _ := vault.AccountKey(account.Address())
	set := func(medium, high, hotWeight uint32) {
		sk, _ := xdr.AddressToAccountId(hot.Address())
		f.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{
			AccountId: key.MustAccount().AccountId, Thresholds: xdr.Thresholds{0, 1, byte(medium), byte(high)},
			Signers: []xdr.Signer{{Key: xdr.SignerKey{Type: xdr.SignerKeyTypeSignerKeyTypeEd25519, Ed25519: sk.Ed25519}, Weight: xdr.Uint32(hotWeight)}},
		}}, 1, nil)
	}
	ctx := context.Background()
	set(2, 10, 2)
	if err := CheckHotSigner(ctx, f, account.Address(), hot); err != nil {
		t.Fatal(err)
	}
	if err := CheckHotSigner(ctx, f, account.Address(), account); err == nil {
		t.Fatal("the master key accepted as the hot signer")
	}
	set(2, 10, 10)
	if err := CheckHotSigner(ctx, f, account.Address(), hot); err == nil {
		t.Fatal("a signer that reaches the high threshold accepted")
	}
	set(2, 10, 1)
	if err := CheckHotSigner(ctx, f, account.Address(), hot); err == nil {
		t.Fatal("a signer below the medium threshold accepted")
	}
}

func TestTheVerifyingKeyMustMatchItsPinAndTheTestnetKeyNeverServesMainnet(t *testing.T) {
	raw, err := os.ReadFile("../../../contracts/verifier/keys/testnet-forgeable/verification_key.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckVerifyingKey(raw, forgeableTestnetSHA256, network.TestNetworkPassphrase); err != nil {
		t.Fatalf("the testnet key on testnet: %v", err)
	}
	if err := CheckVerifyingKey(raw, strings.ToUpper(forgeableTestnetSHA256), network.TestNetworkPassphrase); err != nil {
		t.Fatalf("an upper-case pin: %v", err)
	}
	if err := CheckVerifyingKey(raw, forgeableTestnetSHA256, network.PublicNetworkPassphrase); err == nil {
		t.Fatal("the testnet key accepted on mainnet")
	}
	for _, pin := range []string{"", strings.Repeat("0", 64)} {
		if err := CheckVerifyingKey(raw, pin, network.TestNetworkPassphrase); err == nil {
			t.Fatalf("a key accepted under the pin %q", pin)
		}
	}
}

func TestTheOperatorQueueTestsAChannelThatRefusedAnAlert(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pool, err := pgxpool.New(ctx, testdb.URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	b := &Base{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Alerts: &alert.Alerter{Service: "keeper", Channels: []alert.Channel{
		alert.Webhook{Format: "text", URL: "https://ntfy.example/a"}, alert.Webhook{Format: "text", URL: "https://ntfy.example/b"},
	}}}
	if err := b.StartAlerts(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if q := b.Alerts.Queue; q == nil || q.TestEvery != 5*time.Minute || q.Service != "keeper" {
		t.Fatalf("the operator queue %+v", q)
	}
}
