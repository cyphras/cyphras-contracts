package service

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
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

func TestAlertWebhooksComeFromASecretFile(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := Alerter("keeper", log)
	if err != nil || len(a.Channels) != 0 {
		t.Fatalf("without webhooks: %v", err)
	}
	path := filepath.Join(t.TempDir(), "hooks")
	if err := os.WriteFile(path, []byte("slack https://hooks.example/a\ntext https://ntfy.example/b\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ALERT_WEBHOOKS_FILE", path)
	a, err = Alerter("keeper", log)
	if err != nil || len(a.Channels) != 2 {
		t.Fatalf("with webhooks: %v", err)
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
