package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
)

func TestSecretsMustBePrivateToTheirOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	kp := keypair.MustRandom()
	if err := os.WriteFile(path, []byte("\n"+kp.Seed()+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEEPER_KEY_FILE", path)
	if _, err := Key("KEEPER_KEY"); !errors.Is(err, ErrExposedSecret) {
		t.Fatalf("group-readable secret: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	got, err := Key("KEEPER_KEY")
	if err != nil || got.Address() != kp.Address() {
		t.Fatalf("key: %v", err)
	}
}

func TestKeysParseOnePerLineAndNeverEchoASeed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "channels")
	a, b := keypair.MustRandom(), keypair.MustRandom()
	if err := os.WriteFile(path, []byte(a.Seed()+"\n"+b.Seed()+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHANNEL_KEYS_FILE", path)
	keys, err := Keys("CHANNEL_KEYS")
	if err != nil || len(keys) != 2 || keys[1].Address() != b.Address() {
		t.Fatalf("keys: %v", err)
	}
	if _, err := Key("CHANNEL_KEYS"); err == nil {
		t.Fatal("two keys accepted as one")
	}
	bad := filepath.Join(dir, "bad")
	broken := "S" + strings.Repeat("A", 55)
	if err := os.WriteFile(bad, []byte(broken), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BAD_FILE", bad)
	if _, err := Keys("BAD"); err == nil || strings.Contains(err.Error(), broken) {
		t.Fatalf("invalid seed: %v", err)
	}
}

func TestSettingsParse(t *testing.T) {
	t.Setenv("WINDOW", "200")
	t.Setenv("POLL", "3s")
	if n, err := Int("WINDOW", 1); err != nil || n != 200 {
		t.Fatal(n, err)
	}
	if d, err := Duration("POLL", time.Second); err != nil || d != 3*time.Second {
		t.Fatal(d, err)
	}
	if d, _ := Duration("UNSET_POLL", time.Second); d != time.Second {
		t.Fatal(d)
	}
	t.Setenv("WINDOW", "x")
	if _, err := Int("WINDOW", 1); err == nil {
		t.Fatal("bad integer accepted")
	}
	if _, err := Required("NOT_SET_ANYWHERE"); err == nil {
		t.Fatal("missing variable accepted")
	}
}

func TestTheDeploymentFileSelectsTheVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testnet.json")
	doc := `{
  "network": "testnet",
  "network_passphrase": "Test SDF Network ; September 2015",
  "vaults": [
    {"asset": "native", "vault": "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5",
     "token": "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U", "deploy_ledger": 1234, "fee_tier": "100000"}
  ]
}`
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	d, v, err := LoadDeployment(path, "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5")
	if err != nil {
		t.Fatal(err)
	}
	tier, err := v.Tier()
	if err != nil || tier.Int64() != 100_000 || v.DeployLedger != 1234 || d.Network != "testnet" {
		t.Fatalf("vault %+v", v)
	}
	if _, _, err := LoadDeployment(path, "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"); err == nil {
		t.Fatal("vault outside the deployment accepted")
	}
}
