// Package config reads a service's settings from its environment, its secrets from files only that
// service can read, and its vault from the deployment file.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
)

// Env returns the variable, or def when it is unset or empty.
func Env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// Required returns the variable or an error naming it.
func Required(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("config: %s is not set", name)
	}
	return v, nil
}

// Int returns the variable as an integer, or def.
func Int(name string, def int64) (int64, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("config: %s is not an integer", name)
	}
	return n, nil
}

// Duration returns the variable as a Go duration, or def.
func Duration(name string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(name)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s is not a duration", name)
	}
	return d, nil
}

// ErrExposedSecret reports a secret file that others than its owner can read.
var ErrExposedSecret = errors.New("config: secret file is readable by group or others")

// Secret reads the file named by the variable name + "_FILE". The file must not be readable by
// anyone but its owner.
func Secret(name string) ([]byte, error) {
	path, err := Required(name + "_FILE")
	if err != nil {
		return nil, err
	}
	return ReadSecret(path)
}

// ReadSecret reads a secret file that only this process's user owns and can read. The checks look
// at the opened file, so the path cannot be swapped between the check and the read.
func ReadSecret(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: secret file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("config: secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("config: secret file %s is not a regular file", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s", ErrExposedSecret, path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("%w: %s belongs to another user", ErrExposedSecret, path)
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("config: secret file: %w", err)
	}
	return data, nil
}

// Value reads the variable name, or the secret file named by name + "_FILE" for a value such as a
// provider URL that may carry an access key.
func Value(name string) (string, error) {
	if os.Getenv(name+"_FILE") != "" {
		return SecretString(name)
	}
	return Required(name)
}

// SecretString reads a secret and trims surrounding whitespace.
func SecretString(name string) (string, error) {
	b, err := Secret(name)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("config: secret %s is empty", name)
	}
	return s, nil
}

// Keys parses one Stellar secret seed per line of a secret.
func Keys(name string) ([]*keypair.Full, error) {
	b, err := Secret(name)
	if err != nil {
		return nil, err
	}
	var keys []*keypair.Full
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kp, err := keypair.ParseFull(line)
		if err != nil {
			// The parse error would echo key material.
			return nil, fmt.Errorf("config: %s holds an invalid secret seed", name)
		}
		keys = append(keys, kp)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("config: %s holds no key", name)
	}
	return keys, nil
}

// Key parses a secret holding exactly one seed.
func Key(name string) (*keypair.Full, error) {
	keys, err := Keys(name)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("config: %s must hold one key", name)
	}
	return keys[0], nil
}

// Deployment is the part of deployments/<network>.json the services read.
type Deployment struct {
	Network           string          `json:"network"`
	NetworkPassphrase string          `json:"network_passphrase"`
	Vaults            []DeployedVault `json:"vaults"`
}

// DeployedVault is one vault of the deployment. Asset is the asset contract's name(): native for
// XLM, CODE:ISSUER for an issued asset.
type DeployedVault struct {
	Asset        string `json:"asset"`
	Vault        string `json:"vault"`
	Token        string `json:"token"`
	DeployLedger uint32 `json:"deploy_ledger"`
	// FeeTier is the relayer fee granularity in the asset's smallest unit.
	FeeTier string `json:"fee_tier"`
}

// Tier parses FeeTier.
func (v DeployedVault) Tier() (*big.Int, error) {
	n, ok := new(big.Int).SetString(v.FeeTier, 10)
	if !ok || n.Sign() <= 0 {
		return nil, fmt.Errorf("config: fee tier %q", v.FeeTier)
	}
	return n, nil
}

// LoadDeployment reads the deployment file and returns the entry of the vault.
func LoadDeployment(path, vaultID string) (Deployment, DeployedVault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Deployment{}, DeployedVault{}, fmt.Errorf("config: deployment file: %w", err)
	}
	var d Deployment
	if err := json.Unmarshal(raw, &d); err != nil {
		return Deployment{}, DeployedVault{}, fmt.Errorf("config: deployment file: %w", err)
	}
	if d.NetworkPassphrase == "" {
		return Deployment{}, DeployedVault{}, errors.New("config: deployment file has no network passphrase")
	}
	for _, v := range d.Vaults {
		if v.Vault != vaultID {
			continue
		}
		if !strkey.IsValidContractAddress(v.Vault) || !strkey.IsValidContractAddress(v.Token) || v.DeployLedger == 0 {
			return Deployment{}, DeployedVault{}, fmt.Errorf("config: deployment entry of %s is incomplete", vaultID)
		}
		return d, v, nil
	}
	return Deployment{}, DeployedVault{}, fmt.Errorf("config: %s is not in the deployment file", vaultID)
}
