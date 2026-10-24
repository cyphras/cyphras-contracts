package vaultarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const (
	deploy     = 10
	passphrase = "Test SDF Network ; September 2015"
)

// sample is a vault's history: windows 0 and 1 hold deposits, admissions and a transfer, window 2
// holds nothing and window 3, still open, holds a deposit.
func sample() []vault.RawEvent {
	c := vaulttest.New(deploy, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.NextLedger(5)
	c.Shield(vaulttest.Depositor, 20_000_000)
	c.NextLedger(5)
	c.Attest(2)
	c.NextLedger(5)
	c.Admit(1, 2)
	c.Ledger = WindowLedgers + 39
	c.NextLedger(86_400)
	id := c.Shield(vaulttest.Depositor, 30_000_000)
	c.NextLedger(5)
	c.Attest(id)
	c.NextLedger(5)
	c.Admit(id)
	c.NextLedger(5)
	c.Transact(-1_000_000, 100_000, vaulttest.Relayer)
	c.Ledger = 3*WindowLedgers + 6
	c.NextLedger(2 * 86_400)
	c.Shield(vaulttest.Depositor, 40_000_000)
	return c.Events
}

func head() Header {
	return Header{Network: "testnet", NetworkPassphrase: passphrase, Vault: vaulttest.Vault, DeployLedger: deploy, Producer: "test"}
}

// memSource gives the events of ledgers up to covered and fails for a range past them.
type memSource struct {
	events  []vault.RawEvent
	covered uint32
}

func (m memSource) Events(_ context.Context, from, to uint32) ([]vault.RawEvent, error) {
	if to > m.covered {
		return nil, fmt.Errorf("%w: ledgers %d to %d", archive.ErrNotCovered, from, to)
	}
	var out []vault.RawEvent
	for _, e := range m.events {
		if e.Ledger >= from && e.Ledger <= to {
			out = append(out, e)
		}
	}
	return out, nil
}

// fixedSource gives the same events whatever the range, as a faulty source would.
type fixedSource []vault.RawEvent

func (f fixedSource) Events(context.Context, uint32, uint32) ([]vault.RawEvent, error) {
	return f, nil
}

// good builds the archive of the first three windows of sample.
func good(t *testing.T) (string, Manifest) {
	t.Helper()
	dir := t.TempDir()
	m, err := Build(context.Background(), memSource{sample(), 4 * WindowLedgers}, dir, head(), 0, 3*WindowLedgers-1)
	if err != nil {
		t.Fatal(err)
	}
	return dir, m
}

func readWindow(t *testing.T, dir string, start uint32) []byte {
	t.Helper()
	compressed, err := os.ReadFile(filepath.Join(dir, Window{Start: start}.File()))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeManifestFile(t *testing.T, dir string, m Manifest) {
	t.Helper()
	raw, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readManifestFile(t *testing.T, dir string) Manifest {
	t.Helper()
	m, err := ReadManifest(context.Background(), DirFetcher(dir), Expect{})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// rewrite changes the lines of a window's bytes and brings the manifest's size and hash along, so
// that only the rule the change breaks can refuse the archive.
func rewrite(t *testing.T, dir string, start uint32, change func(lines []string) []string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(readWindow(t, dir, start)), "\n"), "\n")
	data := []byte(strings.Join(change(lines), "\n") + "\n")
	packed, err := gzipBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, Window{Start: start}.File()), packed, 0o644); err != nil {
		t.Fatal(err)
	}
	m := readManifestFile(t, dir)
	for i := range m.Windows {
		if m.Windows[i].Start == start {
			sum := sha256.Sum256(data)
			m.Windows[i].Bytes, m.Windows[i].SHA256 = int64(len(data)), hex.EncodeToString(sum[:])
		}
	}
	writeManifestFile(t, dir, m)
}

func mustInvalid(t *testing.T, name string, err error, reason string) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), reason) {
		t.Fatalf("%s: %v, want an invalid archive: %s", name, err, reason)
	}
}
