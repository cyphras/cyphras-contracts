package vaultarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Source returns the vault's raw events of the ledgers [from, to] in chain order, and fails for
// a range it does not fully cover.
type Source interface {
	Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error)
}

// Header is what a manifest says about the vault it describes.
type Header struct {
	Network           string
	NetworkPassphrase string
	Vault             string
	DeployLedger      uint32
	Producer          string
}

// Build writes the closed windows of ledgers up to to into dir, one window at a time, and the
// manifest last. A manifest already in dir for the same vault is extended: the windows it holds
// stay, and building resumes after them, or from the window of from if from is set. A window the
// source cannot give whole stops the build with the windows before it written and listed.
func Build(ctx context.Context, src Source, dir string, h Header, from, to uint32) (Manifest, error) {
	m := Manifest{
		Format: Format, Network: h.Network, NetworkPassphrase: h.NetworkPassphrase, Vault: h.Vault,
		DeployLedger: h.DeployLedger, WindowLedgers: WindowLedgers, Producer: h.Producer,
	}
	if err := os.MkdirAll(filepath.Join(dir, "windows"), 0o755); err != nil {
		return Manifest{}, err
	}
	if err := m.Validate(Expect{}); err != nil {
		return Manifest{}, err
	}
	existing, err := ReadManifest(ctx, DirFetcher(dir), Expect{})
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return Manifest{}, fmt.Errorf("the directory holds a manifest that cannot be extended: %w", err)
	case existing.Vault != h.Vault || existing.NetworkPassphrase != h.NetworkPassphrase || existing.DeployLedger != h.DeployLedger || existing.Network != h.Network:
		return Manifest{}, errors.New("the directory holds the archive of another vault")
	default:
		m.Windows = existing.Windows
	}
	first := uint64(windowStart(h.DeployLedger))
	next := first + uint64(len(m.Windows))*WindowLedgers
	if from != 0 {
		start := uint64(windowStart(from))
		if start > next {
			return Manifest{}, fmt.Errorf("window %d cannot be built before the window %d that precedes it", start, next)
		}
		if start < first {
			start = first
		}
		m.Windows = m.Windows[:(start-first)/WindowLedgers]
		next = start
	}
	var failure error
	for ; next+WindowLedgers-1 <= uint64(to); next += WindowLedgers {
		w, err := buildWindow(ctx, src, dir, h, m.Windows, uint32(next))
		if err != nil {
			failure = fmt.Errorf("window %d: %w", next, err)
			break
		}
		m.Windows = append(m.Windows, w)
	}
	if n := len(m.Windows); n > 0 {
		m.CoveredTo = m.Windows[n-1].End
	}
	if err := writeManifest(dir, m); err != nil {
		return Manifest{}, errors.Join(failure, err)
	}
	return m, failure
}

func buildWindow(ctx context.Context, src Source, dir string, h Header, done []Window, start uint32) (Window, error) {
	end := start + WindowLedgers - 1
	// The vault has no events before it was deployed, so its first window is read from there.
	events, err := src.Events(ctx, max(start, h.DeployLedger), end)
	if err != nil {
		return Window{}, err
	}
	var firstLeaf uint64
	if n := len(done); n > 0 {
		firstLeaf = done[n-1].Leaves[1]
	}
	data, entry, err := encode(events, start, end, h.Vault, firstLeaf)
	if err != nil {
		return Window{}, err
	}
	name := filepath.Join(dir, entry.File())
	if len(data) == 0 {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Window{}, err
		}
		return entry, nil
	}
	packed, err := gzipBytes(data)
	if err != nil {
		return Window{}, err
	}
	return entry, writeFile(name, packed)
}

func writeManifest(dir string, m Manifest) error {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, ManifestName), append(raw, '\n'))
}

// writeFile replaces name in one step, so a reader never sees half a file.
func writeFile(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".part-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}
