package vaultarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

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
// A window the manifest already lists must come out the same, and a build in which one does not
// is refused, so a published window is never replaced by other bytes.
// Windows are built in a staging directory and moved in only once the manifest that lists them
// has validated, so a build that is refused leaves dir exactly as it was.
func Build(ctx context.Context, src Source, dir string, h Header, from, to uint32) (Manifest, error) {
	m := Manifest{
		Format: Format, Network: h.Network, NetworkPassphrase: h.NetworkPassphrase, Vault: h.Vault,
		DeployLedger: h.DeployLedger, WindowLedgers: WindowLedgers, Producer: h.Producer,
	}
	if err := m.Validate(Expect{}); err != nil {
		return Manifest{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Manifest{}, err
	}
	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(stage)
	existing, err := ReadManifest(ctx, DirFetcher(dir), Expect{})
	var kept int
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return Manifest{}, fmt.Errorf("the directory holds a manifest that cannot be extended: %w", err)
	case existing.Vault != h.Vault || existing.NetworkPassphrase != h.NetworkPassphrase || existing.DeployLedger != h.DeployLedger || existing.Network != h.Network:
		return Manifest{}, errors.New("the directory holds the archive of another vault")
	default:
		m.Windows = slices.Clone(existing.Windows)
		kept = len(existing.Windows)
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
	built := 0
	var rebuilt []Window
	for ; next+WindowLedgers-1 <= uint64(to); next += WindowLedgers {
		w, err := buildWindow(ctx, src, stage, h, m.Windows, uint32(next))
		if err != nil {
			failure = fmt.Errorf("window %d: %w", next, err)
			break
		}
		if i := (next - first) / WindowLedgers; i < uint64(kept) && w != existing.Windows[i] {
			return Manifest{}, fmt.Errorf("window %d is published with sha256 %q and would now be %q: a published window is never rewritten with other bytes", next, existing.Windows[i].SHA256, w.SHA256)
		}
		m.Windows = append(m.Windows, w)
		rebuilt = append(rebuilt, w)
		built++
	}
	if failure != nil && built == 0 {
		// Nothing changed on disk, so the manifest there stays as it is.
		return m, failure
	}
	if len(m.Windows) < kept {
		// Windows after the ones rebuilt stay listed, so a shorter run never shortens the archive.
		m.Windows = append(m.Windows, existing.Windows[len(m.Windows):]...)
	}
	if n := len(m.Windows); n > 0 {
		m.CoveredTo = m.Windows[n-1].End
	}
	if err := m.Validate(Expect{}); err != nil {
		return m, errors.Join(failure, fmt.Errorf("the windows built do not lead into the ones after them: %w", err))
	}
	if err := publish(dir, stage, rebuilt); err != nil {
		return Manifest{}, errors.Join(failure, err)
	}
	if err := writeManifest(dir, m); err != nil {
		return Manifest{}, errors.Join(failure, err)
	}
	return m, errors.Join(failure, removeUnlisted(dir, m))
}

// publish moves the staged window files into place, and removes the file of a window that is now
// empty.
func publish(dir, stage string, rebuilt []Window) error {
	if err := os.MkdirAll(filepath.Join(dir, "windows"), 0o755); err != nil {
		return err
	}
	for _, w := range rebuilt {
		name := filepath.Join(dir, w.File())
		if w.Events == 0 {
			if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		if err := os.Rename(filepath.Join(stage, filepath.Base(w.File())), name); err != nil {
			return err
		}
	}
	return nil
}

// removeUnlisted deletes the window files the manifest does not list, which a shorter or
// emptier rebuild leaves behind.
func removeUnlisted(dir string, m Manifest) error {
	listed := map[string]bool{}
	for _, w := range m.Windows {
		if w.Events > 0 {
			listed[filepath.Base(w.File())] = true
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "windows"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if windowFile.MatchString(e.Name()) && !listed[e.Name()] {
			if err := os.Remove(filepath.Join(dir, "windows", e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

var windowFile = regexp.MustCompile(`^[0-9]{10}\.jsonl\.gz$`)

func buildWindow(ctx context.Context, src Source, stage string, h Header, done []Window, start uint32) (Window, error) {
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
	data, entry, err := encode(events, start, end, h.DeployLedger, h.Vault, firstLeaf)
	if err != nil {
		return Window{}, err
	}
	if len(data) == 0 {
		return entry, nil
	}
	packed, err := gzipBytes(data)
	if err != nil {
		return Window{}, err
	}
	return entry, writeFile(filepath.Join(stage, filepath.Base(entry.File())), packed)
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
