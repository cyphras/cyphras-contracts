package vaultarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// MaxMirrorBytes bounds what one Mirror run stages, counted in the sizes the manifest gives, so a
// manifest of many large windows cannot fill the disk before anything is found wrong.
const MaxMirrorBytes = 2 << 30

// Mirrored says what a Mirror run did.
type Mirrored struct {
	Manifest Manifest
	// Fetched is the number of windows downloaded, Kept the number already in dir.
	Fetched, Kept int
}

// Mirror makes dir hold the archive that remote publishes, for the vault and network want names.
// Every window is checked against the manifest and the format before anything is written, a
// window dir already holds is not fetched again, and the files the new manifest does not list are
// removed. dir only ever grows: a published archive that is behind the copy in dir, or that lists
// a window of the copy with other content, is refused, and so is any failure, with dir exactly as
// it was. Each admit is asked about the published manifest before any window is fetched, and may
// refuse it, as Admits does for a manifest that claims more than the chain has. The windows to
// fetch may not add up to more than MaxMirrorBytes.
func Mirror(ctx context.Context, remote Fetcher, dir string, want Expect, admits ...func(Manifest) error) (Mirrored, error) {
	if want.Vault == "" || want.NetworkPassphrase == "" {
		return Mirrored{}, errors.New("a mirror needs to know which vault and network it is of")
	}
	raw, err := remote.Get(ctx, ManifestName, MaxManifestBytes)
	if err != nil {
		return Mirrored{}, err
	}
	published, err := ParseManifest(raw, want)
	if err != nil {
		return Mirrored{}, err
	}
	for _, admit := range admits {
		if err := admit(published); err != nil {
			return Mirrored{}, err
		}
	}
	if err := refuseLinks(dir, published); err != nil {
		return Mirrored{}, err
	}
	held, err := ReadManifest(ctx, DirFetcher(dir), want)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		held = Manifest{}
	case err != nil:
		return Mirrored{}, fmt.Errorf("the directory holds a manifest that cannot be extended: %w", err)
	}
	if err := extends(published, held); err != nil {
		return Mirrored{}, err
	}

	created := topmostMissing(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return Mirrored{}, err
	}
	stage, err := os.MkdirTemp(dir, ".stage-")
	if err != nil {
		return Mirrored{}, err
	}
	done := false
	defer func() {
		os.RemoveAll(stage)
		if !done && created != "" {
			os.RemoveAll(created)
		}
	}()
	source := &layered{remote: remote, local: DirFetcher(dir), stage: stage, held: map[string]bool{}}
	var fetched []Window
	var staged int64
	for _, w := range published.Windows {
		switch {
		case w.Events == 0:
		case holds(ctx, dir, w):
			source.held[w.File()] = true
		default:
			fetched = append(fetched, w)
			staged += w.Bytes
		}
	}
	if staged > MaxMirrorBytes {
		return Mirrored{}, invalid("the windows to fetch add up to %d bytes, more than the %d a mirror takes in one run", staged, int64(MaxMirrorBytes))
	}
	if _, err := loadWindows(ctx, source, published); err != nil {
		return Mirrored{}, err
	}
	if err := publish(dir, stage, fetched); err != nil {
		return Mirrored{}, err
	}
	canonical, err := published.Canonical()
	if err != nil {
		return Mirrored{}, err
	}
	if err := writeFile(filepath.Join(dir, ManifestName), canonical); err != nil {
		return Mirrored{}, err
	}
	done = true
	return Mirrored{Manifest: published, Fetched: len(fetched), Kept: len(source.held)}, removeUnlisted(dir, published)
}

// extends refuses a published archive that is not the held one carried further.
func extends(published, held Manifest) error {
	if held.Format == "" {
		return nil
	}
	if published.Vault != held.Vault || published.NetworkPassphrase != held.NetworkPassphrase ||
		published.DeployLedger != held.DeployLedger || published.Network != held.Network {
		return errors.New("the directory holds the archive of another vault")
	}
	if published.CoveredTo < held.CoveredTo {
		return fmt.Errorf("the published archive covers to ledger %d, behind the copy that covers to %d", published.CoveredTo, held.CoveredTo)
	}
	for i, w := range held.Windows {
		if published.Windows[i] != w {
			return fmt.Errorf("window %d of the copy is published with other content (sha256 %q, the copy has %q)", w.Start, published.Windows[i].SHA256, w.SHA256)
		}
	}
	return nil
}

// refuseLinks stops a mirror from writing through a symbolic link that someone left in dir: the
// manifest, the windows directory and every window file must be what they say or not exist.
func refuseLinks(dir string, m Manifest) error {
	check := func(name, kind string, plain func(fs.FileMode) bool) error {
		info, err := os.Lstat(filepath.Join(dir, name))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !plain(info.Mode()) {
			return fmt.Errorf("%s is not a plain %s; symbolic links in an archive directory are not followed", name, kind)
		}
		return nil
	}
	file := func(mode fs.FileMode) bool { return mode.IsRegular() }
	if err := check("windows", "directory", fs.FileMode.IsDir); err != nil {
		return err
	}
	if err := check(ManifestName, "file", file); err != nil {
		return err
	}
	for _, w := range m.Windows {
		if err := check(w.File(), "file", file); err != nil {
			return err
		}
	}
	return nil
}

// holds reports whether dir has the window already, by its size and hash.
func holds(ctx context.Context, dir string, w Window) bool {
	compressed, err := DirFetcher(dir).Get(ctx, w.File(), MaxWindowBytes)
	if err != nil {
		return false
	}
	data, err := gunzip(compressed)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(data)
	return int64(len(data)) == w.Bytes && hex.EncodeToString(sum[:]) == w.SHA256
}

// topmostMissing is the first directory a MkdirAll of dir would create, or "" when dir exists, so
// a failed run can take back what it made.
func topmostMissing(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	missing := ""
	for p := abs; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			return missing
		}
		missing = p
	}
}

// layered reads the windows dir already holds from dir and fetches the others into the staging
// directory, where they wait for the whole archive to be checked.
type layered struct {
	remote, local Fetcher
	stage         string
	held          map[string]bool
}

// Get implements Fetcher.
func (l *layered) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	if l.held[name] {
		return l.local.Get(ctx, name, limit)
	}
	data, err := l.remote.Get(ctx, name, limit)
	if err != nil {
		return nil, err
	}
	if err := writeFile(filepath.Join(l.stage, filepath.Base(name)), data); err != nil {
		return nil, err
	}
	return data, nil
}
