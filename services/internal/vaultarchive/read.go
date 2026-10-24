package vaultarchive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// Fetcher reads the files of an archive by their path under its base, refusing one longer than
// limit instead of cutting it short.
type Fetcher interface {
	Get(ctx context.Context, name string, limit int64) ([]byte, error)
}

// DirFetcher reads an archive from a directory.
type DirFetcher string

// Get implements Fetcher.
func (d DirFetcher) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(string(d), filepath.FromSlash(name)))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readLimited(f, limit)
}

// HTTPFetcher reads an archive from a base URL.
type HTTPFetcher struct {
	Base string
	// Client is used for every request; without one, a request that stalls for two minutes fails.
	Client *http.Client
}

var defaultClient = &http.Client{Timeout: 2 * time.Minute}

// Get implements Fetcher.
func (h HTTPFetcher) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(h.Base, "/")+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	client := h.Client
	if client == nil {
		client = defaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", name, os.ErrNotExist)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: the server answered %d", name, resp.StatusCode)
	}
	return readLimited(resp.Body, limit)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, invalid("a file longer than %d bytes", limit)
	}
	return data, nil
}

// ReadManifest reads and validates the manifest.
func ReadManifest(ctx context.Context, f Fetcher, want Expect) (Manifest, error) {
	raw, err := f.Get(ctx, ManifestName, MaxManifestBytes)
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, invalid("manifest: %v", err)
	}
	return m, m.Validate(want)
}

// Contents is everything a verified archive holds that the chain can be asked about: the
// commitments in leaf order and the spent nullifiers.
type Contents struct {
	Manifest    Manifest
	Commitments []fr.Element
	Nullifiers  []fr.Element
}

// Load reads every window, checking each against the manifest and the format, and returns what
// they hold. It does not look at the chain, so it proves the archive is well formed, not true.
func Load(ctx context.Context, f Fetcher, want Expect) (*Contents, error) {
	m, err := ReadManifest(ctx, f, want)
	if err != nil {
		return nil, err
	}
	out := &Contents{Manifest: m}
	for _, w := range m.Windows {
		if w.Events == 0 {
			continue
		}
		compressed, err := f.Get(ctx, w.File(), MaxWindowBytes)
		if errors.Is(err, os.ErrNotExist) {
			return nil, invalid("window %d is in the manifest but has no file", w.Start)
		}
		if err != nil {
			return nil, fmt.Errorf("window %d: %w", w.Start, err)
		}
		c, err := check(w, compressed, m.Vault)
		if err != nil {
			return nil, err
		}
		out.Commitments = append(out.Commitments, c.commitments...)
		out.Nullifiers = append(out.Nullifiers, c.nullifiers...)
	}
	return out, nil
}
