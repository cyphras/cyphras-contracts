package main

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

// snapshot reads every file under dir by its path below it.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		files[strings.TrimPrefix(path, dir)] = string(raw)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func between(events []vault.RawEvent, lo, hi uint32) []vault.RawEvent {
	var out []vault.RawEvent
	for _, e := range events {
		if e.Ledger >= lo && e.Ledger <= hi {
			out = append(out, e)
		}
	}
	return out
}

// growing is an indexer archive that covers the first window and a little of the second, and
// extends to the end of the third window's first hundred ledgers when grow is called.
func growing(t *testing.T) (raw string, grow func()) {
	t.Helper()
	events := sample()
	raw = t.TempDir()
	w := archive.Writer{Dir: raw}
	if err := w.Append(between(events, deployAt, window+100), deployAt, window+100); err != nil {
		t.Fatal(err)
	}
	return raw, func() {
		t.Helper()
		if err := w.Append(between(events, window+101, 3*window+100), window+101, 3*window+100); err != nil {
			t.Fatal(err)
		}
	}
}

// serveArchive publishes dir, and the paths it is asked for are added to the returned list.
func serveArchive(t *testing.T, dir string) (url string, asked func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	inner := handler(dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

func export1(t *testing.T, raw, deployment, out string) {
	t.Helper()
	if _, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", out); err != nil {
		t.Fatal(err)
	}
}

func TestFetchMakesACopyOfAPublishedArchive(t *testing.T) {
	published, deployment := exportSample(t)
	url, _ := serveArchive(t, published)
	out := filepath.Join(t.TempDir(), "copy", "testnet")
	got, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment)
	if err != nil || !strings.Contains(got, "fetched 2 windows, 0 already present") {
		t.Fatalf("fetch: %q, %v", got, err)
	}
	if a, b := snapshot(t, published), snapshot(t, out); !maps.Equal(a, b) {
		t.Fatalf("the copy differs from the published archive:\n%v\n%v", a, b)
	}
	if got, err := do(t, "verify", "--dir", out, "--format-only", "--deployment", deployment); err != nil || !strings.Contains(got, "format checks passed") {
		t.Fatalf("the copy does not verify: %q, %v", got, err)
	}
}

func TestFetchAsksOnlyForTheWindowsTheCopyLacks(t *testing.T) {
	raw, grow := growing(t)
	deployment := writeDeployment(t, vaulttest.Vault)
	published := filepath.Join(t.TempDir(), "published")
	export1(t, raw, deployment, published)
	url, asked := serveArchive(t, published)
	out := filepath.Join(t.TempDir(), "copy")
	if got, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err != nil || !strings.Contains(got, "fetched 1 windows, 0 already present") {
		t.Fatalf("first fetch: %q, %v", got, err)
	}

	grow()
	export1(t, raw, deployment, published)
	before := len(asked())
	got, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment)
	if err != nil || !strings.Contains(got, "fetched 1 windows, 1 already present") {
		t.Fatalf("incremental fetch: %q, %v", got, err)
	}
	for _, path := range asked()[before:] {
		if path == "/windows/0000000000.jsonl.gz" {
			t.Fatal("a window the copy holds was fetched again")
		}
	}
	if a, b := snapshot(t, published), snapshot(t, out); !maps.Equal(a, b) {
		t.Fatalf("the copy differs from the published archive:\n%v\n%v", a, b)
	}

	before = len(asked())
	if got, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err != nil || !strings.Contains(got, "fetched 0 windows, 2 already present") {
		t.Fatalf("a fetch in step: %q, %v", got, err)
	}
	if n := len(asked()) - before; n != 1 {
		t.Fatalf("a fetch in step made %d requests, want only the manifest", n)
	}
}

func TestFetchRefusesATamperedWindowAndLeavesTheCopyAsItWas(t *testing.T) {
	raw, grow := growing(t)
	deployment := writeDeployment(t, vaulttest.Vault)
	published := filepath.Join(t.TempDir(), "published")
	export1(t, raw, deployment, published)
	url, _ := serveArchive(t, published)
	out := filepath.Join(t.TempDir(), "copy")
	if _, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, out)

	grow()
	export1(t, raw, deployment, published)
	name := filepath.Join(published, "windows", fmt.Sprintf("%010d.jsonl.gz", window))
	window1, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, append(window1[:len(window1)-9], 0, 0, 0, 0, 0, 0, 0, 0, 0), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err == nil {
		t.Fatal("a tampered window was accepted")
	}
	if after := snapshot(t, out); !maps.Equal(before, after) {
		t.Fatalf("a refused fetch changed the copy: %v", after)
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 2 {
		t.Fatalf("the copy after the refusal: %v, %v", entries, err)
	}

	fresh := filepath.Join(t.TempDir(), "fresh")
	if _, err := do(t, "fetch", "--url", url, "--out", fresh, "--deployment", deployment); err == nil {
		t.Fatal("a tampered window was accepted into a new directory")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("a refused first fetch left a directory: %v", err)
	}
}

func TestFetchRefusesAPublishedArchiveBehindTheCopy(t *testing.T) {
	raw, grow := growing(t)
	deployment := writeDeployment(t, vaulttest.Vault)
	behind := filepath.Join(t.TempDir(), "behind")
	export1(t, raw, deployment, behind)
	grow()
	ahead := filepath.Join(t.TempDir(), "ahead")
	export1(t, raw, deployment, ahead)

	out := filepath.Join(t.TempDir(), "copy")
	aheadURL, _ := serveArchive(t, ahead)
	if _, err := do(t, "fetch", "--url", aheadURL, "--out", out, "--deployment", deployment); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, out)
	behindURL, _ := serveArchive(t, behind)
	_, err := do(t, "fetch", "--url", behindURL, "--out", out, "--deployment", deployment)
	if err == nil || !strings.Contains(err.Error(), "behind") {
		t.Fatalf("a published archive behind the copy: %v", err)
	}
	if after := snapshot(t, out); !maps.Equal(before, after) {
		t.Fatalf("a refused fetch changed the copy: %v", after)
	}
}

func TestFetchDoesNotFollowASymbolicLinkInItsDirectory(t *testing.T) {
	published, deployment := exportSample(t)
	url, _ := serveArchive(t, published)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "canary"), []byte("canary"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(out, "windows")); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err == nil || !strings.Contains(err.Error(), "symbolic links") {
		t.Fatalf("a windows directory that is a link: %v", err)
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 1 || entries[0].Name() != "canary" {
		t.Fatalf("something was written outside the directory: %v, %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); !os.IsNotExist(err) {
		t.Fatalf("a refused fetch wrote a manifest: %v", err)
	}
}

func TestFetchRefusesWhatItCannotDo(t *testing.T) {
	published, deployment := exportSample(t)
	url, _ := serveArchive(t, published)
	out := filepath.Join(t.TempDir(), "copy")
	for name, args := range map[string][]string{
		"no url":                       {"fetch", "--out", out, "--deployment", deployment},
		"no deployment":                {"fetch", "--url", url, "--out", out},
		"no directory":                 {"fetch", "--url", url, "--deployment", deployment},
		"an archive of another vault":  {"fetch", "--url", url, "--out", out, "--deployment", writeDeployment(t, vaulttest.Token)},
		"a deploy ledger that differs": {"fetch", "--url", url, "--out", out, "--deployment", deploymentAt(t, deployAt+1, "testnet", passphrase)},
		"another network":              {"fetch", "--url", url, "--out", out, "--deployment", deploymentAt(t, deployAt, "mainnet", "Public Global Stellar Network ; September 2015")},
		"an address with no archive":   {"fetch", "--url", url + "/nothing", "--out", out, "--deployment", deployment},
		"an extra argument":            {"fetch", "--url", url, "--out", out, "--deployment", deployment, "more"},
	} {
		if _, err := do(t, args...); err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s left a directory: %v", name, err)
		}
	}
}

func TestExportOnlyAppendsClosedWindowsToAPublishedDirectory(t *testing.T) {
	raw, grow := growing(t)
	deployment := writeDeployment(t, vaulttest.Vault)
	published := filepath.Join(t.TempDir(), "published")
	export1(t, raw, deployment, published)
	first := snapshot(t, published)
	if len(first) != 2 {
		t.Fatalf("the first export wrote %v, want a manifest and the closed window", first)
	}

	grow()
	export1(t, raw, deployment, published)
	second := snapshot(t, published)
	if len(second) != 3 {
		t.Fatalf("the second export wrote %v, want the window after it as well", second)
	}
	for name, content := range first {
		if name != "/manifest.json" && second[name] != content {
			t.Fatalf("export rewrote the published window %s", name)
		}
	}
	m, err := vaultarchive.ReadManifest(t.Context(), vaultarchive.DirFetcher(published), vaultarchive.Expect{})
	if err != nil || m.CoveredTo != 3*window-1 {
		t.Fatalf("the open window was published: %+v, %v", m, err)
	}

	export1(t, raw, deployment, published)
	if again := snapshot(t, published); !maps.Equal(second, again) {
		t.Fatal("an export with nothing new changed the directory")
	}
}

func TestExportFailsWhenAPublishedWindowWouldChange(t *testing.T) {
	raw, grow := growing(t)
	grow()
	deployment := writeDeployment(t, vaulttest.Vault)
	published := filepath.Join(t.TempDir(), "published")
	export1(t, raw, deployment, published)
	before := snapshot(t, published)

	// A later write of the same ledgers replaces the earlier one, here without one event.
	var changed []vault.RawEvent
	for _, e := range between(sample(), deployAt, window-1) {
		if e.Ledger != 12 {
			changed = append(changed, e)
		}
	}
	if err := (archive.Writer{Dir: raw}).Append(changed, deployAt, window-1); err != nil {
		t.Fatal(err)
	}
	_, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", published)
	if err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("an export that changes a published window: %v", err)
	}
	if after := snapshot(t, published); !maps.Equal(before, after) {
		t.Fatal("a refused export changed the published directory")
	}
}

func TestARebuildIntoACopyOfTheArchiveFailsWhenAWindowDiffersFromThePublishedOne(t *testing.T) {
	published, deployment := exportSample(t)
	events := sample()
	var fewer []vault.RawEvent
	for _, e := range events {
		if e.Ledger != 12 {
			fewer = append(fewer, e)
		}
	}
	rebuild := func(t *testing.T, from []vault.RawEvent) (string, error) {
		t.Helper()
		copied := filepath.Join(t.TempDir(), "copy")
		if err := os.CopyFS(copied, os.DirFS(published)); err != nil {
			t.Fatal(err)
		}
		_, err := do(t, "rebuild", "--ledger-meta", ledgerArchive(t, from, 3), "--deployment", deployment,
			"--out", copied, "--from", "1", "--to", fmt.Sprint(3*window-1), "--workers", "4")
		return copied, err
	}
	copied, err := rebuild(t, events)
	if err != nil {
		t.Fatalf("ledgers that agree with the published windows: %v", err)
	}
	if a, b := snapshot(t, published), snapshot(t, copied); !maps.Equal(a, b) {
		t.Fatal("a rebuild that agrees changed the copy")
	}
	if _, err := rebuild(t, fewer); err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("ledgers that differ from the published window: %v", err)
	}
}

func TestFetchWithAnRPCRefusesAManifestOfLedgersThatHaveNotHappenedBeforeAnyWindow(t *testing.T) {
	published, deployment := exportSample(t)
	fake := chainFake(t, published)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	dialRPC = func(string) rpc.Client { return fake }

	// An honest archive passes the RPC, and a manifest of 5000 empty windows to far past the
	// RPC's latest ledger does not.
	url, _ := serveArchive(t, published)
	out := filepath.Join(t.TempDir(), "copy")
	if _, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment, "--rpc", "http://rpc.invalid"); err != nil {
		t.Fatal(err)
	}
	m := vaultarchive.Manifest{
		Format: vaultarchive.Format, Network: "testnet", NetworkPassphrase: passphrase, Vault: vaulttest.Vault,
		DeployLedger: deployAt, WindowLedgers: window, Producer: "test",
	}
	for i := range uint32(5000) {
		m.Windows = append(m.Windows, vaultarchive.Window{Start: i * window, End: (i+1)*window - 1})
	}
	m.CoveredTo = 5000*window - 1
	hostile := t.TempDir()
	raw, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostile, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	hostileURL, hostileAsked := serveArchive(t, hostile)
	before := snapshot(t, out)
	fresh := filepath.Join(t.TempDir(), "fresh")
	for _, target := range []string{out, fresh} {
		_, err := do(t, "fetch", "--url", hostileURL, "--out", target, "--deployment", deployment, "--rpc", "http://rpc.invalid")
		if err == nil || !strings.Contains(err.Error(), "RPC's latest") {
			t.Fatalf("a manifest past the chain: %v", err)
		}
	}
	if after := snapshot(t, out); !maps.Equal(before, after) {
		t.Fatal("a refused fetch changed the copy")
	}
	if _, err := os.Stat(fresh); !os.IsNotExist(err) {
		t.Fatalf("a refused fetch left %s: %v", fresh, err)
	}
	if got := hostileAsked(); len(got) != 2 {
		t.Fatalf("the hostile archive was asked for %v", got)
	}

	// Without an RPC the format is all that is checked, so the same manifest is taken: the flag
	// is what protects a long-lived copy.
	if _, err := do(t, "fetch", "--url", hostileURL, "--out", filepath.Join(t.TempDir(), "unchecked"), "--deployment", deployment); err != nil {
		t.Fatalf("a manifest of empty windows without an RPC: %v", err)
	}
}
