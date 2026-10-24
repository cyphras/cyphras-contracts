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
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

// through publishes dir behind a handler that may answer instead of the archive's own.
func through(t *testing.T, dir string, wrap func(w http.ResponseWriter, r *http.Request, next http.Handler)) string {
	t.Helper()
	inner := handler(dir)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { wrap(w, r, inner) }))
	t.Cleanup(srv.Close)
	return srv.URL
}

func untouched(t *testing.T, out string, before map[string]string) {
	t.Helper()
	if after := snapshot(t, out); !maps.Equal(before, after) {
		t.Fatalf("a failed fetch changed the copy: %v", after)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("%s is left in the copy", e.Name())
		}
	}
}

func TestFetchDoesNotFollowARedirectToAnotherHost(t *testing.T) {
	published, deployment := exportSample(t)
	elsewhere, _ := serveArchive(t, published)
	url := through(t, published, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		http.Redirect(w, r, elsewhere+r.URL.Path, http.StatusFound)
	})
	out := filepath.Join(t.TempDir(), "copy")
	if _, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err == nil {
		t.Fatal("a redirect to another host was followed")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a refused first fetch left a directory: %v", err)
	}
}

func TestFetchRefusesAManifestOverTheCapAndAWindowThatFails(t *testing.T) {
	published, deployment := exportSample(t)
	out := t.TempDir()
	before := snapshot(t, out)

	huge := through(t, published, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if strings.HasSuffix(r.URL.Path, "manifest.json") {
			w.Write([]byte(strings.Repeat(" ", vaultarchive.MaxManifestBytes+10)))
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := do(t, "fetch", "--url", huge, "--out", out, "--deployment", deployment); err == nil {
		t.Fatal("a manifest over the cap was accepted")
	}
	untouched(t, out, before)

	var requests int
	var mu sync.Mutex
	broken := through(t, published, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if strings.Contains(r.URL.Path, "windows/") {
			mu.Lock()
			requests++
			mu.Unlock()
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := do(t, "fetch", "--url", broken, "--out", out, "--deployment", deployment); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("a window the server cannot give: %v", err)
	}
	untouched(t, out, before)
	if requests != 1 {
		t.Fatalf("a 500 was asked %d times, it is not a busy answer", requests)
	}
}

func TestFetchGetsPastABusyServerAndADroppedConnection(t *testing.T) {
	published, deployment := exportSample(t)
	var mu sync.Mutex
	seen := map[string]int{}
	url := through(t, published, func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		mu.Lock()
		seen[r.URL.Path]++
		n := seen[r.URL.Path]
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "manifest.json") && n == 1:
			w.Header().Set("Retry-After", "0")
			http.Error(w, "slow down", http.StatusTooManyRequests)
		case strings.Contains(r.URL.Path, "windows/") && n == 1:
			w.Header().Set("Content-Length", "100000")
			w.Write([]byte("part"))
		default:
			next.ServeHTTP(w, r)
		}
	})
	out := filepath.Join(t.TempDir(), "copy")
	if got, err := do(t, "fetch", "--url", url, "--out", out, "--deployment", deployment); err != nil || !strings.Contains(got, "fetched 2 windows") {
		t.Fatalf("a busy server and a connection that drops: %q, %v", got, err)
	}
	if a, b := snapshot(t, published), snapshot(t, out); !maps.Equal(a, b) {
		t.Fatal("the copy differs from the published archive")
	}
}

func TestExportOverAGapInTheEventArchiveFailsAndKeepsWhatIsPublished(t *testing.T) {
	events := sample()
	deployment := writeDeployment(t, vaulttest.Vault)
	raw := t.TempDir()
	w := archive.Writer{Dir: raw}
	for _, r := range [][2]uint32{{deployAt, window - 1}, {window + 200, 3*window + 100}} {
		if err := w.Append(between(events, r[0], r[1]), r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(t.TempDir(), "published")
	_, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", out)
	if err == nil {
		t.Fatal("an export over a hole in the event archive succeeded")
	}
	m, rerr := vaultarchive.ReadManifest(t.Context(), vaultarchive.DirFetcher(out), vaultarchive.Expect{})
	if rerr != nil || m.CoveredTo != window-1 || len(m.Windows) != 1 {
		t.Fatalf("after the failure: %+v, %v", m, rerr)
	}

	whole := t.TempDir()
	good := filepath.Join(t.TempDir(), "good")
	if err := (archive.Writer{Dir: whole}).Append(between(events, deployAt, 3*window+100), deployAt, 3*window+100); err != nil {
		t.Fatal(err)
	}
	export1(t, whole, deployment, good)
	before := snapshot(t, good)
	if err := os.RemoveAll(whole); err != nil {
		t.Fatal(err)
	}
	holey := t.TempDir()
	hw := archive.Writer{Dir: holey}
	for _, r := range [][2]uint32{{deployAt, window + 99}, {window + 200, 3*window + 100}} {
		if err := hw.Append(between(events, r[0], r[1]), r[0], r[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := do(t, "export", "--dir", holey, "--deployment", deployment, "--out", good); err == nil {
		t.Fatal("an export from an event archive with a hole in a published window succeeded")
	}
	if after := snapshot(t, good); !maps.Equal(before, after) {
		t.Fatal("a failed export changed what is published")
	}
}

func TestExportClosesAWindowOnlyWhenItsLastLedgerIsCovered(t *testing.T) {
	events := sample()
	deployment := writeDeployment(t, vaulttest.Vault)
	for covered, windows := range map[uint32]int{window - 2: 0, window - 1: 1, window: 1, 2*window - 2: 1, 2*window - 1: 2} {
		raw := t.TempDir()
		if err := (archive.Writer{Dir: raw}).Append(between(events, deployAt, covered), deployAt, covered); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "published")
		if _, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", out); err != nil {
			t.Fatalf("covered to %d: %v", covered, err)
		}
		m, err := vaultarchive.ReadManifest(t.Context(), vaultarchive.DirFetcher(out), vaultarchive.Expect{})
		if err != nil || len(m.Windows) != windows {
			t.Fatalf("covered to %d: %d windows, want %d (%v)", covered, len(m.Windows), windows, err)
		}
		for _, w := range m.Windows {
			if w.End > covered {
				t.Fatalf("covered to %d, but window %d ends at %d", covered, w.Start, w.End)
			}
		}
	}
}

func TestExportsRunningAtOnceLeaveAnArchiveThatLoads(t *testing.T) {
	raw, grow := growing(t)
	grow()
	deployment := writeDeployment(t, vaulttest.Vault)
	out := filepath.Join(t.TempDir(), "published")
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", out); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got, err := do(t, "verify", "--dir", out, "--format-only", "--deployment", deployment); err != nil || !strings.Contains(got, "format checks passed") {
		t.Fatalf("the published directory does not verify: %q, %v", got, err)
	}
	var events []vault.RawEvent
	for _, e := range sample() {
		events = append(events, e)
	}
	if len(events) == 0 {
		t.Fatal(fmt.Sprint("no events"))
	}
}

func TestAnArchiveIsNotFetchedOverPlainHTTPFromAnotherMachine(t *testing.T) {
	_, deployment := exportSample(t)
	out := filepath.Join(t.TempDir(), "copy")
	for _, base := range []string{"http://archive.example.invalid/mainnet/xlm/archive", "ftp://127.0.0.1/archive", "//127.0.0.1/archive", "archive"} {
		_, err := do(t, "fetch", "--url", base, "--out", out, "--deployment", deployment)
		if err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("fetch from %s: %v", base, err)
		}
		_, err = do(t, "verify", "--url", base, "--format-only")
		if err == nil || !strings.Contains(err.Error(), "https") {
			t.Errorf("verify from %s: %v", base, err)
		}
	}
	for _, base := range []string{"http://127.0.0.1:1/archive", "http://localhost:1/archive", "http://[::1]:1/archive"} {
		_, err := do(t, "fetch", "--url", base, "--out", out, "--deployment", deployment)
		if err != nil && strings.Contains(err.Error(), "https") {
			t.Errorf("fetch from the machine itself, %s: %v", base, err)
		}
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a refused fetch left a directory: %v", err)
	}
}
