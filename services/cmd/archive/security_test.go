package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

const (
	canary     = "CANARY-A-FILE-THAT-IS-NOT-PART-OF-THE-ARCHIVE"
	windowPath = "/windows/0000000000.jsonl.gz"
)

func fetchBody(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func replaceWithLink(t *testing.T, dir, name, target string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func TestTheServerNeverFollowsASymbolicLink(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "canary.txt")
	if err := os.WriteFile(outside, []byte(canary), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path  string
		setup func(t *testing.T, dir string)
	}{
		"a manifest linked to a file outside": {"/manifest.json", func(t *testing.T, dir string) {
			replaceWithLink(t, dir, "manifest.json", outside)
		}},
		"a window linked to a file outside": {windowPath, func(t *testing.T, dir string) {
			replaceWithLink(t, dir, windowPath[1:], outside)
		}},
		"a window linked to a file inside": {windowPath, func(t *testing.T, dir string) {
			replaceWithLink(t, dir, windowPath[1:], filepath.Join(dir, "windows", "0000000001.jsonl.gz"))
		}},
		"the windows directory linked outside": {windowPath, func(t *testing.T, dir string) {
			moved := filepath.Join(t.TempDir(), "windows")
			if err := os.Rename(filepath.Join(dir, "windows"), moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, filepath.Join(dir, "windows")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		dir, _ := exportSample(t)
		c.setup(t, dir)
		srv := httptest.NewServer(handler(dir))
		status, body := fetchBody(t, srv.URL+c.path)
		srv.Close()
		if status != http.StatusNotFound || strings.Contains(body, canary) {
			t.Fatalf("%s: %s answered %d", name, c.path, status)
		}
	}
}

func TestVerifyFetchesNoWindowForAManifestTheVaultCannotHold(t *testing.T) {
	dir, _ := exportSample(t)
	var windows atomic.Int32
	files := http.FileServer(http.Dir(dir))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/windows/") {
			windows.Add(1)
		}
		files.ServeHTTP(w, r)
	}))
	defer srv.Close()
	fake := chainFake(t, dir)
	fake.SetLatest(window)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	dialRPC = func(string) rpc.Client { return fake }
	_, err := do(t, "verify", "--url", srv.URL, "--rpc", "http://rpc.invalid")
	if err == nil || windows.Load() != 0 {
		t.Fatalf("a manifest that covers ledgers the RPC has not closed: %v, %d windows fetched", err, windows.Load())
	}
}

func TestVerifyAsksEveryRPCItIsGiven(t *testing.T) {
	dir, _ := exportSample(t)
	honest, other := chainFake(t, dir), chainFake(t, dir)
	c, err := vaultarchive.Load(context.Background(), vaultarchive.DirFetcher(dir), vaultarchive.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	k, err := vault.NullifierKey(vaulttest.Vault, c.Nullifiers[1].Bytes())
	if err != nil {
		t.Fatal(err)
	}
	other.DeleteEntry(k)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	dialRPC = func(u string) rpc.Client {
		if u == "http://second.invalid" {
			return other
		}
		return honest
	}
	if _, err := do(t, "verify", "--dir", dir, "--rpc", "http://first.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "verify", "--dir", dir, "--rpc", "http://second.invalid", "--rpc", "http://first.invalid"); err == nil || !strings.Contains(err.Error(), "has no entry in the vault") {
		t.Fatalf("a second RPC that does not know a nullifier: %v", err)
	}
}
