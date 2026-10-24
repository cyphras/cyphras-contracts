package main

import (
	"bytes"
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
	dir, deployment := exportSample(t)
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
	_, err := do(t, "verify", "--url", srv.URL, "--rpc", "http://rpc.invalid", "--deployment", deployment)
	if err == nil || windows.Load() != 0 {
		t.Fatalf("a manifest that covers ledgers the RPC has not closed: %v, %d windows fetched", err, windows.Load())
	}
}

func TestVerifyAsksEveryRPCItIsGiven(t *testing.T) {
	dir, deployment := exportSample(t)
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
	if _, err := do(t, "verify", "--dir", dir, "--rpc", "http://first.invalid", "--deployment", deployment); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "verify", "--dir", dir, "--rpc", "http://second.invalid", "--rpc", "http://first.invalid", "--deployment", deployment); err == nil || !strings.Contains(err.Error(), "has no entry in the vault") {
		t.Fatalf("a second RPC that does not know a nullifier: %v", err)
	}
}

func TestTheChainChecksNeedToKnowWhichVaultTheArchiveIsOf(t *testing.T) {
	dir, deployment := exportSample(t)
	fake := chainFake(t, dir)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	dialRPC = func(string) rpc.Client { return fake }
	rpcFlag := []string{"--dir", dir, "--rpc", "http://rpc.invalid"}
	with := func(more ...string) []string { return append(append([]string{"verify"}, rpcFlag...), more...) }

	if _, err := do(t, with()...); err == nil {
		t.Fatal("an archive was confirmed against whatever vault its manifest names")
	}
	if _, err := do(t, with("--vault", vaulttest.Vault)...); err == nil {
		t.Fatal("a vault without the network it is on pinned nothing")
	}
	if _, err := do(t, with("--passphrase", passphrase)...); err == nil {
		t.Fatal("a network without a vault pinned nothing")
	}
	out, err := do(t, with("--deployment", deployment)...)
	if err != nil || !strings.Contains(out, "chain checks passed for vault "+vaulttest.Vault) {
		t.Fatalf("pinned by the deployment file: %q, %v", out, err)
	}
	out, err = do(t, with("--vault", vaulttest.Vault, "--passphrase", passphrase)...)
	if err != nil || !strings.Contains(out, "chain checks passed for vault "+vaulttest.Vault) {
		t.Fatalf("pinned by vault and passphrase: %q, %v", out, err)
	}
	if _, err := do(t, with("--vault", vaulttest.Token, "--passphrase", passphrase)...); err == nil {
		t.Fatal("an archive of another vault than the pinned one was confirmed")
	}
	if _, err := do(t, with("--vault", vaulttest.Vault, "--passphrase", "Public Global Stellar Network ; September 2015")...); err == nil {
		t.Fatal("an archive of another network than the pinned one was confirmed")
	}
	if _, err := do(t, with("--deployment", deployment, "--passphrase", passphrase)...); err == nil {
		t.Fatal("a passphrase next to a deployment file was taken")
	}
	if _, err := do(t, "verify", "--dir", dir, "--format-only"); err != nil {
		t.Fatalf("the format checks need no pin: %v", err)
	}
}

func TestTheServerRefusesAPageThatReachesItUnderAnotherName(t *testing.T) {
	dir, _ := exportSample(t)
	srv := httptest.NewServer(handler(dir))
	defer srv.Close()
	get := func(host, path string) *http.Response {
		req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	for _, host := range []string{"rebind.evil.example", "rebind.evil.example:8737", "127.0.0.1.evil.example", "10.0.0.5:8737"} {
		resp := get(host, "/manifest.json")
		if resp.StatusCode != http.StatusForbidden || resp.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("host %q: %d %v", host, resp.StatusCode, resp.Header)
		}
	}
	for _, host := range []string{"127.0.0.1", "127.0.0.1:8737", "localhost", "LOCALHOST:8737", "[::1]:8737", "[::1]"} {
		if resp := get(host, "/manifest.json"); resp.StatusCode != http.StatusOK {
			t.Fatalf("host %q: %d", host, resp.StatusCode)
		}
	}
	for _, path := range []string{"/manifest.json", "/windows/0000000000.jsonl.gz", "/nothing"} {
		if resp := get("127.0.0.1", path); resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: %v", path, resp.Header)
		}
	}
	if resp := get("evil.example", "/manifest.json"); resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("a refused request: %v", resp.Header)
	}
}

func TestServeSaysWhenItListensBeyondThisMachine(t *testing.T) {
	dir, _ := exportSample(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	for addr, warns := range map[string]bool{
		"127.0.0.1:0": false, "localhost:0": false, "[::1]:0": false,
		"0.0.0.0:0": true, ":0": true, "192.0.2.1:0": true, "example.org:0": true,
	} {
		var out bytes.Buffer
		_ = run(cancelled, []string{"serve", "--dir", dir, "--addr", addr}, &out)
		if got := strings.Contains(out.String(), "warning"); got != warns {
			t.Fatalf("%s: warning %v, output %q", addr, got, out.String())
		}
	}
}
