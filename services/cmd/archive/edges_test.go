package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

const midDeployAt = window - 10

func deploymentAt(t *testing.T, ledger uint32, network, phrase string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"network":            network,
		"network_passphrase": phrase,
		"vaults": []map[string]any{{
			"asset": "native", "vault": vaulttest.Vault, "token": vaulttest.Token, "deploy_ledger": ledger, "fee_tier": "100000",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(name, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return name
}

// onEdges is a vault deployed ten ledgers before the end of its first window: a first window with
// nullifiers and a pair on its last ledger, a second that opens with a pair on its first ledger
// and holds no nullifier, and a third with only nullifiers.
func onEdges() []vault.RawEvent {
	c := vaulttest.New(midDeployAt, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.Ledger = window - 5
	c.Attest(1)
	c.Ledger = window - 1
	c.Admit(1)
	c.Ledger = window
	c.Tx()
	c.Ledger = window + 40
	c.Shield(vaulttest.Depositor, 20_000_000)
	c.Ledger = 2 * window
	c.Shield(vaulttest.Depositor, 30_000_000)
	c.Ledger = 3*window - 1
	c.Shield(vaulttest.Depositor, 40_000_000)
	return c.Events
}

func TestExportAndRebuildAgreeOnEdgesNullifierOnlyWindowsAndAMidWindowDeploy(t *testing.T) {
	events := onEdges()
	deployment := deploymentAt(t, midDeployAt, "testnet", passphrase)
	raw := t.TempDir()
	if err := (archive.Writer{Dir: raw}).Append(events, midDeployAt, 3*window+50); err != nil {
		t.Fatal(err)
	}
	exported := filepath.Join(t.TempDir(), "exported")
	if _, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", exported); err != nil {
		t.Fatal(err)
	}
	rebuilt := filepath.Join(t.TempDir(), "rebuilt")
	base := ledgerArchive(t, events, 3)
	if _, err := do(t, "rebuild", "--ledger-meta", base, "--deployment", deployment, "--out", rebuilt, "--to", fmt.Sprint(3*window-1), "--workers", "3"); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(filepath.Join(exported, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(rebuilt, "manifest.json"))
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("manifests differ: %v\n%s\n%s", err, a, b)
	}
	var m vaultarchive.Manifest
	if err := json.Unmarshal(a, &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Windows) != 3 || m.Windows[0].Leaves != [2]uint64{0, 2} || m.Windows[1].Leaves != [2]uint64{2, 2} || m.Windows[2].Leaves != [2]uint64{2, 2} {
		t.Fatalf("windows %+v", m.Windows)
	}
	for _, w := range m.Windows {
		if w.Events == 0 {
			continue
		}
		if !bytes.Equal(decompressed(t, exported, w.File()), decompressed(t, rebuilt, w.File())) {
			t.Fatalf("window %d differs", w.Start)
		}
	}
	if out, err := do(t, "verify", "--dir", exported, "--format-only", "--deployment", deployment); err != nil {
		t.Fatalf("%q: %v", out, err)
	}
}

func TestExportStillCoversTheClosedWindowsWhenTheNewestFileHoldsOnlyATornWrite(t *testing.T) {
	events := sample()
	raw := t.TempDir()
	if err := (archive.Writer{Dir: raw}).Append(events, deployAt, 2*window-1); err != nil {
		t.Fatal(err)
	}
	tornOnly := filepath.Join(raw, fmt.Sprintf("%010d.jsonl", 2*window))
	if err := os.WriteFile(tornOnly, []byte(`{"write":7,"event":{"ledger":34`), 0o644); err != nil {
		t.Fatal(err)
	}
	deployment := writeDeployment(t, vaulttest.Vault)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", out); err != nil {
		t.Fatalf("a crash while opening the next window's file stops the export of the windows before it: %v", err)
	}
	var m vaultarchive.Manifest
	data, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &m); err != nil || m.CoveredTo != 2*window-1 {
		t.Fatalf("covered to %d: %v", m.CoveredTo, err)
	}
}

func TestAnExportThatFailsInTheMiddleLeavesAManifestOfTheWindowsBeforeIt(t *testing.T) {
	events := sample()
	raw := t.TempDir()
	w := archive.Writer{Dir: raw}
	if err := w.Append(events, deployAt, window-1); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(events, 2*window, 2*window+10); err != nil {
		t.Fatal(err)
	}
	deployment := writeDeployment(t, vaulttest.Vault)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := do(t, "export", "--dir", raw, "--deployment", deployment, "--out", out); err == nil {
		t.Fatal("an export over a gap passed")
	}
	if msg, err := do(t, "verify", "--dir", out, "--format-only"); err != nil || !strings.Contains(msg, "1 windows") {
		t.Fatalf("the partial result is not a valid archive of the windows before the gap: %q, %v", msg, err)
	}
	if _, err := os.Stat(filepath.Join(out, "windows", fmt.Sprintf("%010d.jsonl.gz", window))); err == nil {
		t.Fatal("the window over the gap has a file")
	}
}

func TestAVerifyThatNamesAVaultWithoutADeploymentFileIsRefused(t *testing.T) {
	dir, _ := exportSample(t)
	_, err := do(t, "verify", "--dir", dir, "--format-only", "--vault", vaulttest.Token)
	if err == nil {
		t.Fatal("--vault was silently ignored, so the check pinned nothing")
	}
}

func TestAVerifyAgainstAnotherNetworkOfTheDeploymentFileIsRefused(t *testing.T) {
	dir, _ := exportSample(t)
	mainnet := deploymentAt(t, deployAt, "mainnet", "Public Global Stellar Network ; September 2015")
	_, err := do(t, "verify", "--dir", dir, "--format-only", "--deployment", mainnet)
	if err == nil || !strings.Contains(err.Error(), "network") {
		t.Fatalf("a testnet archive against the mainnet deployment: %v", err)
	}
	other := deploymentAt(t, deployAt+1, "testnet", passphrase)
	if _, err := do(t, "verify", "--dir", dir, "--format-only", "--deployment", other); err == nil {
		t.Fatal("an archive with another deploy ledger than the deployment file passed")
	}
}

func TestARebuildWithAFromPastItsToIsRefusedAndKeepsTheManifest(t *testing.T) {
	dir, deployment := exportSample(t)
	before, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = do(t, "rebuild", "--ledger-meta", "http://127.0.0.1:1", "--deployment", deployment, "--out", dir, "--from", fmt.Sprint(window), "--to", "100")
	after, readErr := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil || !bytes.Equal(before, after) {
		t.Fatalf("--from %d --to 100: err %v, manifest kept %v", window, err, bytes.Equal(before, after))
	}
}

func quickRetries(t *testing.T) {
	t.Helper()
	old := patientClient
	patientClient = &http.Client{Timeout: time.Minute, Transport: retrying{next: http.DefaultTransport, delay: time.Millisecond}}
	t.Cleanup(func() { patientClient = old })
}

func TestARebuildFromAnArchiveOfAnotherNetworkOrThatFailsWritesNoManifest(t *testing.T) {
	quickRetries(t)
	deployment := writeDeployment(t, vaulttest.Vault)
	wrong := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".config.json") {
			_, _ = io.WriteString(w, `{"networkPassphrase":"Public Global Stellar Network ; September 2015","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":1}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer wrong.Close()
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".config.json") {
			_, _ = io.WriteString(w, fmt.Sprintf(`{"networkPassphrase":%q,"compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":1}`, passphrase))
			return
		}
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer limited.Close()
	for name, base := range map[string]string{"another network": wrong.URL, "429 on every ledger": limited.URL} {
		out := filepath.Join(t.TempDir(), "out")
		if _, err := do(t, "rebuild", "--ledger-meta", base, "--deployment", deployment, "--out", out, "--to", fmt.Sprint(window-1), "--workers", "2"); err == nil {
			t.Fatalf("%s: the rebuild passed", name)
		}
		if _, err := os.Stat(filepath.Join(out, "manifest.json")); err == nil {
			t.Fatalf("%s: a failed rebuild left a manifest", name)
		}
	}
}

func TestAnExportIntoAPathThatIsAFileFails(t *testing.T) {
	deployment := writeDeployment(t, vaulttest.Vault)
	file := filepath.Join(t.TempDir(), "in-the-way")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := do(t, "export", "--dir", indexerArchive(t, sample()), "--deployment", deployment, "--out", file); err == nil {
		t.Fatal("an export into a file passed")
	}
}

func TestTheServerHandlesTraversalContentTypesAndRanges(t *testing.T) {
	dir, _ := exportSample(t)
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "windows", ".part-123"), []byte("p"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "secret.txt"), filepath.Join(dir, "windows", "0000000099.jsonl.gz")); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler(dir))
	defer srv.Close()
	raw := func(method, target string, header map[string]string) (*http.Response, []byte) {
		conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		var req strings.Builder
		fmt.Fprintf(&req, "%s %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n", method, target)
		for k, v := range header {
			fmt.Fprintf(&req, "%s: %s\r\n", k, v)
		}
		req.WriteString("\r\n")
		if _, err := io.WriteString(conn, req.String()); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, body
	}
	for _, target := range []string{
		"/windows/../secret.txt", "/windows/%2e%2e/secret.txt", "/windows/..%2fsecret.txt", "/windows//../secret.txt",
		"/manifest.json/", "//manifest.json", "/manifest.json/.", "/windows/", "/windows", "/", "/windows/.part-123",
		"/windows/0000000099.jsonl.gz.", "/windows/0000000000.jsonl.gz/", "/windows/0000000000.jsonl.gz%00", "/windows/00000000000.jsonl.gz",
		"/manifest.json%0a", "/MANIFEST.JSON", "/index.html",
	} {
		resp, body := raw("GET", target, nil)
		if resp.StatusCode == http.StatusOK && string(body) == "s" {
			t.Fatalf("%s served a file outside the archive", target)
		}
		if resp.StatusCode == http.StatusOK && !strings.HasSuffix(strings.Split(target, "?")[0], "manifest.json") && !strings.Contains(target, "0000000000.jsonl.gz") {
			t.Fatalf("%s answered 200", target)
		}
		if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("%s: no CORS header on a %d", target, resp.StatusCode)
		}
	}
	resp, _ := raw("GET", "/manifest.json", nil)
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("manifest content type %q", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("manifest cache control %q", resp.Header.Get("Cache-Control"))
	}
	resp, body := raw("GET", "/windows/0000000000.jsonl.gz", nil)
	if ct := resp.Header.Get("Content-Type"); resp.StatusCode != http.StatusOK || ct == "" || strings.HasPrefix(ct, "text/") {
		t.Fatalf("window content type %q (%d)", ct, resp.StatusCode)
	}
	if resp.Header.Get("Content-Encoding") != "" {
		t.Fatalf("the window is sent with content encoding %q, so a client would unpack it before the hash", resp.Header.Get("Content-Encoding"))
	}
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatal("the window is not served as stored")
	}
	resp, part := raw("GET", "/windows/0000000000.jsonl.gz", map[string]string{"Range": "bytes=0-9"})
	if resp.StatusCode != http.StatusPartialContent || len(part) != 10 {
		t.Fatalf("range: %d, %d bytes", resp.StatusCode, len(part))
	}
	resp, head := raw("HEAD", "/manifest.json", nil)
	if resp.StatusCode != http.StatusOK || len(head) != 0 || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("head: %d, %d bytes", resp.StatusCode, len(head))
	}
}

func TestServeStopsWithTheContextAndFailsOnAPortInUse(t *testing.T) {
	dir, _ := exportSample(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	if _, err := do(t, "serve", "--dir", dir, "--addr", busy.Addr().String()); err == nil {
		t.Fatal("serving on a busy port passed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"serve", "--dir", dir, "--addr", "127.0.0.1:0"}, io.Discard) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a stopped server returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the server ignored the context")
	}
}

// flaky forwards to base and answers the first request of some paths with a server error or a
// rate limit, as an object store under load does.
func flaky(t *testing.T, base string) string {
	t.Helper()
	var mu sync.Mutex
	seen := map[string]bool{}
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		first := !seen[r.URL.Path]
		seen[r.URL.Path] = true
		fail := first && (n%300 == 1 || strings.HasSuffix(r.URL.Path, ".config.json"))
		code := http.StatusServiceUnavailable
		if n%2 == 0 {
			code = http.StatusTooManyRequests
		}
		mu.Unlock()
		if fail {
			http.Error(w, "try later", code)
			return
		}
		resp, err := http.Get(strings.TrimSuffix(base, "/pubnet") + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/pubnet"
}

func TestARebuildSurvivesAnObjectStoreThatAnswers503And429NowAndThen(t *testing.T) {
	quickRetries(t)
	events := sample()
	deployment := writeDeployment(t, vaulttest.Vault)
	out := filepath.Join(t.TempDir(), "rebuilt")
	base := flaky(t, ledgerArchive(t, events, 1))
	if _, err := do(t, "rebuild", "--ledger-meta", base, "--deployment", deployment, "--out", out, "--to", fmt.Sprint(window-1), "--workers", "8"); err != nil {
		t.Fatalf("one failed request in a window of %d fails the whole window: %v", window, err)
	}
}
