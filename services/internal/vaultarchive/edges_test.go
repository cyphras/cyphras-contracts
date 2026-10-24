package vaultarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const midDeploy = WindowLedgers - 10

func midHead() Header {
	h := head()
	h.DeployLedger = midDeploy
	return h
}

// onBoundaries is a vault deployed ten ledgers before the end of its first window, with events on
// the deploy ledger, on both sides of every window edge, and a pair admitted on the last ledger of
// a window followed by a pair on the first ledger of the next.
func onBoundaries() []vault.RawEvent {
	c := vaulttest.New(midDeploy, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 10_000_000)
	c.Ledger = WindowLedgers - 5
	c.Attest(1)
	c.Ledger = WindowLedgers - 1
	c.Admit(1)
	c.Ledger = WindowLedgers
	id := c.Shield(vaulttest.Depositor, 20_000_000)
	c.Transact(-1_000_000, 100_000, vaulttest.Relayer)
	c.Ledger = 2*WindowLedgers - 1
	c.Attest(id)
	c.Ledger = 2 * WindowLedgers
	c.Admit(id)
	return c.Events
}

type recordingSource struct {
	inner memSource
	calls [][2]uint32
}

func (r *recordingSource) Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error) {
	r.calls = append(r.calls, [2]uint32{from, to})
	return r.inner.Events(ctx, from, to)
}

func TestEventsOnWindowEdgesAndAMidWindowDeployLandInTheRightWindows(t *testing.T) {
	dir := t.TempDir()
	src := &recordingSource{inner: memSource{onBoundaries(), 10 * WindowLedgers}}
	m, err := Build(context.Background(), src, dir, midHead(), 0, 3*WindowLedgers-1)
	if err != nil {
		t.Fatal(err)
	}
	wantCalls := [][2]uint32{{midDeploy, WindowLedgers - 1}, {WindowLedgers, 2*WindowLedgers - 1}, {2 * WindowLedgers, 3*WindowLedgers - 1}}
	if fmt.Sprint(src.calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("ranges read %v, want %v", src.calls, wantCalls)
	}
	if len(m.Windows) != 3 {
		t.Fatalf("windows %+v", m.Windows)
	}
	wantLeaves := [][2]uint64{{0, 2}, {2, 4}, {4, 6}}
	for i, w := range m.Windows {
		if w.Leaves != wantLeaves[i] {
			t.Fatalf("window %d leaves %v, want %v", i, w.Leaves, wantLeaves[i])
		}
	}
	first := string(readWindow(t, dir, 0))
	if !strings.Contains(first, fmt.Sprintf(`"ledger":%d,`, midDeploy)) || !strings.Contains(first, fmt.Sprintf(`"ledger":%d,`, WindowLedgers-1)) {
		t.Fatalf("the deploy ledger or the last ledger of the window is missing:\n%s", first)
	}
	if strings.Contains(first, fmt.Sprintf(`"ledger":%d,`, WindowLedgers)) {
		t.Fatal("an event of the next window sits in the first")
	}
	if !strings.HasSuffix(first, fmt.Sprintf("{\"covered\":[0,%d],\"count\":%d}\n", WindowLedgers-1, m.Windows[0].Events)) {
		t.Fatalf("closing line of the deploy window:\n%s", first)
	}
	if _, err := Load(context.Background(), DirFetcher(dir), Expect{Vault: vaulttest.Vault, NetworkPassphrase: passphrase, DeployLedger: midDeploy}); err != nil {
		t.Fatal(err)
	}
}

func TestAWindowWithOnlyNullifiersAndOneThatContinuesTheLeavesAreBothSound(t *testing.T) {
	c := vaulttest.New(deploy, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 1_000_000)
	c.NextLedger(5)
	c.Shield(vaulttest.Depositor, 2_000_000)
	c.Ledger = WindowLedgers + 3
	c.Attest(2)
	c.NextLedger(1)
	c.Admit(1, 2)
	dir := t.TempDir()
	m, err := Build(context.Background(), memSource{c.Events, 3 * WindowLedgers}, dir, head(), 0, 2*WindowLedgers-1)
	if err != nil {
		t.Fatal(err)
	}
	if m.Windows[0].Nullifiers != 4 || m.Windows[0].Leaves != [2]uint64{0, 0} || m.Windows[1].Leaves != [2]uint64{0, 4} {
		t.Fatalf("windows %+v", m.Windows)
	}
	contents, err := Load(context.Background(), DirFetcher(dir), Expect{})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents.Commitments) != 4 || len(contents.Nullifiers) != 4 {
		t.Fatalf("%d commitments, %d nullifiers", len(contents.Commitments), len(contents.Nullifiers))
	}
}

func TestAPairCannotBeSplitAcrossAWindowEdge(t *testing.T) {
	c := vaulttest.New(WindowLedgers-1, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 1_000_000)
	c.Attest(1)
	c.Admit(1)
	events := append([]vault.RawEvent(nil), c.Events...)
	for i := range events {
		d, err := vault.Decode(events[i])
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := d.Body.(vault.NewCommitment); ok && n.Index == 1 {
			events[i].Ledger = WindowLedgers
		}
	}
	_, err := Build(context.Background(), fixedSource(events), t.TempDir(), Header{Network: "testnet", NetworkPassphrase: passphrase, Vault: vaulttest.Vault, DeployLedger: WindowLedgers - 1}, 0, WindowLedgers-1)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("a pair cut at the edge: %v", err)
	}
}

func TestAnEventBeforeTheDeployLedgerIsRefused(t *testing.T) {
	var events []vault.RawEvent
	for _, e := range onBoundaries() {
		if e.Ledger < WindowLedgers {
			events = append(events, e)
		}
	}
	early := events[0]
	early.Ledger = midDeploy - 1
	events = append([]vault.RawEvent{early}, events...)
	dir := t.TempDir()
	_, err := Build(context.Background(), fixedSource(events), dir, midHead(), 0, WindowLedgers-1)
	if err == nil {
		t.Fatal("a vault event from before the vault existed was written")
	}
	good := t.TempDir()
	if _, err := Build(context.Background(), memSource{onBoundaries(), 10 * WindowLedgers}, good, midHead(), 0, WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	rewrite(t, good, 0, func(l []string) []string {
		prefix := strings.Replace(l[0], fmt.Sprintf(`"ledger":%d,`, midDeploy), fmt.Sprintf(`"ledger":%d,`, midDeploy-1), 1)
		return append([]string{prefix}, l[1:]...)
	})
	_, err = Load(context.Background(), DirFetcher(good), Expect{})
	mustInvalid(t, "an event before the deploy ledger", err, "deploy")
}

func TestATruncatedGzipIsRefusedWhateverWhereItIsCut(t *testing.T) {
	dir, _ := good(t)
	name := filepath.Join(dir, Window{Start: 0}.File())
	whole, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, cut := range []int{len(whole) - 1, len(whole) - 8, len(whole) / 2, 12, 3} {
		if err := os.WriteFile(name, whole[:cut], 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(context.Background(), DirFetcher(dir), Expect{})
		mustInvalid(t, fmt.Sprintf("a gzip cut at %d of %d", cut, len(whole)), err, "not gzip")
	}
	if err := os.WriteFile(name, append(append([]byte(nil), whole...), []byte("trailing")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), DirFetcher(dir), Expect{}); err == nil {
		t.Fatal("bytes after the gzip stream were accepted")
	}
}

func TestADuplicatedWindowOrAWindowMissingFromTheManifestIsRefused(t *testing.T) {
	cases := map[string]func(m *Manifest){
		"windows out of order": func(m *Manifest) { m.Windows[0], m.Windows[1] = m.Windows[1], m.Windows[0] },
		"a window missing":     func(m *Manifest) { m.Windows = []Window{m.Windows[0], m.Windows[2]} },
		"the first window gone": func(m *Manifest) {
			m.Windows = m.Windows[1:]
		},
		"a window twice": func(m *Manifest) { m.Windows = append(m.Windows[:2], m.Windows[1], m.Windows[2]) },
	}
	for name, damage := range cases {
		dir, _ := good(t)
		m := readManifestFile(t, dir)
		damage(&m)
		if n := len(m.Windows); n > 0 {
			m.CoveredTo = m.Windows[n-1].End
		}
		writeManifestFile(t, dir, m)
		_, err := Load(context.Background(), DirFetcher(dir), Expect{})
		mustInvalid(t, name, err, "window")
	}
}

func TestAManifestWithAnotherWindowSizeOrALeavesRangeOfThreeNumbersIsRefused(t *testing.T) {
	dir, _ := good(t)
	m := readManifestFile(t, dir)
	m.WindowLedgers = 8640
	writeManifestFile(t, dir, m)
	_, err := Load(context.Background(), DirFetcher(dir), Expect{})
	mustInvalid(t, "half-size windows", err, "windows of")

	dir, _ = good(t)
	var loose map[string]any
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &loose); err != nil {
		t.Fatal(err)
	}
	loose["windows"].([]any)[0].(map[string]any)["leaves"] = []uint64{0, 4, 99}
	raw, err = json.Marshal(loose)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), DirFetcher(dir), Expect{}); err == nil {
		t.Fatal("a leaves range of three numbers was read as two")
	}
}

func TestANullifierListedTwiceIsRefused(t *testing.T) {
	events := sample()[:13]
	var first vault.RawEvent
	for _, e := range events {
		d, err := vault.Decode(e)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.Body.(vault.NewNullifier); ok {
			first = e
			break
		}
	}
	again := first
	again.Index += 50
	twice := append(append([]vault.RawEvent(nil), events...), again)
	_, err := Build(context.Background(), fixedSource(twice), t.TempDir(), head(), 0, WindowLedgers-1)
	if err == nil {
		t.Fatal("a nullifier that appears in two events was written")
	}
}

func TestAnHTTPServerThatFailsMidWayNeverGivesAGoodArchive(t *testing.T) {
	dir, _ := good(t)
	files := http.FileServer(http.Dir(dir))
	window := "/" + Window{Start: 0}.File()
	cases := map[string]http.HandlerFunc{
		"429 on a window": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == window {
				http.Error(w, "slow down", http.StatusTooManyRequests)
				return
			}
			files.ServeHTTP(w, r)
		},
		"a dropped connection on a window": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == window {
				w.Header().Set("Content-Length", "100000")
				_, _ = w.Write([]byte("partial"))
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
			files.ServeHTTP(w, r)
		},
		"an HTML page for the manifest": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/"+ManifestName {
				_, _ = w.Write([]byte("<html>captive portal</html>"))
				return
			}
			files.ServeHTTP(w, r)
		},
		"a 500 for the manifest": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/"+ManifestName {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			files.ServeHTTP(w, r)
		},
	}
	for name, h := range cases {
		srv := httptest.NewServer(h)
		_, err := Load(context.Background(), HTTPFetcher{Base: srv.URL}, Expect{})
		srv.Close()
		if err == nil {
			t.Fatalf("%s: the archive was accepted", name)
		}
	}
	srv := httptest.NewServer(files)
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, HTTPFetcher{Base: srv.URL}, Expect{}); err == nil {
		t.Fatal("a cancelled load passed")
	}
}

func TestAFailedBuildOfAFreshDirectoryLeavesNoManifest(t *testing.T) {
	dir := t.TempDir()
	_, err := Build(context.Background(), memSource{sample(), 0}, dir, head(), 0, WindowLedgers-1)
	if !errors.Is(err, archive.ErrNotCovered) {
		t.Fatalf("build: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ManifestName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed first build left a manifest that reads as a valid archive: %v", err)
	}
}

func TestACommitmentPairIsRecognisedWhateverEventsSitBetweenItsLeaves(t *testing.T) {
	c := vaulttest.New(deploy, 1_728_000_000)
	c.Shield(vaulttest.Depositor, 1_000_000)
	c.NextLedger(1)
	c.Attest(1)
	c.NextLedger(1)
	c.Admit(1)
	dir := t.TempDir()
	if _, err := Build(context.Background(), memSource{c.Events, 2 * WindowLedgers}, dir, head(), 0, WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), DirFetcher(dir), Expect{}); err != nil {
		t.Fatal(err)
	}
}

func pairs(n int) []fr.Element {
	out := make([]fr.Element, 0, 2*n)
	for i := range 2 * n {
		out = append(out, fr.SetUint64(uint64(70_000+i)))
	}
	return out
}

func manifestOnly() Manifest {
	return Manifest{Format: Format, Network: "testnet", NetworkPassphrase: passphrase, Vault: vaulttest.Vault, DeployLedger: deploy, WindowLedgers: WindowLedgers}
}

func TestTheRootRingIsReadRightAtItsEdges(t *testing.T) {
	all := pairs(400)
	cases := []struct {
		name         string
		archive, vlt int
		ok           bool
	}{
		{"both empty", 0, 0, true},
		{"archive empty, vault a few pairs on", 0, 5, true},
		{"archive empty, vault 255 pairs on", 0, 255, true},
		{"archive empty, vault 256 pairs on", 0, 256, false},
		{"the vault one pair on", 7, 8, true},
		{"255 pairs behind", 3, 3 + 255, true},
		{"256 pairs behind", 3, 3 + 256, false},
		{"behind across the wrap of the ring", 100, 300, true},
		{"255 behind across the wrap", 90, 345, true},
		{"256 behind across the wrap", 90, 346, false},
		{"equal after the ring has wrapped", 300, 300, true},
		{"one pair ahead of the vault", 5, 4, false},
		{"far ahead of the vault", 40, 4, false},
	}
	for _, c := range cases {
		onChain := &Contents{Manifest: manifestOnly(), Commitments: all[:2*c.vlt]}
		f := chainOf(t, onChain)
		got := &Contents{Manifest: manifestOnly(), Commitments: all[:2*c.archive]}
		report, err := VerifyChain(context.Background(), f, got)
		if c.ok && err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, ErrChain) {
			t.Fatalf("%s: %v (report %+v)", c.name, err, report)
		}
	}
}

func TestAnArchiveWithAPairReplacedByItsNeighbourIsRefused(t *testing.T) {
	all := pairs(10)
	f := chainOf(t, &Contents{Manifest: manifestOnly(), Commitments: all})
	for k := range 9 {
		got := &Contents{Manifest: manifestOnly(), Commitments: append([]fr.Element(nil), all...)}
		copy(got.Commitments[2*k:2*k+2], all[2*k+2:2*k+4])
		if _, err := VerifyChain(context.Background(), f, got); !errors.Is(err, ErrChain) {
			t.Fatalf("pair %d replaced by its neighbour: %v", k, err)
		}
	}
}

func TestNullifiersAreCheckedAcrossEveryBatchBoundary(t *testing.T) {
	var all []fr.Element
	for i := range 2_001 {
		all = append(all, fr.SetUint64(uint64(40_000+i)))
	}
	build := func() *Contents { return &Contents{Manifest: manifestOnly(), Nullifiers: all} }
	f := chainOf(t, build())
	if _, err := VerifyChain(context.Background(), f, build()); err != nil {
		t.Fatal(err)
	}
	if calls := f.CallCount("getLedgerEntries"); calls != 1+11 {
		t.Fatalf("%d getLedgerEntries calls for 2001 nullifiers", calls)
	}
	for _, missing := range []int{0, 199, 200, 1_999, 2_000} {
		f := chainOf(t, build())
		key, err := vault.NullifierKey(vaulttest.Vault, all[missing].Bytes())
		if err != nil {
			t.Fatal(err)
		}
		f.DeleteEntry(key)
		_, err = VerifyChain(context.Background(), f, build())
		if !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), all[missing].Hex()) {
			t.Fatalf("nullifier %d missing: %v", missing, err)
		}
	}
}

// shortChange answers like an RPC that drops the last entry of every response.
type shortChange struct{ rpc.Client }

func (s shortChange) GetLedgerEntries(ctx context.Context, req protocol.GetLedgerEntriesRequest) (protocol.GetLedgerEntriesResponse, error) {
	resp, err := s.Client.GetLedgerEntries(ctx, req)
	if n := len(resp.Entries); n > 0 {
		resp.Entries = resp.Entries[:n-1]
	}
	return resp, err
}

func TestAnRPCThatReturnsFewerEntriesThanAskedFailsTheChecks(t *testing.T) {
	c := loaded(t)
	f := chainOf(t, c)
	if _, err := VerifyChain(context.Background(), shortChange{f}, c); !errors.Is(err, ErrChain) {
		t.Fatalf("an RPC that drops the last entry of the tree read: %v", err)
	}
	only := &Contents{Manifest: manifestOnly(), Nullifiers: []fr.Element{fr.SetUint64(1), fr.SetUint64(2), fr.SetUint64(3)}}
	if _, err := VerifyChain(context.Background(), shortChange{chainOf(t, only)}, only); !errors.Is(err, ErrChain) {
		t.Fatalf("an RPC that drops the last nullifier: %v", err)
	}
}

func TestTheNetworkOfTheRPCMustBeTheArchivesEvenWhenTheEntriesMatch(t *testing.T) {
	c := loaded(t)
	f := chainOf(t, c)
	f.Passphrase = "Public Global Stellar Network ; September 2015"
	if _, err := VerifyChain(context.Background(), f, c); err == nil || !strings.Contains(err.Error(), "serves") {
		t.Fatalf("an RPC of another network with the same entries: %v", err)
	}
	if f.CallCount("getLedgerEntries") != 0 {
		t.Fatal("entries were read from an RPC of the wrong network")
	}
}

func TestACompressedWindowIsTheSameBytesEveryTime(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	src := memSource{sample(), 4 * WindowLedgers}
	if _, err := Build(context.Background(), src, a, head(), 0, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), src, b, head(), 0, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	for _, start := range []uint32{0, WindowLedgers} {
		x, err := os.ReadFile(filepath.Join(a, Window{Start: start}.File()))
		if err != nil {
			t.Fatal(err)
		}
		y, err := os.ReadFile(filepath.Join(b, Window{Start: start}.File()))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x, y) {
			t.Fatalf("window %d compresses to different bytes", start)
		}
		zr, err := gzip.NewReader(bytes.NewReader(x))
		if err != nil {
			t.Fatal(err)
		}
		if !zr.ModTime.IsZero() || zr.Name != "" {
			t.Fatalf("window %d carries a time or a name in its gzip header", start)
		}
	}
}
