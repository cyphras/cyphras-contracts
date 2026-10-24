package vaultarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// goldenSHA is the SHA-256 of the canonical bytes of the first window of sample.
const goldenSHA = "d8f760d33a83e541510d0226940a5d6016db978135206518f3fdd63df1781d0e"

func TestAnIndexerArchiveWithTornReplacedAndSeveralWritesGivesTheCanonicalBytes(t *testing.T) {
	events := sample()[:13]
	raw := t.TempDir()
	w := archive.Writer{Dir: raw}
	if err := w.Append(events, 10, 10); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(raw, "0000000000.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"write":5,"event":{"ledger":13,"tx`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	// A first try at ledgers 11 and 12 that the second replaces.
	wrong := append([]vault.RawEvent(nil), events...)
	for i := range wrong {
		wrong[i].TxHash = strings.Repeat("ab", 32)
	}
	if err := w.Append(wrong, 11, 12); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(events, 11, 12); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(events, 13, 30); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(nil, 31, WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	m, err := Build(context.Background(), archive.Reader{Dir: raw, Vault: vaulttest.Vault}, out, head(), 0, WindowLedgers-1)
	if err != nil {
		t.Fatal(err)
	}
	var want strings.Builder
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		want.Write(line)
		want.WriteByte('\n')
	}
	want.WriteString(`{"covered":[0,17279],"count":13}` + "\n")
	got := readWindow(t, out, 0)
	if string(got) != want.String() {
		t.Fatalf("canonical bytes differ:\n%s\nwant\n%s", got, want.String())
	}
	sum := sha256.Sum256(got)
	if hex.EncodeToString(sum[:]) != goldenSHA {
		t.Fatalf("sha256 %x", sum)
	}
	entry := Window{Start: 0, End: WindowLedgers - 1, Events: 13, Leaves: [2]uint64{0, 4}, Nullifiers: 4, Bytes: int64(len(got)), SHA256: goldenSHA}
	if len(m.Windows) != 1 || m.Windows[0] != entry || m.CoveredTo != WindowLedgers-1 {
		t.Fatalf("manifest %+v", m)
	}
	if _, err := Load(context.Background(), DirFetcher(out), Expect{Vault: vaulttest.Vault, NetworkPassphrase: passphrase, DeployLedger: deploy}); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyClosedWindowsAreWrittenAndEmptyOnesHaveNoFile(t *testing.T) {
	dir, m := good(t)
	if len(m.Windows) != 3 || m.CoveredTo != 3*WindowLedgers-1 {
		t.Fatalf("manifest %+v", m)
	}
	if m.Windows[1].Leaves != [2]uint64{4, 8} || m.Windows[2].Leaves != [2]uint64{8, 8} || m.Windows[2].Events != 0 || m.Windows[2].SHA256 != "" {
		t.Fatalf("windows %+v", m.Windows)
	}
	for _, start := range []uint32{0, WindowLedgers} {
		if _, err := os.Stat(filepath.Join(dir, Window{Start: start}.File())); err != nil {
			t.Fatal(err)
		}
	}
	for _, start := range []uint32{2 * WindowLedgers, 3 * WindowLedgers} {
		if _, err := os.Stat(filepath.Join(dir, Window{Start: start}.File())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("window %d: %v", start, err)
		}
	}
	contents, err := Load(context.Background(), DirFetcher(dir), Expect{})
	if err != nil {
		t.Fatal(err)
	}
	if len(contents.Commitments) != 8 || len(contents.Nullifiers) != 8 {
		t.Fatalf("%d commitments and %d nullifiers", len(contents.Commitments), len(contents.Nullifiers))
	}
}

func TestBuildingInStepsGivesTheArchiveOfBuildingAtOnce(t *testing.T) {
	ctx := context.Background()
	dir, whole := good(t)
	steps := t.TempDir()
	src := memSource{sample(), 4 * WindowLedgers}
	if _, err := Build(ctx, src, steps, head(), 0, WindowLedgers+5); err != nil {
		t.Fatal(err)
	}
	// Nothing new has closed, so another run changes nothing.
	again, err := Build(ctx, src, steps, head(), 0, WindowLedgers+6)
	if err != nil || len(again.Windows) != 1 {
		t.Fatalf("a run with no new window: %+v, %v", again, err)
	}
	if _, err := Build(ctx, src, steps, head(), 0, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	// A file left in the place of a window that holds nothing is taken away.
	stale := filepath.Join(steps, Window{Start: 2 * WindowLedgers}.File())
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Building again from the second window replaces it with the same bytes.
	if _, err := Build(ctx, src, steps, head(), WindowLedgers+3, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ManifestName, Window{Start: 0}.File(), Window{Start: WindowLedgers}.File()} {
		a, errA := os.ReadFile(filepath.Join(dir, name))
		b, errB := os.ReadFile(filepath.Join(steps, name))
		if errA != nil || errB != nil || !bytes.Equal(a, b) {
			t.Fatalf("%s differs: %v %v", name, errA, errB)
		}
	}
	if m := readManifestFile(t, steps); m.CoveredTo != whole.CoveredTo || len(m.Windows) != 3 {
		t.Fatalf("manifest %+v", m)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stale file of an empty window stays: %v", err)
	}
	if _, err := Build(ctx, memSource{sample(), 20 * WindowLedgers}, steps, head(), 5*WindowLedgers, 6*WindowLedgers-1); err == nil {
		t.Fatal("a build that skips windows was accepted")
	}
	other := head()
	other.Vault = vaulttest.Token
	if _, err := Build(ctx, src, steps, other, 0, 3*WindowLedgers-1); err == nil {
		t.Fatal("a directory of another vault was extended")
	}
}

func TestEventsInAnyOrderAreWrittenInChainOrder(t *testing.T) {
	events := sample()[:13]
	reversed := make([]vault.RawEvent, len(events))
	for i, e := range events {
		reversed[len(events)-1-i] = e
	}
	shuffled, ordered := t.TempDir(), t.TempDir()
	if _, err := Build(context.Background(), fixedSource(reversed), shuffled, head(), 0, WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(context.Background(), fixedSource(events), ordered, head(), 0, WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readWindow(t, shuffled, 0), readWindow(t, ordered, 0)) {
		t.Fatal("the order of the source changed the window")
	}
}

func TestABuildStopsAtTheFirstWindowItCannotCover(t *testing.T) {
	dir := t.TempDir()
	m, err := Build(context.Background(), memSource{sample(), WindowLedgers + 100}, dir, head(), 0, 3*WindowLedgers-1)
	if !errors.Is(err, archive.ErrNotCovered) {
		t.Fatalf("build: %v", err)
	}
	if len(m.Windows) != 1 || readManifestFile(t, dir).CoveredTo != WindowLedgers-1 {
		t.Fatalf("manifest after the stop %+v", m)
	}
	if _, err := os.Stat(filepath.Join(dir, Window{Start: WindowLedgers}.File())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the window that was not covered has a file: %v", err)
	}
}

func TestABuildRefusesWhatAReaderWouldRefuse(t *testing.T) {
	events := sample()
	at := func(i int) vault.RawEvent { return events[i] }
	other := at(0)
	other.Contract = vaulttest.Token
	duplicate := at(1)
	duplicate.Value = at(0).Value
	outside := at(0)
	outside.Ledger = WindowLedgers + 1
	large := at(6)
	large.Value = strings.Repeat("A", MaxLineBytes)
	for name, bad := range map[string][]vault.RawEvent{
		"an event of another contract": {at(0), other},
		"two events at one position":   {at(1), duplicate},
		"an event of another window":   {at(0), outside},
		"an event that fills a line":   {at(0), large},
	} {
		dir := t.TempDir()
		_, err := Build(context.Background(), fixedSource(bad), dir, head(), 0, WindowLedgers-1)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Stat(filepath.Join(dir, Window{Start: 0}.File())); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the window was written: %v", name, err)
		}
	}
}

func TestAReaderRefusesEveryBreakOfTheFormat(t *testing.T) {
	ctx := context.Background()
	events := sample()
	stolen, err := xdr.MarshalBase64(vault.Symbol("steal"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, reason string
		damage       func(t *testing.T, dir string)
	}{
		{"an event of another contract", "an event of contract", lines(func(l []string) []string {
			l[0] = strings.Replace(l[0], vaulttest.Vault, vaulttest.Token, 1)
			return l
		})},
		{"a duplicate position", "does not follow", lines(func(l []string) []string {
			return append(l[:3], l[2:]...)
		})},
		{"events out of order", "does not follow", lines(func(l []string) []string {
			l[3], l[4] = l[4], l[3]
			return l
		})},
		{"a ledger outside the window", "outside the window", lines(func(l []string) []string {
			l[6] = strings.Replace(l[6], `"ledger":12,`, `"ledger":17280,`, 1)
			return l
		})},
		{"a line as long as a megabyte", "line 7 of", lines(func(l []string) []string {
			l[6] = strings.Replace(l[6], `"value":"`, `"value":"`+strings.Repeat("A", MaxLineBytes), 1)
			return l
		})},
		{"a pair split over two transactions", "second of a pair in one transaction", lines(func(l []string) []string {
			l[8] = strings.Replace(l[8], `"tx":1,`, `"tx":2,`, 1)
			return l
		})},
		{"a leaf gone", "where 1 belongs", lines(func(l []string) []string {
			return append(l[:8], l[9:]...)
		})},
		{"a pair cut short at the end of the window", "has no partner", lines(func(l []string) []string {
			return []string{l[0], l[1], l[2], l[7], l[len(l)-1]}
		})},
		{"an unknown topic", "unknown event topic", lines(func(l []string) []string {
			l[6] = strings.Replace(l[6], events[6].Topics[0], stolen, 1)
			return l
		})},
		{"a field out of order", "not in canonical form", lines(func(l []string) []string {
			l[0] = strings.Replace(l[0], `"ledger":10,"closed_at":1728000000,`, `"closed_at":1728000000,"ledger":10,`, 1)
			return l
		})},
		{"a transaction hash in capitals", "transaction hash", lines(func(l []string) []string {
			l[0] = strings.Replace(l[0], events[0].TxHash, strings.ToUpper(events[0].TxHash), 1)
			return l
		})},
		{"a space in a line", "not in canonical form", lines(func(l []string) []string {
			l[0] = strings.Replace(l[0], `"ledger":10,`, `"ledger": 10,`, 1)
			return l
		})},
		{"a field of its own", "unknown field", lines(func(l []string) []string {
			l[0] = strings.Replace(l[0], `{"ledger"`, `{"extra":1,"ledger"`, 1)
			return l
		})},
		{"no closing line", "closing line", lines(func(l []string) []string {
			return l[:len(l)-1]
		})},
		{"a closing line of another count", "closing line", lines(func(l []string) []string {
			l[len(l)-1] = `{"covered":[0,17279],"count":12}`
			return l
		})},
		{"a closing line of another coverage", "closing line", lines(func(l []string) []string {
			l[len(l)-1] = `{"covered":[0,17278],"count":13}`
			return l
		})},
		{"a window of another hash", "another sha256", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Windows[0].SHA256 = strings.Repeat("0", 64)
			writeManifestFile(t, dir, m)
		}},
		{"a window of another size", "the manifest says", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Windows[0].Bytes++
			writeManifestFile(t, dir, m)
		}},
		{"a window with other counts", "the manifest says", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Windows[0].Nullifiers--
			m.Windows[0].Events++
			writeManifestFile(t, dir, m)
		}},
		{"a window that is not gzip", "not gzip", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, Window{Start: 0}.File()), []byte("plain"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"a window that expands without end", "expands past", func(t *testing.T, dir string) {
			// The manifest claims the largest window, so only the expanded size can refuse it.
			m := readManifestFile(t, dir)
			m.Windows[0].Bytes = MaxWindowBytes
			writeManifestFile(t, dir, m)
			var packed bytes.Buffer
			zw := gzip.NewWriter(&packed)
			if _, err := zw.Write(make([]byte, MaxWindowBytes+1)); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, Window{Start: 0}.File()), packed.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"a window with no file", "has no file", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, Window{Start: WindowLedgers}.File())); err != nil {
				t.Fatal(err)
			}
		}},
		{"leaves that do not continue", "holds leaves", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Windows[1].Leaves[0] = 2
			writeManifestFile(t, dir, m)
		}},
		{"a window that skips ledgers", "want the window from", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Windows[1].Start += WindowLedgers
			m.Windows[1].End += WindowLedgers
			writeManifestFile(t, dir, m)
		}},
		{"a coverage the windows do not reach", "covered to", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.CoveredTo += WindowLedgers
			writeManifestFile(t, dir, m)
		}},
		{"an empty window with a hash", "no events but has content", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Windows[2].SHA256 = strings.Repeat("0", 64)
			writeManifestFile(t, dir, m)
		}},
		{"another format", "format", func(t *testing.T, dir string) {
			m := readManifestFile(t, dir)
			m.Format = "cyphras-vault-archive/2"
			writeManifestFile(t, dir, m)
		}},
	}
	for _, c := range cases {
		dir, _ := good(t)
		c.damage(t, dir)
		_, err := Load(ctx, DirFetcher(dir), Expect{})
		mustInvalid(t, c.name, err, c.reason)
	}
	dir, _ := good(t)
	raw := bytes.Repeat([]byte(" "), MaxManifestBytes+1)
	if err := os.WriteFile(filepath.Join(dir, ManifestName), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Load(ctx, DirFetcher(dir), Expect{})
	mustInvalid(t, "a manifest past its cap", err, "longer than")
	dir, _ = good(t)
	for name, want := range map[string]Expect{
		"another vault":    {Vault: vaulttest.Token},
		"another network":  {NetworkPassphrase: "Public Global Stellar Network ; September 2015"},
		"another deploy":   {DeployLedger: deploy + 1},
		"unpinned control": {},
	} {
		_, err := Load(ctx, DirFetcher(dir), want)
		if name == "unpinned control" {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		mustInvalid(t, name, err, "want")
	}
}

func TestAnArchiveIsReadOverHTTPUnderTheSameRules(t *testing.T) {
	dir, _ := good(t)
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	if _, err := Load(context.Background(), HTTPFetcher{Base: srv.URL}, Expect{}); err != nil {
		t.Fatal(err)
	}
	rewrite(t, dir, 0, func(l []string) []string { return l[:len(l)-1] })
	_, err := Load(context.Background(), HTTPFetcher{Base: srv.URL}, Expect{})
	mustInvalid(t, "a damaged window over HTTP", err, "closing line")
	if err := os.Remove(filepath.Join(dir, Window{Start: 0}.File())); err != nil {
		t.Fatal(err)
	}
	_, err = Load(context.Background(), HTTPFetcher{Base: srv.URL}, Expect{})
	mustInvalid(t, "a missing window over HTTP", err, "has no file")
}

func lines(change func(l []string) []string) func(t *testing.T, dir string) {
	return func(t *testing.T, dir string) {
		rewrite(t, dir, 0, change)
	}
}
