package vaultarchive

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

func pin() Expect {
	return Expect{Vault: vaulttest.Vault, NetworkPassphrase: passphrase, DeployLedger: deploy}
}

// asking records the files a mirror asks the published archive for.
type asking struct {
	Fetcher
	names []string
}

func (a *asking) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	a.names = append(a.names, name)
	return a.Fetcher.Get(ctx, name, limit)
}

// published builds the first n closed windows of sample into a new directory.
func published(t *testing.T, n uint32) string {
	t.Helper()
	dir := t.TempDir()
	if _, err := Build(context.Background(), memSource{sample(), 4 * WindowLedgers}, dir, head(), 0, n*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sameFiles(t *testing.T, a, b string) {
	t.Helper()
	if x, y := snapshot(t, a), snapshot(t, b); !maps.Equal(x, y) {
		t.Fatalf("the directories differ:\n%v\n%v", keys(x), keys(y))
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestAMirrorOfAPublishedArchiveHoldsItsFilesAndLoads(t *testing.T) {
	remote := published(t, 3)
	dir := filepath.Join(t.TempDir(), "deeper", "copy")
	got, err := Mirror(context.Background(), DirFetcher(remote), dir, pin())
	if err != nil || got.Fetched != 2 || got.Kept != 0 || got.Manifest.CoveredTo != 3*WindowLedgers-1 {
		t.Fatalf("mirror: %+v, %v", got, err)
	}
	sameFiles(t, remote, dir)
	if _, err := Load(context.Background(), DirFetcher(dir), pin()); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("%s is left in the directory", e.Name())
		}
	}
}

func TestAMirrorFetchesOnlyTheWindowsItLacks(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 1)
	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(ctx, memSource{sample(), 4 * WindowLedgers}, remote, head(), 0, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	first := Window{Start: 0}.File()
	before, err := os.Stat(filepath.Join(dir, first))
	if err != nil {
		t.Fatal(err)
	}
	spy := &asking{Fetcher: DirFetcher(remote)}
	got, err := Mirror(ctx, spy, dir, pin())
	if err != nil || got.Fetched != 1 || got.Kept != 1 {
		t.Fatalf("incremental mirror: %+v, %v", got, err)
	}
	for _, name := range spy.names {
		if name == first {
			t.Fatal("a window the copy holds was fetched again")
		}
	}
	if after, err := os.Stat(filepath.Join(dir, first)); err != nil || !after.ModTime().Equal(before.ModTime()) {
		t.Fatalf("the window the copy held was rewritten: %v", err)
	}
	sameFiles(t, remote, dir)

	again := &asking{Fetcher: DirFetcher(remote)}
	if got, err := Mirror(ctx, again, dir, pin()); err != nil || got.Fetched != 0 || got.Kept != 2 || len(again.names) != 1 {
		t.Fatalf("a mirror in step: %+v, %v, asked %v", got, err, again.names)
	}
}

func TestAMirrorFetchesAgainAWindowItsCopyHoldsDamaged(t *testing.T) {
	remote := published(t, 2)
	dir := t.TempDir()
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, Window{Start: WindowLedgers}.File()), []byte("damaged"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Mirror(context.Background(), DirFetcher(remote), dir, pin())
	if err != nil || got.Fetched != 1 || got.Kept != 1 {
		t.Fatalf("mirror: %+v, %v", got, err)
	}
	sameFiles(t, remote, dir)
}

func TestAMirrorRefusesAWindowThatIsNotWhatTheManifestSaysAndChangesNothing(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 3)
	damaged := Window{Start: WindowLedgers}.File()
	other := append(readWindow(t, remote, WindowLedgers), []byte("x\n")...)
	packed, err := gzipBytes(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(remote, damaged), packed, 0o644); err != nil {
		t.Fatal(err)
	}

	fresh := filepath.Join(t.TempDir(), "copy")
	if _, err := Mirror(ctx, DirFetcher(remote), fresh, pin()); err == nil {
		t.Fatal("a window with other bytes than the manifest lists was accepted")
	} else if !errors.Is(err, ErrInvalid) {
		t.Fatalf("refused for another reason: %v", err)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed first mirror left %s behind: %v", fresh, err)
	}

	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(published(t, 1)), dir, pin()); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err == nil {
		t.Fatal("a window with other bytes than the manifest lists was accepted")
	}
	if after := snapshot(t, dir); !maps.Equal(before, after) {
		t.Fatal("a refused mirror changed the directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("directory after the refusal: %v, %v", entries, err)
	}
}

func TestAMirrorRefusesAPublishedArchiveBehindItsCopyOrChangedInIt(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 3)
	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dir)

	_, err := Mirror(ctx, DirFetcher(published(t, 2)), dir, pin())
	if err == nil || !strings.Contains(err.Error(), "behind") {
		t.Fatalf("a published archive behind the copy: %v", err)
	}
	if _, err := Mirror(ctx, DirFetcher(published(t, 1)), dir, pin()); err == nil {
		t.Fatal("a published archive of one window replaced a copy of three")
	}

	// The same windows, one of them with another event set that is a well formed archive on its own.
	var fewer []vault.RawEvent
	for _, e := range sample() {
		if e.Ledger != 12 {
			fewer = append(fewer, e)
		}
	}
	changed := t.TempDir()
	if _, err := Build(ctx, memSource{fewer, 4 * WindowLedgers}, changed, head(), 0, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	if _, err := Mirror(ctx, DirFetcher(changed), dir, pin()); err == nil || !strings.Contains(err.Error(), "other content") {
		t.Fatalf("a published window that changed: %v", err)
	}
	if after := snapshot(t, dir); !maps.Equal(before, after) {
		t.Fatal("a refused mirror changed the directory")
	}
}

func TestAMirrorKeepsToTheVaultItWasToldAndToItsOwnCopy(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 2)
	other := pin()
	other.Vault = vaulttest.Token
	if _, err := Mirror(ctx, DirFetcher(remote), t.TempDir(), other); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an archive of another vault than the pinned one: %v", err)
	}
	if _, err := Mirror(ctx, DirFetcher(remote), t.TempDir(), Expect{}); err == nil {
		t.Fatal("a mirror with no pin was accepted")
	}

	// A copy that is labelled for another network than the published archive cannot be carried on.
	copyOf := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(remote), copyOf, pin()); err != nil {
		t.Fatal(err)
	}
	m := readManifestFile(t, copyOf)
	m.Network = "mainnet"
	writeManifestFile(t, copyOf, m)
	if _, err := Mirror(ctx, DirFetcher(remote), copyOf, pin()); err == nil || !strings.Contains(err.Error(), "another vault") {
		t.Fatalf("a copy labelled for another network: %v", err)
	}
}

func TestAMirrorDoesNotFollowASymbolicLinkInItsDirectory(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 2)
	for name, link := range map[string]func(dir, outside string){
		"the windows directory": func(dir, outside string) {
			if err := os.Symlink(outside, filepath.Join(dir, "windows")); err != nil {
				t.Fatal(err)
			}
		},
		"a window file": func(dir, outside string) {
			if err := os.Mkdir(filepath.Join(dir, "windows"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "canary"), filepath.Join(dir, Window{Start: 0}.File())); err != nil {
				t.Fatal(err)
			}
		},
		"the manifest": func(dir, outside string) {
			if err := os.Symlink(filepath.Join(outside, "canary"), filepath.Join(dir, ManifestName)); err != nil {
				t.Fatal(err)
			}
		},
	} {
		outside, dir := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "canary"), []byte("canary"), 0o644); err != nil {
			t.Fatal(err)
		}
		link(dir, outside)
		before := snapshot(t, outside)
		if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err == nil || !strings.Contains(err.Error(), "symbolic links") {
			t.Fatalf("%s is a link: %v", name, err)
		}
		if after := snapshot(t, outside); !maps.Equal(before, after) {
			t.Fatalf("%s: a file outside the directory changed: %v", name, after)
		}
	}
}

func TestAMirrorRemovesTheWindowFilesTheManifestDoesNotList(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 3)
	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, Window{Start: 7 * WindowLedgers}.File())
	emptyWindow := filepath.Join(dir, Window{Start: 2 * WindowLedgers}.File())
	notes := filepath.Join(dir, "windows", "notes.txt")
	for _, name := range []string{stale, emptyWindow, notes} {
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{stale, emptyWindow} {
		if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stays: %v", name, err)
		}
	}
	if _, err := os.Stat(notes); err != nil {
		t.Fatalf("a file that is not a window was removed: %v", err)
	}
}

func TestAMirrorTakesTheManifestByteForByte(t *testing.T) {
	remote := published(t, 2)
	writeManifestFile(t, remote, readManifestFile(t, remote))
	dir := t.TempDir()
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	a, errA := os.ReadFile(filepath.Join(remote, ManifestName))
	b, errB := os.ReadFile(filepath.Join(dir, ManifestName))
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		t.Fatalf("manifests differ: %v %v", errA, errB)
	}
}

func TestABuildNeverRewritesAPublishedWindowWithOtherBytes(t *testing.T) {
	ctx := context.Background()
	dir, _ := good(t)
	before := snapshot(t, dir)
	if _, err := Build(ctx, memSource{sample(), 4 * WindowLedgers}, dir, head(), 1, 3*WindowLedgers-1); err != nil {
		t.Fatalf("a rebuild that gives the same windows: %v", err)
	}
	if after := snapshot(t, dir); !maps.Equal(before, after) {
		t.Fatal("a rebuild with the same windows changed the directory")
	}

	var fewer []vault.RawEvent
	for _, e := range sample() {
		if e.Ledger != 12 {
			fewer = append(fewer, e)
		}
	}
	_, err := Build(ctx, memSource{fewer, 4 * WindowLedgers}, dir, head(), 1, 3*WindowLedgers-1)
	if err == nil || !strings.Contains(err.Error(), "never rewritten") {
		t.Fatalf("a rebuild that changes window 0: %v", err)
	}
	if after := snapshot(t, dir); !maps.Equal(before, after) {
		t.Fatal("a refused rebuild changed the directory")
	}
}

func TestAMirrorAsksEveryAdmitBeforeItFetchesAWindow(t *testing.T) {
	remote := published(t, 3)
	dir := filepath.Join(t.TempDir(), "copy")
	refuse := errors.New("the chain has less")
	spy := &asking{Fetcher: DirFetcher(remote)}
	agree := func(Manifest) error { return nil }
	if _, err := Mirror(context.Background(), spy, dir, pin(), agree, func(Manifest) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("a manifest an admit refused: %v", err)
	}
	if len(spy.names) != 1 || spy.names[0] != ManifestName {
		t.Fatalf("a refused manifest cost %v", spy.names)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused mirror left %s: %v", dir, err)
	}
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin(), agree); err != nil {
		t.Fatal(err)
	}
}

func TestAMirrorRefusesAManifestOfMoreWindowsThanItWillStage(t *testing.T) {
	remote := t.TempDir()
	m := Manifest{Format: Format, Network: "testnet", NetworkPassphrase: passphrase, Vault: vaulttest.Vault, DeployLedger: deploy,
		WindowLedgers: WindowLedgers, Producer: "test"}
	for i := range uint32(40) {
		start := windowStart(deploy) + i*WindowLedgers
		m.Windows = append(m.Windows, Window{
			Start: start, End: start + WindowLedgers - 1, Events: 1, Leaves: [2]uint64{0, 0}, Nullifiers: 1,
			Bytes: MaxWindowBytes, SHA256: strings.Repeat("ab", 32),
		})
		m.CoveredTo = start + WindowLedgers - 1
	}
	writeManifestFile(t, remote, m)
	dir := filepath.Join(t.TempDir(), "copy")
	spy := &asking{Fetcher: DirFetcher(remote)}
	_, err := Mirror(context.Background(), spy, dir, pin())
	mustInvalid(t, "forty windows of the largest size", err, "more than")
	if len(spy.names) != 1 {
		t.Fatalf("asked for %v", spy.names)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused mirror left %s: %v", dir, err)
	}
}
