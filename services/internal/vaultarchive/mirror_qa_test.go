package vaultarchive

import (
	"context"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// failingAt makes the nth request of a mirror fail, or cancels the run at it.
type failingAt struct {
	Fetcher
	n      int
	cancel context.CancelFunc
	calls  int
}

func (f *failingAt) Get(ctx context.Context, name string, limit int64) ([]byte, error) {
	f.calls++
	if f.calls == f.n {
		if f.cancel != nil {
			f.cancel()
			return nil, ctx.Err()
		}
		return nil, errors.New("connection reset")
	}
	return f.Fetcher.Get(ctx, name, limit)
}

// leftovers names the entries of dir, at any depth, that are neither the manifest nor a window.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if strings.HasPrefix(name, ".") && path != dir {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAMirrorThatFailsAtAnyRequestLeavesItsDirectoryAsItWas(t *testing.T) {
	remote := published(t, 3)
	for _, held := range []uint32{0, 1} {
		for n := 1; n <= int(3-held); n++ {
			for _, cancelled := range []bool{false, true} {
				var dir string
				var before map[string]string
				if held == 0 {
					dir = filepath.Join(t.TempDir(), "new")
				} else {
					dir = t.TempDir()
					if _, err := Mirror(context.Background(), DirFetcher(published(t, 1)), dir, pin()); err != nil {
						t.Fatal(err)
					}
					before = snapshot(t, dir)
				}
				ctx, cancel := context.WithCancel(context.Background())
				spy := &failingAt{Fetcher: DirFetcher(remote), n: n}
				if cancelled {
					spy.cancel = cancel
				}
				_, err := Mirror(ctx, spy, dir, pin())
				cancel()
				if err == nil {
					t.Fatalf("held %d, request %d, cancelled %v: the mirror survived a failing request", held, n, cancelled)
				}
				if held == 0 {
					if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("held %d, request %d: a failed first mirror left %s: %v", held, n, dir, err)
					}
					continue
				}
				if after := snapshot(t, dir); !maps.Equal(before, after) {
					t.Fatalf("held %d, request %d, cancelled %v: the directory changed", held, n, cancelled)
				}
				if left := leftovers(t, dir); len(left) != 0 {
					t.Fatalf("held %d, request %d: %v are left behind", held, n, left)
				}
			}
		}
	}
}

func TestAMirrorOfAnArchiveWithNoClosedWindowYetAndThenOneWith(t *testing.T) {
	ctx := context.Background()
	empty := t.TempDir()
	if _, err := Build(ctx, memSource{sample(), 4 * WindowLedgers}, empty, head(), 0, 5); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "copy")
	got, err := Mirror(ctx, DirFetcher(empty), dir, pin())
	if err != nil || got.Fetched != 0 || got.Manifest.CoveredTo != 0 {
		t.Fatalf("an archive with no window: %+v, %v", got, err)
	}
	if _, err := Mirror(ctx, DirFetcher(empty), dir, pin()); err != nil {
		t.Fatalf("the same again: %v", err)
	}
	remote := published(t, 2)
	if got, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil || got.Fetched != 2 {
		t.Fatalf("the first windows: %+v, %v", got, err)
	}
	sameFiles(t, remote, dir)
}

func TestAMirrorRestoresTheWindowsDirectoryOfACopyThatLostIt(t *testing.T) {
	remote := published(t, 3)
	dir := t.TempDir()
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "windows")); err != nil {
		t.Fatal(err)
	}
	got, err := Mirror(context.Background(), DirFetcher(remote), dir, pin())
	if err != nil || got.Fetched != 2 || got.Kept != 0 {
		t.Fatalf("mirror: %+v, %v", got, err)
	}
	sameFiles(t, remote, dir)
}

func TestAMirrorRefusesAWindowThatIsADirectory(t *testing.T) {
	remote := published(t, 2)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, Window{Start: 0}.File()), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin()); err == nil {
		t.Fatal("a directory in place of a window file was written through")
	}
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("%v are left behind", left)
	}
}

func TestAMirrorIntoAPathUnderAFileFailsWithoutTouchingIt(t *testing.T) {
	remote := published(t, 2)
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Mirror(context.Background(), DirFetcher(remote), filepath.Join(file, "copy"), pin()); err == nil {
		t.Fatal("a mirror into a path under a file succeeded")
	}
	if raw, err := os.ReadFile(file); err != nil || string(raw) != "data" {
		t.Fatalf("the file changed: %q, %v", raw, err)
	}
}

func TestMirrorsRunningAtOnceInOneDirectoryLeaveAnArchiveThatLoads(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 3)
	dir := t.TempDir()
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = Mirror(ctx, DirFetcher(remote), dir, pin())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("mirror %d: %v", i, err)
		}
	}
	if _, err := Load(ctx, DirFetcher(dir), pin()); err != nil {
		t.Fatalf("the directory does not load: %v", err)
	}
	sameFiles(t, remote, dir)
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("%v are left behind", left)
	}
}

func TestAMirrorTakesANewProducerWithoutFetchingAnyWindow(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 2)
	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	m := readManifestFile(t, remote)
	m.Producer = "cyphras-archive/other"
	writeManifestFile(t, remote, m)
	spy := &asking{Fetcher: DirFetcher(remote)}
	got, err := Mirror(ctx, spy, dir, pin())
	if err != nil || got.Fetched != 0 || len(spy.names) != 1 {
		t.Fatalf("mirror: %+v, %v, asked %v", got, err, spy.names)
	}
	sameFiles(t, remote, dir)
}

func TestAMirrorFinishesWhatACrashAfterTheWindowsWereMovedInLeftHalfDone(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 3)
	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(published(t, 1)), dir, pin()); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(filepath.Join(dir, "scratch"), os.DirFS(remote)); err != nil {
		t.Fatal(err)
	}
	for _, w := range readManifestFile(t, remote).Windows {
		if w.Events == 0 {
			continue
		}
		if err := os.Rename(filepath.Join(dir, "scratch", w.File()), filepath.Join(dir, w.File())); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.RemoveAll(filepath.Join(dir, "scratch")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".stage-12345"), 0o755); err != nil {
		t.Fatal(err)
	}
	spy := &asking{Fetcher: DirFetcher(remote)}
	got, err := Mirror(ctx, spy, dir, pin())
	if err != nil || got.Fetched != 0 || got.Kept != 2 || len(spy.names) != 1 {
		t.Fatalf("mirror: %+v, %v, asked %v", got, err, spy.names)
	}
	if err := os.Remove(filepath.Join(dir, ".stage-12345")); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, remote, dir)
}
