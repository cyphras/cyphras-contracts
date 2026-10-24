package vaultarchive

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// linkOutside moves a file, or the windows directory, of the archive in dir to outside and leaves
// a link to it, so that following the link would still give a readable archive.
func linkOutside(t *testing.T, dir, name, outside string) {
	t.Helper()
	src := filepath.Join(dir, filepath.FromSlash(name))
	dst := filepath.Join(outside, "moved-"+filepath.Base(name))
	if err := os.Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dst, src); err != nil {
		t.Fatal(err)
	}
}

func TestAReaderDoesNotFollowSymbolicLinks(t *testing.T) {
	for name, moved := range map[string]string{
		"a manifest linked outside the directory": ManifestName,
		"a window linked outside the directory":   Window{Start: 0}.File(),
		"the windows directory linked outside":    "windows",
	} {
		dir, _ := good(t)
		linkOutside(t, dir, moved, t.TempDir())
		if _, err := Load(context.Background(), DirFetcher(dir), Expect{}); err == nil {
			t.Fatalf("%s was read", name)
		}
	}
	// A link that stays inside the directory is refused as well: an archive is plain files.
	dir, _ := good(t)
	const inside = "kept-inside"
	if err := os.Rename(filepath.Join(dir, ManifestName), filepath.Join(dir, inside)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(dir, ManifestName)); err != nil {
		t.Fatal(err)
	}
	_, err := Load(context.Background(), DirFetcher(dir), Expect{})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a manifest linked inside the directory: %v", err)
	}
}

// respelled returns a base64 string that decodes to the same bytes as s but is written
// differently, by changing the spare bits of its last data character.
func respelled(t *testing.T, s string) string {
	t.Helper()
	i := strings.IndexByte(s, '=')
	if i < 1 {
		t.Fatalf("%q has no padding to respell", s)
	}
	want, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		other := s[:i-1] + string(c) + s[i:]
		got, err := base64.StdEncoding.DecodeString(other)
		if err == nil && other != s && string(got) == string(want) {
			return other
		}
	}
	t.Fatalf("no other spelling of %q", s)
	return ""
}

func TestAnEventWrittenWithOtherSpareBitsInItsBase64IsNotCanonical(t *testing.T) {
	events := sample()
	// The attested event's topic is a symbol of 16 bytes and its value 32, so both end in padding.
	for name, old := range map[string]string{"topic": events[6].Topics[0], "value": events[6].Value} {
		dir, _ := good(t)
		rewrite(t, dir, 0, func(l []string) []string {
			l[6] = strings.Replace(l[6], `"`+old+`"`, `"`+respelled(t, old)+`"`, 1)
			return l
		})
		_, err := Load(context.Background(), DirFetcher(dir), Expect{})
		mustInvalid(t, "a respelled "+name, err, "not in canonical form")
	}
}

func TestATimeBeyondWhatAJavaScriptNumberHoldsIsRefusedByReaderAndWriter(t *testing.T) {
	const largest, past = "9007199254740991", "9007199254740992"
	dir, _ := good(t)
	rewrite(t, dir, 0, func(l []string) []string {
		l[0] = strings.Replace(l[0], `"closed_at":1728000000`, `"closed_at":`+largest, 1)
		return l
	})
	if _, err := Load(context.Background(), DirFetcher(dir), Expect{}); err != nil {
		t.Fatalf("the largest exact time: %v", err)
	}
	rewrite(t, dir, 0, func(l []string) []string {
		l[0] = strings.Replace(l[0], `"closed_at":`+largest, `"closed_at":`+past, 1)
		return l
	})
	_, err := Load(context.Background(), DirFetcher(dir), Expect{})
	mustInvalid(t, "a time past 2^53", err, "closed_at")

	late := sample()[0]
	late.ClosedAt = 1 << 53
	_, err = Build(context.Background(), fixedSource{late}, t.TempDir(), head(), 0, WindowLedgers-1)
	mustInvalid(t, "the writer", err, "closed_at")
}

func TestABuildThatEndsBeforeTheArchiveDoesNotShortenIt(t *testing.T) {
	ctx := context.Background()
	dir, whole := good(t)
	m, err := Build(ctx, memSource{sample(), 4 * WindowLedgers}, dir, head(), WindowLedgers, 2*WindowLedgers-1)
	if err != nil {
		t.Fatal(err)
	}
	if got := readManifestFile(t, dir); len(got.Windows) != 3 || got.CoveredTo != whole.CoveredTo || len(m.Windows) != 3 {
		t.Fatalf("manifest after a shorter run %+v", got)
	}
	// A run that fails after one window keeps the windows after it listed as well.
	if _, err := Build(ctx, memSource{sample(), WindowLedgers + 100}, dir, head(), 1, 3*WindowLedgers-1); err == nil {
		t.Fatal("a build over an uncovered window passed")
	}
	if got := readManifestFile(t, dir); len(got.Windows) != 3 || got.CoveredTo != whole.CoveredTo {
		t.Fatalf("manifest after a failed run %+v", got)
	}
	if _, err := Load(ctx, DirFetcher(dir), Expect{}); err != nil {
		t.Fatal(err)
	}
}

func TestRebuiltWindowsThatNoLongerLeadIntoTheOnesAfterThemAreNotPublished(t *testing.T) {
	ctx := context.Background()
	dir, _ := good(t)
	before, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var fewer []vault.RawEvent
	for _, e := range sample() {
		if e.Ledger != 13 {
			fewer = append(fewer, e)
		}
	}
	if _, err := Build(ctx, memSource{fewer, 4 * WindowLedgers}, dir, head(), 1, WindowLedgers-1); err == nil {
		t.Fatal("a first window with fewer leaves was accepted in front of a second that expects them")
	}
	after, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the manifest changed: %v", err)
	}
}

func TestWindowFilesTheManifestDoesNotListAreRemoved(t *testing.T) {
	dir, _ := good(t)
	stale := filepath.Join(dir, Window{Start: 7 * WindowLedgers}.File())
	other := filepath.Join(dir, "windows", "notes.txt")
	for _, name := range []string{stale, other} {
		if err := os.WriteFile(name, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Build(context.Background(), memSource{sample(), 4 * WindowLedgers}, dir, head(), 0, 3*WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a window the manifest does not list stays: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("a file that is not a window was removed: %v", err)
	}
}

func TestARedirectOffTheBaseHostOrDownToHTTPIsNotFollowed(t *testing.T) {
	dir, _ := good(t)
	files := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer files.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, files.URL+r.URL.Path, http.StatusFound)
	}))
	defer secure.Close()
	_, err := ReadManifest(context.Background(), HTTPFetcher{Base: secure.URL, Client: secure.Client()}, Expect{})
	if err == nil || !strings.Contains(err.Error(), "redirected") {
		t.Fatalf("a redirect from https to a plain http server: %v", err)
	}

	same := http.NewServeMux()
	same.Handle("/moved/", http.StripPrefix("/moved", http.FileServer(http.Dir(dir))))
	same.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/moved"+r.URL.Path, http.StatusFound)
	})
	inside := httptest.NewServer(same)
	defer inside.Close()
	if _, err := ReadManifest(context.Background(), HTTPFetcher{Base: inside.URL}, Expect{}); err != nil {
		t.Fatalf("a redirect inside the host: %v", err)
	}

	from := httptest.NewRequest(http.MethodGet, "https://mirror.example/manifest.json", nil)
	for target, refused := range map[string]bool{
		"https://mirror.example/other":  false,
		"http://mirror.example/other":   true,
		"https://elsewhere.example/x":   true,
		"https://mirror.example:444/x":  true,
		"https://user@mirror.example/x": false,
	} {
		err := followsOnlyOnTheBase(httptest.NewRequest(http.MethodGet, target, nil), []*http.Request{from})
		if (err != nil) != refused {
			t.Fatalf("redirect to %s: %v", target, err)
		}
	}
}

func TestAnErrorNamesTheFileAndNotTheURLItWasFetchedFrom(t *testing.T) {
	_, err := HTTPFetcher{Base: "http://127.0.0.1:1/token-s3cret"}.Get(context.Background(), ManifestName, MaxManifestBytes)
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), ManifestName) {
		t.Fatalf("error %v", err)
	}
	_, err = HTTPFetcher{Base: "http://127.0.0.1:1/token\x7f-s3cret"}.Get(context.Background(), ManifestName, MaxManifestBytes)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error for an unusable base %v", err)
	}
}
