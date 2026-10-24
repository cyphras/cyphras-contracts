package vaultarchive

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
