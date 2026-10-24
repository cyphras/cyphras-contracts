package vaultarchive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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
