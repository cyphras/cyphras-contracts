package vaultarchive

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// emptyMember is a gzip member with no content.
func emptyMember(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := gzip.NewWriter(&b).Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestAWindowFileCannotBePaddedPastWhatItsManifestAccountsFor(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 3)
	name := filepath.Join(remote, Window{Start: 0}.File())
	honest, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	named := func(size int) []byte {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		zw.Name = strings.Repeat("x", size)
		if _, err := zw.Write(readWindow(t, remote, 0)); err != nil {
			t.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
	for name, c := range map[string]struct {
		file   []byte
		reason string
	}{
		"eight MiB of empty members after the content": {append(append([]byte{}, honest...), bytes.Repeat(emptyMember(t), 8<<20/len(emptyMember(t)))...), "more than the"},
		"one empty member after the content":           {append(append([]byte{}, honest...), emptyMember(t)...), "after its gzip member"},
		"zero bytes after the content":                 {append(append([]byte{}, honest...), 0, 0, 0, 0), "after its gzip member"},
		"a header that carries a long name":            {named(64 << 10), "more than the"},
	} {
		if err := os.WriteFile(filepath.Join(remote, Window{Start: 0}.File()), c.file, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(ctx, DirFetcher(remote), pin())
		mustInvalid(t, name+" (load)", err, c.reason)
		dir := filepath.Join(t.TempDir(), "copy")
		_, err = Mirror(ctx, DirFetcher(remote), dir, pin())
		mustInvalid(t, name+" (mirror)", err, c.reason)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("%s: a refused mirror left %s: %v", name, dir, err)
		}
	}
}

func TestAMirrorReplacesAWindowItsCopyHoldsPaddedWithTheHonestFile(t *testing.T) {
	ctx := context.Background()
	remote := published(t, 2)
	dir := t.TempDir()
	if _, err := Mirror(ctx, DirFetcher(remote), dir, pin()); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, Window{Start: 0}.File())
	honest, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, append(append([]byte{}, honest...), emptyMember(t)...), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Mirror(ctx, DirFetcher(remote), dir, pin())
	if err != nil || got.Fetched != 1 {
		t.Fatalf("mirror over a padded copy: %+v, %v", got, err)
	}
	if after, err := os.ReadFile(name); err != nil || !bytes.Equal(after, honest) {
		t.Fatalf("the padded file stays: %v", err)
	}
}

func TestAWindowIsReadFromItsFirstMemberOnly(t *testing.T) {
	data, err := gunzip(gzipOf(t, "first"))
	if err != nil || string(data) != "first" {
		t.Fatalf("one member: %q, %v", data, err)
	}
	two := append(gzipOf(t, "first"), gzipOf(t, "second")...)
	_, err = gunzip(two)
	mustInvalid(t, "two members", err, "after its gzip member")
}

func gzipOf(t *testing.T, s string) []byte {
	t.Helper()
	b, err := gzipBytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
