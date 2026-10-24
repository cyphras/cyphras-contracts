package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
