//go:build unix

package vaultarchive

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAMirrorRefusesAWindowThatIsAFifo(t *testing.T) {
	remote := published(t, 2)
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "windows"), 0o755); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, Window{Start: 0}.File())
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	if _, err := Mirror(context.Background(), DirFetcher(remote), dir, pin()); err == nil {
		t.Fatal("a FIFO in place of a window file was written through")
	}
	if info, err := os.Lstat(fifo); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the FIFO was replaced: %v", err)
	}
	if left := leftovers(t, dir); len(left) != 0 {
		t.Fatalf("%v are left behind", left)
	}
}
