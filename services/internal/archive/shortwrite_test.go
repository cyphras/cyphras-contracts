//go:build unix

package archive

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// A write the file system cuts short, as a full disk does, is taken back off the file, so two
// failures in a row leave nothing a reader cannot read.
func TestShortWritesLeaveTheFileReadable(t *testing.T) {
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &orig); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &orig) }()
	dir := t.TempDir()
	const v = "CVAULT"
	if err := (Writer{Dir: dir}).Append([]vault.RawEvent{{Ledger: 100, Tx: 1, Contract: v, TxHash: "a", Topics: []string{"t"}, Value: "x"}}, 100, 110); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "0000000000.jsonl")
	var big []vault.RawEvent
	for i := range 60 {
		big = append(big, vault.RawEvent{Ledger: 111 + uint32(i%10), Tx: uint32(i), Contract: v, TxHash: strings.Repeat("h", 64), Topics: []string{strings.Repeat("t", 80)}, Value: strings.Repeat("v", 2000)})
	}
	sound, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		limit := syscall.Rlimit{Cur: uint64(sound.Size()) + 100, Max: orig.Max}
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
			t.Fatal(err)
		}
		if err := (Writer{Dir: dir}).Append(big, 111, 120); err == nil {
			t.Fatal("a write past the size limit succeeded")
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &orig); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(name); err != nil || info.Size() != sound.Size() {
			t.Fatalf("a failed write left %d bytes of %d: %v", info.Size(), sound.Size(), err)
		}
	}
	if err := (Writer{Dir: dir}).Append(big, 111, 120); err != nil {
		t.Fatal(err)
	}
	if got, err := (Reader{Dir: dir, Vault: v}).Events(context.Background(), 100, 120); err != nil || len(got) != 61 {
		t.Fatalf("read %d events: %v", len(got), err)
	}
}
