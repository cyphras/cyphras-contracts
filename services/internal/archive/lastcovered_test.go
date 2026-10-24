package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTheCoverageIsFoundBehindANewestFileThatHoldsNoFinishedWrite(t *testing.T) {
	dir := t.TempDir()
	if err := (Writer{Dir: dir}).Append(nil, 5, WindowLedgers-1); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"empty":      "",
		"torn write": `{"write":7,"event":{"ledger":17300`,
	} {
		next := path(dir, WindowLedgers)
		if err := os.WriteFile(next, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		last, err := LastCovered(dir)
		if err != nil || last != WindowLedgers-1 {
			t.Fatalf("%s: covered to %d, %v", name, last, err)
		}
		if err := os.Remove(next); err != nil {
			t.Fatal(err)
		}
	}
	if last, err := LastCovered(filepath.Join(dir, "none")); err != nil || last != 0 {
		t.Fatalf("a directory with no file: %d, %v", last, err)
	}
}
