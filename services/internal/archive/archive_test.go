package archive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const testVault = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"

func event(ledger, tx, index uint32) vault.RawEvent {
	return vault.RawEvent{Ledger: ledger, Tx: tx, Index: index, TxHash: "h", Contract: testVault, Topics: []string{"t"}, Value: "v"}
}

func TestEventsRoundTripAcrossWindowsAndRewrites(t *testing.T) {
	dir := t.TempDir()
	w := Writer{Dir: dir}
	r := Reader{Dir: dir, Vault: testVault}
	ctx := context.Background()
	start := uint32(WindowLedgers - 10)
	if err := w.Append([]vault.RawEvent{event(start, 1, 0), event(start, 1, 1)}, start, start+5); err != nil {
		t.Fatal(err)
	}
	// This write crosses into the next file.
	crossing := []vault.RawEvent{event(start+8, 2, 0), event(WindowLedgers+3, 1, 0)}
	if err := w.Append(crossing, start+6, WindowLedgers+20); err != nil {
		t.Fatal(err)
	}
	// A window written twice, as after a crash before the database committed it, is read once.
	if err := w.Append(crossing, start+6, WindowLedgers+20); err != nil {
		t.Fatal(err)
	}
	got, err := r.Events(ctx, start, WindowLedgers+20)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[2].Ledger != start+8 || got[3].Ledger != WindowLedgers+3 {
		t.Fatalf("events %+v", got)
	}
	got, err = r.Events(ctx, start+6, start+9)
	if err != nil || len(got) != 1 {
		t.Fatalf("sub-range: %d events, %v", len(got), err)
	}
	if _, err := r.Events(ctx, start, WindowLedgers+21); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("range past the end: %v", err)
	}
	if _, err := r.Events(ctx, start-1, start); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("range before the start: %v", err)
	}
	if _, err := r.Events(ctx, 3*WindowLedgers, 3*WindowLedgers+1); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestATornLineCannotSwallowTheNextWrite(t *testing.T) {
	dir := t.TempDir()
	w := Writer{Dir: dir}
	if err := w.Append([]vault.RawEvent{event(10, 1, 0)}, 10, 10); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "0000000000.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"event":{"ledger":11,"tx`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := w.Append([]vault.RawEvent{event(11, 1, 0), event(11, 1, 1)}, 11, 12); err != nil {
		t.Fatal(err)
	}
	got, err := Reader{Dir: dir, Vault: testVault}.Events(context.Background(), 10, 12)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d events after a torn line", len(got))
	}
}

func TestOtherContractsAreIgnored(t *testing.T) {
	dir := t.TempDir()
	other := event(5, 1, 0)
	other.Contract = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"
	if err := (Writer{Dir: dir}).Append([]vault.RawEvent{other, event(5, 1, 1)}, 5, 5); err != nil {
		t.Fatal(err)
	}
	got, err := Reader{Dir: dir, Vault: testVault}.Events(context.Background(), 5, 5)
	if err != nil || len(got) != 1 || got[0].Index != 1 {
		t.Fatalf("events %+v, %v", got, err)
	}
}
