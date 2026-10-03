package archive

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestAnEventOfAnotherContractFailsTheRead(t *testing.T) {
	dir := t.TempDir()
	other := event(5, 1, 0)
	other.Contract = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"
	if err := (Writer{Dir: dir}).Append([]vault.RawEvent{other, event(5, 1, 1)}, 5, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := (Reader{Dir: dir, Vault: testVault}).Events(context.Background(), 5, 5); !errors.Is(err, ErrDamaged) {
		t.Fatalf("read %v", err)
	}
}

func TestADamagedLineOfAFinishedWriteFailsTheRead(t *testing.T) {
	write := func(t *testing.T) (string, []string) {
		dir := t.TempDir()
		events := []vault.RawEvent{event(100, 1, 0), event(101, 1, 0), event(102, 1, 0)}
		if err := (Writer{Dir: dir}).Append(events, 100, 110); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "0000000000.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		return dir, strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	}
	for name, damage := range map[string]func([]string) []string{
		"a cut line": func(l []string) []string {
			l[1] = l[1][:len(l[1])-3]
			return l
		},
		"another contract": func(l []string) []string {
			l[2] = strings.Replace(l[2], testVault, "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U", 1)
			return l
		},
		"a changed value": func(l []string) []string {
			l[0] = strings.Replace(l[0], `"value":"v"`, `"value":"w"`, 1)
			return l
		},
		"a line gone": func(l []string) []string {
			return append(l[:1], l[2:]...)
		},
		"two torn lines": func(l []string) []string {
			return append(l, `{"write":9,"event":{"ledger":111`, `{"write":9,"event":{"ledger":112`)
		},
	} {
		dir, lines := write(t)
		if err := os.WriteFile(filepath.Join(dir, "0000000000.jsonl"), []byte(strings.Join(damage(lines), "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := (Reader{Dir: dir, Vault: testVault}).Events(context.Background(), 100, 110); !errors.Is(err, ErrDamaged) {
			t.Fatalf("%s: read %d events, %v", name, len(got), err)
		}
	}
	// A crash that tears the last line of a write leaves the writes before it readable.
	dir, lines := write(t)
	torn := strings.Join(lines, "\n") + "\n" + `{"write":9,"event":{"ledger":111`
	if err := os.WriteFile(filepath.Join(dir, "0000000000.jsonl"), []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := (Reader{Dir: dir, Vault: testVault}).Events(context.Background(), 100, 110); err != nil || len(got) != 3 {
		t.Fatalf("after a torn tail: %d events, %v", len(got), err)
	}
}

func TestALaterWriteReplacesAnEarlierOneAndAnUnfinishedWriteIsIgnored(t *testing.T) {
	dir := t.TempDir()
	w := Writer{Dir: dir}
	if err := w.Append([]vault.RawEvent{event(20, 1, 0), event(21, 1, 0), event(22, 3, 0)}, 20, 22); err != nil {
		t.Fatal(err)
	}
	// The same ledgers again, where ledger 21 turned out to hold no event.
	if err := w.Append([]vault.RawEvent{event(20, 1, 0)}, 20, 21); err != nil {
		t.Fatal(err)
	}
	// A write a crash cut short before its coverage record.
	f, err := os.OpenFile(filepath.Join(dir, "0000000000.jsonl"), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"write":7,"event":{"ledger":22,"closed_at":0,"tx_hash":"h","tx":9,"op":0,"index":0,"contract":"` + testVault + `","topics":["t"],"value":"v"}}` + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	got, err := Reader{Dir: dir, Vault: testVault}.Events(context.Background(), 20, 22)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Ledger != 20 || got[1].Ledger != 22 || got[1].Tx != 3 {
		t.Fatalf("events %+v", got)
	}
	last, err := LastCovered(dir)
	if err != nil || last != 22 {
		t.Fatalf("last covered %d, %v", last, err)
	}
}

func TestARangeThatEndsBeforeItStartsIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := (Writer{Dir: dir}).Append(nil, 11, 10); !errors.Is(err, ErrRange) {
		t.Fatalf("append: %v", err)
	}
	if _, err := (Reader{Dir: dir, Vault: "CVAULT"}).Events(context.Background(), 11, 10); !errors.Is(err, ErrRange) {
		t.Fatalf("read: %v", err)
	}
}

func TestAWriteWithAnEventTooLargeForALineIsRefusedWhole(t *testing.T) {
	dir := t.TempDir()
	const v = "CVAULT"
	var tooLarge []uint32
	w := Writer{Dir: dir, TooLarge: func(e vault.RawEvent) { tooLarge = append(tooLarge, e.Ledger) }}
	if err := w.Append([]vault.RawEvent{{Ledger: 100, Tx: 1, Contract: v, TxHash: "a", Topics: []string{"t"}, Value: "x"}}, 100, 100); err != nil {
		t.Fatal(err)
	}
	big := vault.RawEvent{Ledger: 101, Tx: 1, Contract: v, TxHash: "b", Topics: []string{"t"}, Value: strings.Repeat("A", 2<<20)}
	fits := vault.RawEvent{Ledger: 101, Tx: 2, Contract: v, TxHash: "c", Topics: []string{"t"}, Value: "y"}
	if err := w.Append([]vault.RawEvent{big, fits}, 101, 101); !errors.Is(err, ErrTooLarge) || len(tooLarge) != 1 || tooLarge[0] != 101 {
		t.Fatalf("an oversized event's write: %v, told of %v", err, tooLarge)
	}
	// Its ledger stays uncovered, so a rebuild reads it elsewhere rather than missing an event.
	if _, err := (Reader{Dir: dir, Vault: v}).Events(context.Background(), 100, 101); !errors.Is(err, ErrNotCovered) {
		t.Fatalf("read across the refused ledger: %v", err)
	}
	if last, err := LastCovered(dir); err != nil || last != 100 {
		t.Fatalf("covered to %d, %v", last, err)
	}
	if err := w.Append([]vault.RawEvent{fits}, 101, 101); err != nil {
		t.Fatal(err)
	}
	got, err := (Reader{Dir: dir, Vault: v}).Events(context.Background(), 100, 101)
	if err != nil || len(got) != 2 || got[1].TxHash != "c" {
		t.Fatalf("read %+v: %v", got, err)
	}
}
