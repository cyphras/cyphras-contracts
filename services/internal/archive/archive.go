// Package archive keeps every raw vault event in append-only files, one per window of ledgers, so
// the vault can be rebuilt after RPC has dropped the events. Each write ends with the ledger range
// it covers, so a reader can tell an empty range from a missing one, and a write that never
// finished from one that did.
package archive

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// WindowLedgers is the number of ledgers per file, about one day.
const WindowLedgers = 17_280

// ErrNotCovered reports a ledger range the archive does not hold.
var ErrNotCovered = errors.New("archive: range not covered")

// line is one record of a file. Write groups the records of one Append, and the covered record
// closes it.
type line struct {
	Write   uint64          `json:"write"`
	Event   *vault.RawEvent `json:"event,omitempty"`
	Covered *[2]uint32      `json:"covered,omitempty"`
}

func windowStart(ledger uint32) uint32 {
	return ledger - ledger%WindowLedgers
}

func path(dir string, start uint32) string {
	return filepath.Join(dir, fmt.Sprintf("%010d.jsonl", start))
}

// Writer appends to the archive in dir.
type Writer struct {
	Dir string
}

// Append records the events of ledgers [from, to] and that the range is complete. It returns
// only once the data is on disk. A later write of the same ledgers replaces an earlier one.
func (w Writer) Append(events []vault.RawEvent, from, to uint32) error {
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		return err
	}
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	write := binary.BigEndian.Uint64(id[:])
	created := false
	for start := windowStart(from); start <= to; start += WindowLedgers {
		lo, hi := max(from, start), min(to, start+WindowLedgers-1)
		name := path(w.Dir, start)
		if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
			created = true
		}
		f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		buf := bufio.NewWriter(f)
		if err := terminateTornLine(f, buf); err != nil {
			f.Close()
			return err
		}
		enc := json.NewEncoder(buf)
		for i := range events {
			if events[i].Ledger >= lo && events[i].Ledger <= hi {
				if err := enc.Encode(line{Write: write, Event: &events[i]}); err != nil {
					f.Close()
					return err
				}
			}
		}
		if err := enc.Encode(line{Write: write, Covered: &[2]uint32{lo, hi}}); err != nil {
			f.Close()
			return err
		}
		if err := buf.Flush(); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if created {
		// A new file is only durable once its directory entry is.
		return syncDir(w.Dir)
	}
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// terminateTornLine ends a line a crash left half written, so it cannot swallow the next one.
func terminateTornLine(f *os.File, buf *bufio.Writer) error {
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, info.Size()-1); err != nil {
		return err
	}
	if last[0] != '\n' {
		return buf.WriteByte('\n')
	}
	return nil
}

// Reader serves events from an archive directory, for example a restored off-host copy.
type Reader struct {
	Dir   string
	Vault string
}

// finished is one completed write of one file.
type finished struct {
	covered [2]uint32
	events  []vault.RawEvent
}

// Events returns the archived events of ledgers [from, to] in chain order. Each ledger is read
// from the last finished write that covers it.
func (r Reader) Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error) {
	var writes []finished
	for start := windowStart(from); start <= to; start += WindowLedgers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		done, err := r.file(path(r.Dir, start))
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: no file for ledger %d", ErrNotCovered, start)
		}
		if err != nil {
			return nil, err
		}
		writes = append(writes, done...)
	}
	owner := make([]int, uint64(to)-uint64(from)+1)
	for i := range owner {
		owner[i] = -1
	}
	for i, w := range writes {
		for l := max(w.covered[0], from); l <= min(w.covered[1], to); l++ {
			owner[l-from] = i
			if l == to {
				break
			}
		}
	}
	if i := slices.Index(owner, -1); i >= 0 {
		return nil, fmt.Errorf("%w: ledger %d of %d to %d", ErrNotCovered, from+uint32(i), from, to)
	}
	var out []vault.RawEvent
	for i, w := range writes {
		for _, e := range w.events {
			if e.Ledger >= from && e.Ledger <= to && owner[e.Ledger-from] == i {
				out = append(out, e)
			}
		}
	}
	slices.SortFunc(out, func(a, b vault.RawEvent) int {
		switch {
		case a.Pos().Less(b.Pos()):
			return -1
		case b.Pos().Less(a.Pos()):
			return 1
		}
		return 0
	})
	for i := 1; i < len(out); i++ {
		if out[i].Pos() == out[i-1].Pos() {
			return nil, fmt.Errorf("%w: two archived events at ledger %d", vault.ErrMalformed, out[i].Ledger)
		}
	}
	return out, nil
}

// file returns the finished writes of one file in the order they were made. A write a crash cut
// short has no covered record and is left out.
func (r Reader) file(name string) ([]finished, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	open := map[uint64][]vault.RawEvent{}
	var done []finished
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var l line
		if err := json.Unmarshal(scanner.Bytes(), &l); err != nil {
			// A torn line belongs to a write that never finished.
			continue
		}
		switch {
		case l.Event != nil && l.Event.Contract == r.Vault:
			open[l.Write] = append(open[l.Write], *l.Event)
		case l.Covered != nil && l.Covered[0] <= l.Covered[1]:
			done = append(done, finished{covered: *l.Covered, events: open[l.Write]})
			delete(open, l.Write)
		}
	}
	return done, scanner.Err()
}

// LastCovered returns the last ledger of the newest file's coverage, or 0 for an empty archive.
func LastCovered(dir string) (uint32, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) == 0 {
		return 0, err
	}
	slices.Sort(files)
	f, err := os.Open(files[len(files)-1])
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var last uint32
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var l line
		if json.Unmarshal(scanner.Bytes(), &l) == nil && l.Covered != nil {
			last = max(last, l.Covered[1])
		}
	}
	return last, scanner.Err()
}
