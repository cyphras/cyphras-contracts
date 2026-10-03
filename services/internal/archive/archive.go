// Package archive keeps every raw vault event in append-only files, one per window of ledgers, so
// the vault can be rebuilt after RPC has dropped the events. Each write also records the ledger
// range it covers, so a reader can tell an empty range from a missing one.
package archive

import (
	"bufio"
	"context"
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

type line struct {
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
// only once the data is on disk.
func (w Writer) Append(events []vault.RawEvent, from, to uint32) error {
	if err := os.MkdirAll(w.Dir, 0o700); err != nil {
		return err
	}
	for start := windowStart(from); start <= to; start += WindowLedgers {
		lo, hi := max(from, start), min(to, start+WindowLedgers-1)
		f, err := os.OpenFile(path(w.Dir, start), os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o600)
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
				if err := enc.Encode(line{Event: &events[i]}); err != nil {
					f.Close()
					return err
				}
			}
		}
		if err := enc.Encode(line{Covered: &[2]uint32{lo, hi}}); err != nil {
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
	return nil
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

// Events returns the archived events of ledgers [from, to] in chain order.
func (r Reader) Events(ctx context.Context, from, to uint32) ([]vault.RawEvent, error) {
	seen := map[vault.Position]vault.RawEvent{}
	var covered [][2]uint32
	for start := windowStart(from); start <= to; start += WindowLedgers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f, err := os.Open(path(r.Dir, start))
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: no file for ledger %d", ErrNotCovered, start)
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			var l line
			if err := json.Unmarshal(scanner.Bytes(), &l); err != nil {
				// A crash can leave a torn last line, which the next write supersedes.
				continue
			}
			switch {
			case l.Event != nil && l.Event.Contract == r.Vault && l.Event.Ledger >= from && l.Event.Ledger <= to:
				seen[l.Event.Pos()] = *l.Event
			case l.Covered != nil:
				covered = append(covered, *l.Covered)
			}
		}
		err = scanner.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	if !contains(covered, from, to) {
		return nil, fmt.Errorf("%w: %d to %d", ErrNotCovered, from, to)
	}
	out := make([]vault.RawEvent, 0, len(seen))
	for _, e := range seen {
		out = append(out, e)
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
	return out, nil
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

// contains reports whether the union of the ranges covers [from, to].
func contains(ranges [][2]uint32, from, to uint32) bool {
	slices.SortFunc(ranges, func(a, b [2]uint32) int { return int(a[0]) - int(b[0]) })
	next := uint64(from)
	for _, r := range ranges {
		if uint64(r[0]) > next {
			break
		}
		next = max(next, uint64(r[1])+1)
	}
	return next > uint64(to)
}
