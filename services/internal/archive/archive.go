// Package archive keeps every raw vault event in append-only files, one per window of ledgers, so
// the vault can be rebuilt after RPC has dropped the events. Each write ends with the ledger range
// it covers and the number and SHA-256 of the event lines it wrote, so a reader can tell an empty
// range from a missing one, a write that never finished from one that did, and a damaged write
// from a sound one.
package archive

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"slices"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// WindowLedgers is the number of ledgers per file, about one day.
const WindowLedgers = 17_280

// ErrNotCovered reports a ledger range the archive does not hold.
var ErrNotCovered = errors.New("archive: range not covered")

// ErrRange reports a range whose first ledger comes after its last.
var ErrRange = errors.New("archive: a range that ends before it starts")

// ErrDamaged reports a file with a line that is neither part of a sound write nor the torn end of
// a write a crash cut short. It is malformed data, as an ingest fault is.
var ErrDamaged = fmt.Errorf("archive: damaged file: %w", vault.ErrMalformed)

// line is one record of a file. Write groups the records of one Append, and the covered record
// closes it with the number of event lines the write put in the file and their SHA-256, newlines
// included.
type line struct {
	Write   uint64          `json:"write"`
	Event   *vault.RawEvent `json:"event,omitempty"`
	Covered *[2]uint32      `json:"covered,omitempty"`
	Count   *int            `json:"count,omitempty"`
	SHA256  string          `json:"sha256,omitempty"`
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
	// TooLarge, when set, is told of each event left out of a write for being larger than a line
	// of the archive may be.
	TooLarge func(vault.RawEvent)
}

// maxLine is the longest line a write puts in a file, well below what the reader takes, so one
// event no vault can emit, served by a faulty RPC, never makes a file unreadable.
const maxLine = 1 << 20

// maxRead is the longest line the reader takes.
const maxRead = 4 << 20

// Append records the events of ledgers [from, to] and that the range is complete. It returns
// only once the data is on disk. A later write of the same ledgers replaces an earlier one. A
// write that fails is cut off the file again, so a failure leaves no torn line behind.
func (w Writer) Append(events []vault.RawEvent, from, to uint32) error {
	if from > to {
		return fmt.Errorf("%w: ledgers %d to %d", ErrRange, from, to)
	}
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
		if err := appendWrite(f, write, events, lo, hi, w.TooLarge); err != nil {
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

// appendWrite writes the events of ledgers [lo, hi] and the record that closes the write, and
// syncs them. On a failure it truncates the file to where the write began.
func appendWrite(f *os.File, write uint64, events []vault.RawEvent, lo, hi uint32, tooLarge func(vault.RawEvent)) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := writeLines(f, write, events, lo, hi, tooLarge); err != nil {
		if cut := f.Truncate(info.Size()); cut != nil {
			return errors.Join(err, cut)
		}
		return errors.Join(err, f.Sync())
	}
	return nil
}

func writeLines(f *os.File, write uint64, events []vault.RawEvent, lo, hi uint32, tooLarge func(vault.RawEvent)) error {
	buf := bufio.NewWriter(f)
	if err := terminateTornLine(f, buf); err != nil {
		return err
	}
	sum, count := sha256.New(), 0
	for i := range events {
		if events[i].Ledger >= lo && events[i].Ledger <= hi {
			b, err := json.Marshal(line{Write: write, Event: &events[i]})
			if err != nil {
				return err
			}
			if len(b) >= maxLine {
				if tooLarge != nil {
					tooLarge(events[i])
				}
				continue
			}
			b = append(b, '\n')
			sum.Write(b)
			count++
			if _, err := buf.Write(b); err != nil {
				return err
			}
		}
	}
	closing, err := json.Marshal(line{Write: write, Covered: &[2]uint32{lo, hi}, Count: &count, SHA256: hex.EncodeToString(sum.Sum(nil))})
	if err != nil {
		return err
	}
	if _, err := buf.Write(append(closing, '\n')); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	return f.Sync()
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
	if from > to {
		return nil, fmt.Errorf("%w: ledgers %d to %d", ErrRange, from, to)
	}
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

// file returns the finished writes of one file in the order they were made, each checked against
// the count and SHA-256 its covered record holds. A write a crash cut short has no covered record
// and is left out; the one line a crash can tear is its last, and only a new write may follow it.
// Any other line that does not belong to a sound write fails the read.
func (r Reader) file(name string) ([]finished, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type openWrite struct {
		events []vault.RawEvent
		sum    hash.Hash
		count  int
	}
	open := map[uint64]*openWrite{}
	// ended holds the writes that finished or were torn; none of them may write again.
	ended := map[uint64]bool{}
	var done []finished
	damaged := func(n int, why string) error {
		return fmt.Errorf("%w: %s line %d: %s", ErrDamaged, filepath.Base(name), n, why)
	}
	torn := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), maxRead)
	for n := 1; scanner.Scan(); n++ {
		var l line
		if err := json.Unmarshal(scanner.Bytes(), &l); err != nil {
			if torn {
				return nil, damaged(n, "a second unreadable line")
			}
			// Only a crash leaves an unreadable line, and it ends the write it cut short.
			torn = true
			for w := range open {
				ended[w] = true
				delete(open, w)
			}
			continue
		}
		if ended[l.Write] {
			return nil, damaged(n, "a line of a write that had ended")
		}
		w, known := open[l.Write]
		torn = false
		switch {
		case l.Event != nil && l.Covered == nil && l.Count == nil && l.SHA256 == "":
			if l.Event.Contract != r.Vault {
				return nil, damaged(n, "an event of another contract")
			}
			if !known {
				w = &openWrite{sum: sha256.New()}
				open[l.Write] = w
			}
			w.events = append(w.events, *l.Event)
			w.sum.Write(scanner.Bytes())
			w.sum.Write([]byte{'\n'})
			w.count++
		case l.Event == nil && l.Covered != nil && l.Count != nil && l.Covered[0] <= l.Covered[1]:
			if !known {
				w = &openWrite{sum: sha256.New()}
			}
			if w.count != *l.Count || hex.EncodeToString(w.sum.Sum(nil)) != l.SHA256 {
				return nil, damaged(n, fmt.Sprintf("the write holds %d event lines that do not match its record of %d", w.count, *l.Count))
			}
			done = append(done, finished{covered: *l.Covered, events: w.events})
			delete(open, l.Write)
			ended[l.Write] = true
		default:
			return nil, damaged(n, "neither an event nor a covered record")
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
	scanner.Buffer(make([]byte, 64*1024), maxRead)
	for scanner.Scan() {
		var l line
		if json.Unmarshal(scanner.Bytes(), &l) == nil && l.Covered != nil {
			last = max(last, l.Covered[1])
		}
	}
	return last, scanner.Err()
}
