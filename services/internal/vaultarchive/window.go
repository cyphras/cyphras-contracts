package vaultarchive

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// closing is the last line of a window's bytes. Its fields are in this order and it is the only
// line that is not an event.
type closing struct {
	Covered [2]uint32 `json:"covered"`
	Count   int       `json:"count"`
}

// content is what a window's events add up to.
type content struct {
	events      int
	leaves      [2]uint64
	commitments []fr.Element
	nullifiers  []fr.Element
}

// encode returns the canonical bytes of the vault's events of ledgers [start, end] and the
// manifest entry for them, whose leaves start at firstLeaf. A window with no events has no bytes.
// It refuses what a reader would refuse, so a writer cannot publish a window nobody takes.
func encode(events []vault.RawEvent, start, end, deployLedger uint32, vaultID string, firstLeaf uint64) ([]byte, Window, error) {
	sorted := slices.Clone(events)
	slices.SortStableFunc(sorted, func(a, b vault.RawEvent) int {
		switch {
		case a.Pos().Less(b.Pos()):
			return -1
		case b.Pos().Less(a.Pos()):
			return 1
		}
		return 0
	})
	entry := Window{Start: start, End: end, Leaves: [2]uint64{firstLeaf, firstLeaf}}
	if len(sorted) == 0 {
		return nil, entry, nil
	}
	var out bytes.Buffer
	for _, e := range sorted {
		line, err := marshalLine(e)
		if err != nil {
			return nil, Window{}, err
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	tail, err := json.Marshal(closing{Covered: [2]uint32{start, end}, Count: len(sorted)})
	if err != nil {
		return nil, Window{}, err
	}
	out.Write(tail)
	out.WriteByte('\n')
	data := out.Bytes()
	c, err := parse(data, start, end, deployLedger, vaultID, firstLeaf)
	if err != nil {
		return nil, Window{}, err
	}
	sum := sha256.Sum256(data)
	entry.Events, entry.Leaves, entry.Nullifiers = c.events, c.leaves, len(c.nullifiers)
	entry.Bytes, entry.SHA256 = int64(len(data)), hex.EncodeToString(sum[:])
	return data, entry, nil
}

// marshalLine is the canonical form of an event: compact JSON with the fields of RawEvent in
// their fixed order.
func marshalLine(e vault.RawEvent) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// parse checks a window's decompressed bytes against every rule of the format and returns what
// they hold. firstLeaf is where the window's leaf indices must begin.
func parse(data []byte, start, end, deployLedger uint32, vaultID string, firstLeaf uint64) (content, error) {
	if len(data) > MaxWindowBytes {
		return content{}, invalid("window of %d bytes", len(data))
	}
	c := content{leaves: [2]uint64{firstLeaf, firstLeaf}}
	var last *vault.RawEvent
	var left *vault.NewCommitment
	var leftAt vault.Position
	var tail []byte
	spent := map[fr.Element]bool{}
	for n := 1; len(data) > 0; n++ {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return content{}, invalid("line %d is not ended by a newline", n)
		}
		line := data[:i]
		data = data[i+1:]
		if len(line) >= MaxLineBytes {
			return content{}, invalid("line %d of %d bytes", n, len(line))
		}
		if len(data) == 0 {
			tail = line
			break
		}
		e, err := parseEvent(line, n, vaultID)
		if err != nil {
			return content{}, err
		}
		if e.Ledger < start || e.Ledger > end {
			return content{}, invalid("line %d: ledger %d outside the window %d to %d", n, e.Ledger, start, end)
		}
		if e.Ledger < deployLedger {
			return content{}, invalid("line %d: ledger %d is before the deploy ledger %d", n, e.Ledger, deployLedger)
		}
		if last != nil && !last.Pos().Less(e.Pos()) {
			return content{}, invalid("line %d: position %v does not follow %v", n, e.Pos(), last.Pos())
		}
		last = &e
		decoded, err := vault.Decode(e)
		if err != nil {
			return content{}, invalid("line %d: %v", n, err)
		}
		c.events++
		switch body := decoded.Body.(type) {
		case vault.NewNullifier:
			if spent[body.Nullifier] {
				return content{}, invalid("line %d: nullifier %s is spent twice", n, body.Nullifier.Hex())
			}
			spent[body.Nullifier] = true
			c.nullifiers = append(c.nullifiers, body.Nullifier)
		case vault.NewCommitment:
			if body.Index != c.leaves[1] {
				return content{}, invalid("line %d: leaf %d where %d belongs", n, body.Index, c.leaves[1])
			}
			if body.Index%2 == 0 {
				left, leftAt = &body, e.Pos()
			} else {
				if leftAt.Ledger != e.Ledger || leftAt.Tx != e.Tx {
					return content{}, invalid("line %d: leaf %d is not the second of a pair in one transaction", n, body.Index)
				}
				c.commitments = append(c.commitments, left.Commitment, body.Commitment)
				left = nil
			}
			c.leaves[1]++
		}
	}
	if left != nil {
		return content{}, invalid("leaf %d has no partner in the window", left.Index)
	}
	want, err := json.Marshal(closing{Covered: [2]uint32{start, end}, Count: c.events})
	if err != nil {
		return content{}, err
	}
	if !bytes.Equal(tail, want) {
		return content{}, invalid("closing line %.120q, want %s", tail, want)
	}
	return c, nil
}

// parseEvent reads one event line and accepts it only if writing it back gives the same bytes,
// which leaves no room for a field out of order, an extra field or any other spelling.
func parseEvent(line []byte, n int, vaultID string) (vault.RawEvent, error) {
	var e vault.RawEvent
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return vault.RawEvent{}, invalid("line %d: %v", n, err)
	}
	again, err := marshalLine(e)
	if err != nil {
		return vault.RawEvent{}, err
	}
	if !bytes.Equal(again, line) {
		return vault.RawEvent{}, invalid("line %d is not in canonical form", n)
	}
	if e.Contract != vaultID {
		return vault.RawEvent{}, invalid("line %d: an event of contract %.80q", n, e.Contract)
	}
	if err := e.Valid(); err != nil {
		return vault.RawEvent{}, invalid("line %d: %v", n, err)
	}
	for _, s := range append([]string{e.Value}, e.Topics...) {
		if !canonicalXDR(s) {
			return vault.RawEvent{}, invalid("line %d is not in canonical form: a topic or value is not the base64 of its own XDR", n)
		}
	}
	return e, nil
}

// canonicalXDR reports whether s is exactly what encoding its own decoding gives. The base64
// decoder takes spellings with non-zero spare bits, so the same event could otherwise be
// written in more than one way.
func canonicalXDR(s string) bool {
	var v xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(s, &v); err != nil {
		return false
	}
	again, err := xdr.MarshalBase64(v)
	return err == nil && again == s
}

// gunzip returns the bytes of a gzip file, refusing one that expands past the window limit.
func gunzip(compressed []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, invalid("window is not gzip: %v", err)
	}
	data, err := io.ReadAll(io.LimitReader(zr, MaxWindowBytes+1))
	if err != nil {
		return nil, invalid("window is not gzip: %v", err)
	}
	if len(data) > MaxWindowBytes {
		return nil, invalid("window expands past %d bytes", MaxWindowBytes)
	}
	return data, nil
}

func gzipBytes(data []byte) ([]byte, error) {
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(data); err != nil {
		return nil, errors.Join(err, zw.Close())
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// check reads a window's file against its manifest entry: size, hash, then every rule of
// parse, then the counts the entry states.
func check(w Window, compressed []byte, deployLedger uint32, vaultID string) (content, error) {
	data, err := gunzip(compressed)
	if err != nil {
		return content{}, fmt.Errorf("window %d: %w", w.Start, err)
	}
	if int64(len(data)) != w.Bytes {
		return content{}, invalid("window %d holds %d bytes, the manifest says %d", w.Start, len(data), w.Bytes)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != w.SHA256 {
		return content{}, invalid("window %d has another sha256 than the manifest", w.Start)
	}
	c, err := parse(data, w.Start, w.End, deployLedger, vaultID, w.Leaves[0])
	if err != nil {
		return content{}, fmt.Errorf("window %d: %w", w.Start, err)
	}
	if c.events != w.Events || c.leaves != w.Leaves || len(c.nullifiers) != w.Nullifiers {
		return content{}, invalid("window %d holds %d events, %d to %d leaves and %d nullifiers, the manifest says %d, %d to %d and %d",
			w.Start, c.events, c.leaves[0], c.leaves[1], len(c.nullifiers), w.Events, w.Leaves[0], w.Leaves[1], w.Nullifiers)
	}
	return c, nil
}
