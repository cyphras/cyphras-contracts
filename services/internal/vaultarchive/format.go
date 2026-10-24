// Package vaultarchive is the canonical, publishable form of a vault's event history, format
// cyphras-vault-archive/1: a manifest and one gzip file per closed window of ledgers. Whoever
// builds it from the same ledgers gets the same decompressed bytes, so the SHA-256 of a window
// names its content, and a reader trusts nothing it cannot check against the chain.
package vaultarchive

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
)

// Format names the version of the layout; a reader refuses any other.
const Format = "cyphras-vault-archive/1"

// WindowLedgers is the number of ledgers per window, about one day.
const WindowLedgers = archive.WindowLedgers

const (
	// ManifestName is the manifest's path under the base.
	ManifestName = "manifest.json"

	// MaxManifestBytes, MaxWindowBytes and MaxLineBytes bound what a reader takes before it has
	// checked anything: a window is far larger than a day of the vault's events, and a line is the
	// bound the raw archive writer already keeps.
	MaxManifestBytes = 4 << 20
	MaxWindowBytes   = 64 << 20
	MaxLineBytes     = 1 << 20
)

// maxProducerBytes bounds the free text a manifest carries.
const maxProducerBytes = 128

// maxExactInteger is the largest integer a JavaScript number holds exactly, which readers in that
// language need every number of the format to stay under.
const maxExactInteger = 1<<53 - 1

// ErrInvalid reports an archive, or part of one, that breaks a rule of the format.
var ErrInvalid = errors.New("vault archive: invalid")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// Manifest describes the archive. Producer says what wrote it and nothing depends on it.
type Manifest struct {
	Format            string   `json:"format"`
	Network           string   `json:"network"`
	NetworkPassphrase string   `json:"networkPassphrase"`
	Vault             string   `json:"vault"`
	DeployLedger      uint32   `json:"deployLedger"`
	WindowLedgers     uint32   `json:"windowLedgers"`
	CoveredTo         uint32   `json:"coveredTo"`
	Windows           []Window `json:"windows"`
	Producer          string   `json:"producer"`
}

// Window is one window of ledgers [Start, End]. Leaves is the range [first, end) of leaf indices
// its commitments take. A window with no events has no file, no size and no hash.
type Window struct {
	Start      uint32    `json:"start"`
	End        uint32    `json:"end"`
	Events     int       `json:"events"`
	Leaves     [2]uint64 `json:"leaves"`
	Nullifiers int       `json:"nullifiers"`
	Bytes      int64     `json:"bytes"`
	SHA256     string    `json:"sha256,omitempty"`
}

// UnmarshalJSON refuses a leaves range of any length but two, which a fixed array would cut short
// without a word.
func (w *Window) UnmarshalJSON(raw []byte) error {
	type plain Window
	shadow := struct {
		*plain
		Leaves []uint64 `json:"leaves"`
	}{plain: (*plain)(w)}
	if err := json.Unmarshal(raw, &shadow); err != nil {
		return err
	}
	if len(shadow.Leaves) != 2 {
		return fmt.Errorf("leaves range of %d numbers", len(shadow.Leaves))
	}
	w.Leaves = [2]uint64{shadow.Leaves[0], shadow.Leaves[1]}
	return nil
}

// Canonical is the manifest as it is written and the only form a reader takes: indented by two
// spaces, fields in the order of the struct, one newline at the end.
func (m Manifest) Canonical() ([]byte, error) {
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// File is the window's path under the base.
func (w Window) File() string {
	return fmt.Sprintf("windows/%010d.jsonl.gz", w.Start)
}

// Expect pins what a reader requires of a manifest; a zero field is not checked.
type Expect struct {
	Vault             string
	NetworkPassphrase string
	DeployLedger      uint32
}

// Validate checks the manifest alone: the format, the vault, and windows that follow one another
// from the deploy ledger's window with leaves that continue from window to window.
func (m Manifest) Validate(want Expect) error {
	switch {
	case m.Format != Format:
		return invalid("format %q, want %q", m.Format, Format)
	case m.WindowLedgers != WindowLedgers:
		return invalid("windows of %d ledgers, want %d", m.WindowLedgers, WindowLedgers)
	case !strkey.IsValidContractAddress(m.Vault):
		return invalid("vault %.80q is not a contract address", m.Vault)
	case m.NetworkPassphrase == "" || m.Network == "" || strings.ContainsAny(m.Network, " \t\n"):
		return invalid("manifest without a network")
	case m.DeployLedger == 0:
		return invalid("manifest without a deploy ledger")
	case len(m.Producer) > maxProducerBytes || strings.ContainsFunc(m.Producer, func(r rune) bool { return r < ' ' || r > '~' }):
		return invalid("producer is not printable ASCII of at most %d bytes", maxProducerBytes)
	case want.Vault != "" && m.Vault != want.Vault:
		return invalid("archive of vault %s, want %s", m.Vault, want.Vault)
	case want.NetworkPassphrase != "" && m.NetworkPassphrase != want.NetworkPassphrase:
		return invalid("archive of network %q, want %q", m.NetworkPassphrase, want.NetworkPassphrase)
	case want.DeployLedger != 0 && m.DeployLedger != want.DeployLedger:
		return invalid("deploy ledger %d, want %d", m.DeployLedger, want.DeployLedger)
	}
	next, leaves := windowStart(m.DeployLedger), uint64(0)
	for i, w := range m.Windows {
		if w.Start != next || uint64(w.End) != uint64(w.Start)+WindowLedgers-1 {
			return invalid("window %d is ledgers %d to %d, want the window from %d", i, w.Start, w.End, next)
		}
		if w.Leaves[0] != leaves || w.Leaves[1] < w.Leaves[0] || (w.Leaves[1]-w.Leaves[0])%2 != 0 {
			return invalid("window %d holds leaves %d to %d after %d", i, w.Leaves[0], w.Leaves[1], leaves)
		}
		if w.Leaves[1] > tree.Capacity {
			return invalid("window %d ends at leaf %d, past the %d the tree holds", i, w.Leaves[1], tree.Capacity)
		}
		if w.Events > maxExactInteger || w.Nullifiers > maxExactInteger {
			return invalid("window %d counts more than a JavaScript number holds exactly", i)
		}
		if w.Events < 0 || w.Nullifiers < 0 || w.Bytes < 0 || w.Bytes > MaxWindowBytes || uint64(w.Events) < uint64(w.Nullifiers)+w.Leaves[1]-w.Leaves[0] {
			return invalid("window %d counts do not fit", i)
		}
		if w.Events == 0 {
			if w.Bytes != 0 || w.SHA256 != "" || w.Leaves[0] != w.Leaves[1] || w.Nullifiers != 0 {
				return invalid("window %d has no events but has content", i)
			}
		} else if w.Bytes == 0 || !isHash(w.SHA256) {
			return invalid("window %d has no size or hash", i)
		}
		next, leaves = w.End+1, w.Leaves[1]
	}
	var coveredTo uint32
	if len(m.Windows) > 0 {
		coveredTo = m.Windows[len(m.Windows)-1].End
	}
	if m.CoveredTo != coveredTo {
		return invalid("covered to %d, the windows end at %d", m.CoveredTo, coveredTo)
	}
	return nil
}

func windowStart(ledger uint32) uint32 {
	return ledger - ledger%WindowLedgers
}

func isHash(s string) bool {
	return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == ""
}
