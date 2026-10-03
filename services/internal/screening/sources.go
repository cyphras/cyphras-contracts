// Package screening is the association set provider: it screens deposits and unshield
// destinations against the sources of the screening policy, decides each deposit on chain with
// attest and flag, and records every decision.
package screening

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/freeze"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
)

// Reason codes of the screening policy. A code keeps its meaning forever.
const (
	ReasonCancelled = 0
	ReasonSanctions = 1
	ReasonExploit   = 2
	ReasonFrozen    = 3
	ReasonFraud     = 4
	ReasonReview    = 5
	// ReasonHeld holds a deposit that waits for a person or for its own final check. It is not a
	// refusal: the hold is lifted once the deposit clears, and replaced by the refusal's reason when
	// it is refused. The keeper refunds a deposit still held a day after the hold.
	ReasonHeld  = 6
	ReasonOther = 99
	// ReasonCourtOrder refuses a deposit a written order from an authority concerns. The keeper
	// never refunds it; the depositor still can.
	ReasonCourtOrder = 100
)

func validReason(r uint32) bool {
	switch r {
	case ReasonSanctions, ReasonExploit, ReasonFrozen, ReasonFraud, ReasonReview, ReasonOther:
		return true
	}
	return false
}

// Hit is a match of an address in a source. A hit either refuses with a reason or refers the
// deposit to manual review.
type Hit struct {
	Source string
	Reason uint32
	Refer  bool
	Detail string
}

// SourceStatus is what the policy endpoint and the decision records say about a source.
type SourceStatus struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	FetchedAt time.Time `json:"fetched_at"`
	MaxAge    int64     `json:"max_age_seconds"`
}

// Source is one list the screening consults.
type Source interface {
	Name() string
	Refresh(ctx context.Context) error
	Lookup(address string) (Hit, bool)
	Status() SourceStatus
}

// Guard refuses a source update that looks broken: one that shrinks the list by more than
// MaxShrinkPct percent, or that lacks a canary, an entry every good copy holds. The previous list
// stays in use, and ages until a good update arrives.
type Guard struct {
	MaxShrinkPct int
	Canaries     []string
}

func (g *Guard) check(name string, prev, size int, has func(string) bool) error {
	if g == nil {
		return nil
	}
	if prev > 0 && g.MaxShrinkPct > 0 && size*100 < prev*(100-g.MaxShrinkPct) {
		return fmt.Errorf("%s: %w: the update shrinks the list from %d to %d entries", name, ErrSuspect, prev, size)
	}
	for _, c := range g.Canaries {
		if !has(c) {
			return fmt.Errorf("%s: %w: the update lacks the canary %q", name, ErrSuspect, c)
		}
	}
	return nil
}

// ErrSuspect reports a source update the guard refused.
var ErrSuspect = errors.New("suspect update refused")

// list holds a source's entries and when they were fetched.
type list struct {
	name   string
	maxAge time.Duration
	guard  *Guard

	mu        sync.RWMutex
	entries   map[string]Hit
	version   string
	fetchedAt time.Time
	// size is how big the source's last accepted copy was, in the unit its guard counts.
	size int
}

// Guard sets the checks every update of the source must pass.
func (l *list) Guard(g *Guard) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.guard = g
}

// accept checks an update against the guard and the last accepted copy, and keeps it.
func (l *list) accept(entries map[string]Hit, version string, fetchedAt time.Time, size int, has func(string) bool) error {
	l.mu.RLock()
	g, prev := l.guard, l.size
	l.mu.RUnlock()
	if err := g.check(l.name, prev, size, has); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries, l.version, l.fetchedAt, l.size = entries, version, fetchedAt, size
	return nil
}

func inEntries(entries map[string]Hit) func(string) bool {
	return func(address string) bool {
		_, ok := entries[address]
		return ok
	}
}

func (l *list) Name() string { return l.name }

func (l *list) Lookup(address string) (Hit, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	h, ok := l.entries[address]
	return h, ok
}

func (l *list) Status() SourceStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return SourceStatus{Name: l.name, Version: l.version, FetchedAt: l.fetchedAt, MaxAge: int64(l.maxAge.Seconds())}
}

func (l *list) set(entries map[string]Hit, version string, fetchedAt time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries, l.version, l.fetchedAt = entries, version, fetchedAt
}

// FrozenSource is the CAP-77 frozen key list, read from the ledger.
type FrozenSource struct {
	list
	RPC rpc.Client
	now func() time.Time
}

// NewFrozenSource reads the freeze list through c.
func NewFrozenSource(c rpc.Client, maxAge time.Duration) *FrozenSource {
	return &FrozenSource{list: list{name: "cap77_frozen", maxAge: maxAge}, RPC: c, now: time.Now}
}

// Refresh implements Source.
func (s *FrozenSource) Refresh(ctx context.Context) error {
	set, err := freeze.Read(ctx, s.RPC)
	if err != nil {
		return err
	}
	entries := map[string]Hit{}
	for a := range set.Accounts {
		entries[a] = Hit{Source: s.name, Reason: ReasonFrozen, Detail: "frozen by validators"}
	}
	for c := range set.Contracts {
		entries[c] = Hit{Source: s.name, Reason: ReasonFrozen, Detail: "frozen by validators"}
	}
	s.set(entries, fmt.Sprintf("%d keys", len(set.Keys)), s.now())
	return nil
}

// FileSource is a curated list kept by the operator: published exploit and theft addresses,
// sanctioned addresses and credible fraud reports.
type FileSource struct {
	list
	Path string
}

// NewFileSource reads the list at path; maxAge applies to the list's own updated_at.
func NewFileSource(name, path string, maxAge time.Duration) *FileSource {
	return &FileSource{list: list{name: name, maxAge: maxAge}, Path: path}
}

// listFile is the curated list's schema: every member is required, and no other is allowed.
type listFile struct {
	Version   string    `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	Entries   *[]struct {
		Address string `json:"address"`
		Reason  uint32 `json:"reason"`
		Source  string `json:"source"`
	} `json:"entries"`
}

// Refresh implements Source.
func (s *FileSource) Refresh(context.Context) error {
	raw, err := os.ReadFile(s.Path)
	if err != nil {
		return err
	}
	var f listFile
	if err := jsonv2.Unmarshal(raw, &f, jsonv2.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("%s: %w", s.name, err)
	}
	if f.Version == "" || f.UpdatedAt.IsZero() || f.Entries == nil {
		return fmt.Errorf("%s: the list lacks its version, update time or entries", s.name)
	}
	entries := map[string]Hit{}
	for i, e := range *f.Entries {
		if !strkey.IsValidEd25519PublicKey(e.Address) && !strkey.IsValidContractAddress(e.Address) {
			return fmt.Errorf("%s: entry %d has no valid address", s.name, i)
		}
		if !validReason(e.Reason) || e.Reason == ReasonFrozen || e.Reason == ReasonReview {
			return fmt.Errorf("%s: entry %d has reason %d", s.name, i, e.Reason)
		}
		if strings.TrimSpace(e.Source) == "" {
			return fmt.Errorf("%s: entry %d names no source", s.name, i)
		}
		entries[e.Address] = Hit{Source: s.name, Reason: e.Reason, Detail: e.Source}
	}
	return s.accept(entries, f.Version, f.UpdatedAt, len(entries), inEntries(entries))
}

// OFACSource reads the Stellar addresses of the OFAC SDN list.
type OFACSource struct {
	list
	URL  string
	HTTP *http.Client
	now  func() time.Time
}

// NewOFACSource reads the SDN list in CSV form from url.
func NewOFACSource(url string, maxAge time.Duration) *OFACSource {
	return &OFACSource{list: list{name: "ofac_sdn", maxAge: maxAge}, URL: url, HTTP: &http.Client{Timeout: time.Minute}, now: time.Now}
}

var digitalCurrency = regexp.MustCompile(`Digital Currency Address - ([A-Z0-9]+) ([A-Za-z0-9]+)`)

// sdnFields is the number of fields of each record of the SDN list in CSV form.
const sdnFields = 12

// sdnRecords checks the SDN list's form: CSV whose every record has the SDN fields and starts
// with an entity number, optionally after a header, and returns how many records it holds.
func sdnRecords(body []byte) (int, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimRight(body, "\x1a\r\n ")))
	r.FieldsPerRecord = sdnFields
	r.LazyQuotes = true
	n := 0
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("ofac: not the SDN list in CSV form: %w", err)
		}
		if n == 0 && strings.EqualFold(strings.TrimSpace(rec[0]), "ent_num") {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(rec[0]), 10, 64); err != nil {
			return 0, errors.New("ofac: a record does not start with an entity number")
		}
		n++
	}
	if n == 0 {
		return 0, errors.New("ofac: the list is empty")
	}
	return n, nil
}

// Refresh implements Source.
func (s *OFACSource) Refresh(ctx context.Context) error {
	body, err := fetch(ctx, s.HTTP, s.URL, 128<<20)
	if err != nil {
		return err
	}
	records, err := sdnRecords(body)
	if err != nil {
		return err
	}
	entries := map[string]Hit{}
	for _, m := range digitalCurrency.FindAllSubmatch(body, -1) {
		if string(m[1]) != "XLM" {
			continue
		}
		address := string(m[2])
		if strkey.IsValidEd25519PublicKey(address) || strkey.IsValidContractAddress(address) {
			entries[address] = Hit{Source: s.name, Reason: ReasonSanctions, Detail: "OFAC SDN"}
		}
	}
	sum := sha256.Sum256(body)
	// The list holds few Stellar addresses, so its size and canaries are those of the whole list.
	return s.accept(entries, hex.EncodeToString(sum[:8]), s.now(), records, func(token string) bool { return bytes.Contains(body, []byte(token)) })
}

// DirectorySource reads the accounts the stellar.expert directory tags as malicious, and refers
// those it tags as unsafe to manual review.
type DirectorySource struct {
	list
	BaseURL string
	HTTP    *http.Client
	now     func() time.Time
}

// NewDirectorySource reads the directory API at baseURL, such as https://api.stellar.expert.
func NewDirectorySource(baseURL string, maxAge time.Duration) *DirectorySource {
	return &DirectorySource{list: list{name: "stellar_expert", maxAge: maxAge}, BaseURL: strings.TrimSuffix(baseURL, "/"), HTTP: &http.Client{Timeout: time.Minute}, now: time.Now}
}

type directoryPage struct {
	Links struct {
		Next struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
	Embedded *struct {
		Records *[]directoryRecord `json:"records"`
	} `json:"_embedded"`
}

type directoryRecord struct {
	Address string   `json:"address"`
	Name    string   `json:"name"`
	Tags    []string `json:"tags"`
}

const directoryPageSize = 200

// Refresh implements Source. The whole tagged list is downloaded, so no address being screened is
// ever sent to the directory.
func (s *DirectorySource) Refresh(ctx context.Context) error {
	entries := map[string]Hit{}
	for _, tag := range []string{"malicious", "unsafe"} {
		next := fmt.Sprintf("/explorer/directory?tag[]=%s&limit=%d", url.QueryEscape(tag), directoryPageSize)
		for pages := 0; next != ""; pages++ {
			if pages == 500 {
				return errors.New("stellar.expert: the directory does not end")
			}
			body, err := fetch(ctx, s.HTTP, s.BaseURL+next, 16<<20)
			if err != nil {
				return err
			}
			var page directoryPage
			if err := json.Unmarshal(body, &page); err != nil {
				return fmt.Errorf("stellar.expert: %w", err)
			}
			if page.Embedded == nil || page.Embedded.Records == nil {
				return errors.New("stellar.expert: a page without records")
			}
			records := *page.Embedded.Records
			for _, r := range records {
				if !strkey.IsValidEd25519PublicKey(r.Address) && !strkey.IsValidContractAddress(r.Address) {
					continue
				}
				if tag == "malicious" {
					entries[r.Address] = Hit{Source: s.name, Reason: ReasonExploit, Detail: "tagged malicious: " + r.Name}
				} else if _, ok := entries[r.Address]; !ok {
					entries[r.Address] = Hit{Source: s.name, Refer: true, Detail: "tagged unsafe: " + r.Name}
				}
			}
			next = ""
			if len(records) == directoryPageSize {
				next = page.Links.Next.Href
			}
		}
	}
	return s.accept(entries, fmt.Sprintf("%d accounts", len(entries)), s.now(), len(entries), inEntries(entries))
}

// ReportSource holds the addresses of accepted compromised-address self-reports.
type ReportSource struct {
	list
	load func(ctx context.Context) ([]string, error)
	now  func() time.Time
}

func (s *ReportSource) directOnly() bool { return true }

// Refresh implements Source.
func (s *ReportSource) Refresh(ctx context.Context) error {
	addresses, err := s.load(ctx)
	if err != nil {
		return err
	}
	entries := map[string]Hit{}
	for _, a := range addresses {
		entries[a] = Hit{Source: s.name, Reason: ReasonFraud, Detail: "compromised-address self-report"}
	}
	s.set(entries, fmt.Sprintf("%d reports", len(entries)), s.now())
	return nil
}

func fetch(ctx context.Context, client *http.Client, target string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", req.URL.Host, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}
