// Package indexer rebuilds a vault from its events, reconciles the result with the chain after
// every ledger, and serves leaves, nullifiers and the entry queue in bulk.
package indexer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/archive"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// Config identifies the vault and sets the readiness bounds.
type Config struct {
	Vault        string
	NetworkID    [32]byte
	DeployLedger uint32
	// ArchiveDir receives every raw event; empty disables the archive.
	ArchiveDir string
	// MaxLag is how far behind the RPC's latest ledger the indexer may be and still be ready.
	MaxLag uint32
	// ProbeMaxAge is how old the last successful probe of the RPC may be.
	ProbeMaxAge time.Duration
	// Native is set for a vault of the native asset.
	Native bool
}

// Not-ready codes of the health endpoint.
const (
	CodeProbeFailed = "probe_failed"
	CodeLagging     = "lagging"
	CodeMismatch    = "mismatch"
	CodeFault       = "fault"
)

// Indexer is the follower's sink and the API's source.
type Indexer struct {
	cfg     Config
	rpc     rpc.Client
	chain   *chainstate.Store
	db      store
	archive *archive.Writer
	// archiveMu orders the archive's writers, ingest and the copy from RPC that runs even when
	// ingest is stuck, and guards archivedTo and archived.
	archiveMu  sync.Mutex
	archivedTo uint32
	// archived holds a digest of the events archived for each ledger ingest has not applied yet, so
	// an applied window is archived again only when its events differ from the copy kept.
	archived map[uint32][32]byte
	alerts   *alert.Alerter
	log      *slog.Logger
	hub      *hub
	now      func() time.Time

	mu         sync.RWMutex
	state      *chainstate.State
	cursor     uint32
	latest     uint32
	probedAt   time.Time
	reconciled uint32
	matched    bool
	mismatch   bool
	fault      bool
	instance   *vault.Instance
	delays     map[uint64]uint64
	// reconciledAt is when the chain last vouched for every leaf served.
	reconciledAt time.Time
	// vouched is the most leaves the chain has vouched for: a full page below it never changes.
	vouched uint64
	// unstored is a mismatch latched in memory whose database write has not succeeded yet.
	unstored *mismatchNote
	// roots holds the tree's recent roots by leaf count, as the vault's root ring does.
	roots     map[uint64]fr.Element
	rootOrder []uint64

	memoMu sync.Mutex
	memos  map[string]*memoEntry
}

// rootHistory is how many recent roots the indexer keeps to compare with the vault's.
const rootHistory = 1024

// reconcileMaxAge is how long the indexer stays ready without the chain vouching for all it serves.
const reconcileMaxAge = 10 * time.Minute

func (ix *Indexer) keepRoot(r chainstate.RootAt) {
	if _, ok := ix.roots[r.LeafCount]; ok {
		return
	}
	ix.roots[r.LeafCount] = r.Root
	ix.rootOrder = append(ix.rootOrder, r.LeafCount)
	if len(ix.rootOrder) > rootHistory {
		delete(ix.roots, ix.rootOrder[0])
		ix.rootOrder = ix.rootOrder[1:]
	}
}

// New loads the stored state. The database must already hold the chain-state and indexer tables.
func New(ctx context.Context, cfg Config, client rpc.Client, chain *chainstate.Store, alerts *alert.Alerter, log *slog.Logger) (*Indexer, error) {
	ix := &Indexer{
		cfg: cfg, rpc: client, chain: chain, db: store{chain.Pool}, alerts: alerts, log: log,
		hub: newHub(1000), now: time.Now, delays: map[uint64]uint64{}, memos: map[string]*memoEntry{}, archived: map[uint32][32]byte{},
	}
	state, cursor, err := chain.Load(ctx, cfg.Vault, cfg.DeployLedger)
	if err != nil {
		return nil, err
	}
	ix.state, ix.cursor = state, cursor
	ix.roots = map[uint64]fr.Element{}
	ix.keepRoot(chainstate.RootAt{LeafCount: state.Tree.Len(), Root: state.Tree.Root()})
	if ix.mismatch, err = ix.db.mismatch(ctx); err != nil {
		return nil, err
	}
	if cfg.ArchiveDir != "" {
		ix.archive = &archive.Writer{Dir: cfg.ArchiveDir, TooLarge: func(e vault.RawEvent) {
			ix.alerts.Raise(context.Background(), alert.Critical, fmt.Sprintf("archive_event_too_large_%d", e.Ledger),
				"an event of ledger %d, larger than any the vault emits, was left out of the archive; the RPC that served it is not to be trusted", e.Ledger)
		}}
		if ix.archivedTo, err = archive.LastCovered(cfg.ArchiveDir); err != nil {
			return nil, err
		}
	}
	return ix, nil
}

// Cursor implements follow.Sink.
func (ix *Indexer) Cursor() uint32 {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.cursor
}

// Apply implements follow.Sink: check the window against the vault's rules, archive its raw
// events, store it, then reconcile with the chain.
func (ix *Indexer) Apply(ctx context.Context, b follow.Batch) error {
	// The raw events are kept before they are judged: a window that faults must still outlive RPC.
	// Only what was archived before keep is judged against the window: what it adds is this copy
	// itself.
	archived, err := ix.keep(b.Raw, b.From, b.To)
	if err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	ix.mu.RLock()
	next := ix.state.Clone()
	ix.mu.RUnlock()
	delta, err := next.Apply(b.Txs)
	if err != nil {
		return fmt.Errorf("%w: %w", follow.ErrFault, err)
	}
	// The archive must hold what was applied, not an earlier copy of the window that faulted.
	if err := ix.confirm(ctx, ix.state, b.Raw, b.From, b.To, archived); err != nil {
		return fmt.Errorf("archive: %w", err)
	}
	if err := ix.chain.Commit(ctx, b.From, b.To, next, delta, nil); err != nil {
		if errors.Is(err, chainstate.ErrInconsistent) {
			return fmt.Errorf("%w: %w", follow.ErrFault, err)
		}
		return err
	}
	ix.mu.Lock()
	ix.state, ix.cursor = next, b.To
	ix.latest = max(ix.latest, b.Latest)
	for _, r := range delta.Roots {
		ix.keepRoot(r)
	}
	if ix.fault {
		ix.fault = false
		ix.alerts.Clear(ctx, "ingest_fault", "ingest moved past ledger %d", b.To)
	}
	for _, r := range delta.Resolved {
		delete(ix.delays, r.Deposit.ID)
	}
	ix.mu.Unlock()
	ix.log.Info("ingested", "from", b.From, "to", b.To, "leaves", next.Tree.Len(), "nullifiers", next.NullifierCount)
	if len(delta.Leaves)+len(delta.Nullifiers)+len(delta.Created)+len(delta.Updated)+len(delta.Resolved)+len(delta.Notices) > 0 {
		ix.hub.publish(Wake{Ledger: b.To, LeafCount: next.Tree.Len(), NullifierCount: next.NullifierCount, ExitHead: next.ExitHead, ExitTail: next.ExitTail})
	}
	if b.To == b.Latest {
		if err := ix.Reconcile(ctx); err != nil {
			ix.log.Warn("reconciliation incomplete", "error", err.Error())
		}
	}
	return nil
}

// Fault records an ingest failure from the follower.
func (ix *Indexer) Fault(ctx context.Context, err error) {
	if errors.Is(err, follow.ErrFault) {
		ix.mu.Lock()
		ix.fault = true
		ix.mu.Unlock()
		ix.alerts.Raise(ctx, alert.Critical, "ingest_fault", "ingest stopped after ledger %d: %v", ix.Cursor(), err)
		return
	}
	ix.log.Warn("ingest retry", "error", err.Error())
}

// Reconcile compares the vault's storage with the indexer's state. Entries the vault last modified
// at or before the indexer's ledger, read at or after it, must match the state at that ledger
// exactly: the tree's leaf count and root, and the vault's status. Otherwise the vault's current
// root is compared with the indexer's root at the vault's leaf count, which the indexer keeps by
// leaf count so the comparison holds when the vault moved on between the read and the ingest, and
// the status waits for a later round.
func (ix *Indexer) Reconcile(ctx context.Context) error {
	if err := ix.storeMismatch(ctx); err != nil {
		return err
	}
	instKey, err := vault.InstanceKey(ix.cfg.Vault)
	if err != nil {
		return err
	}
	nextKey, err := vault.NextLeafKey(ix.cfg.Vault)
	if err != nil {
		return err
	}
	rootsKey, err := vault.RootsKey(ix.cfg.Vault)
	if err != nil {
		return err
	}
	entries, latest, err := rpc.Entries(ctx, ix.rpc, []xdr.LedgerKey{instKey, nextKey, rootsKey})
	if err != nil {
		return err
	}
	ix.mu.RLock()
	cursor, have, root, status := ix.cursor, ix.state.Tree.Len(), ix.state.Tree.Root(), ix.state.Status()
	ix.mu.RUnlock()
	instEntry, ok0 := entries[mustKeyString(instKey)]
	nextEntry, ok1 := entries[mustKeyString(nextKey)]
	rootsEntry, ok2 := entries[mustKeyString(rootsKey)]
	if !ok0 || !ok1 || !ok2 {
		return ix.mismatchAt(ctx, cursor, "the vault's instance or tree entries are missing")
	}
	nextVal, err := rpc.ContractValue(nextEntry)
	if err != nil {
		return err
	}
	nextLeaf, ok := nextVal.GetU64()
	if !ok {
		return ix.mismatchAt(ctx, cursor, "the next leaf entry is not a u64")
	}
	ringVal, err := rpc.ContractValue(rootsEntry)
	if err != nil {
		return err
	}
	ring, err := vault.DecodeRootRing(ringVal)
	if err != nil {
		return ix.mismatchAt(ctx, cursor, "the root ring does not decode")
	}
	n := uint64(nextLeaf)
	modified := max(nextEntry.LastModified, rootsEntry.LastModified)
	full := false
	switch {
	case modified <= cursor && cursor <= latest:
		if n != have || ring.Current() != root {
			return ix.mismatchAt(ctx, cursor, fmt.Sprintf("the chain holds %d leaves with root %s, the indexer %d with root %s", n, ring.Current().Hex(), have, root.Hex()))
		}
		full = true
	case n > have && modified <= cursor:
		return ix.mismatchAt(ctx, cursor, fmt.Sprintf("the chain held %d leaves by ledger %d, the indexer holds %d", n, modified, have))
	case n > have:
		// The chain is ahead of the indexer; compare on the next round.
	default:
		ix.mu.RLock()
		ours, known := ix.roots[n]
		ix.mu.RUnlock()
		if !known {
			// The read is older than the roots kept; compare on the next round.
			break
		}
		if ring.Current() != ours {
			return ix.mismatchAt(ctx, cursor, fmt.Sprintf("at %d leaves the chain has root %s, the indexer %s", n, ring.Current().Hex(), ours.Hex()))
		}
		ix.mu.Lock()
		ix.vouched = max(ix.vouched, n)
		ix.mu.Unlock()
		// The read vouches only for the leaves up to n; the ones after it wait for a later round.
		full = n == have
	}
	if instEntry.LastModified <= cursor && cursor <= latest {
		instVal, err := rpc.ContractValue(instEntry)
		if err != nil {
			return err
		}
		inst, err := vault.DecodeInstance(instVal)
		if err != nil {
			return ix.mismatchAt(ctx, cursor, "the vault's instance does not decode")
		}
		if diff := chainstate.StatusDiff(inst.Status, status, max(inst.Status.OutflowDay, status.OutflowDay)); len(diff) > 0 {
			return ix.mismatchAt(ctx, cursor, strings.Join(diff, "; "))
		}
	}
	ix.mu.Lock()
	if full {
		ix.reconciled, ix.matched, ix.reconciledAt = cursor, true, ix.now()
		ix.vouched = max(ix.vouched, have)
	}
	ix.latest = max(ix.latest, latest)
	ix.mu.Unlock()
	return nil
}

// mismatchNote is the first mismatch found, as the database keeps it.
type mismatchNote struct {
	ledger uint32
	detail string
}

func (ix *Indexer) mismatchAt(ctx context.Context, ledger uint32, detail string) error {
	ix.mu.Lock()
	if !ix.mismatch {
		ix.unstored = &mismatchNote{ledger: ledger, detail: detail}
	}
	ix.mismatch, ix.matched = true, false
	ix.mu.Unlock()
	ix.alerts.Raise(ctx, alert.Critical, "reconcile_mismatch", "at ledger %d: %s", ledger, detail)
	return ix.storeMismatch(ctx)
}

// storeMismatch writes a mismatch latched in memory to the database, so a restart keeps it. A write
// that fails is tried again at the next reconciliation.
func (ix *Indexer) storeMismatch(ctx context.Context) error {
	ix.mu.RLock()
	note := ix.unstored
	ix.mu.RUnlock()
	if note == nil {
		return nil
	}
	if err := ix.db.setMismatch(ctx, note.ledger, note.detail); err != nil {
		return fmt.Errorf("store the mismatch: %w", err)
	}
	ix.mu.Lock()
	ix.unstored = nil
	ix.mu.Unlock()
	return nil
}

// Probe asks the RPC for its latest ledger; readiness needs a recent successful probe.
func (ix *Indexer) Probe(ctx context.Context) {
	h, err := ix.rpc.GetHealth(ctx)
	if err != nil {
		ix.log.Warn("rpc probe failed", "error", err.Error())
		return
	}
	ix.mu.Lock()
	ix.latest, ix.probedAt = h.LatestLedger, ix.now()
	ix.mu.Unlock()
}

// RefreshPending reads the vault's configuration and the delay snapshot of pending deposits that
// lack one, so the API can show when each becomes eligible.
func (ix *Indexer) RefreshPending(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, ix.rpc, ix.cfg.Vault)
	if err != nil {
		return err
	}
	ix.mu.RLock()
	var missing []uint64
	for id := range ix.state.Pending {
		if _, ok := ix.delays[id]; !ok {
			missing = append(missing, id)
		}
	}
	ix.mu.RUnlock()
	found := map[uint64]uint64{}
	keys := make([]xdr.LedgerKey, 0, len(missing))
	for _, id := range missing {
		k, err := vault.PendingKey(ix.cfg.Vault, id)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	entries, _, err := rpc.Entries(ctx, ix.rpc, keys)
	if err != nil {
		return err
	}
	for i, id := range missing {
		e, ok := entries[mustKeyString(keys[i])]
		if !ok {
			continue
		}
		v, err := rpc.ContractValue(e)
		if err != nil {
			continue
		}
		d, err := vault.DecodePendingDeposit(v)
		if err != nil {
			return err
		}
		found[id] = d.Delay
	}
	ix.mu.Lock()
	ix.instance = &inst
	for id, delay := range found {
		ix.delays[id] = delay
	}
	ix.mu.Unlock()
	return nil
}

// Run follows the vault and keeps the probe and the pending deposits fresh until ctx ends.
func (ix *Indexer) Run(ctx context.Context, f *follow.Follower, poll time.Duration) {
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			ix.Probe(ctx)
			if err := ix.RefreshPending(ctx); err != nil {
				ix.log.Warn("pending refresh failed", "error", err.Error())
			}
			if err := ix.Reconcile(ctx); err != nil {
				ix.log.Warn("reconciliation incomplete", "error", err.Error())
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	if ix.archive != nil {
		go ix.archiveLoop(ctx, follow.RPCSource{Client: ix.rpc, Contract: ix.cfg.Vault, PageLimit: 1000}, poll)
	}
	f.Run(ctx, poll, func(err error) { ix.Fault(ctx, err) })
}

// keep appends the part of a window the archive does not hold yet, and returns the last ledger
// the archive held before. Append writes every event of the range or none, so the digests of the
// events it is given are those of what it wrote.
func (ix *Indexer) keep(raw []vault.RawEvent, from, to uint32) (uint32, error) {
	if ix.archive == nil {
		return 0, nil
	}
	if from > to {
		return 0, fmt.Errorf("%w: ledgers %d to %d", archive.ErrRange, from, to)
	}
	ix.archiveMu.Lock()
	defer ix.archiveMu.Unlock()
	before := ix.archivedTo
	if to <= before {
		return before, nil
	}
	from = max(from, before+1)
	var events []vault.RawEvent
	for _, e := range raw {
		if e.Ledger >= from {
			events = append(events, e)
		}
	}
	if err := ix.archive.Append(events, from, to); err != nil {
		return before, err
	}
	ix.archivedTo = to
	if len(ix.archived) > maxArchivedDigests {
		// Ledgers forgotten here are archived again once applied, which costs only space.
		clear(ix.archived)
	}
	for l, d := range digests(events, from, to) {
		ix.archived[l] = d
	}
	return before, nil
}

// maxArchivedDigests bounds the digests kept while ingest is stuck and the archive copies ahead.
const maxArchivedDigests = 200_000

// confirm makes sure the archive holds the events of an applied window, judging the ledgers up to
// archived, those archived before the window was applied: as this process archived them, or, for
// ledgers archived before it started, as the archive reads them back. A copy that differs is
// replaced only when it does not apply to the state before the window, as a copy a faulty RPC
// served does not, and the replacement pages; a copy that applies too leaves two histories, and
// the archive keeps its own while the operator is paged.
func (ix *Indexer) confirm(ctx context.Context, base *chainstate.State, raw []vault.RawEvent, from, to, archived uint32) error {
	if ix.archive == nil {
		return nil
	}
	if from > to {
		return fmt.Errorf("%w: ledgers %d to %d", archive.ErrRange, from, to)
	}
	ix.archiveMu.Lock()
	defer ix.archiveMu.Unlock()
	// The whole window is applied, so none of its digests is needed again.
	last := to
	defer func() {
		for l := uint64(from); l <= uint64(last); l++ {
			delete(ix.archived, uint32(l))
		}
	}()
	if from > archived {
		return nil
	}
	to = min(to, archived)
	applied := digests(raw, from, to)
	same := true
	for l, d := range applied {
		if kept, ok := ix.archived[l]; !ok || kept != d {
			same = false
		}
	}
	if same {
		return nil
	}
	kept, err := archive.Reader{Dir: ix.cfg.ArchiveDir, Vault: ix.cfg.Vault}.Events(ctx, from, to)
	switch {
	case errors.Is(err, archive.ErrNotCovered):
	case err != nil:
		ix.log.Error("archive unreadable", "from", from, "to", to, "error", err.Error())
		ix.alerts.Raise(ctx, alert.Critical, "archive_unreadable", "the archive of ledgers %d to %d cannot be read: %v", from, to, err)
	case maps.Equal(applied, digests(kept, from, to)):
		return nil
	case applies(base, kept):
		ix.log.Error("archive disagrees", "from", from, "to", to)
		ix.alerts.Raise(ctx, alert.Critical, "archive_disagrees", "the archive and ingest hold different events for ledgers %d to %d, and both apply; the archive keeps its own", from, to)
		return nil
	default:
		ix.log.Error("archive copy replaced", "from", from, "to", to)
		ix.alerts.Raise(ctx, alert.Critical, "archive_replaced", "the archive held a copy of ledgers %d to %d that does not apply; it now holds the applied one", from, to)
	}
	if err := ix.archive.Append(raw, from, to); err != nil {
		return err
	}
	ix.archivedTo = max(ix.archivedTo, to)
	return nil
}

// applies reports whether raw events apply to a state under the vault's rules.
func applies(base *chainstate.State, raw []vault.RawEvent) bool {
	events := make([]vault.Event, 0, len(raw))
	for _, r := range raw {
		e, err := vault.Decode(r)
		if err != nil {
			return false
		}
		events = append(events, e)
	}
	txs, err := vault.ParseTxs(events)
	if err != nil {
		return false
	}
	_, err = base.Clone().Apply(txs)
	return err == nil
}

// digests gives each ledger of [from, to] a digest of its events in chain order; equal events give
// equal digests, and a ledger without events the zero digest.
func digests(raw []vault.RawEvent, from, to uint32) map[uint32][32]byte {
	sums := map[uint32]hash.Hash{}
	for _, e := range raw {
		if e.Ledger < from || e.Ledger > to {
			continue
		}
		h, ok := sums[e.Ledger]
		if !ok {
			h = sha256.New()
			sums[e.Ledger] = h
		}
		b, _ := json.Marshal(e)
		h.Write(append(b, '\n'))
	}
	out := map[uint32][32]byte{}
	for l := uint64(from); l <= uint64(to); l++ {
		var d [32]byte
		if h, ok := sums[uint32(l)]; ok {
			copy(d[:], h.Sum(nil))
		}
		out[uint32(l)] = d
	}
	return out
}

// ArchiveStep copies the next window of the vault's raw events from RPC into the archive, whether
// or not ingest can apply it, and reports whether it copied one. Ledgers RPC dropped before they
// were copied are a gap, which pages.
func (ix *Indexer) ArchiveStep(ctx context.Context, src follow.Source) (bool, error) {
	h, err := ix.rpc.GetHealth(ctx)
	if err != nil {
		return false, err
	}
	if h.OldestLedger > h.LatestLedger {
		return false, fmt.Errorf("the RPC reports its oldest ledger %d past its latest %d", h.OldestLedger, h.LatestLedger)
	}
	ix.archiveMu.Lock()
	next := max(ix.archivedTo+1, ix.cfg.DeployLedger)
	ix.archiveMu.Unlock()
	if next > h.LatestLedger {
		return false, nil
	}
	if next < h.OldestLedger {
		ix.alerts.Raise(ctx, alert.Critical, "archive_gap", "ledgers %d to %d were dropped by RPC before the archive copied them", next, h.OldestLedger-1)
		next = h.OldestLedger
	}
	to := min(next+archiveWindow-1, h.LatestLedger)
	raw, err := src.Events(ctx, next, to)
	if err != nil {
		return false, err
	}
	_, err = ix.keep(raw, next, to)
	return true, err
}

// archiveWindow is the most ledgers the archive copies at once.
const archiveWindow = 500

func (ix *Indexer) archiveLoop(ctx context.Context, src follow.Source, poll time.Duration) {
	for ctx.Err() == nil {
		copied, err := ix.ArchiveStep(ctx, src)
		if err != nil {
			ix.log.Warn("archive copy failed", "error", err.Error())
		}
		if copied && err == nil {
			continue
		}
		t := time.NewTimer(max(poll, time.Second))
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}

// Health is the identity and readiness of the indexer.
type Health struct {
	Ready          bool   `json:"ready"`
	Code           string `json:"code,omitempty"`
	Vault          string `json:"vault"`
	NetworkID      string `json:"network_id"`
	DeployLedger   uint32 `json:"deploy_ledger"`
	LatestLedger   uint32 `json:"latest_ledger"`
	IngestedLedger uint32 `json:"ingested_ledger"`
	Reconciled     uint32 `json:"reconciled_ledger"`
	LeafCount      uint64 `json:"leaf_count"`
	Root           string `json:"root"`
	NullifierCount uint64 `json:"nullifier_count"`
	PendingCount   int    `json:"pending_count"`
	// AlertLanes are the indexer's alert channels, by name, and whether each takes alerts.
	AlertLanes []alert.LaneState `json:"alert_lanes"`
}

// Health reports readiness. A failed or stale probe is never read as "no lag".
func (ix *Indexer) Health() Health {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	h := Health{
		Vault: ix.cfg.Vault, NetworkID: fmt.Sprintf("%x", ix.cfg.NetworkID), DeployLedger: ix.cfg.DeployLedger,
		LatestLedger: ix.latest, IngestedLedger: ix.cursor, Reconciled: ix.reconciled,
		LeafCount: ix.state.Tree.Len(), Root: ix.state.Tree.Root().Hex(), NullifierCount: ix.state.NullifierCount,
		PendingCount: len(ix.state.Pending), AlertLanes: ix.alerts.Lanes(ix.now()),
	}
	switch {
	case ix.mismatch:
		h.Code = CodeMismatch
	case ix.fault:
		h.Code = CodeFault
	case ix.probedAt.IsZero() || ix.now().Sub(ix.probedAt) > ix.cfg.ProbeMaxAge:
		h.Code = CodeProbeFailed
	case ix.latest > ix.cursor+ix.cfg.MaxLag || !ix.matched || ix.now().Sub(ix.reconciledAt) > reconcileMaxAge:
		h.Code = CodeLagging
	default:
		h.Ready = true
	}
	return h
}

// Rebuild deletes the stored state so the next start ingests again from the deploy ledger. The
// event archive is kept; it is a source for the rebuild.
func Rebuild(ctx context.Context, chain *chainstate.Store) error {
	if err := chain.Reset(ctx); err != nil {
		return err
	}
	return store{chain.Pool}.reset(ctx)
}

// mustKeyString encodes a key the indexer built itself, which always encodes.
func mustKeyString(k xdr.LedgerKey) string {
	s, err := rpc.KeyString(k)
	if err != nil {
		panic(err)
	}
	return s
}

var _ follow.Sink = (*Indexer)(nil)
