// Package indexer rebuilds a vault from its events, reconciles the result with the chain after
// every ledger, and serves leaves, nullifiers and the entry queue in bulk.
package indexer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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
	alerts  *alert.Alerter
	log     *slog.Logger
	hub     *hub
	now     func() time.Time

	mu         sync.RWMutex
	state      *chainstate.State
	cursor     uint32
	archivedTo uint32
	latest     uint32
	probedAt   time.Time
	reconciled uint32
	matched    bool
	mismatch   bool
	fault      bool
	instance   *vault.Instance
	delays     map[uint64]uint64
	// roots holds the tree's recent roots by leaf count, as the vault's root ring does.
	roots     map[uint64]fr.Element
	rootOrder []uint64

	memoMu sync.Mutex
	memos  map[string]*memoEntry
}

// rootHistory is how many recent roots the indexer keeps to compare with the vault's.
const rootHistory = 1024

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
		hub: newHub(1000), now: time.Now, delays: map[uint64]uint64{}, memos: map[string]*memoEntry{},
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
		ix.archive = &archive.Writer{Dir: cfg.ArchiveDir}
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
	ix.mu.RLock()
	next := ix.state.Clone()
	ix.mu.RUnlock()
	delta, err := next.Apply(b.Txs)
	if err != nil {
		return fmt.Errorf("%w: %w", follow.ErrFault, err)
	}
	if ix.archive != nil && b.To > ix.archivedTo {
		from := max(b.From, ix.archivedTo+1)
		var raw []vault.RawEvent
		for _, e := range b.Raw {
			if e.Ledger >= from {
				raw = append(raw, e)
			}
		}
		if err := ix.archive.Append(raw, from, b.To); err != nil {
			return fmt.Errorf("archive: %w", err)
		}
		ix.archivedTo = b.To
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

// Reconcile compares the vault's current root with the indexer's root at the vault's next leaf
// index. Roots are kept by leaf count, so the comparison holds even when the vault moves on between
// the read and the ingest.
func (ix *Indexer) Reconcile(ctx context.Context) error {
	nextKey, err := vault.NextLeafKey(ix.cfg.Vault)
	if err != nil {
		return err
	}
	rootsKey, err := vault.RootsKey(ix.cfg.Vault)
	if err != nil {
		return err
	}
	entries, latest, err := rpc.Entries(ctx, ix.rpc, []xdr.LedgerKey{nextKey, rootsKey})
	if err != nil {
		return err
	}
	ix.mu.RLock()
	cursor := ix.cursor
	ix.mu.RUnlock()
	nextEntry, ok1 := entries[mustKeyString(nextKey)]
	rootsEntry, ok2 := entries[mustKeyString(rootsKey)]
	if !ok1 || !ok2 {
		return ix.mismatchAt(ctx, cursor, "the vault's tree entries are missing or archived")
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
	ix.mu.RLock()
	ours, known := ix.roots[n]
	have := ix.state.Tree.Len()
	ix.mu.RUnlock()
	if n > have || !known {
		// The chain is ahead of the indexer, or the read is older than the roots kept; compare on
		// the next round.
		return nil
	}
	if ring.Current() != ours {
		return ix.mismatchAt(ctx, cursor, fmt.Sprintf("at %d leaves the chain has root %s, the indexer %s", n, ring.Current().Hex(), ours.Hex()))
	}
	ix.mu.Lock()
	ix.reconciled, ix.matched = cursor, true
	ix.latest = max(ix.latest, latest)
	ix.mu.Unlock()
	return nil
}

func (ix *Indexer) mismatchAt(ctx context.Context, ledger uint32, detail string) error {
	ix.mu.Lock()
	already := ix.mismatch
	ix.mismatch, ix.matched = true, false
	ix.mu.Unlock()
	if !already {
		if err := ix.db.setMismatch(ctx, ledger, detail); err != nil {
			return err
		}
	}
	ix.alerts.Raise(ctx, alert.Critical, "reconcile_mismatch", "at ledger %d: %s", ledger, detail)
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
	f.Run(ctx, poll, func(err error) { ix.Fault(ctx, err) })
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
}

// Health reports readiness. A failed or stale probe is never read as "no lag".
func (ix *Indexer) Health() Health {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	h := Health{
		Vault: ix.cfg.Vault, NetworkID: fmt.Sprintf("%x", ix.cfg.NetworkID), DeployLedger: ix.cfg.DeployLedger,
		LatestLedger: ix.latest, IngestedLedger: ix.cursor, Reconciled: ix.reconciled,
		LeafCount: ix.state.Tree.Len(), Root: ix.state.Tree.Root().Hex(), NullifierCount: ix.state.NullifierCount,
		PendingCount: len(ix.state.Pending),
	}
	switch {
	case ix.mismatch:
		h.Code = CodeMismatch
	case ix.fault:
		h.Code = CodeFault
	case ix.probedAt.IsZero() || ix.now().Sub(ix.probedAt) > ix.cfg.ProbeMaxAge:
		h.Code = CodeProbeFailed
	case ix.latest > ix.cursor+ix.cfg.MaxLag || !ix.matched:
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
