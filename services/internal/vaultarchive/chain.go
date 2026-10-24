package vaultarchive

import (
	"context"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// ErrChain reports an archive the vault's own entries do not confirm.
var ErrChain = errors.New("vault archive: the chain does not confirm it")

// nullifierBatch is how many nullifiers are read between two checks of the context; the RPC is
// asked for 200 keys at a time inside it.
const nullifierBatch = 2_000

// Report is what a chain check found.
type Report struct {
	// Leaves is the number of leaves the archive holds and ChainLeaves the vault's. TailLeaves is
	// how many of the vault's leaves after the archive's were read from the RPC's events, which
	// happens only when the vault is further ahead than its root ring reaches.
	Leaves, ChainLeaves, TailLeaves uint64
	Nullifiers                      int
	// Ledger is the latest ledger the RPC reported while the checks ran.
	Ledger uint32
}

// View is what one RPC says about the vault's tree, read in one snapshot.
type View struct {
	client rpc.Client
	vault  string
	ring   vault.RootRing
	// events gives the vault's events after the archive's last ledger.
	events Source
	// Next is the vault's leaf count and Latest the ledger of the snapshot.
	Next   uint64
	Latest uint32
}

// ReadView reads the vault's root ring and leaf count from an RPC of the named network.
func ReadView(ctx context.Context, c rpc.Client, vaultID, passphrase string) (*View, error) {
	if err := rpc.CheckNetwork(ctx, c, passphrase); err != nil {
		return nil, err
	}
	rootsKey, err := vault.RootsKey(vaultID)
	if err != nil {
		return nil, err
	}
	nextKey, err := vault.NextLeafKey(vaultID)
	if err != nil {
		return nil, err
	}
	entries, latest, err := rpc.Entries(ctx, c, []xdr.LedgerKey{rootsKey, nextKey})
	if err != nil {
		return nil, err
	}
	rootsEntry, ok0 := entryOf(entries, rootsKey)
	nextEntry, ok1 := entryOf(entries, nextKey)
	if !ok0 || !ok1 {
		return nil, fmt.Errorf("%w: the vault's tree entries are missing", ErrChain)
	}
	ringVal, err := rpc.ContractValue(rootsEntry)
	if err != nil {
		return nil, err
	}
	ring, err := vault.DecodeRootRing(ringVal)
	if err != nil {
		return nil, err
	}
	nextVal, err := rpc.ContractValue(nextEntry)
	if err != nil {
		return nil, err
	}
	next, ok := nextVal.GetU64()
	if !ok || next%2 != 0 {
		return nil, fmt.Errorf("%w: the vault's next leaf is not an even u64", ErrChain)
	}
	if want := uint32((uint64(next) / 2) % vault.RootHistory); ring.Newest != want {
		return nil, fmt.Errorf("%w: the root ring ends at slot %d, but %d leaves put it at %d", ErrChain, ring.Newest, next, want)
	}
	return &View{client: c, vault: vaultID, ring: ring, events: follow.RPCSource{Client: c, Contract: vaultID}, Next: uint64(next), Latest: latest}, nil
}

// Admits refuses a manifest that claims more than the vault has: more leaves than it holds or
// ledgers past the one the RPC has closed. It is the check made before any window is fetched.
func (v *View) Admits(m Manifest) error {
	if n := len(m.Windows); n > 0 && m.Windows[n-1].Leaves[1] > v.Next {
		return fmt.Errorf("%w: the manifest lists %d leaves, the vault holds %d", ErrChain, m.Windows[n-1].Leaves[1], v.Next)
	}
	if m.CoveredTo > v.Latest {
		return fmt.Errorf("%w: the manifest covers ledger %d, the RPC's latest is %d", ErrChain, m.CoveredTo, v.Latest)
	}
	return nil
}

// Verify asks the vault whether the archive is its own. The archive's commitments, rebuilt into
// the tree, must give the vault's current root, or the root it held at that many leaves if it
// has moved on by up to 255 pairs. Past that the root ring no longer holds it, and the tree is
// carried on with the vault's own events after the archive's last ledger, read from the RPC,
// until it must give the current root; that needs the RPC to still keep those ledgers. Every
// nullifier the archive lists must have an entry, live or archived, so a nullifier made up cannot
// pass. A nullifier the archive leaves out cannot be seen from here.
func (v *View) Verify(ctx context.Context, contents *Contents) (Report, error) {
	report := Report{Leaves: uint64(len(contents.Commitments)), ChainLeaves: v.Next, Nullifiers: len(contents.Nullifiers), Ledger: v.Latest}
	if err := v.checkRoot(ctx, contents, &report); err != nil {
		return report, err
	}
	for start := 0; start < len(contents.Nullifiers); start += nullifierBatch {
		batch := contents.Nullifiers[start:min(start+nullifierBatch, len(contents.Nullifiers))]
		keys := make([]xdr.LedgerKey, len(batch))
		for i, n := range batch {
			var err error
			if keys[i], err = vault.NullifierKey(v.vault, n.Bytes()); err != nil {
				return report, err
			}
		}
		found, seen, err := rpc.Entries(ctx, v.client, keys)
		if err != nil {
			return report, err
		}
		report.Ledger = max(report.Ledger, seen)
		for i, k := range keys {
			if _, ok := entryOf(found, k); !ok {
				return report, fmt.Errorf("%w: nullifier %s has no entry in the vault", ErrChain, batch[i].Hex())
			}
		}
	}
	return report, nil
}

// VerifyChain reads the vault the pin names through one RPC and verifies contents against it.
// The contents must be of that vault: what the archive says about itself is never the question.
func VerifyChain(ctx context.Context, c rpc.Client, want Expect, contents *Contents) (Report, error) {
	if want.Vault == "" || want.NetworkPassphrase == "" {
		return Report{}, errors.New("vault archive: a chain check needs the vault and network to check against")
	}
	if err := contents.Manifest.Validate(want); err != nil {
		return Report{}, err
	}
	v, err := ReadView(ctx, c, want.Vault, want.NetworkPassphrase)
	if err != nil {
		return Report{}, err
	}
	return v.Verify(ctx, contents)
}

// VerifyArchive reads the manifest, has every RPC refuse it if it claims more than the vault
// has, and only then fetches the windows, so a hostile archive costs a manifest and not a
// download. Every RPC must then confirm the whole archive.
func VerifyArchive(ctx context.Context, f Fetcher, want Expect, clients ...rpc.Client) (*Contents, Report, error) {
	if len(clients) == 0 {
		return nil, Report{}, errors.New("vault archive: a chain check needs an RPC")
	}
	if want.Vault == "" || want.NetworkPassphrase == "" {
		return nil, Report{}, errors.New("vault archive: a chain check needs the vault and network to check against")
	}
	m, err := ReadManifest(ctx, f, want)
	if err != nil {
		return nil, Report{}, err
	}
	views := make([]*View, len(clients))
	for i, c := range clients {
		if views[i], err = ReadView(ctx, c, want.Vault, want.NetworkPassphrase); err != nil {
			return nil, Report{}, err
		}
		if err := views[i].Admits(m); err != nil {
			return nil, Report{}, err
		}
	}
	contents, err := loadWindows(ctx, f, m)
	if err != nil {
		return nil, Report{}, err
	}
	var report Report
	for i, v := range views {
		r, err := v.Verify(ctx, contents)
		if err != nil {
			return contents, r, err
		}
		if i == 0 || r.Ledger < report.Ledger {
			report = r
		}
	}
	return contents, report, nil
}

func (v *View) checkRoot(ctx context.Context, contents *Contents, report *Report) error {
	if report.Leaves > report.ChainLeaves {
		return fmt.Errorf("%w: the archive holds %d leaves, the vault %d", ErrChain, report.Leaves, report.ChainLeaves)
	}
	var t tree.Tree
	for i := 0; i+1 < len(contents.Commitments); i += 2 {
		if _, err := t.AppendPair(contents.Commitments[i], contents.Commitments[i+1]); err != nil {
			return err
		}
	}
	behind := (report.ChainLeaves - report.Leaves) / 2
	if behind >= vault.RootHistory {
		return v.checkRootThroughEvents(ctx, &t, contents.Manifest.CoveredTo, report, behind)
	}
	at := (uint64(v.ring.Newest) + vault.RootHistory - behind) % vault.RootHistory
	if v.ring.Roots[at] != t.Root() {
		return fmt.Errorf("%w: the archive's %d leaves give root %s, which the vault never held at that count", ErrChain, report.Leaves, t.Root().Hex())
	}
	return nil
}

// checkRootThroughEvents carries t, the archive's tree, on with the vault's events of the ledgers
// after covered up to the ledger the root ring was read at, and requires the result to be the
// vault's current root. Every leaf must follow the one before it, so an event the RPC leaves out
// or repeats ends in a root the vault does not have.
func (v *View) checkRootThroughEvents(ctx context.Context, t *tree.Tree, covered uint32, report *Report, behind uint64) error {
	var events []vault.RawEvent
	if covered < v.Latest {
		var err error
		if events, err = v.events.Events(ctx, covered+1, v.Latest); err != nil {
			return fmt.Errorf("%w: the vault is %d pairs ahead of the archive, past the %d roots it keeps, and its events after ledger %d cannot be read: %w", ErrChain, behind, vault.RootHistory, covered, err)
		}
	}
	next := report.Leaves
	var left vault.NewCommitment
	var leftAt vault.Position
	for _, e := range events {
		if e.Contract != v.vault {
			return fmt.Errorf("%w: an event of contract %.80q among the vault's", ErrChain, e.Contract)
		}
		decoded, err := vault.Decode(e)
		if err != nil {
			return fmt.Errorf("%w: an event after the archive: %w", ErrChain, err)
		}
		leaf, ok := decoded.Body.(vault.NewCommitment)
		if !ok {
			continue
		}
		if leaf.Index != next {
			return fmt.Errorf("%w: leaf %d where %d belongs among the events after the archive", ErrChain, leaf.Index, next)
		}
		if next%2 == 0 {
			left, leftAt = leaf, e.Pos()
		} else {
			if leftAt.Ledger != e.Ledger || leftAt.Tx != e.Tx {
				return fmt.Errorf("%w: leaf %d is not the second of a pair in one transaction", ErrChain, leaf.Index)
			}
			if _, err := t.AppendPair(left.Commitment, leaf.Commitment); err != nil {
				return err
			}
		}
		next++
	}
	if next != report.ChainLeaves {
		return fmt.Errorf("%w: the vault is %d pairs ahead of the archive, past the %d roots it keeps, and the events after ledger %d account for %d of its %d leaves", ErrChain, behind, vault.RootHistory, covered, next, report.ChainLeaves)
	}
	if t.Root() != v.ring.Current() {
		return fmt.Errorf("%w: the archive's leaves and the events after it give root %s, not the vault's current root", ErrChain, t.Root().Hex())
	}
	report.TailLeaves = next - report.Leaves
	return nil
}

// entryOf returns the entry the RPC gave for key if the entry is that one: the RPC names the key
// it answers for, so its own data must name it too.
func entryOf(found map[string]rpc.Entry, key xdr.LedgerKey) (rpc.Entry, bool) {
	name := mustKeyString(key)
	e, ok := found[name]
	if !ok {
		return rpc.Entry{}, false
	}
	own, err := e.Data.LedgerKey()
	if err != nil {
		return rpc.Entry{}, false
	}
	got, err := rpc.KeyString(own)
	return e, err == nil && got == name
}

func mustKeyString(k xdr.LedgerKey) string {
	s, err := rpc.KeyString(k)
	if err != nil {
		panic(err)
	}
	return s
}
