package vaultarchive

import (
	"context"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

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
	// Leaves is the number of leaves the archive holds and ChainLeaves the vault's.
	Leaves, ChainLeaves uint64
	Nullifiers          int
	// Ledger is the latest ledger the RPC reported while the checks ran.
	Ledger uint32
}

// View is what one RPC says about the vault's tree, read in one snapshot.
type View struct {
	client rpc.Client
	vault  string
	ring   vault.RootRing
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
	return &View{client: c, vault: vaultID, ring: ring, Next: uint64(next), Latest: latest}, nil
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
// has moved on by up to 255 pairs. Every nullifier the archive lists must have an entry, live or
// archived, so a nullifier made up cannot pass. A nullifier the archive leaves out cannot be
// seen from here.
func (v *View) Verify(ctx context.Context, contents *Contents) (Report, error) {
	report := Report{Leaves: uint64(len(contents.Commitments)), ChainLeaves: v.Next, Nullifiers: len(contents.Nullifiers), Ledger: v.Latest}
	if err := v.checkRoot(contents, report); err != nil {
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

// VerifyChain reads the vault through one RPC and verifies contents against it.
func VerifyChain(ctx context.Context, c rpc.Client, contents *Contents) (Report, error) {
	v, err := ReadView(ctx, c, contents.Manifest.Vault, contents.Manifest.NetworkPassphrase)
	if err != nil {
		return Report{}, err
	}
	return v.Verify(ctx, contents)
}

// VerifyArchive reads the manifest, has every RPC refuse it if it claims more than the vault
// has, and only then fetches the windows, so a hostile archive costs a manifest and not a
// download. Every RPC must then confirm the whole archive.
func VerifyArchive(ctx context.Context, f Fetcher, want Expect, clients ...rpc.Client) (*Contents, Report, error) {
	m, err := ReadManifest(ctx, f, want)
	if err != nil {
		return nil, Report{}, err
	}
	views := make([]*View, len(clients))
	for i, c := range clients {
		if views[i], err = ReadView(ctx, c, m.Vault, m.NetworkPassphrase); err != nil {
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

func (v *View) checkRoot(contents *Contents, report Report) error {
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
		return fmt.Errorf("%w: the vault is %d pairs ahead of the archive, past the %d roots it keeps", ErrChain, behind, vault.RootHistory)
	}
	at := (uint64(v.ring.Newest) + vault.RootHistory - behind) % vault.RootHistory
	if v.ring.Roots[at] != t.Root() {
		return fmt.Errorf("%w: the archive's %d leaves give root %s, which the vault never held at that count", ErrChain, report.Leaves, t.Root().Hex())
	}
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
