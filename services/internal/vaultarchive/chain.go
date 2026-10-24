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

// VerifyChain asks the vault whether the archive is its own. The archive's commitments, rebuilt
// into the tree, must give the vault's current root, or the root it held at that many leaves if
// it has moved on by up to 255 pairs. Every nullifier the archive lists must have an entry,
// live or archived, so a nullifier made up cannot pass. A nullifier the archive leaves out
// cannot be seen from here.
func VerifyChain(ctx context.Context, c rpc.Client, contents *Contents) (Report, error) {
	m := contents.Manifest
	if err := rpc.CheckNetwork(ctx, c, m.NetworkPassphrase); err != nil {
		return Report{}, err
	}
	rootsKey, err := vault.RootsKey(m.Vault)
	if err != nil {
		return Report{}, err
	}
	nextKey, err := vault.NextLeafKey(m.Vault)
	if err != nil {
		return Report{}, err
	}
	entries, latest, err := rpc.Entries(ctx, c, []xdr.LedgerKey{rootsKey, nextKey})
	if err != nil {
		return Report{}, err
	}
	rootsEntry, ok0 := entries[mustKeyString(rootsKey)]
	nextEntry, ok1 := entries[mustKeyString(nextKey)]
	if !ok0 || !ok1 {
		return Report{}, fmt.Errorf("%w: the vault's tree entries are missing", ErrChain)
	}
	ringVal, err := rpc.ContractValue(rootsEntry)
	if err != nil {
		return Report{}, err
	}
	ring, err := vault.DecodeRootRing(ringVal)
	if err != nil {
		return Report{}, err
	}
	nextVal, err := rpc.ContractValue(nextEntry)
	if err != nil {
		return Report{}, err
	}
	next, ok := nextVal.GetU64()
	if !ok || next%2 != 0 {
		return Report{}, fmt.Errorf("%w: the vault's next leaf is not an even u64", ErrChain)
	}
	report := Report{Leaves: uint64(len(contents.Commitments)), ChainLeaves: uint64(next), Nullifiers: len(contents.Nullifiers), Ledger: latest}
	if err := checkRoot(contents, ring, report); err != nil {
		return report, err
	}
	for start := 0; start < len(contents.Nullifiers); start += nullifierBatch {
		batch := contents.Nullifiers[start:min(start+nullifierBatch, len(contents.Nullifiers))]
		keys := make([]xdr.LedgerKey, len(batch))
		for i, n := range batch {
			if keys[i], err = vault.NullifierKey(m.Vault, n.Bytes()); err != nil {
				return report, err
			}
		}
		found, seen, err := rpc.Entries(ctx, c, keys)
		if err != nil {
			return report, err
		}
		report.Ledger = max(report.Ledger, seen)
		for i, k := range keys {
			if _, ok := found[mustKeyString(k)]; !ok {
				return report, fmt.Errorf("%w: nullifier %s has no entry in the vault", ErrChain, batch[i].Hex())
			}
		}
	}
	return report, nil
}

func checkRoot(contents *Contents, ring vault.RootRing, report Report) error {
	var t tree.Tree
	for i := 0; i+1 < len(contents.Commitments); i += 2 {
		if _, err := t.AppendPair(contents.Commitments[i], contents.Commitments[i+1]); err != nil {
			return err
		}
	}
	if report.Leaves > report.ChainLeaves {
		return fmt.Errorf("%w: the archive holds %d leaves, the vault %d", ErrChain, report.Leaves, report.ChainLeaves)
	}
	behind := (report.ChainLeaves - report.Leaves) / 2
	if behind >= vault.RootHistory {
		return fmt.Errorf("%w: the vault is %d pairs ahead of the archive, past the %d roots it keeps", ErrChain, behind, vault.RootHistory)
	}
	at := (uint64(ring.Newest) + vault.RootHistory - behind) % vault.RootHistory
	if ring.Roots[at] != t.Root() {
		return fmt.Errorf("%w: the archive's %d leaves give root %s, which the vault never held at that count", ErrChain, report.Leaves, t.Root().Hex())
	}
	return nil
}

func mustKeyString(k xdr.LedgerKey) string {
	s, err := rpc.KeyString(k)
	if err != nil {
		panic(err)
	}
	return s
}
