package vaultarchive

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

func mustKey(k xdr.LedgerKey, err error) xdr.LedgerKey {
	if err != nil {
		panic(err)
	}
	return k
}

// chainOf is a vault that holds every leaf and nullifier of the contents, with the ring of roots
// after each pair. Nullifiers are stored as archived entries, which the RPC still returns.
func chainOf(t *testing.T, c *Contents) *rpctest.Fake {
	t.Helper()
	var tr tree.Tree
	roots := []fr.Element{tree.Zero(tree.Depth)}
	for i := 0; i < len(c.Commitments); i += 2 {
		if _, err := tr.AppendPair(c.Commitments[i], c.Commitments[i+1]); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, tr.Root())
	}
	f := rpctest.New(passphrase, 5*WindowLedgers)
	v := vaulttest.Vault
	f.SetContractData(mustKey(vault.RootsKey(v)), ringOf(roots), 100, nil)
	f.SetContractData(mustKey(vault.NextLeafKey(v)), vault.U64(uint64(len(c.Commitments))), 100, nil)
	archived := uint32(1)
	for _, n := range c.Nullifiers {
		f.SetContractData(mustKey(vault.NullifierKey(v, n.Bytes())), vault.Bool(true), 100, &archived)
	}
	return f
}

func loaded(t *testing.T) *Contents {
	t.Helper()
	dir, _ := good(t)
	c, err := Load(context.Background(), DirFetcher(dir), Expect{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnArchiveOfTheVaultsOwnHistoryPassesTheChainChecks(t *testing.T) {
	c := loaded(t)
	f := chainOf(t, c)
	report, err := VerifyChain(context.Background(), f, c)
	if err != nil {
		t.Fatal(err)
	}
	if report.Leaves != 8 || report.ChainLeaves != 8 || report.Nullifiers != 8 || report.Ledger != 5*WindowLedgers {
		t.Fatalf("report %+v", report)
	}
}

func TestAnArchiveBehindTheVaultPassesWhileItsRootIsInTheRing(t *testing.T) {
	c := loaded(t)
	// The vault took one more pair after the archive's last window.
	more := &Contents{Manifest: c.Manifest, Commitments: append(append([]fr.Element(nil), c.Commitments...), fr.SetUint64(7), fr.SetUint64(8)), Nullifiers: c.Nullifiers}
	f := chainOf(t, more)
	report, err := VerifyChain(context.Background(), f, c)
	if err != nil || report.ChainLeaves != 10 || report.Leaves != 8 {
		t.Fatalf("report %+v, %v", report, err)
	}
	// Far enough ahead that the archive's root has left the ring.
	var far []fr.Element
	far = append(far, c.Commitments...)
	for i := range 2 * vault.RootHistory {
		far = append(far, fr.SetUint64(uint64(1000+i)))
	}
	f = chainOf(t, &Contents{Manifest: c.Manifest, Commitments: far, Nullifiers: c.Nullifiers})
	if _, err := VerifyChain(context.Background(), f, c); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "ahead of the archive") {
		t.Fatalf("an archive 256 pairs behind: %v", err)
	}
}

func TestATamperedLeafIsNotAnyRootTheVaultHeld(t *testing.T) {
	c := loaded(t)
	f := chainOf(t, c)
	for _, i := range []int{0, 3, len(c.Commitments) - 1} {
		tampered := &Contents{Manifest: c.Manifest, Commitments: append([]fr.Element(nil), c.Commitments...), Nullifiers: c.Nullifiers}
		tampered.Commitments[i] = fr.SetUint64(424242)
		if _, err := VerifyChain(context.Background(), f, tampered); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "never held") {
			t.Fatalf("leaf %d changed: %v", i, err)
		}
	}
	reordered := &Contents{Manifest: c.Manifest, Commitments: append([]fr.Element(nil), c.Commitments...), Nullifiers: c.Nullifiers}
	reordered.Commitments[0], reordered.Commitments[1] = reordered.Commitments[1], reordered.Commitments[0]
	if _, err := VerifyChain(context.Background(), f, reordered); !errors.Is(err, ErrChain) {
		t.Fatalf("leaves swapped: %v", err)
	}
	omitted := &Contents{Manifest: c.Manifest, Commitments: append(append([]fr.Element(nil), c.Commitments[:2]...), c.Commitments[4:]...), Nullifiers: c.Nullifiers}
	if _, err := VerifyChain(context.Background(), f, omitted); !errors.Is(err, ErrChain) {
		t.Fatalf("a pair left out: %v", err)
	}
	ahead := &Contents{Manifest: c.Manifest, Commitments: append(append([]fr.Element(nil), c.Commitments...), fr.SetUint64(1), fr.SetUint64(2)), Nullifiers: c.Nullifiers}
	if _, err := VerifyChain(context.Background(), f, ahead); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "holds 10 leaves") {
		t.Fatalf("a pair the vault never took: %v", err)
	}
}

func TestANullifierTheVaultNeverSpentFailsTheChainChecks(t *testing.T) {
	c := loaded(t)
	f := chainOf(t, c)
	v := vaulttest.Vault
	f.DeleteEntry(mustKey(vault.NullifierKey(v, c.Nullifiers[5].Bytes())))
	if _, err := VerifyChain(context.Background(), f, c); !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), c.Nullifiers[5].Hex()) {
		t.Fatalf("a nullifier with no entry: %v", err)
	}
	made := &Contents{Manifest: c.Manifest, Commitments: c.Commitments, Nullifiers: append(append([]fr.Element(nil), c.Nullifiers...), fr.SetUint64(31337))}
	if _, err := VerifyChain(context.Background(), chainOf(t, c), made); !errors.Is(err, ErrChain) {
		t.Fatalf("a nullifier made up: %v", err)
	}
}

func TestNullifiersAreReadInBatchesOfAtMostTwoHundredKeys(t *testing.T) {
	c := loaded(t)
	for i := range 450 {
		c.Nullifiers = append(c.Nullifiers, fr.SetUint64(uint64(9000+i)))
	}
	f := chainOf(t, c)
	if _, err := VerifyChain(context.Background(), f, c); err != nil {
		t.Fatal(err)
	}
	// One call for the tree entries, then 458 nullifiers in batches of 200.
	if calls := f.CallCount("getLedgerEntries"); calls != 1+3 {
		t.Fatalf("%d calls", calls)
	}
}

func TestTheChainChecksRefuseAnotherNetworkAndMissingEntries(t *testing.T) {
	c := loaded(t)
	f := chainOf(t, c)
	f.Passphrase = "Public Global Stellar Network ; September 2015"
	if _, err := VerifyChain(context.Background(), f, c); err == nil {
		t.Fatal("an RPC of another network was read")
	}
	f = chainOf(t, c)
	f.DeleteEntry(mustKey(vault.NextLeafKey(vaulttest.Vault)))
	if _, err := VerifyChain(context.Background(), f, c); !errors.Is(err, ErrChain) {
		t.Fatalf("a vault with no tree: %v", err)
	}
	f = chainOf(t, c)
	f.Fail["getLedgerEntries"] = errors.New("down")
	if _, err := VerifyChain(context.Background(), f, c); err == nil {
		t.Fatal("a failing RPC passed")
	}
}

// ringOf lays the roots out as the vault does: the root after pair j in slot j modulo the ring.
func ringOf(roots []fr.Element) xdr.ScVal {
	ring := make([]xdr.ScVal, vault.RootHistory)
	for i := range ring {
		ring[i] = vaulttest.Field(fr.Element{})
	}
	for j, r := range roots {
		ring[j%vault.RootHistory] = vaulttest.Field(r)
	}
	newest := uint32((len(roots) - 1) % vault.RootHistory)
	return vault.Struct(vault.Field{Name: "roots", Value: vault.Vec(ring...)}, vault.Field{Name: "newest", Value: vault.U32(newest)})
}
