package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
	"github.com/cyphras/cyphras-contracts/services/internal/vaultarchive"
)

// aheadFake is a vault that took pairs more admissions after the archive in dir, with an RPC that
// still keeps their events.
func aheadFake(t *testing.T, dir string, pairs int) *rpctest.Fake {
	t.Helper()
	c, err := vaultarchive.Load(context.Background(), vaultarchive.DirFetcher(dir), vaultarchive.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	chain := vaulttest.New(3*window+10, 1_730_000_000)
	chain.NextLeaf = uint64(len(c.Commitments))
	for i := range pairs {
		chain.NextLedger(5)
		chain.Admit(uint64(100 + i))
	}
	commitments := append([]fr.Element(nil), c.Commitments...)
	for _, e := range chain.Events {
		d, err := vault.Decode(e)
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := d.Body.(vault.NewCommitment); ok {
			commitments = append(commitments, n.Commitment)
		}
	}
	var tr tree.Tree
	ring := make([]xdr.ScVal, vault.RootHistory)
	for i := range ring {
		ring[i] = vaulttest.Field(fr.Element{})
	}
	ring[0] = vaulttest.Field(tree.Zero(tree.Depth))
	for i := 0; i < len(commitments); i += 2 {
		if _, err := tr.AppendPair(commitments[i], commitments[i+1]); err != nil {
			t.Fatal(err)
		}
		ring[(i/2+1)%vault.RootHistory] = vaulttest.Field(tr.Root())
	}
	f := rpctest.New(passphrase, 5*window)
	set := func(k xdr.LedgerKey, err error, v xdr.ScVal) {
		if err != nil {
			t.Fatal(err)
		}
		f.SetContractData(k, v, 100, nil)
	}
	k, err := vault.RootsKey(vaulttest.Vault)
	set(k, err, vault.Struct(vault.Field{Name: "roots", Value: vault.Vec(ring...)}, vault.Field{Name: "newest", Value: vault.U32(uint32((len(commitments) / 2) % vault.RootHistory))}))
	k, err = vault.NextLeafKey(vaulttest.Vault)
	set(k, err, vault.U64(uint64(len(commitments))))
	for _, n := range c.Nullifiers {
		k, err = vault.NullifierKey(vaulttest.Vault, n.Bytes())
		set(k, err, vault.Bool(true))
	}
	for _, e := range chain.Events {
		f.AddEvent(rpctest.EventInfo(e))
	}
	return f
}

func TestVerifyChecksAnArchiveTheVaultHasLeftFarBehindAgainstTheRPCsEvents(t *testing.T) {
	dir, deployment := exportSample(t)
	t.Cleanup(func(old func(string) rpc.Client) func() { return func() { dialRPC = old } }(dialRPC))
	fake := aheadFake(t, dir, vault.RootHistory+20)
	dialRPC = func(string) rpc.Client { return fake }
	out, err := do(t, "verify", "--dir", dir, "--rpc", "http://rpc.invalid", "--deployment", deployment)
	if err != nil || !strings.Contains(out, "8 of its 560 leaves") || !strings.Contains(out, "552 leaves after the archive were read from the RPC's events") {
		t.Fatalf("an archive %d pairs behind: %q, %v", vault.RootHistory+20, out, err)
	}

	forgetful := aheadFake(t, dir, vault.RootHistory+20)
	forgetful.Events = nil
	dialRPC = func(string) rpc.Client { return forgetful }
	if _, err := do(t, "verify", "--dir", dir, "--rpc", "http://rpc.invalid", "--deployment", deployment); err == nil || !strings.Contains(err.Error(), "ahead of the archive") {
		t.Fatalf("an RPC with no events for the ledgers after the archive: %v", err)
	}
}
