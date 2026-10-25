package keeper

import (
	"context"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// After a long stop the vault's code and its oldest nullifiers archive within a few hundred
// ledgers of each other. When neither can be restored in the same cycle, the page that goes out
// must still name the code and the restore by hand, not only the nullifiers.
func TestAnArchivedCodeIsNamedWhenNullifiersFailInTheSameCycle(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.sync()
	latest := h.chain.Ledger
	h.vaultLive(latest + holdWithin + renewStep)
	archived := latest - 1
	h.fake.SetEntry(vault.CodeKey([32]byte{9}), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.ContractCodeEntry{Hash: xdr.Hash{9}}}, 10, &archived)
	for i := uint64(1); i <= 2; i++ {
		h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_000+i).Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &archived)
	}
	h.simFail = func(d string) bool { return strings.HasPrefix(d, "restore") }
	h.playTTL = true
	if err := h.k.TTLCycle(context.Background()); err == nil {
		t.Fatal("the cycle completed")
	}
	var delivered []string
	for _, p := range h.pages {
		if p.Code == "entry_expiring" {
			delivered = append(delivered, p.Message)
		}
	}
	for _, m := range delivered {
		if strings.Contains(m, "archived: vault code") && strings.Contains(m, "restore them by hand") {
			return
		}
	}
	t.Fatalf("entry_expiring delivered %q", delivered)
}

// An archived nullifier whose restore fails is paged as archived, not as one that could not be
// extended.
func TestAnArchivedNullifierThatCannotBeRestoredIsPagedAsArchived(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.sync()
	latest := h.chain.Ledger
	h.vaultLive(latest + holdWithin + renewStep)
	archived := latest - 1
	h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_001).Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &archived)
	far := latest + 3_000_000
	h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_002).Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &far)
	h.simFail = func(d string) bool { return strings.HasPrefix(d, "restore") }
	h.playTTL = true
	if err := h.k.TTLCycle(context.Background()); err == nil {
		t.Fatal("the cycle completed")
	}
	var paged string
	for _, p := range h.pages {
		if p.Code == "entry_expiring" {
			paged = p.Message
		}
	}
	if !strings.Contains(paged, "archived") {
		t.Fatalf("entry_expiring paged %q", paged)
	}
}
