package keeper

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// A page about nullifiers alone does not keep the next cycle's page, which names the vault's
// code archived since, from going out once the alerter's cooldown has passed.
func TestTheNextCyclePagesTheCodeArchivedAfterANullifierPage(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.sync()
	latest := h.chain.Ledger
	h.vaultLive(latest + holdWithin + renewStep)
	archived := latest - 1
	for i := uint64(1); i <= 2; i++ {
		h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_000+i).Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &archived)
	}
	h.simFail = func(d string) bool { return strings.HasPrefix(d, "restore") }
	h.playTTL = true
	if err := h.k.TTLCycle(context.Background()); err == nil {
		t.Fatal("the first cycle completed")
	}
	pages := func() []string {
		var out []string
		for _, p := range h.pages {
			if p.Code == "entry_expiring" {
				out = append(out, p.Message)
			}
		}
		return out
	}
	first := pages()
	if len(first) != 1 || !strings.Contains(first[0], "archived: 2 nullifiers") || strings.Contains(first[0], "vault code") {
		t.Fatalf("first cycle paged %q", first)
	}

	h.now = h.now.Add(time.Hour + time.Minute)
	h.fake.SetEntry(vault.CodeKey([32]byte{9}), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.ContractCodeEntry{Hash: xdr.Hash{9}}}, 10, &archived)
	if err := h.k.TTLCycle(context.Background()); err == nil {
		t.Fatal("the second cycle completed")
	}
	all := pages()
	if len(all) != 2 || !strings.Contains(all[1], "archived: vault code") || !strings.Contains(all[1], "2 nullifiers") {
		t.Fatalf("pages %q", all)
	}
}
