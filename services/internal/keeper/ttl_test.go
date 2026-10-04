package keeper

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// vaultLive gives the vault's instance, code and tree entries a life until the ledger until, and
// the asset contract's instance a far one.
func (h *harness) vaultLive(until uint32) {
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: h.limit, Large: 5_000_000_000, Status: h.status, WasmHash: [32]byte{9},
	}), 10, &until)
	h.fake.SetEntry(vault.CodeKey([32]byte{9}), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.ContractCodeEntry{Hash: xdr.Hash{9}}}, 10, &until)
	for _, key := range mustKey(vault.TreeKeys(vaulttest.Vault)) {
		h.fake.SetContractData(key, vault.U64(0), 10, &until)
	}
	far := h.fake.Latest + 3_000_000
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Token)), vault.U64(0), 10, &far)
}

// nullifiersLive gives the first n nullifiers the chain spent a life until the ledger until.
func (h *harness) nullifiersLive(n uint64, until uint32) {
	for i := uint64(1); i <= n; i++ {
		h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_000+i).Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &until)
	}
}

func has(keys []xdr.LedgerKey, key xdr.LedgerKey) bool {
	return slices.ContainsFunc(keys, func(k xdr.LedgerKey) bool { return k.Equals(key) })
}

func TestTheVaultsEntriesAreExtendedADayAtATimeBeforeAWriteWouldPayForThem(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.chain.Attest(1)
	h.chain.Admit(1)
	h.chain.QueueExit(1, -400, 0, vaulttest.Depositor)
	h.shield(10, nil, 0)
	h.sync()
	latest := h.chain.Ledger
	// As a user's transaction leaves them: 30 days and an hour.
	written := latest + vault.EntryTTL
	h.vaultLive(written)
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, 2)), vaulttest.Pending(2, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &written)
	h.fake.SetContractData(mustKey(vault.ExitKey(vaulttest.Vault, 1)), vaulttest.ExitEntry(vaulttest.Depositor, 400, 0, 1), 10, &written)
	h.nullifiersLive(6, latest+3_000_000)
	h.playTTL = true

	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	// The instance, the code, the three tree entries, deposit 2 and exit 1 go to 32 days, a day
	// past the renewal, in one transaction, rather than to the network's maximum.
	if got := h.take(); !equal(got, []string{"extend 7 to 552960"}) || !has(h.footprints[0].ReadOnly, vault.CodeKey([32]byte{9})) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	// They wait a day before the next extension, which keeps them above the 30 days below which
	// the vault's own writes would extend them at a user's cost.
	h.fake.SetLatest(latest + ledgersPerDay)
	if err := h.k.TTLCycle(ctx); err != nil || len(h.take()) != 0 {
		t.Fatalf("extended within the day: %v", err)
	}
	h.fake.SetLatest(latest + ledgersPerDay + 1)
	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"extend 7 to 552960"}) {
		t.Fatalf("ttl cycle sent %v a day later", got)
	}
	for _, key := range append(mustKey(vault.TreeKeys(vaulttest.Vault)), vault.CodeKey([32]byte{9})) {
		if until, _ := h.fake.LiveUntil(key); until != latest+ledgersPerDay+1+renewWithin+renewStep {
			t.Fatalf("an entry lives until %d", until)
		}
	}
}

func TestAnExtensionAboveTheFeeCapIsSplitThenShortened(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.sync()
	latest := h.chain.Ledger
	h.vaultLive(latest + vault.EntryTTL)
	code := vault.CodeKey([32]byte{9})
	// The code's rent is a hundred times any other entry's.
	h.rent = func(key xdr.LedgerKey, ledgers uint32) int64 {
		if key.Equals(code) {
			return 100 * int64(ledgers)
		}
		return int64(ledgers)
	}
	h.k.engine.MaxTTLFee = 2_000_000
	h.playTTL = true

	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	// The five together, and the instance with the code, are above the cap. The instance and the
	// tree go to 32 days, and the code half as far past its life: 33,840 ledgers would cost
	// 3,384,100 stroops, 16,920 cost 1,692,100.
	if got := h.take(); !equal(got, []string{"extend 1 to 552960", "extend 1 to 536040", "extend 3 to 552960"}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	// An hour later the code is due again, and a day's step now fits the cap.
	h.fake.SetLatest(latest + minStep)
	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"extend 1 to 552960"}) {
		t.Fatalf("ttl cycle sent %v an hour later", got)
	}

	// Below the rent of an hour of the code, the code is left and the cycle fails, but every other
	// entry is still extended.
	h2 := newHarness(t)
	h2.sync()
	h2.vaultLive(h2.chain.Ledger + vault.EntryTTL)
	h2.rent, h2.playTTL = h.rent, true
	h2.k.engine.MaxTTLFee = 50_000
	err := h2.k.TTLCycle(ctx)
	if err == nil || !strings.Contains(err.Error(), "vault code") || !strings.Contains(err.Error(), "above the cap") {
		t.Fatalf("a code the cap refuses: %v", err)
	}
	if got := h2.take(); !equal(got, []string{"extend 1 to 552960", "extend 1 to 552960", "extend 1 to 552960", "extend 1 to 552960"}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	if until, _ := h2.fake.LiveUntil(code); until != h2.chain.Ledger+vault.EntryTTL {
		t.Fatalf("the code lives until %d", until)
	}
}

func TestArchivedEntriesAreRestoredFirstAndARefusedEntryHoldsBackNoOther(t *testing.T) {
	h := newHarness(t)
	for range 8 {
		h.shield(10, nil, 0)
	}
	h.sync()
	latest := h.chain.Ledger
	archived, near := latest-1, latest+100_000
	h.vaultLive(latest + 3_000_000)
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: h.limit, Large: 5_000_000_000, Status: h.status, WasmHash: [32]byte{9},
	}), 10, &archived)
	for id := uint64(1); id <= 8; id++ {
		h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &near)
	}
	h.nullifiersLive(16, latest+3_000_000)
	// Deposit 5's entry was archived after the keeper read it, so the simulation refuses any
	// extension that names it.
	gone := mustKey(vault.PendingKey(vaulttest.Vault, 5))
	h.refuse = func(fp xdr.LedgerFootprint) bool { return has(fp.ReadOnly, gone) }

	err := h.k.TTLCycle(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pending deposit 5") {
		t.Fatalf("a refused deposit: %v", err)
	}
	// The instance is restored first; the nine due entries are split until deposit 5 stands alone.
	want := []string{"restore 1", "extend 4 to 552960", "extend 1 to 552960", "extend 3 to 552960"}
	if got := h.take(); !equal(got, want) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	for _, fp := range h.footprints[1:] {
		if has(fp.ReadOnly, gone) {
			t.Fatal("an extension carried the refused deposit")
		}
	}
}

func TestExtensionsGoInBatchesThatFitATransaction(t *testing.T) {
	h := newHarness(t)
	var ids []uint64
	for range 70 {
		ids = append(ids, h.shield(10, nil, 0))
	}
	h.sync()
	latest := h.chain.Ledger
	near := latest + 100_000
	h.vaultLive(latest + 3_000_000)
	for _, id := range ids {
		h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &near)
	}
	h.nullifiersLive(140, latest+3_000_000)
	if err := h.k.TTLCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"extend 50 to 552960", "extend 20 to 552960"}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
}
