package keeper

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// The ExtendTo of the vault's own entries, 46 days, and of pending deposits and exits, 32 days.
const (
	holdTo  = "794880"
	renewTo = "552960"
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
	far := h.fake.LatestLedger() + 3_000_000
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Token)), vault.U64(0), 10, &far)
}

// nullifiersLive gives the first n nullifiers the chain spent a life until the ledger until.
func (h *harness) nullifiersLive(n uint64, until uint32) {
	for i := uint64(1); i <= n; i++ {
		h.fake.SetContractData(mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_000+i).Bytes())), xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &until)
	}
}

// codeRent prices the code's rent at code stroops a ledger and every other entry's at other.
func (h *harness) codeRent(code, other int64) {
	key := vault.CodeKey([32]byte{9})
	h.rent = func(k xdr.LedgerKey, ledgers uint32) int64 {
		if k.Equals(key) {
			return code * int64(ledgers)
		}
		return other * int64(ledgers)
	}
}

func has(keys []xdr.LedgerKey, key xdr.LedgerKey) bool {
	return slices.ContainsFunc(keys, func(k xdr.LedgerKey) bool { return k.Equals(key) })
}

func life(h *harness, key xdr.LedgerKey) uint32 {
	until, _ := h.fake.LiveUntil(key)
	return until - h.fake.LatestLedger()
}

func TestTheVaultsEntriesAreHeldTwoWeeksAboveTheVaultsOwnRenewal(t *testing.T) {
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
	// The instance, the code and the three tree entries go to 46 days; deposit 2 and exit 1, whose
	// rent is lost when the vault deletes them, to 32.
	if got := h.take(); !equal(got, []string{"extend 5 to " + holdTo, "extend 2 to " + renewTo}) || !has(h.footprints[0].ReadOnly, vault.CodeKey([32]byte{9})) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	// Each is extended again a day later, by a day.
	h.fake.SetLatest(latest + ledgersPerDay)
	if err := h.k.TTLCycle(ctx); err != nil || len(h.take()) != 0 {
		t.Fatalf("extended within the day: %v", err)
	}
	h.fake.SetLatest(latest + ledgersPerDay + 1)
	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"extend 5 to " + holdTo, "extend 2 to " + renewTo}) {
		t.Fatalf("ttl cycle sent %v a day later", got)
	}
	// A keeper stopped for fifteen days leaves them above the 30 days below which the vault's own
	// writes extend them at a user's cost.
	h.fake.SetLatest(h.fake.LatestLedger() + 15*ledgersPerDay)
	for _, key := range append(mustKey(vault.TreeKeys(vaulttest.Vault)), vault.CodeKey([32]byte{9}), mustKey(vault.InstanceKey(vaulttest.Vault))) {
		if left := life(h, key); left <= 30*ledgersPerDay {
			t.Fatalf("an entry has %d ledgers left after fifteen days", left)
		}
	}
	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); len(got) == 0 || got[0] != "extend 5 to "+holdTo || h.has("ttl_behind") {
		t.Fatalf("after fifteen days the cycle sent %v, pages %v", got, h.pages)
	}
}

func TestAnExtensionAboveTheFeeCapIsSplitThenShortenedToAnHour(t *testing.T) {
	ctx := context.Background()
	start := func(capped int64) (*harness, uint32) {
		h := newHarness(t)
		h.sync()
		written := h.chain.Ledger + vault.EntryTTL
		h.vaultLive(written)
		h.codeRent(100, 1)
		h.k.engine.MaxTTLFee = capped
		h.playTTL = true
		return h, written - h.chain.Ledger
	}

	// Each entry is 275,760 ledgers short of 46 days. The cap applies to the fee the simulation
	// asks for, which pads the rent already, and not to the engine's margin on top. The five
	// together, and the instance with the code, are above it; the code alone is halved until
	// 17,235 ledgers cost 1,723,600 stroops, exactly the cap.
	h, written := start(1_723_600)
	if err := h.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"extend 1 to " + holdTo, fmt.Sprintf("extend 1 to %d", written+17_235), "extend 3 to " + holdTo}
	if got := h.take(); !equal(got, want) {
		t.Fatalf("ttl cycle sent %v", got)
	}

	// When even half the last step is short of an hour, an hour is tried, and fits a cap of 1,000
	// ledgers of the code's rent.
	h2, written := start(100_100)
	if err := h2.k.TTLCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h2.take(); !slices.Contains(got, fmt.Sprintf("extend 1 to %d", written+minStep)) {
		t.Fatalf("ttl cycle sent %v", got)
	}

	// Below an hour of the code's rent the code is left and the cycle fails, but every other entry
	// is extended alone.
	h3, written := start(300_000)
	h3.codeRent(1_000, 1)
	err := h3.k.TTLCycle(ctx)
	if err == nil || !strings.Contains(err.Error(), "vault code") || !strings.Contains(err.Error(), "above the cap") {
		t.Fatalf("a code the cap refuses: %v", err)
	}
	if got := h3.take(); !equal(got, []string{"extend 1 to " + holdTo, "extend 1 to " + holdTo, "extend 1 to " + holdTo, "extend 1 to " + holdTo}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	if left := life(h3, vault.CodeKey([32]byte{9})); left != written {
		t.Fatalf("the code has %d ledgers left", left)
	}
}

func TestARestoredEntryIsExtendedFromTheLifeItsRestorationGave(t *testing.T) {
	h := newHarness(t)
	h.sync()
	latest := h.chain.Ledger
	h.vaultLive(latest + holdWithin + renewStep)
	code := vault.CodeKey([32]byte{9})
	archived := latest - 1
	h.fake.SetEntry(code, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.ContractCodeEntry{Hash: xdr.Hash{9}}}, 10, &archived)
	h.codeRent(100, 1)
	h.k.engine.MaxTTLFee = 2_000_000
	// Testnet restores an entry for 7 days.
	h.playTTL, h.restoreTTL = true, 120_960

	if err := h.k.TTLCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// From the 120,959 ledgers the restoration gave it, the halved step of 10,530 ledgers fits.
	if got := h.take(); !equal(got, []string{"restore 1", fmt.Sprintf("extend 1 to %d", 120_959+10_530)}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	if left := life(h, code); left != 120_959+10_530 {
		t.Fatalf("the code has %d ledgers left", left)
	}
}

func TestARestorationThatFailsHoldsBackNoOtherEntry(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.sync()
	latest := h.chain.Ledger
	h.vaultLive(latest + vault.EntryTTL)
	archived := latest - 1
	frontier := mustKey(vault.FrontierKey(vaulttest.Vault))
	h.fake.SetContractData(frontier, vault.U64(0), 10, &archived)
	h.chainFail = func(d string) bool { return strings.HasPrefix(d, "restore") }
	h.playTTL = true
	err := h.k.TTLCycle(ctx)
	if err == nil || !strings.Contains(err.Error(), "restore of 1 entries") {
		t.Fatalf("a restoration failed on chain: %v", err)
	}
	// The instance, the code and the two live tree entries are extended all the same, without the
	// archived frontier, which pages.
	if got := h.take(); !equal(got, []string{"restore 1", "extend 4 to " + holdTo}) || has(h.footprints[1].ReadOnly, frontier) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	if !h.has("entry_expiring") || !h.has("call_failed") {
		t.Fatalf("pages %+v", h.pages)
	}

	// Nor does a queued exit whose restoration fails hold back the vault's entries.
	h2 := newHarness(t)
	h2.chain.Shield(vaulttest.Depositor, 5000)
	h2.chain.Attest(1)
	h2.chain.Admit(1)
	h2.chain.QueueExit(1, -400, 0, vaulttest.Depositor)
	h2.sync()
	latest = h2.chain.Ledger
	h2.vaultLive(latest + vault.EntryTTL)
	archived = latest - 1
	h2.fake.SetContractData(mustKey(vault.ExitKey(vaulttest.Vault, 1)), vaulttest.ExitEntry(vaulttest.Depositor, 400, 0, 1), 10, &archived)
	h2.nullifiersLive(4, latest+3_000_000)
	h2.chainFail = func(d string) bool { return strings.HasPrefix(d, "restore") }
	h2.playTTL = true
	if err := h2.k.TTLCycle(ctx); err == nil {
		t.Fatal("a failed restoration went unreported")
	}
	if got := h2.take(); !equal(got, []string{"extend 5 to " + holdTo, "restore 1"}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
}

func TestAnEntryWithinFourteenDaysThatCannotBeExtendedPages(t *testing.T) {
	for _, days := range []uint32{13, 15} {
		h := newHarness(t)
		h.sync()
		h.vaultLive(h.chain.Ledger + days*ledgersPerDay)
		// The code's rent is above the cap even for an hour.
		h.codeRent(1_000_000, 1)
		h.k.engine.MaxTTLFee = 50_000_000
		h.playTTL = true
		if err := h.k.TTLCycle(context.Background()); err == nil {
			t.Fatalf("%d days: the cycle completed", days)
		}
		if h.has("entry_expiring") != (days < 14) || !h.has("ttl_behind") {
			t.Fatalf("%d days left: pages %+v", days, h.pages)
		}
	}
}

func TestANullifierThatCannotBeReadStillLetsTheCyclePage(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t)
	h.sync()
	h.vaultLive(h.chain.Ledger + 13*ledgersPerDay)
	h.codeRent(1_000_000, 1)
	h.k.engine.MaxTTLFee = 50_000_000
	if _, err := h.k.chain.Pool.Exec(ctx, `ALTER TABLE nullifiers RENAME TO nullifiers_away`); err != nil {
		t.Fatal(err)
	}
	err := h.k.TTLCycle(ctx)
	if err == nil || !strings.Contains(err.Error(), "nullifiers") {
		t.Fatalf("a nullifier read that failed: %v", err)
	}
	if !h.has("entry_expiring") {
		t.Fatalf("pages %+v", h.pages)
	}
}

func TestACycleSendsNoMoreOnceChargedTenTimesTheFeeCap(t *testing.T) {
	h := newHarness(t)
	var ids []uint64
	for range 20 {
		ids = append(ids, h.shield(10, nil, 0))
	}
	h.sync()
	latest := h.chain.Ledger
	near := latest + 100_000
	h.vaultLive(latest + 3_000_000)
	for _, id := range ids {
		h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)), vaulttest.Pending(id, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &near)
	}
	h.nullifiersLive(40, latest+3_000_000)
	// One deposit an extension, each charged an inclusion fee of 100 stroops and a resource fee of
	// 100: fifteen reach ten times a cap of 300.
	h.k.cfg.MaxExtensions = 1
	h.k.engine.MaxTTLFee = 300
	h.playTTL = true
	err := h.k.TTLCycle(context.Background())
	if err == nil || !strings.Contains(err.Error(), "10 times the TTL fee cap") {
		t.Fatalf("a cycle past its ceiling: %v", err)
	}
	if got := h.take(); len(got) != 15 {
		t.Fatalf("%d extensions sent", len(got))
	}
	// The next cycle starts afresh.
	if err := h.k.TTLCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); len(got) != 5 {
		t.Fatalf("%d extensions sent", len(got))
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
	h.playTTL = true

	err := h.k.TTLCycle(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pending deposit 5") {
		t.Fatalf("a refused deposit: %v", err)
	}
	// The instance is restored first, for 120 days, which needs no extension; the eight due
	// deposits are split until deposit 5 stands alone, and it is not tried shorter, as the cap did
	// not refuse it: one simulation for the restoration and seven for the splits.
	want := []string{"restore 1", "extend 4 to " + renewTo, "extend 1 to " + renewTo, "extend 2 to " + renewTo}
	if got := h.take(); !equal(got, want) || h.fake.CallCount("simulateTransaction") != 8 {
		t.Fatalf("ttl cycle sent %v after %d simulations", got, h.fake.CallCount("simulateTransaction"))
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
	if got := h.take(); !equal(got, []string{"extend 50 to " + renewTo, "extend 20 to " + renewTo}) {
		t.Fatalf("ttl cycle sent %v", got)
	}
}

func TestTheVaultsEntriesHoldAtEachNetworksRent(t *testing.T) {
	// The rent of the code and of each other entry, in stroops a ledger as measured on each
	// network, with the 15% the simulation pads it by, over five days of hours of 733 ledgers. A
	// day's step goes in one transaction unless the cap is below its fee.
	for _, c := range []struct {
		name        string
		code, other float64
		capped      int64
		split       bool
	}{
		{"mainnet under the default cap", 453.3, 2.4, 50_000_000, false},
		{"testnet under a 10 XLM cap", 2_427.8, 12.9, 100_000_000, false},
		{"testnet under the default cap", 2_427.8, 12.9, 50_000_000, true},
	} {
		h := newHarness(t)
		h.sync()
		h.vaultLive(h.chain.Ledger + holdWithin + renewStep)
		code := vault.CodeKey([32]byte{9})
		h.rent = func(k xdr.LedgerKey, ledgers uint32) int64 {
			if k.Equals(code) {
				return int64(c.code * 1.15 * float64(ledgers))
			}
			return int64(c.other * 1.15 * float64(ledgers))
		}
		h.k.engine.MaxTTLFee = c.capped
		h.playTTL = true
		least, refused := ^uint32(0), 0
		for range 24 * 5 {
			least = min(least, life(h, code))
			before := h.fake.CallCount("simulateTransaction")
			if err := h.k.TTLCycle(context.Background()); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			refused += h.fake.CallCount("simulateTransaction") - before - len(h.take())
			h.fake.SetLatest(h.fake.LatestLedger() + 733)
		}
		if least < holdWithin-733 || (refused > 0) != c.split || h.has("ttl_behind") {
			t.Fatalf("%s: the code fell to %d ledgers, %d simulations refused, pages %+v", c.name, least, refused, h.pages)
		}
	}
}
