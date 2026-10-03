package vault

import (
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

const testToken = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"

func testConfig(t *testing.T) xdr.ScVal {
	return Struct(
		Field{"token", addr(t, testToken)},
		Field{"domain", fieldScVal(5)},
		Field{"guardian", addr(t, testDepositor)},
		Field{"asp", addr(t, testRelayer)},
		Field{"delay_small", U64(3600)},
		Field{"delay_large", U64(86400)},
	)
}

func testStatus(t *testing.T) xdr.ScVal {
	return Struct(
		Field{"deposits_paused", Bool(false)},
		Field{"transfers_paused", Bool(true)},
		Field{"halted_until", U64(10)},
		Field{"next_halt_at", U64(20)},
		Field{"next_deposit_id", U64(4)},
		Field{"attested_up_to", U64(2)},
		Field{"tvl", i128(t, 300)},
		Field{"pending_total", i128(t, 100)},
		Field{"queued_total", i128(t, 50)},
		Field{"exit_head", U64(3)},
		Field{"exit_tail", U64(5)},
		Field{"outflow_day", U64(19000)},
		Field{"outflow", i128(t, 7)},
	)
}

func instance(t *testing.T, entries map[string]xdr.ScVal) xdr.ScVal {
	var storage xdr.ScMap
	for _, name := range []string{"Config", "Limits", "QueuedLimits", "Status"} {
		if v, ok := entries[name]; ok {
			storage = append(storage, xdr.ScMapEntry{Key: enumKey(name), Val: v})
		}
	}
	hash := xdr.Hash{1, 2, 3}
	inst := xdr.ScContractInstance{
		Executable: xdr.ContractExecutable{Type: xdr.ContractExecutableTypeContractExecutableWasm, WasmHash: &hash},
		Storage:    &storage,
	}
	return xdr.ScVal{Type: xdr.ScValTypeScvContractInstance, Instance: &inst}
}

func TestTheInstanceStorageDecodes(t *testing.T) {
	v := instance(t, map[string]xdr.ScVal{
		"Config":       testConfig(t),
		"Limits":       testLimits(t),
		"QueuedLimits": Struct(Field{"limits", testLimits(t)}, Field{"ready_at", U64(77)}),
		"Status":       testStatus(t),
	})
	inst, err := DecodeInstance(v)
	if err != nil {
		t.Fatal(err)
	}
	if inst.Config.Token != testToken || inst.Config.DelayLarge != 86400 || inst.Config.Domain != fr.SetUint64(5) {
		t.Fatalf("config %+v", inst.Config)
	}
	if inst.Status.NextDepositID != 4 || !inst.Status.TransfersPaused || inst.Status.PendingTotal.Int64() != 100 || inst.Status.QueuedTotal.Int64() != 50 || inst.Status.ExitTail != 5 {
		t.Fatalf("status %+v", inst.Status)
	}
	if inst.QueuedLimits == nil || inst.QueuedLimits.ReadyAt != 77 {
		t.Fatalf("queued limits %+v", inst.QueuedLimits)
	}
	if inst.WasmHash[2] != 3 || !inst.Status.Halted(9) || inst.Status.Halted(10) {
		t.Fatal("wasm hash or halt window")
	}

	without := instance(t, map[string]xdr.ScVal{"Config": testConfig(t), "Limits": testLimits(t), "Status": testStatus(t)})
	if inst, err := DecodeInstance(without); err != nil || inst.QueuedLimits != nil {
		t.Fatalf("instance without a queued loosening: %v", err)
	}
	missing := instance(t, map[string]xdr.ScVal{"Config": testConfig(t), "Limits": testLimits(t)})
	if _, err := DecodeInstance(missing); !errors.Is(err, ErrMalformed) {
		t.Fatalf("instance without status: %v", err)
	}
}

func TestAPendingDepositDecodesAndKnowsWhenItIsEligible(t *testing.T) {
	v := Struct(
		Field{"depositor", addr(t, testDepositor)},
		Field{"amount", i128(t, 6_000_000_000)},
		Field{"commitment0", fieldScVal(1)},
		Field{"commitment1", fieldScVal(2)},
		Field{"encrypted_output0", Bytes(make([]byte, CiphertextLen))},
		Field{"encrypted_output1", Bytes(make([]byte, CiphertextLen))},
		Field{"created_at", U64(1000)},
		Field{"delay", U64(3600)},
		Field{"flag", U32(4)},
		Field{"flagged_at", U64(2000)},
	)
	d, err := DecodePendingDeposit(v)
	if err != nil {
		t.Fatal(err)
	}
	if d.Flag == nil || *d.Flag != 4 || d.FlaggedAt != 2000 {
		t.Fatalf("flag %+v", d)
	}
	cfg, err := DecodeConfig(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	limits, err := DecodeLimits(testLimits(t))
	if err != nil {
		t.Fatal(err)
	}
	// The current threshold makes it large, which outweighs the shorter delay of its snapshot.
	if got := d.EligibleAt(cfg, limits); got != 1000+86400 {
		t.Fatalf("eligible at %d", got)
	}
	unflagged := Struct(
		Field{"depositor", addr(t, testDepositor)},
		Field{"amount", i128(t, 10)},
		Field{"commitment0", fieldScVal(1)},
		Field{"commitment1", fieldScVal(2)},
		Field{"encrypted_output0", Bytes(make([]byte, CiphertextLen))},
		Field{"encrypted_output1", Bytes(make([]byte, CiphertextLen))},
		Field{"created_at", U64(1000)},
		Field{"delay", U64(86400)},
		Field{"flag", xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
		Field{"flagged_at", U64(0)},
	)
	d, err = DecodePendingDeposit(unflagged)
	if err != nil || d.Flag != nil {
		t.Fatalf("unflagged deposit: %v", err)
	}
	// A loosening after the shield does not shorten the delay the deposit was made under.
	if got := d.EligibleAt(cfg, limits); got != 1000+86400 {
		t.Fatalf("eligible at %d", got)
	}
}

func TestAnExitDecodes(t *testing.T) {
	e, err := DecodeExit(Struct(
		Field{"recipient", addr(t, testDepositor)}, Field{"payout", i128(t, 700)}, Field{"relayer", addr(t, testRelayer)},
		Field{"fee", i128(t, 10)}, Field{"queued_at", U64(99)},
	))
	if err != nil || e.Payout.Int64() != 700 || e.QueuedAt != 99 || e.Recipient != testDepositor {
		t.Fatalf("exit %+v %v", e, err)
	}
	for name, build := range map[string]func(string, uint64) (xdr.LedgerKey, error){"Exit": ExitKey, "Stranded": StrandedKey} {
		k, err := build("CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5", 4)
		if err != nil {
			t.Fatal(err)
		}
		cd := k.MustContractData()
		v := *cd.Key.MustVec()
		if cd.Durability != xdr.ContractDataDurabilityPersistent || len(v) != 2 || string(v[0].MustSym()) != name || uint64(v[1].MustU64()) != 4 {
			t.Fatalf("%s key %+v", name, cd)
		}
	}
}

func TestTheRootRingDecodes(t *testing.T) {
	roots := make([]xdr.ScVal, RootHistory)
	for i := range roots {
		roots[i] = fieldScVal(uint64(i))
	}
	ring, err := DecodeRootRing(Struct(Field{"roots", Vec(roots...)}, Field{"newest", U32(9)}))
	if err != nil {
		t.Fatal(err)
	}
	if ring.Current() != fr.SetUint64(9) {
		t.Fatal("current root")
	}
	if _, err := DecodeRootRing(Struct(Field{"roots", Vec(roots[:3]...)}, Field{"newest", U32(0)})); !errors.Is(err, ErrMalformed) {
		t.Fatalf("short ring: %v", err)
	}
	if _, err := DecodeRootRing(Struct(Field{"roots", Vec(roots...)}, Field{"newest", U32(RootHistory)})); !errors.Is(err, ErrMalformed) {
		t.Fatalf("newest out of range: %v", err)
	}
}

func TestStorageKeysUseTheContractTypeEnum(t *testing.T) {
	vault := "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"
	k, err := PendingKey(vault, 7)
	if err != nil {
		t.Fatal(err)
	}
	items, err := vecOf(k.ContractData.Key)
	if err != nil || len(items) != 2 {
		t.Fatal("pending key is not a two-item vec")
	}
	if name, _ := symbolOf(items[0]); name != "Pending" {
		t.Fatalf("variant %q", name)
	}
	if n, _ := u64Of(items[1]); n != 7 {
		t.Fatal("pending id")
	}
	if k.ContractData.Durability != xdr.ContractDataDurabilityPersistent {
		t.Fatal("pending deposits are persistent")
	}
	keys, err := TreeKeys(vault)
	if err != nil || len(keys) != 3 {
		t.Fatalf("tree keys: %v", err)
	}
	if _, err := InstanceKey("GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH"); err == nil {
		t.Fatal("an account has no instance")
	}
	if _, err := BalanceKey(testToken, vault); err != nil {
		t.Fatal(err)
	}
}
