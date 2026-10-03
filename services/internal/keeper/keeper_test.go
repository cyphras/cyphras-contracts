package keeper

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/testdb"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const passphrase = "Test SDF Network ; September 2015"

type harness struct {
	t       *testing.T
	fake    *rpctest.Fake
	chain   *vaulttest.Chain
	k       *Keeper
	f       *follow.Follower
	now     time.Time
	mu      sync.Mutex
	sent    []string
	pages   []alert.Alert
	simFail func(string) bool
	status  vault.Status
}

func (h *harness) Send(_ context.Context, a alert.Alert) error {
	h.pages = append(h.pages, a)
	return nil
}

func describe(env xdr.TransactionEnvelope) string {
	op := env.V1.Tx.Operations[0].Body
	switch op.Type {
	case xdr.OperationTypeInvokeHostFunction:
		inv := op.InvokeHostFunctionOp.HostFunction.InvokeContract
		parts := []string{string(inv.FunctionName)}
		for _, a := range inv.Args {
			switch a.Type {
			case xdr.ScValTypeScvU64:
				parts = append(parts, fmt.Sprint(uint64(*a.U64)))
			case xdr.ScValTypeScvVec:
				var ids []string
				for _, v := range **a.Vec {
					ids = append(ids, fmt.Sprint(uint64(*v.U64)))
				}
				parts = append(parts, "["+strings.Join(ids, ",")+"]")
			}
		}
		return strings.Join(parts, " ")
	case xdr.OperationTypeExtendFootprintTtl:
		return fmt.Sprintf("extend %d to %d", len(env.V1.Tx.Ext.SorobanData.Resources.Footprint.ReadOnly), op.ExtendFootprintTtlOp.ExtendTo)
	case xdr.OperationTypeRestoreFootprint:
		return fmt.Sprintf("restore %d", len(env.V1.Tx.Ext.SorobanData.Resources.Footprint.ReadWrite))
	}
	return "?"
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, fake: rpctest.New(passphrase, 9), chain: vaulttest.New(10, 1_728_000_000), now: time.Unix(1_728_000_000, 0)}
	pool, err := chainstate.Open(context.Background(), testdb.URL(t), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	kp := keypair.MustRandom()
	key, _ := vault.AccountKey(kp.Address())
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, SeqNum: 1, Balance: 500_000_000}}, 1, nil)
	h.fake.SetEntry(vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingStateArchival), xdr.LedgerEntryData{
		Type: xdr.LedgerEntryTypeConfigSetting,
		ConfigSetting: &xdr.ConfigSettingEntry{
			ConfigSettingId: xdr.ConfigSettingIdConfigSettingStateArchival, StateArchivalSettings: &xdr.StateArchivalSettings{MaxEntryTtl: 3_110_400},
		},
	}, 1, nil)
	h.fake.Simulate = func(req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		var env xdr.TransactionEnvelope
		_ = xdr.SafeUnmarshalBase64(req.Transaction, &env)
		if h.simFail != nil && h.simFail(describe(env)) {
			return protocol.SimulateTransactionResponse{Error: "resource limit exceeded"}, nil
		}
		data := xdr.SorobanTransactionData{}
		if env.V1.Tx.Ext.SorobanData != nil {
			data = *env.V1.Tx.Ext.SorobanData
		}
		encoded, _ := xdr.MarshalBase64(data)
		return protocol.SimulateTransactionResponse{TransactionDataXDR: encoded, MinResourceFee: 100, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	h.fake.Send = func(req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		var env xdr.TransactionEnvelope
		_ = xdr.SafeUnmarshalBase64(req.Transaction, &env)
		h.mu.Lock()
		h.sent = append(h.sent, describe(env))
		h.mu.Unlock()
		return protocol.SendTransactionResponse{Status: "PENDING"}, nil
	}
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		r, _ := xdr.MarshalBase64(xdr.TransactionResult{Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}})
		return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusSuccess, ResultXDR: r}}, nil
	}
	engine := &submit.Engine{RPC: h.fake, Passphrase: passphrase, Validity: time.Minute, Poll: time.Millisecond, Now: func() time.Time { return h.now }}
	alerts := &alert.Alerter{Service: "keeper", Channels: []alert.Channel{h}, Cooldown: time.Hour, Now: func() time.Time { return h.now }}
	k, err := New(context.Background(), Config{
		Vault: vaulttest.Vault, DeployLedger: 10, MaxAdmissions: 17, MaxExtensions: 50, RefundDelay: 24 * time.Hour,
		HoldReasons: map[uint32]bool{99: true}, BalanceFloor: 1_000_000_000,
	}, h.fake, &chainstate.Store{Pool: pool}, engine, submit.NewAccount(kp.Address(), kp), alerts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	k.now = func() time.Time { return h.now }
	h.k = k
	h.f = &follow.Follower{RPC: h.fake, Live: follow.RPCSource{Client: h.fake, Vault: vaulttest.Vault}, Window: 100, Sink: k}
	return h
}

func mustKey[T any](k T, err error) T {
	if err != nil {
		panic(err)
	}
	return k
}

// sync publishes the chain, the vault instance and the clock, and lets the keeper ingest.
func (h *harness) sync() {
	h.t.Helper()
	h.fake.Events = nil
	for _, e := range h.chain.Events {
		h.fake.AddEvent(rpctest.EventInfo(e))
	}
	h.fake.SetLatest(h.chain.Ledger)
	h.fake.CloseTime = h.now.Unix()
	h.status.NextDepositID = h.chain.NextID
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: 1_000_000_000_000, Large: 5_000_000_000, Status: h.status, WasmHash: [32]byte{9},
	}), 10, h.live(4_000_000))
	for range 50 {
		progressed, err := h.f.Step(context.Background())
		if err != nil {
			h.t.Fatal(err)
		}
		if !progressed {
			return
		}
	}
}

func (h *harness) live(ledgers uint32) *uint32 {
	v := h.chain.Ledger + ledgers
	return &v
}

func (h *harness) shield(amount int64, flag *uint32, flaggedAt uint64) uint64 {
	id := h.chain.Shield(vaulttest.Depositor, amount)
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, id)),
		vaulttest.Pending(id, vaulttest.Depositor, amount, uint64(h.chain.ClosedAt), 3600, flag, flaggedAt), h.chain.Ledger, h.live(600_000))
	return id
}

func (h *harness) take() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := h.sent
	h.sent = nil
	return out
}

func equal(a, b []string) bool {
	return strings.Join(a, "|") == strings.Join(b, "|")
}

func TestEligibleDepositsAreAdmittedInBatchesThatFit(t *testing.T) {
	h := newHarness(t)
	five := uint32(5)
	for i := range 21 {
		if i == 2 {
			h.shield(10, &five, uint64(h.now.Unix()))
			continue
		}
		h.shield(10, nil, 0)
	}
	h.status.AttestedUpTo = 20
	h.sync()
	if err := h.k.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); len(got) != 0 {
		t.Fatalf("admitted before the delay: %v", got)
	}
	h.now = h.now.Add(time.Hour)
	h.sync()
	if err := h.k.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"admit [1,2,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]", "admit [19,20]"}
	if got := h.take(); !equal(got, want) {
		t.Fatalf("admissions %v", got)
	}

	// A batch that does not fit the transaction is halved.
	h2 := newHarness(t)
	for range 10 {
		h2.shield(10, nil, 0)
	}
	h2.status.AttestedUpTo = 10
	h2.now = h2.now.Add(2 * time.Hour)
	h2.sync()
	h2.simFail = func(d string) bool { return strings.HasPrefix(d, "admit [1,2,3,4,5,6,7,8,9,10]") }
	if err := h2.k.Admit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h2.take(); !equal(got, []string{"admit [1,2,3,4,5]", "admit [6,7,8,9,10]"}) {
		t.Fatalf("halved batches %v", got)
	}

	// Nothing is admitted while halted.
	h3 := newHarness(t)
	h3.shield(10, nil, 0)
	h3.status.AttestedUpTo, h3.status.HaltedUntil = 1, uint64(h3.now.Add(48*time.Hour).Unix())
	h3.now = h3.now.Add(2 * time.Hour)
	h3.sync()
	if err := h3.k.Admit(context.Background()); err != nil || len(h3.take()) != 0 {
		t.Fatal("admitted while halted")
	}
}

func TestADepositLeftUnadmittedPages(t *testing.T) {
	h := newHarness(t)
	h.shield(10, nil, 0)
	h.status.AttestedUpTo = 1
	h.now = h.now.Add(time.Hour + 11*time.Minute)
	h.sync()
	h.simFail = func(string) bool { return true }
	_ = h.k.Admit(context.Background())
	if len(h.pages) == 0 || h.pages[0].Code != "admission_late" {
		t.Fatalf("pages %+v", h.pages)
	}
}

func TestFlaggedDepositsAreRefundedAfterTheCorrectionWindowUnlessHeld(t *testing.T) {
	h := newHarness(t)
	four, ninetyNine := uint32(4), uint32(99)
	flaggedAt := uint64(h.now.Unix())
	h.shield(10, &four, flaggedAt)
	h.shield(10, &ninetyNine, flaggedAt)
	h.shield(10, nil, 0)
	h.sync()
	h.now = h.now.Add(23 * time.Hour)
	h.sync()
	if err := h.k.Refund(context.Background()); err != nil || len(h.take()) != 0 {
		t.Fatalf("refunded inside the correction window: %v", err)
	}
	h.now = h.now.Add(time.Hour)
	h.sync()
	if err := h.k.Refund(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"refund 1"}) {
		t.Fatalf("refunds %v", got)
	}
}

func TestTheTTLCycleExtendsEveryEntryNearExpiry(t *testing.T) {
	h := newHarness(t)
	h.shield(10, nil, 0)
	h.shield(10, nil, 0)
	h.sync()
	latest := h.chain.Ledger
	far, near := latest+3_000_000, latest+100_000
	for _, key := range mustKey(vault.TreeKeys(vaulttest.Vault)) {
		h.fake.SetContractData(key, vault.U64(0), 10, &far)
	}
	// Deposit 1 is close to expiry, deposit 2 is not.
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, 1)), vaulttest.Pending(1, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &near)
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, 2)), vaulttest.Pending(2, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &far)
	// The code is due, the asset contract is not, and the vault's balance entry is archived.
	h.fake.SetEntry(vault.CodeKey([32]byte{9}), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.ContractCodeEntry{Hash: xdr.Hash{9}}}, 10, &near)
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Token)), vault.U64(0), 10, &far)
	// Of the four nullifiers, one is fresh, two are due and one is archived.
	var nfKeys []xdr.LedgerKey
	for i := range 4 {
		k := mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_000+uint64(i)+1).Bytes()))
		nfKeys = append(nfKeys, k)
	}
	h.fake.SetContractData(nfKeys[0], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &far)
	h.fake.SetContractData(nfKeys[1], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &near)
	h.fake.SetContractData(nfKeys[2], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &near)

	if err := h.k.TTLCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{"bump_ttl [1]", "restore 1", "extend 2 to 3110399", "restore 1", "extend 3 to 3110399"}
	if got := h.take(); !equal(got, want) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	var tracked int
	_ = h.k.chain.Pool.QueryRow(context.Background(), `SELECT count(*) FROM nullifiers WHERE live_until IS NOT NULL`).Scan(&tracked)
	if tracked != 4 {
		t.Fatalf("%d nullifiers tracked", tracked)
	}
	// The next cycle reads only the nullifiers that may be due.
	before := h.fake.CallCount("getLedgerEntries")
	if err := h.k.TTLCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.fake.CallCount("getLedgerEntries")-before > 6 {
		t.Fatal("fresh nullifiers were read again")
	}
}

func TestAStaleCycleAndALowBalancePage(t *testing.T) {
	h := newHarness(t)
	h.k.Watch(context.Background())
	h.now = h.now.Add(3 * time.Hour)
	h.k.Watch(context.Background())
	if len(h.pages) != 1 || h.pages[0].Code != "ttl_cycle_stale" {
		t.Fatalf("pages %+v", h.pages)
	}
	if err := h.k.CheckBalance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.pages[len(h.pages)-1].Code != "balance_low" {
		t.Fatalf("pages %+v", h.pages)
	}
}
