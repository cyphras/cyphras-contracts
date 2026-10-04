package keeper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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
	// sentHook sees each sent transaction, so a test can play its effect on the chain.
	sentHook func(string)
	// chainFail makes the sent transactions it matches fail on chain, and conflict fail on the
	// host's storage, as a call does that the exit queue moved under.
	chainFail func(string) bool
	conflict  func(string) bool
	// footprints holds the footprint of each sent transaction.
	footprints []xdr.LedgerFootprint
	last       string
	status     vault.Status
	limit      int64
	// outflows holds the outflow of each queued exit by ID.
	outflows map[uint64]int64
	// partial makes the simulated vault pay the head exit in part when it does not fit whole.
	partial bool
	// creates marks exits whose recipient account does not exist yet, which the vault does not pay
	// in a part below 1 XLM.
	creates map[uint64]bool
	// skipped are deposits a simulated admit no longer finds.
	skipped map[uint64]bool
	// funds is the vault's balance, unlimited when nil; deauthorized makes the issuer refuse to
	// let the vault hold the asset.
	funds        *big.Int
	deauthorized bool
	// flaggedAt is when each flagged deposit was flagged, which the simulated vault refunds only a
	// day after.
	flaggedAt map[uint64]uint64
	// rent, when set, prices each ledger an extension adds to an entry's life in the simulated
	// resource fee; refuse makes the simulation refuse a footprint; playTTL makes sent extensions
	// and restorations change the entries, a restoration giving an entry restoreTTL ledgers, or
	// mainnet's least life of a persistent entry when that is zero.
	rent       func(key xdr.LedgerKey, ledgers uint32) int64
	refuse     func(xdr.LedgerFootprint) bool
	playTTL    bool
	restoreTTL uint32
	// lastFee is the fee the last sent transaction offered, which its result reports charged.
	lastFee int64
}

// released is what the simulated vault's release(max) returns: how many exits it handles from the
// head while the window has room.
func (h *harness) released(max uint64) uint64 {
	day := uint64(h.now.Unix()) / secondsPerDay
	used := int64(0)
	if h.status.OutflowDay == day && h.status.Outflow != nil {
		used = h.status.Outflow.Int64()
	}
	room := h.limit - used
	n := uint64(0)
	for id := h.status.ExitHead; id < h.status.ExitTail && n < max && room > 0; id++ {
		o := h.outflows[id]
		if o > room {
			if h.creates[id] && room < vault.MinNewAccountPayout && o >= vault.MinNewAccountPayout {
				break
			}
			if h.partial {
				n++
			}
			break
		}
		room -= o
		n++
	}
	return n
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
			case xdr.ScValTypeScvU32:
				parts = append(parts, fmt.Sprint(uint32(*a.U32)))
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
	h := &harness{t: t, fake: rpctest.New(passphrase, 9), chain: vaulttest.New(10, 1_728_000_000), now: time.Unix(1_728_000_000, 0), limit: 1_000_000_000_000}
	pool, err := chainstate.Open(context.Background(), testdb.URL(t), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	kp := keypair.MustRandom()
	key, _ := vault.AccountKey(kp.Address())
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, SeqNum: 1, Balance: 500_000_000}}, 1, nil)
	h.fake.SetSettings(rpctest.Mainnet)
	h.fake.Simulate = func(req protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		var env xdr.TransactionEnvelope
		_ = xdr.SafeUnmarshalBase64(req.Transaction, &env)
		if h.simFail != nil && h.simFail(describe(env)) {
			return protocol.SimulateTransactionResponse{Error: "resource limit exceeded"}, nil
		}
		if data := env.V1.Tx.Ext.SorobanData; h.refuse != nil && data != nil && h.refuse(data.Resources.Footprint) {
			return protocol.SimulateTransactionResponse{Error: "entry is archived"}, nil
		}
		latest := h.fake.LatestLedger()
		// As the RPC does, an extension that names an archived entry is refused.
		if op := env.V1.Tx.Operations[0].Body.ExtendFootprintTtlOp; op != nil {
			for _, key := range env.V1.Tx.Ext.SorobanData.Resources.Footprint.ReadOnly {
				if until, ok := h.fake.LiveUntil(key); ok && until < latest {
					return protocol.SimulateTransactionResponse{Error: "an archived entry must be restored before it is extended"}, nil
				}
			}
		}
		var refunded uint64
		if _, err := fmt.Sscanf(describe(env), "refund %d", &refunded); err == nil {
			if at, ok := h.flaggedAt[refunded]; ok && uint64(h.now.Unix()) < at+86_400 {
				return protocol.SimulateTransactionResponse{Error: "HostError: Error(Contract, #138)"}, nil
			}
		}
		data := xdr.SorobanTransactionData{}
		if env.V1.Tx.Ext.SorobanData != nil {
			data = *env.V1.Tx.Ext.SorobanData
		}
		encoded, _ := xdr.MarshalBase64(data)
		fee := int64(100)
		if op := env.V1.Tx.Operations[0].Body.ExtendFootprintTtlOp; op != nil && h.rent != nil {
			target := latest + uint32(op.ExtendTo)
			for _, key := range data.Resources.Footprint.ReadOnly {
				if until, ok := h.fake.LiveUntil(key); ok && until < target {
					fee += h.rent(key, target-until)
				}
			}
		}
		result := protocol.SimulateHostFunctionResult{}
		var max uint64
		if _, err := fmt.Sscanf(describe(env), "release %d", &max); err == nil {
			ret, _ := xdr.MarshalBase64(vault.U32(uint32(h.released(max))))
			result.ReturnValueXDR = &ret
		}
		if inv := env.V1.Tx.Operations[0].Body.InvokeHostFunctionOp; inv != nil && inv.HostFunction.InvokeContract.FunctionName == "admit" {
			var admitted []xdr.ScVal
			for _, v := range **inv.HostFunction.InvokeContract.Args[0].Vec {
				if !h.skipped[uint64(*v.U64)] {
					admitted = append(admitted, v)
				}
			}
			ret, _ := xdr.MarshalBase64(vault.Vec(admitted...))
			result.ReturnValueXDR = &ret
		}
		return protocol.SimulateTransactionResponse{TransactionDataXDR: encoded, MinResourceFee: fee, Results: []protocol.SimulateHostFunctionResult{result}}, nil
	}
	h.fake.Send = func(req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		var env xdr.TransactionEnvelope
		_ = xdr.SafeUnmarshalBase64(req.Transaction, &env)
		h.mu.Lock()
		h.sent = append(h.sent, describe(env))
		h.last = describe(env)
		h.lastFee = int64(env.V1.Tx.Fee)
		if data := env.V1.Tx.Ext.SorobanData; data != nil {
			h.footprints = append(h.footprints, data.Resources.Footprint)
		}
		hook, play := h.sentHook, h.playTTL
		h.mu.Unlock()
		if play {
			h.playFootprint(env)
		}
		if hook != nil {
			hook(describe(env))
		}
		return protocol.SendTransactionResponse{Status: "PENDING"}, nil
	}
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		h.mu.Lock()
		failed := h.chainFail != nil && h.chainFail(h.last)
		conflict := h.conflict != nil && h.conflict(h.last)
		fee := xdr.Int64(h.lastFee)
		h.mu.Unlock()
		if conflict {
			return conflictOnChain(), nil
		}
		if failed {
			r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: fee, Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxFailed, Results: &[]xdr.OperationResult{}}})
			return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusFailed, ResultXDR: r}}, nil
		}
		r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: fee, Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}})
		return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusSuccess, ResultXDR: r}}, nil
	}
	engine := &submit.Engine{RPC: h.fake, Passphrase: passphrase, ResourceMarginPct: 15, Validity: time.Minute, Poll: time.Millisecond, Now: func() time.Time { return h.now }}
	alerts := &alert.Alerter{Service: "keeper", Channels: []alert.Channel{h}, Cooldown: time.Hour, Now: func() time.Time { return h.now }}
	k, err := New(context.Background(), Config{
		Vault: vaulttest.Vault, DeployLedger: 10, Asset: "native", MaxAdmissions: 16, MaxExtensions: 50, MaxReleases: 10, RefundDelay: 24 * time.Hour,
		HoldReasons: map[uint32]bool{100: true}, BalanceFloor: 1_000_000_000,
	}, h.fake, &chainstate.Store{Pool: pool}, engine, submit.NewAccount(kp.Address(), kp), alerts, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	k.now = func() time.Time { return h.now }
	h.k = k
	h.f = &follow.Follower{RPC: h.fake, Live: follow.RPCSource{Client: h.fake, Contract: vaulttest.Vault}, Window: 100, Sink: k}
	return h
}

// playFootprint plays a sent extension or restoration on the chain as the network does: an
// extension makes every live entry it names live until its target at least, and a restoration
// gives every archived entry it names the least life of a persistent entry.
func (h *harness) playFootprint(env xdr.TransactionEnvelope) {
	data := env.V1.Tx.Ext.SorobanData
	if data == nil {
		return
	}
	latest := h.fake.LatestLedger()
	restored := h.restoreTTL
	if restored == 0 {
		restored = rpctest.Mainnet.MinPersistentTTL
	}
	op := env.V1.Tx.Operations[0].Body
	switch op.Type {
	case xdr.OperationTypeExtendFootprintTtl:
		target := latest + uint32(op.ExtendFootprintTtlOp.ExtendTo)
		for _, key := range data.Resources.Footprint.ReadOnly {
			if until, ok := h.fake.LiveUntil(key); ok && until >= latest && until < target {
				h.fake.SetLiveUntil(key, target)
			}
		}
	case xdr.OperationTypeRestoreFootprint:
		for _, key := range data.Resources.Footprint.ReadWrite {
			if until, ok := h.fake.LiveUntil(key); ok && until < latest {
				h.fake.SetLiveUntil(key, latest+restored-1)
			}
		}
	}
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
	h.setInstance()
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

func (h *harness) setInstance() {
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Vault)), vaulttest.Instance(vaulttest.InstanceOptions{
		DelaySmall: 3600, DelayLarge: 86400, Limit: h.limit, Large: 5_000_000_000, Status: h.status, WasmHash: [32]byte{9},
	}), 10, h.live(4_000_000))
	funds := h.funds
	if funds == nil {
		funds = big.NewInt(1_000_000_000_000_000)
	}
	h.fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vaulttest.Balance(funds, !h.deauthorized), 10, h.live(4_000_000))
}

func (h *harness) live(ledgers uint32) *uint32 {
	v := h.chain.Ledger + ledgers
	return &v
}

func (h *harness) shield(amount int64, flag *uint32, flaggedAt uint64) uint64 {
	id := h.chain.Shield(vaulttest.Depositor, amount)
	if flag != nil {
		if h.flaggedAt == nil {
			h.flaggedAt = map[uint64]uint64{}
		}
		h.flaggedAt[id] = flaggedAt
	}
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
	want := []string{"admit [1,2,4,5,6,7,8,9,10,11,12,13,14,15,16,17]", "admit [18,19,20]"}
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
	four, courtOrder := uint32(4), uint32(100)
	flaggedAt := uint64(h.now.Unix())
	h.shield(10, &four, flaggedAt)
	h.shield(10, &courtOrder, flaggedAt)
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

func TestAScreeningHoldIsRefundedADayAfterItAndNotBefore(t *testing.T) {
	h := newHarness(t)
	hold := uint32(6)
	heldAt := uint64(h.now.Unix())
	h.shield(10, &hold, heldAt)
	h.sync()
	h.now = h.now.Add(24*time.Hour - time.Second)
	h.sync()
	// The vault would refuse the refund, so the keeper does not even simulate it.
	simulated := h.fake.CallCount("simulateTransaction")
	if err := h.k.Refund(context.Background()); err != nil || len(h.take()) != 0 || h.fake.CallCount("simulateTransaction") != simulated {
		t.Fatalf("refunded, or tried to, before a day passed: %v", err)
	}
	h.now = h.now.Add(time.Second)
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
	far, near, archived := latest+3_000_000, latest+100_000, latest-1
	for _, key := range mustKey(vault.TreeKeys(vaulttest.Vault)) {
		h.fake.SetContractData(key, vault.U64(0), 10, &far)
	}
	// Deposit 1 is close to expiry, deposit 2 is not.
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, 1)), vaulttest.Pending(1, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &near)
	h.fake.SetContractData(mustKey(vault.PendingKey(vaulttest.Vault, 2)), vaulttest.Pending(2, vaulttest.Depositor, 10, 0, 3600, nil, 0), 10, &far)
	// The code and the asset contract are due, and the vault's balance entry is archived.
	h.fake.SetEntry(vault.CodeKey([32]byte{9}), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeContractCode, ContractCode: &xdr.ContractCodeEntry{Hash: xdr.Hash{9}}}, 10, &near)
	h.fake.SetContractData(mustKey(vault.InstanceKey(vaulttest.Token)), vault.U64(0), 10, &near)
	h.fake.SetContractData(mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), vault.U64(0), 10, &archived)
	// Of the four nullifiers, one is fresh, two are due and one is archived.
	var nfKeys []xdr.LedgerKey
	for i := range 4 {
		k := mustKey(vault.NullifierKey(vaulttest.Vault, fr.SetUint64(1_000_000+uint64(i)+1).Bytes()))
		nfKeys = append(nfKeys, k)
	}
	h.fake.SetContractData(nfKeys[0], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &far)
	h.fake.SetContractData(nfKeys[1], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &near)
	h.fake.SetContractData(nfKeys[2], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &near)
	h.fake.SetContractData(nfKeys[3], xdr.ScVal{Type: xdr.ScValTypeScvVoid}, 10, &archived)
	h.playTTL = true

	if err := h.k.TTLCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The code goes to 46 days and deposit 1 to 32. The archived balance entry and nullifier are
	// restored, for the 120 days that need no extension, and the asset contract and the other two
	// due nullifiers go to the maximum.
	want := []string{"extend 1 to 794880", "extend 1 to 552960", "restore 1", "extend 1 to 3110399", "restore 1", "extend 2 to 3110399"}
	if got := h.take(); !equal(got, want) {
		t.Fatalf("ttl cycle sent %v", got)
	}
	tracked := func() int {
		var n int
		_ = h.k.chain.Pool.QueryRow(context.Background(), `SELECT count(*) FROM nullifiers WHERE live_until IS NOT NULL`).Scan(&n)
		return n
	}
	if n := tracked(); n != 4 {
		t.Fatalf("%d nullifiers tracked", n)
	}
	// No recorded life is beyond the entry's own, so none is read again later than it is due.
	rows, err := h.k.chain.Pool.Query(context.Background(), `SELECT nullifier, live_until FROM nullifiers`)
	if err != nil {
		t.Fatal(err)
	}
	// A failure inside the loop must release the connection, or the pool's cleanup waits for it.
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var until int64
		if err := rows.Scan(&raw, &until); err != nil {
			t.Fatal(err)
		}
		e, _ := fr.SetBytes([32]byte(raw))
		if actual, _ := h.fake.LiveUntil(mustKey(vault.NullifierKey(vaulttest.Vault, e.Bytes()))); until > int64(actual) {
			t.Fatalf("a nullifier recorded live until %d lives until %d", until, actual)
		}
	}
	rows.Close()
	// The next cycle reads only the vault's own entries and the asset contract's, and sends nothing.
	before := h.fake.CallCount("getLedgerEntries")
	if err := h.k.TTLCycle(context.Background()); err != nil || len(h.take()) != 0 {
		t.Fatalf("the next cycle extended again: %v", err)
	}
	if n := h.fake.CallCount("getLedgerEntries") - before; n != 4 {
		t.Fatalf("%d reads: fresh nullifiers were read again", n)
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

// queueExits stores exit entries the way transact leaves them and moves the queue's tail.
func (h *harness) queueExits(outflows ...int64) {
	if h.outflows == nil {
		h.outflows = map[uint64]int64{}
	}
	for _, o := range outflows {
		id := h.status.ExitTail
		h.fake.SetContractData(mustKey(vault.ExitKey(vaulttest.Vault, id)), vaulttest.ExitEntry(vaulttest.Depositor, o, 0, 1), h.chain.Ledger, h.live(500_000))
		h.outflows[id] = o
		h.status.ExitTail++
	}
}

// release plays a release of n exits on the harness's vault status.
func (h *harness) release(n uint64) {
	day := uint64(h.now.Unix()) / secondsPerDay
	if h.status.OutflowDay != day {
		h.status.OutflowDay, h.status.Outflow = day, new(big.Int)
	}
	for range n {
		paid := big.NewInt(h.outflows[h.status.ExitHead])
		h.status.Outflow = new(big.Int).Add(h.status.Outflow, paid)
		if h.funds != nil {
			h.funds = new(big.Int).Sub(h.funds, paid)
		}
		h.status.ExitHead++
	}
	h.setInstance()
}

func TestReleasePaysWhatFitsTheWindowAndWaitsForMidnight(t *testing.T) {
	h := newHarness(t)
	h.limit = 1000
	h.status.ExitHead, h.status.ExitTail = 1, 1
	h.queueExits(300, 250, 500)
	h.status.OutflowDay, h.status.Outflow = uint64(h.now.Unix())/secondsPerDay, big.NewInt(600)
	h.sentHook = func(d string) {
		var n uint64
		if _, err := fmt.Sscanf(d, "release %d", &n); err == nil {
			h.release(n)
		}
	}
	h.sync()
	if err := h.k.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	// 300 fits the 400 left today; 250 does not fit the 100 left after it.
	if got := h.take(); !equal(got, []string{"release 1"}) {
		t.Fatalf("releases %v", got)
	}
	if err := h.k.Release(context.Background()); err != nil || len(h.take()) != 0 {
		t.Fatalf("released with the window spent: %v", err)
	}
	// After midnight the whole window is free: 250 and 500 both fit.
	h.now = h.now.Add(24 * time.Hour)
	h.sync()
	h.simFail = func(d string) bool { return d == "release 2" }
	if err := h.k.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"release 1", "release 1"}) {
		t.Fatalf("halved releases %v", got)
	}
	if h.status.ExitHead != h.status.ExitTail {
		t.Fatalf("queue left at %d of %d", h.status.ExitHead, h.status.ExitTail)
	}

	// A vault that pays exits in parts is asked to release the head even when it does not fit.
	h.partial, h.simFail = true, nil
	h.queueExits(900)
	h.status.Outflow = big.NewInt(500)
	h.setInstance()
	if err := h.k.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"release 1"}) {
		t.Fatalf("part payment %v", got)
	}
	if d := untilRelease(time.Date(2026, 10, 3, 23, 59, 50, 0, time.UTC), 30*time.Second); d != 20*time.Second {
		t.Fatalf("sleeps %s before midnight", d)
	}
}

func TestReleaseWaitsWhileTheVaultCannotPay(t *testing.T) {
	h := newHarness(t)
	h.limit = 1000
	h.status.ExitHead, h.status.ExitTail = 1, 1
	h.queueExits(300, 250)
	h.sentHook = func(d string) {
		var n uint64
		if _, err := fmt.Sscanf(d, "release %d", &n); err == nil {
			h.release(n)
		}
	}
	h.deauthorized = true
	h.sync()
	if err := h.k.Release(context.Background()); err != nil || len(h.take()) != 0 || h.fake.CallCount("simulateTransaction") != 0 {
		t.Fatalf("released from a vault the issuer does not let hold the asset: %v", err)
	}
	// Authorized again, the vault holds enough for the first exit only.
	h.deauthorized, h.funds = false, big.NewInt(400)
	h.setInstance()
	if err := h.k.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"release 1"}) {
		t.Fatalf("releases %v", got)
	}

	// Nor is the head tried in part when the vault cannot pay what the window allows of it.
	h2 := newHarness(t)
	h2.limit, h2.partial = 1000, true
	h2.status.ExitHead, h2.status.ExitTail = 1, 1
	h2.queueExits(2000)
	h2.sentHook = func(string) {
		h2.status.OutflowDay, h2.status.Outflow = uint64(h2.now.Unix())/secondsPerDay, big.NewInt(1000)
		h2.setInstance()
	}
	h2.funds = big.NewInt(999)
	h2.sync()
	if err := h2.k.Release(context.Background()); err != nil || len(h2.take()) != 0 {
		t.Fatalf("released in part beyond the vault's funds: %v", err)
	}
	h2.funds = big.NewInt(1000)
	h2.setInstance()
	if err := h2.k.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h2.take(); !equal(got, []string{"release 1"}) {
		t.Fatalf("part payment %v", got)
	}
}

func TestStrandedExitsAreClaimedOnceAPartyCanReceive(t *testing.T) {
	h := newHarness(t)
	h.chain.Shield(vaulttest.Depositor, 5000)
	h.chain.Attest(1)
	h.chain.Admit(1)
	first := h.chain.QueueExit(1, -400, 0, vaulttest.Depositor)
	second := h.chain.QueueExit(2, -300, 0, vaulttest.Relayer)
	h.chain.NextLedger(5)
	h.chain.Strand(first, 400, 0)
	h.chain.Strand(second, 300, 0)
	h.chain.NextLedger(5)
	h.status.ExitHead, h.status.ExitTail = 3, 3
	for id, payout := range map[uint64]int64{1: 400, 2: 300} {
		h.fake.SetContractData(mustKey(vault.StrandedKey(vaulttest.Vault, id)), vaulttest.ExitEntry(vaulttest.Depositor, payout, 0, 1), h.chain.Ledger, h.live(500_000))
	}
	h.sync()
	tries := 0
	h.simFail = func(d string) bool {
		if d == "claim 1" {
			tries++
			return true
		}
		return false
	}
	// The depositor cannot receive yet, the relayer can.
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"claim 2"}) || tries != 1 || len(h.pages) != 0 {
		t.Fatalf("claims %v after %d tries, pages %+v", got, tries, h.pages)
	}
	// Both stranded entries are kept alive by the TTL cycle.
	exits, err := h.k.exitEntries()
	if err != nil || len(exits) != 2 || exits[0].name != "stranded exit 1" {
		t.Fatalf("exit entries %+v, %v", exits, err)
	}
	h.chain.NextLedger(5)
	h.chain.Requeue(second, 3, 300, 0)
	h.chain.NextLedger(5)
	h.status.ExitTail = 4
	h.sync()
	// Nothing the depositor holds has changed, so exit 1 waits for the hourly retry.
	if err := h.k.Claims(context.Background()); err != nil || tries != 1 || len(h.take()) != 0 {
		t.Fatalf("tried again unchanged: %d tries, %v", tries, err)
	}
	h.now = h.now.Add(time.Hour)
	if err := h.k.Claims(context.Background()); err != nil || tries != 2 {
		t.Fatalf("not tried after an hour: %d tries, %v", tries, err)
	}
	// The depositor's account changes, and the claim goes through at once.
	h.simFail = nil
	key := mustKey(vault.AccountKey(vaulttest.Depositor))
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, SeqNum: 1, Balance: 10_000_000}}, h.chain.Ledger, nil)
	if err := h.k.Claims(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"claim 1"}) {
		t.Fatalf("claims %v", got)
	}
	// Nothing is claimed while the vault is halted.
	h.now = h.now.Add(2 * time.Hour)
	h.status.HaltedUntil = uint64(h.now.Add(time.Hour).Unix())
	h.sync()
	before := h.fake.CallCount("simulateTransaction")
	if err := h.k.Claims(context.Background()); err != nil || h.fake.CallCount("simulateTransaction") != before {
		t.Fatalf("claimed while halted: %v", err)
	}
}

func TestARefundWaitsForAQueuedCorrection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	four := uint32(4)
	flaggedAt := uint64(h.now.Unix())
	h.shield(10, &four, flaggedAt)
	h.shield(10, &four, flaggedAt)
	h.sync()
	h.now = h.now.Add(24 * time.Hour)
	h.sync()
	until := uint64(h.now.Unix()) + 600
	var down error
	h.k.cfg.Unflags = func(context.Context) (map[uint64]uint64, error) { return map[uint64]uint64{1: until}, down }
	if err := h.k.Refund(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"refund 2"}) {
		t.Fatalf("refunds %v", got)
	}
	// Unread, the list holds back every refund.
	down = errors.New("screening down")
	h.now = h.now.Add(10 * time.Minute)
	h.sync()
	if err := h.k.Refund(ctx); err == nil || len(h.take()) != 0 || !h.has("refunds_wait") {
		t.Fatalf("refunded without the list: %v", err)
	}
	// Past the end of its final window, the correction no longer holds the refund back; the
	// simulated vault still holds deposit 2, as nothing played its refund.
	down = nil
	if err := h.k.Refund(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.take(); !equal(got, []string{"refund 1", "refund 2"}) {
		t.Fatalf("refunds %v", got)
	}
}
