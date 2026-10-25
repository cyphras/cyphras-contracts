package submit

import (
	"context"
	"errors"
	"testing"

	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const liveContract = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"

// liveHarness is a harness whose simulation reads the vault's instance at simulatedAt, and whose
// calls get an exit entry added after the simulation, which the simulation cannot mark archived.
func liveHarness(t *testing.T, simulatedAt uint32) (*harness, xdr.LedgerKey, Extend) {
	t.Helper()
	h := newHarness(t)
	h.fake.SetSettings(rpctest.Mainnet)
	simulated, _ := vault.InstanceKey(liveContract)
	added, _ := vault.ExitKey(liveContract, 9)
	far := h.fake.LatestLedger() + 100_000
	h.fake.SetContractData(simulated, vault.U64(0), 10, &far)
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{Resources: xdr.SorobanResources{Footprint: xdr.LedgerFootprint{ReadOnly: []xdr.LedgerKey{simulated}}}})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 50_000, LatestLedger: simulatedAt,
			Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	room := func(context.Context, xdr.LedgerFootprint) (Extra, error) {
		return Extra{ReadWrite: []xdr.LedgerKey{added}}, nil
	}
	h.engine.RefuseRestores = true
	return h, added, room
}

// An entry whose last live ledger is the latest one closed is archived in every ledger a new
// transaction can land in, so the call needs a restore; a ledger bound at latest+1 would only have
// the network refuse the transaction as too late.
func TestAnEntryLiveOnlyInTheLatestLedgerNeedsARestore(t *testing.T) {
	h, added, room := liveHarness(t, 0)
	latest := h.fake.LatestLedger()
	h.fake.SetContractData(added, vault.U64(0), 10, &latest)
	p, err := h.engine.PrepareUntil(context.Background(), h.account, invoke(), latest+120, room)
	if !errors.Is(err, ErrRestoreNeeded) {
		bound := uint32(0)
		if p != nil {
			bound = p.MaxLedger
		}
		t.Fatalf("an entry live until the latest ledger %d: %v, bounded at %d", latest, err, bound)
	}
	// One live a ledger longer still leaves the next ledger to land in.
	next := latest + 1
	h.fake.SetContractData(added, vault.U64(0), 10, &next)
	if p, err := h.engine.PrepareUntil(context.Background(), h.account, invoke(), latest+120, room); err != nil || p.MaxLedger != latest+2 {
		t.Fatalf("an entry live in the next ledger: %v", err)
	}
}

// The entries may be read from an RPC node behind the one that simulated. A bound that the
// simulation's own ledger has passed already can never be met.
func TestAFootprintReadBehindTheSimulationIsJudgedAtTheNewestLedger(t *testing.T) {
	latest := uint32(1000)
	h, added, room := liveHarness(t, latest+5)
	lapsed := latest + 3
	h.fake.SetContractData(added, vault.U64(0), 10, &lapsed)
	p, err := h.engine.PrepareUntil(context.Background(), h.account, invoke(), latest+120, room)
	if err == nil && p.MaxLedger <= p.SimulatedAt+1 {
		t.Fatalf("bounded at %d although the simulation read ledger %d", p.MaxLedger, p.SimulatedAt)
	}
	if !errors.Is(err, ErrRestoreNeeded) {
		t.Fatalf("an entry lapsed by the simulation's ledger: %v", err)
	}
}

// When the entries cannot be read, nothing is sent and the error is not a simulation's refusal,
// which a relayer would remember as settled.
func TestAFailedFootprintReadIsNotARefusal(t *testing.T) {
	h, added, room := liveHarness(t, 0)
	far := h.fake.LatestLedger() + 100_000
	h.fake.SetContractData(added, vault.U64(0), 10, &far)
	ctx := context.Background()
	// The network's settings are read once, by a call that goes through.
	if _, err := h.engine.PrepareUntil(ctx, h.account, invoke(), 0, room); err != nil {
		t.Fatal(err)
	}
	down := errors.New("rpc down")
	failing := func(ctx context.Context, fp xdr.LedgerFootprint) (Extra, error) {
		h.fake.Fail["getLedgerEntries"] = down
		return room(ctx, fp)
	}
	_, err := h.engine.PrepareUntil(ctx, h.account, invoke(), 0, failing)
	if err == nil || errors.Is(err, ErrSimulation) || !errors.Is(err, down) {
		t.Fatalf("a failed read: %v", err)
	}
	if h.fake.CallCount("sendTransaction") != 0 {
		t.Fatal("a transaction was sent")
	}
}
