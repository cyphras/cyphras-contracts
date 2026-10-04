package submit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const passphrase = "Test SDF Network ; September 2015"

type harness struct {
	fake    *rpctest.Fake
	engine  *Engine
	account *Account
	clock   time.Time
	sends   []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	kp := keypair.MustRandom()
	h := &harness{fake: rpctest.New(passphrase, 1000), clock: time.Unix(1_728_000_000, 0)}
	h.fake.FeeStats.SorobanInclusionFee.P90 = 2500
	h.setSequence(t, kp.Address(), 41)
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data := xdr.SorobanTransactionData{ResourceFee: 50_000}
		encoded, _ := xdr.MarshalBase64(data)
		auth := xdr.SorobanAuthorizationEntry{Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount}, RootInvocation: rootInvocation()}
		authB64, _ := xdr.MarshalBase64(auth)
		return protocol.SimulateTransactionResponse{TransactionDataXDR: encoded, MinResourceFee: 50_000,
			Results: []protocol.SimulateHostFunctionResult{{AuthXDR: &[]string{authB64}}}}, nil
	}
	h.engine = &Engine{RPC: h.fake, Passphrase: passphrase, MaxInclusionFee: 10_000, ResourceMarginPct: 10,
		Validity: 60 * time.Second, Poll: time.Millisecond, Now: func() time.Time { return h.clock }}
	h.account = NewAccount(kp.Address(), kp)
	return h
}

func (h *harness) setSequence(t *testing.T, id string, seq int64) {
	t.Helper()
	key, err := vault.AccountKey(id)
	if err != nil {
		t.Fatal(err)
	}
	accountID := key.MustAccount().AccountId
	h.fake.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{
		AccountId: accountID, SeqNum: xdr.SequenceNumber(seq),
	}}, 1, nil)
}

func (h *harness) sendStatuses(statuses ...string) {
	h.fake.Send = func(req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		h.sends = append(h.sends, req.Transaction)
		status := statuses[0]
		if len(statuses) > 1 {
			statuses = statuses[1:]
		}
		resp := protocol.SendTransactionResponse{Status: status}
		if status == "ERROR" {
			r := xdr.TransactionResult{Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxBadSeq}}
			resp.ErrorResultXDR, _ = xdr.MarshalBase64(r)
		}
		return resp, nil
	}
}

func success(feeCharged, nonRefundable, refundable int64) protocol.GetTransactionResponse {
	r := xdr.TransactionResult{FeeCharged: xdr.Int64(feeCharged), Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}}
	resultXDR, _ := xdr.MarshalBase64(r)
	ret := vault.U32(7)
	meta := xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{SorobanMeta: &xdr.SorobanTransactionMetaV2{
		Ext: xdr.SorobanTransactionMetaExt{V: 1, V1: &xdr.SorobanTransactionMetaExtV1{
			TotalNonRefundableResourceFeeCharged: xdr.Int64(nonRefundable), TotalRefundableResourceFeeCharged: xdr.Int64(refundable),
		}},
		ReturnValue: &ret,
	}}}
	metaXDR, _ := xdr.MarshalBase64(meta)
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{
		Status: protocol.TransactionStatusSuccess, ResultXDR: resultXDR, ResultMetaXDR: metaXDR, Ledger: 1001,
	}}
}

func invoke() *txnbuild.InvokeHostFunction {
	addr, _ := vault.ScAddress("CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5")
	return &txnbuild.InvokeHostFunction{HostFunction: xdr.HostFunction{
		Type:           xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
		InvokeContract: &xdr.InvokeContractArgs{ContractAddress: addr, FunctionName: "bump_ttl", Args: []xdr.ScVal{vault.Vec()}},
	}}
}

func rootInvocation() xdr.SorobanAuthorizedInvocation {
	return xdr.SorobanAuthorizedInvocation{Function: xdr.SorobanAuthorizedFunction{
		Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn, ContractFn: invoke().HostFunction.InvokeContract,
	}}
}

func envelopeOf(t *testing.T, b64 string) xdr.TransactionEnvelope {
	t.Helper()
	var env xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(b64, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestATransactionIsReportedOnlyAfterItSucceeds(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("PENDING")
	polls := 0
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		polls++
		if polls < 3 {
			return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}, nil
		}
		return success(60_000, 40_000, 15_000), nil
	}
	res, err := h.engine.Do(context.Background(), h.account, func() (txnbuild.Operation, error) { return invoke(), nil }, 3)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != Success || res.FeeCharged != 60_000 || res.ResourceFeeCharged != 55_000 || polls != 3 {
		t.Fatalf("result %+v after %d polls", res, polls)
	}
	if v, ok := res.Return.GetU32(); !ok || v != 7 {
		t.Fatal("return value")
	}
	env := envelopeOf(t, h.sends[0])
	tx := env.V1.Tx
	// The p90 inclusion fee plus the simulated resource fee with its margin.
	if tx.SeqNum != 42 || tx.Fee != 2500+55_000 || tx.Ext.SorobanData.ResourceFee != 55_000 {
		t.Fatalf("sequence %d, fee %d", tx.SeqNum, tx.Fee)
	}
	if len(tx.Operations[0].Body.InvokeHostFunctionOp.Auth) != 1 || len(env.V1.Signatures) != 1 {
		t.Fatal("auth or signature missing")
	}
	// The next transaction uses the next sequence number without reading the chain.
	entries := h.fake.CallCount("getLedgerEntries")
	if _, err := h.engine.Do(context.Background(), h.account, func() (txnbuild.Operation, error) { return invoke(), nil }, 1); err != nil {
		t.Fatal(err)
	}
	if envelopeOf(t, h.sends[1]).V1.Tx.SeqNum != 43 || h.fake.CallCount("getLedgerEntries") != entries {
		t.Fatal("cached sequence not used")
	}
}

func TestTryAgainLaterResendsTheSameEnvelopeUntilItIsHeld(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("TRY_AGAIN_LATER", "TRY_AGAIN_LATER", "DUPLICATE")
	p, err := h.engine.Prepare(context.Background(), h.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.engine.Send(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.sends) != 3 || h.sends[0] != h.sends[2] || s.Hash == "" {
		t.Fatalf("%d sends", len(h.sends))
	}
}

func TestTryAgainLaterPastTheTimeBoundIsNotSuccess(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("TRY_AGAIN_LATER")
	p, err := h.engine.Prepare(context.Background(), h.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	h.clock = h.clock.Add(61 * time.Second)
	if _, err := h.engine.Send(context.Background(), p); !errors.Is(err, ErrExpired) {
		t.Fatalf("send past the time bound: %v", err)
	}
	if h.account.known {
		t.Fatal("sequence still trusted after an expiry")
	}
}

func TestABadSequenceReloadsItFromTheChain(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("ERROR")
	p, err := h.engine.Prepare(context.Background(), h.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.engine.Send(context.Background(), p); !errors.Is(err, ErrRejected) {
		t.Fatalf("bad sequence: %v", err)
	}
	h.setSequence(t, h.account.ID, 90)
	h.sendStatuses("PENDING")
	p, err = h.engine.Prepare(context.Background(), h.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	if p.Seq != 91 {
		t.Fatalf("sequence %d after a reload", p.Seq)
	}
}

func TestATransactionNotFoundAfterItsTimeBoundExpires(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("PENDING")
	p, err := h.engine.Prepare(context.Background(), h.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.engine.Send(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		return protocol.GetTransactionResponse{LatestLedgerCloseTime: p.MaxTime + 1, TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}, nil
	}
	res, err := h.engine.Track(context.Background(), s)
	if err != nil || res.Outcome != Expired {
		t.Fatalf("track: %+v %v", res, err)
	}
}

func TestAFailedSimulationIsNotRetriedOrSent(t *testing.T) {
	h := newHarness(t)
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		return protocol.SimulateTransactionResponse{Error: "HostError: Error(WasmVm, InvalidAction)"}, nil
	}
	_, err := h.engine.Do(context.Background(), h.account, func() (txnbuild.Operation, error) { return invoke(), nil }, 5)
	if !errors.Is(err, ErrSimulation) || h.fake.CallCount("sendTransaction") != 0 || h.fake.CallCount("simulateTransaction") != 1 {
		t.Fatalf("failed simulation: %v", err)
	}
}

func TestACallThatNeedsAnotherSignatureIsRefused(t *testing.T) {
	h := newHarness(t)
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{})
		addr, _ := vault.ScAddress("GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH")
		auth := xdr.SorobanAuthorizationEntry{Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress, Address: &xdr.SorobanAddressCredentials{Address: addr, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
		}, RootInvocation: rootInvocation()}
		authB64, _ := xdr.MarshalBase64(auth)
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, Results: []protocol.SimulateHostFunctionResult{{AuthXDR: &[]string{authB64}}}}, nil
	}
	if _, err := h.engine.Prepare(context.Background(), h.account, invoke()); !errors.Is(err, ErrSimulation) {
		t.Fatalf("foreign authorization: %v", err)
	}
}

func TestTheInclusionFeeIsTheCappedP90(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct{ p90, want int64 }{{50, 100}, {2500, 2500}, {99_999, 10_000}} {
		h.fake.FeeStats.SorobanInclusionFee.P90 = uint64(c.p90)
		if got, err := h.engine.InclusionFee(context.Background()); err != nil || got != c.want {
			t.Fatalf("p90 %d gave %d", c.p90, got)
		}
	}
}

func TestAnUnansweredSendIsResolvedByItsHash(t *testing.T) {
	h := newHarness(t)
	sends := 0
	h.fake.Send = func(req protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		sends++
		if sends == 1 {
			// The first copy reaches the network but the answer is lost.
			return protocol.SendTransactionResponse{}, errors.New("timeout")
		}
		r := xdr.TransactionResult{Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxBadSeq}}
		b, _ := xdr.MarshalBase64(r)
		return protocol.SendTransactionResponse{Status: "ERROR", ErrorResultXDR: b}, nil
	}
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		return success(10, 5, 0), nil
	}
	res, err := h.engine.Do(context.Background(), h.account, func() (txnbuild.Operation, error) { return invoke(), nil }, 3)
	if err != nil || res.Outcome != Success {
		t.Fatalf("applied transaction reported as %+v %v", res, err)
	}
	if sends != 2 || h.fake.CallCount("simulateTransaction") != 1 {
		t.Fatalf("%d sends, %d simulations", sends, h.fake.CallCount("simulateTransaction"))
	}

	// When the hash never lands before the time bound, the attempt is an expiry.
	h2 := newHarness(t)
	h2.fake.Send = func(protocol.SendTransactionRequest) (protocol.SendTransactionResponse, error) {
		return protocol.SendTransactionResponse{}, errors.New("timeout")
	}
	p, err := h2.engine.Prepare(context.Background(), h2.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	h2.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		return protocol.GetTransactionResponse{LatestLedgerCloseTime: p.MaxTime + 1, TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}, nil
	}
	h2.clock = h2.clock.Add(2 * time.Minute)
	if _, err := h2.engine.Send(context.Background(), p); !errors.Is(err, ErrExpired) {
		t.Fatalf("unanswered and never applied: %v", err)
	}
}

func TestAResourceFeeAboveTheCapIsRefused(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// The simulation asks for 50,000 stroops, which the margin makes 55,000 for a call.
	h.engine.MaxResourceFee = 54_999
	if _, err := h.engine.Prepare(ctx, h.account, invoke()); !errors.Is(err, ErrFeeCap) || !errors.Is(err, ErrSimulation) {
		t.Fatalf("resource fee above the cap: %v", err)
	}

	// An extension or a restoration takes no margin, as the simulation pads its rent already, and
	// has a cap of its own when one is set.
	extend := func() txnbuild.Operation {
		return &txnbuild.ExtendFootprintTtl{ExtendTo: 1_000, Ext: xdr.TransactionExt{V: 1, SorobanData: &xdr.SorobanTransactionData{}}}
	}
	restore := func() txnbuild.Operation {
		return &txnbuild.RestoreFootprint{Ext: xdr.TransactionExt{V: 1, SorobanData: &xdr.SorobanTransactionData{}}}
	}
	for _, op := range []txnbuild.Operation{extend(), restore()} {
		if p, err := h.engine.Prepare(ctx, h.account, op); err != nil || p.ResourceFee != 50_000 {
			t.Fatalf("%T under the call cap: %v", op, err)
		}
	}
	h.engine.MaxTTLFee = 49_999
	if h.engine.TTLFeeCap() != 49_999 {
		t.Fatalf("the TTL fee cap is %d", h.engine.TTLFeeCap())
	}
	for _, op := range []txnbuild.Operation{extend(), restore()} {
		if _, err := h.engine.Prepare(ctx, h.account, op); !errors.Is(err, ErrFeeCap) {
			t.Fatalf("%T above its own cap: %v", op, err)
		}
	}
	h.engine.MaxResourceFee, h.engine.MaxTTLFee = 55_000, 50_000
	if p, err := h.engine.Prepare(ctx, h.account, invoke()); err != nil || p.ResourceFee != 55_000 {
		t.Fatalf("a call within its cap: %v", err)
	}
	for _, op := range []txnbuild.Operation{extend(), restore()} {
		if _, err := h.engine.Prepare(ctx, h.account, op); err != nil {
			t.Fatalf("%T within its cap: %v", op, err)
		}
	}
	h.engine.MaxTTLFee = 0
	if h.engine.TTLFeeCap() != 55_000 {
		t.Fatalf("without a TTL fee cap, extensions are capped at %d", h.engine.TTLFeeCap())
	}
}

func TestALedgerBoundStopsInclusionAtTheDeadline(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("PENDING")
	p, err := h.engine.PrepareUntil(context.Background(), h.account, invoke(), 1_020, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.engine.Send(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	cond := envelopeOf(t, h.sends[0]).V1.Tx.Cond
	if cond.V2 == nil || cond.V2.LedgerBounds == nil || cond.V2.LedgerBounds.MaxLedger != 1_020 || cond.V2.TimeBounds == nil {
		t.Fatalf("preconditions %+v", cond)
	}
	// Unseen once the network closed the bound ledger, it can never be included: it expired,
	// although its time bound has not passed.
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		return protocol.GetTransactionResponse{LatestLedger: 1_020, LatestLedgerCloseTime: h.clock.Unix(), TransactionDetails: protocol.TransactionDetails{Status: protocol.TransactionStatusNotFound}}, nil
	}
	res, err := h.engine.Track(context.Background(), s)
	if err != nil || res.Outcome != Expired {
		t.Fatalf("track: %+v %v", res, err)
	}
	// Without a bound, the same transaction keeps waiting for its time bound.
	if q, err := h.engine.Prepare(context.Background(), h.account, invoke()); err != nil || q.MaxLedger != 0 {
		t.Fatalf("unbounded %+v %v", q, err)
	}
}

func TestAFailedCallNamesTheErrorClosestToItsCause(t *testing.T) {
	trapped := xdr.InvokeHostFunctionResultCodeInvokeHostFunctionTrapped
	tr, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: 100, Result: xdr.TransactionResultResult{
		Code: xdr.TransactionResultCodeTxFailed,
		Results: &[]xdr.OperationResult{{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{
			Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionResult: &xdr.InvokeHostFunctionResult{Code: trapped},
		}}},
	}})
	errorEvent := func(contract byte, code uint32) string {
		id := xdr.ContractId{contract}
		c := xdr.Uint32(code)
		sym := xdr.ScSymbol("error")
		raw, _ := xdr.MarshalBase64(xdr.DiagnosticEvent{Event: xdr.ContractEvent{
			ContractId: &id, Type: xdr.ContractEventTypeDiagnostic,
			Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{
				{Type: xdr.ScValTypeScvSymbol, Sym: &sym},
				{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceContract, ContractCode: &c}},
			}, Data: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}},
		}})
		return raw
	}
	// The host's own errors, such as an authorization failure, name no contract's code.
	host := func() string {
		id := xdr.ContractId{3}
		code := xdr.ScErrorCodeScecInvalidAction
		sym := xdr.ScSymbol("error")
		raw, _ := xdr.MarshalBase64(xdr.DiagnosticEvent{Event: xdr.ContractEvent{
			ContractId: &id, Type: xdr.ContractEventTypeDiagnostic,
			Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{
				{Type: xdr.ScValTypeScvSymbol, Sym: &sym},
				{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceAuth, Code: &code}},
			}, Data: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}},
		}})
		return raw
	}
	resp := protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{
		Status: protocol.TransactionStatusFailed, ResultXDR: tr,
		// The asset contract refused a transfer, and the vault passed its error up unchanged.
		DiagnosticEventsXDR: []string{host(), errorEvent(1, 13), errorEvent(2, 13)},
	}}
	res := (&Engine{}).result(&Signed{Hash: "h"}, resp)
	if res.Outcome != Failed || res.InvokeCode == nil || *res.InvokeCode != trapped {
		t.Fatalf("result %+v", res)
	}
	want := strkey.MustEncode(strkey.VersionByteContract, []byte{1, 31: 0})
	if res.ContractError == nil || res.ContractError.Code != 13 || res.ContractError.Contract != want {
		t.Fatalf("contract error %+v", res.ContractError)
	}
	resp.Status, resp.DiagnosticEventsXDR = protocol.TransactionStatusSuccess, nil
	if res := (&Engine{}).result(&Signed{Hash: "h"}, resp); res.ContractError != nil {
		t.Fatal("a success named an error")
	}
}

// ledgerCostSettings publishes mainnet's settings with the given fees and limits for read and
// written bytes.
func (h *harness) ledgerCostSettings(read1KB, write1KB int64, maxRead, maxWrite uint32) {
	s := rpctest.Mainnet
	s.DiskRead1KB, s.Write1KB, s.MaxDiskReadBytes, s.MaxWriteBytes = read1KB, write1KB, maxRead, maxWrite
	h.fake.SetSettings(s)
}

func TestTheClassicEntriesACallTouchesGetRoomToGrow(t *testing.T) {
	h := newHarness(t)
	h.engine.ResourceMarginPct = 0
	account, err := vault.AccountKey(keypair.MustRandom().Address())
	if err != nil {
		t.Fatal(err)
	}
	contract, err := vault.InstanceKey("CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5")
	if err != nil {
		t.Fatal(err)
	}
	trustline := xdr.LedgerKey{Type: xdr.LedgerEntryTypeTrustline, TrustLine: &xdr.LedgerKeyTrustLine{
		AccountId: account.MustAccount().AccountId, Asset: xdr.MustNewCreditAsset("USDC", keypair.MustRandom().Address()).ToTrustLineAsset(),
	}}
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data := xdr.SorobanTransactionData{Resources: xdr.SorobanResources{
			Footprint:     xdr.LedgerFootprint{ReadOnly: []xdr.LedgerKey{trustline, contract}, ReadWrite: []xdr.LedgerKey{account}},
			DiskReadBytes: 500, WriteBytes: 300,
		}}
		encoded, _ := xdr.MarshalBase64(data)
		return protocol.SimulateTransactionResponse{TransactionDataXDR: encoded, MinResourceFee: 10_000, Results: []protocol.SimulateHostFunctionResult{{}}, LatestLedger: 990}, nil
	}
	// Without the network's byte fees there is nothing to pad by.
	if _, err := h.engine.Prepare(context.Background(), h.account, invoke()); err == nil {
		t.Fatal("prepared without the network's byte fees")
	}
	h.ledgerCostSettings(1000, 3000, 200_000, 132_096)
	p, err := h.engine.Prepare(context.Background(), h.account, invoke())
	if err != nil {
		t.Fatal(err)
	}
	res := sorobanData(t, p).Resources
	// The account and the trustline are read, and the account written.
	if res.DiskReadBytes != 500+2*2048 || res.WriteBytes != 300+2048 {
		t.Fatalf("read %d, write %d", res.DiskReadBytes, res.WriteBytes)
	}
	if p.ResourceFee != 10_000+4_000+6_000 || p.SimulatedAt != 990 {
		t.Fatalf("resource fee %d at ledger %d", p.ResourceFee, p.SimulatedAt)
	}
	// The padding stays within the network's limits.
	h.engine.costs = ledgerCosts{}
	h.ledgerCostSettings(1000, 3000, 2_000, 1_000)
	if p, err = h.engine.Prepare(context.Background(), h.account, invoke()); err != nil {
		t.Fatal(err)
	}
	if res := sorobanData(t, p).Resources; res.DiskReadBytes != 2_000 || res.WriteBytes != 1_000 || p.ResourceFee != 10_000+1_465+2_051 {
		t.Fatalf("read %d, write %d, fee %d", res.DiskReadBytes, res.WriteBytes, p.ResourceFee)
	}
}

func sorobanData(t *testing.T, p *Prepared) xdr.SorobanTransactionData {
	t.Helper()
	env := p.Tx.ToXDR()
	data, ok := env.V1.Tx.Ext.GetSorobanData()
	if !ok {
		t.Fatal("no Soroban data")
	}
	return data
}

func TestAnotherPathsEntriesAndResourcesArePaidFor(t *testing.T) {
	h := newHarness(t)
	h.engine.ResourceMarginPct = 0
	h.fake.SetSettings(rpctest.Mainnet)
	const vaultID = "CBYJTWEOBJL52FA7J7JNDVM65TW64PXO2EIQBF5YVEE3OROZSBVMP2N5"
	key := func(k xdr.LedgerKey, err error) xdr.LedgerKey {
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	payee, newcomer := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	exit, next := key(vault.ExitKey(vaultID, 7)), key(vault.ExitKey(vaultID, 8))
	account, fresh := key(vault.AccountKey(payee)), key(vault.AccountKey(newcomer))
	trustline := key(vault.TrustlineKey(payee, "USDC:"+keypair.MustRandom().Address()))
	instance, balance := key(vault.InstanceKey(vaultID)), key(vault.BalanceKey(vaultID, vaultID))
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		data := xdr.SorobanTransactionData{Resources: xdr.SorobanResources{
			Footprint:    xdr.LedgerFootprint{ReadOnly: []xdr.LedgerKey{account, trustline, instance}, ReadWrite: []xdr.LedgerKey{exit}},
			Instructions: 1_000_000, DiskReadBytes: 500, WriteBytes: 300,
		}}
		encoded, _ := xdr.MarshalBase64(data)
		return protocol.SimulateTransactionResponse{TransactionDataXDR: encoded, MinResourceFee: 100_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
	extra := Extra{ReadWrite: []xdr.LedgerKey{exit, next, account, balance, fresh}, Instructions: 1_000_000, WriteBytes: 656,
		NewBytes: 656, RentLedgers: 519_120, EventBytes: 512}
	var seen xdr.LedgerFootprint
	p, err := h.engine.PrepareUntil(context.Background(), h.account, invoke(), 0, func(_ context.Context, fp xdr.LedgerFootprint) (Extra, error) {
		seen = fp
		return extra, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen.ReadWrite) != 1 {
		t.Fatalf("extend saw %d written entries", len(seen.ReadWrite))
	}
	res := sorobanData(t, p).Resources
	names := func(keys []xdr.LedgerKey) []string {
		var out []string
		for _, k := range keys {
			b, _ := k.MarshalBinary()
			out = append(out, string(b))
		}
		return out
	}
	if want := names([]xdr.LedgerKey{exit, next, balance, fresh, account}); !equalStrings(names(res.Footprint.ReadWrite), want) {
		t.Fatal("written entries are not the simulated, added and promoted ones")
	}
	if want := names([]xdr.LedgerKey{trustline, instance}); !equalStrings(names(res.Footprint.ReadOnly), want) {
		t.Fatal("a promoted entry is still read only")
	}
	// Four entries written more, one more read from disk, a million instructions, 656 bytes
	// written, 232 bytes of keys sent, and the rent of 656 new bytes for mainnet's least TTL of
	// a new persistent entry with its TTL entry, and 512 bytes of events.
	want := int64(4*2_500 + 1_563 + 700 + (817 - 257) + 92 + 920 + 1_093_334 + 2_500 + 42 + 2_500)
	// The classic entries are padded as written or read: two written, three read.
	if res.Instructions != 2_000_000 || res.WriteBytes != 300+656+2*2048 || res.DiskReadBytes != 500+3*2048 {
		t.Fatalf("instructions %d, write bytes %d, read bytes %d", res.Instructions, res.WriteBytes, res.DiskReadBytes)
	}
	if got := p.ResourceFee - 100_000 - perKB(3*2048, 447) - perKB(2*2048, 875); got != want {
		t.Fatalf("the other path adds %d, want %d", got, want)
	}
	// The network's limit on written entries stops the additions in their order, and says so.
	limited := rpctest.Mainnet
	limited.MaxWriteEntries = 3
	h.fake.SetSettings(limited)
	h.engine.costs = ledgerCosts{}
	var logs bytes.Buffer
	h.engine.Log = slog.New(slog.NewTextHandler(&logs, nil))
	if p, err = h.engine.PrepareUntil(context.Background(), h.account, invoke(), 0, func(context.Context, xdr.LedgerFootprint) (Extra, error) {
		return extra, nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := sorobanData(t, p).Resources.Footprint.ReadWrite; !equalStrings(names(got), names([]xdr.LedgerKey{exit, next, account})) {
		t.Fatalf("%d written entries past the limit", len(got))
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "asked=4 left_out=2") {
		t.Fatalf("logs %q", logs.String())
	}
	// Room within the limits says nothing.
	logs.Reset()
	h.fake.SetSettings(rpctest.Mainnet)
	h.engine.costs = ledgerCosts{}
	if _, err = h.engine.PrepareUntil(context.Background(), h.account, invoke(), 0, func(context.Context, xdr.LedgerFootprint) (Extra, error) {
		return extra, nil
	}); err != nil || logs.Len() != 0 {
		t.Fatalf("logs %q, %v", logs.String(), err)
	}
	// The cap bounds the fee with its padding.
	h.engine.MaxResourceFee = 1_000_000
	if _, err := h.engine.PrepareUntil(context.Background(), h.account, invoke(), 0, func(context.Context, xdr.LedgerFootprint) (Extra, error) {
		return extra, nil
	}); !errors.Is(err, ErrSimulation) {
		t.Fatalf("a padded fee above the cap: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// storageFailure is a call that failed on the host's storage, as one that wrote an entry outside
// its footprint does.
func storageFailure() protocol.GetTransactionResponse {
	tr, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: 100, Result: xdr.TransactionResultResult{
		Code: xdr.TransactionResultCodeTxFailed,
		Results: &[]xdr.OperationResult{{Code: xdr.OperationResultCodeOpInner, Tr: &xdr.OperationResultTr{
			Type: xdr.OperationTypeInvokeHostFunction, InvokeHostFunctionResult: &xdr.InvokeHostFunctionResult{Code: xdr.InvokeHostFunctionResultCodeInvokeHostFunctionTrapped},
		}}},
	}})
	id := xdr.ContractId{1}
	code := xdr.ScErrorCodeScecExceededLimit
	sym := xdr.ScSymbol("error")
	event, _ := xdr.MarshalBase64(xdr.DiagnosticEvent{Event: xdr.ContractEvent{ContractId: &id, Type: xdr.ContractEventTypeDiagnostic,
		Body: xdr.ContractEventBody{V: 0, V0: &xdr.ContractEventV0{Topics: []xdr.ScVal{
			{Type: xdr.ScValTypeScvSymbol, Sym: &sym},
			{Type: xdr.ScValTypeScvError, Error: &xdr.ScError{Type: xdr.ScErrorTypeSceStorage, Code: &code}},
		}, Data: xdr.ScVal{Type: xdr.ScValTypeScvVoid}}}}})
	return protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{
		Status: protocol.TransactionStatusFailed, ResultXDR: tr, Ledger: 1001, DiagnosticEventsXDR: []string{event},
	}}
}

func TestACallTheChainMovedUnderIsSimulatedAgain(t *testing.T) {
	h := newHarness(t)
	h.sendStatuses("PENDING")
	failures := 1
	h.fake.Get = func(protocol.GetTransactionRequest) (protocol.GetTransactionResponse, error) {
		if failures > 0 {
			failures--
			return storageFailure(), nil
		}
		return success(1_000, 900, 0), nil
	}
	if res := (&Engine{}).result(&Signed{Hash: "h"}, storageFailure()); !res.Conflict || res.ContractError != nil {
		t.Fatalf("a storage failure read as %+v", res)
	}
	h.engine.Poll = time.Millisecond
	res, err := h.engine.Do(context.Background(), h.account, func() (txnbuild.Operation, error) { return invoke(), nil }, 3)
	if err != nil || res.Outcome != Success || len(h.sends) != 2 {
		t.Fatalf("after a conflict: %+v %v, %d sent", res, err, len(h.sends))
	}
	// A conflict every time is reported as one.
	failures = 10
	if _, err := h.engine.Do(context.Background(), h.account, func() (txnbuild.Operation, error) { return invoke(), nil }, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicts every time: %v", err)
	}
}
