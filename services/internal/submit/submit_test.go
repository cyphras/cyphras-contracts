package submit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
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
		return protocol.SimulateTransactionResponse{Error: "HostError: Error(Contract, #26)"}, nil
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
	h.engine.MaxResourceFee = 49_999
	if _, err := h.engine.Prepare(context.Background(), h.account, invoke()); !errors.Is(err, ErrSimulation) {
		t.Fatalf("resource fee above the cap: %v", err)
	}
}
