package relayer

import (
	"context"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// confirmedAs makes every relayed transaction confirm charged an inclusion fee of 100 stroops,
// nonRefundable for the resources it declared and refundable for the rent and events it used.
func (h *harness) confirmedAs(nonRefundable, refundable int64) {
	r, _ := xdr.MarshalBase64(xdr.TransactionResult{FeeCharged: xdr.Int64(100 + nonRefundable + refundable),
		Result: xdr.TransactionResultResult{Code: xdr.TransactionResultCodeTxSuccess, Results: &[]xdr.OperationResult{}}})
	meta, _ := xdr.MarshalBase64(xdr.TransactionMeta{V: 4, V4: &xdr.TransactionMetaV4{SorobanMeta: &xdr.SorobanTransactionMetaV2{
		Ext: xdr.SorobanTransactionMetaExt{V: 1, V1: &xdr.SorobanTransactionMetaExtV1{
			TotalNonRefundableResourceFeeCharged: xdr.Int64(nonRefundable), TotalRefundableResourceFeeCharged: xdr.Int64(refundable),
		}},
	}}})
	h.mu.Lock()
	h.status = protocol.GetTransactionResponse{TransactionDetails: protocol.TransactionDetails{
		Status: protocol.TransactionStatusSuccess, ResultXDR: r, ResultMetaXDR: meta, Ledger: 1001,
	}}
	h.mu.Unlock()
}

// The RPC's simulation names 15% more than the refundable fee and rent it measured, and prices a
// transaction larger than the one sent, so a relay is charged less than its simulation names. The
// figures are those of two relays confirmed on mainnet at ledgers 64,939,967 (a transfer) and
// 64,939,990 (an unshield): the non-refundable fee of their declared resources, the refundable
// fee they used, and the simulated resource fee their declared resource fee gives back once the
// margin, padding and exit room are taken off. Once 50 such relays have confirmed, the quote they
// price must still pay for the next one, or no relay confirms again and the quote never moves.
func TestTheQuoteLearnedFromConfirmedRelaysPaysForTheNextOne(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		unshield                             bool
		nonRefundable, refundable, simulated int64
	}{
		{"transfer", false, 107_310, 439_330, 606_772},
		{"unshield", true, 114_417, 440_248, 612_309},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, vault.Status{}, func(c *Config) { c.Key = trapdoorKey(t) })
			h.productionEngine()
			h.r.costly = httpapi.NewLimiter(60_000, 1_000)
			h.r.simulateLimit = httpapi.NewLimiter(60_000, 1_000)
			h.plainSimulation(tc.simulated)
			h.confirmedAs(tc.nonRefundable, tc.refundable)
			relay := func(fee int64) *failure {
				t.Helper()
				recipient, amount := feeAddress, int64(0)
				if tc.unshield {
					recipient, amount = keypair.MustRandom().Address(), -20_000_000
					h.fund(recipient)
				}
				_, f := h.r.Submit(context.Background(), h.forged(t, recipient, amount, fee))
				h.waitIdle()
				return f
			}
			for i := range Samples {
				if f := relay(h.publishedQuote()); f != nil {
					t.Fatalf("relay %d at the bootstrap quote: %s", i, f.code)
				}
			}
			h.mu.Lock()
			h.now = h.now.Add(QuoteLifetime + time.Second)
			h.mu.Unlock()
			h.fake.CloseTime = h.now.Unix()
			if err := h.r.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			quote := h.publishedQuote()
			if quote >= 1_100_000 {
				t.Fatalf("the quote %d did not follow the confirmed relays", quote)
			}
			if f := relay(quote); f != nil {
				fee := int64(-1)
				if f.networkFee != nil {
					fee = *f.networkFee
				}
				t.Fatalf("quote %d after %d relays charged %d: refused %s, network fee %d", quote, Samples, tc.nonRefundable+tc.refundable, f.code, fee)
			}
		})
	}
}
