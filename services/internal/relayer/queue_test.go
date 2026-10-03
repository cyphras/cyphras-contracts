package relayer

import (
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	protocol "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// queuedAt makes the harness's simulations queue the exit at the tail, as the vault does while
// the queue holds exits or the day's window is full; a tail of 0 pays at once.
func (h *harness) queuedAt(tail uint64, payees ...string) {
	h.fake.Simulate = func(protocol.SimulateTransactionRequest) (protocol.SimulateTransactionResponse, error) {
		var fp xdr.LedgerFootprint
		for _, p := range payees {
			fp.ReadOnly = append(fp.ReadOnly, mustKey(vault.AccountKey(p)))
		}
		if tail > 0 {
			fp.ReadWrite = append(fp.ReadWrite, mustKey(vault.ExitKey(vaulttest.Vault, tail)))
		}
		data, _ := xdr.MarshalBase64(xdr.SorobanTransactionData{Resources: xdr.SorobanResources{Footprint: fp, Instructions: 40_000_000}})
		return protocol.SimulateTransactionResponse{TransactionDataXDR: data, MinResourceFee: 800_000, Results: []protocol.SimulateHostFunctionResult{{}}}, nil
	}
}

func keyNames(keys []xdr.LedgerKey) map[string]bool {
	out := map[string]bool{}
	for _, k := range keys {
		b, _ := k.MarshalBinary()
		out[string(b)] = true
	}
	return out
}

func TestARelayedExitHasRoomForTheOtherPathOfTheQueue(t *testing.T) {
	for _, tail := range []uint64{9, 0} {
		h := newHarness(t, vault.Status{ExitHead: 5, ExitTail: 5}, func(c *Config) { c.Key = trapdoorKey(t) })
		sent := h.sentEnvelopes()
		dest := keypair.MustRandom().Address()
		h.fund(dest)
		h.queuedAt(tail, dest, feeAddress)
		h.lose(t, func() Request { return h.forged(t, dest, -20_000_000, 5_000_000) })
		parsed, err := txnbuild.TransactionFromXDR((*sent)[0])
		if err != nil {
			t.Fatal(err)
		}
		tx, _ := parsed.Transaction()
		data := tx.ToXDR().V1.Tx.Ext.SorobanData
		written, read := keyNames(data.Resources.Footprint.ReadWrite), keyNames(data.Resources.Footprint.ReadOnly)
		first := tail
		if tail == 0 {
			// Paid at once in the simulation, it may queue at the vault's tail.
			first = 5
		}
		want := []xdr.LedgerKey{mustKey(vault.BalanceKey(vaulttest.Token, vaulttest.Vault)), mustKey(vault.AccountKey(dest)), mustKey(vault.AccountKey(feeAddress))}
		for id := first; id <= first+4; id++ {
			want = append(want, mustKey(vault.ExitKey(vaulttest.Vault, id)))
		}
		for name := range keyNames(want) {
			if !written[name] || read[name] {
				t.Fatalf("tail %d: an entry of the other path is not written", tail)
			}
		}
		if len(written) != len(want) || data.Resources.Instructions != 40_000_000+vault.SwitchInstructions {
			t.Fatalf("tail %d: %d written entries, %d instructions", tail, len(written), data.Resources.Instructions)
		}
	}
}
