package vault

import (
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// DecodeBalance reads an asset contract's Balance(holder) entry, a map of amount, authorized and
// clawback, and returns the amount and whether the holder may hold the asset.
func DecodeBalance(v xdr.ScVal) (*big.Int, bool, error) {
	d := newDecoder(v, []string{"amount", "authorized", "clawback"})
	if d.err != nil {
		return nil, false, d.err
	}
	amount, authorized := d.i128("amount"), d.bool("authorized")
	return amount, authorized, d.err
}

// Transfer is an asset contract's transfer event.
type Transfer struct {
	From string
	// To is the destination account; a muxed destination is reported as its account.
	To     string
	Amount *big.Int
}

// DecodeTransfer reads a transfer event, whose data is the amount, or, for a muxed destination, a
// map of the amount and the destination's muxed ID.
func DecodeTransfer(raw RawEvent) (Transfer, error) {
	if len(raw.Topics) < 3 {
		return Transfer{}, malformed("transfer with %d topics", len(raw.Topics))
	}
	var topics [3]xdr.ScVal
	for i := range topics {
		if err := xdr.SafeUnmarshalBase64(raw.Topics[i], &topics[i]); err != nil {
			return Transfer{}, malformed("transfer topic: %v", err)
		}
	}
	if name, ok := symbolOf(topics[0]); !ok || name != "transfer" {
		return Transfer{}, malformed("not a transfer event")
	}
	from, err := addressOf(topics[1])
	if err != nil {
		return Transfer{}, err
	}
	to, err := addressOf(topics[2])
	if err != nil {
		return Transfer{}, err
	}
	if to, err = AccountOf(to); err != nil {
		return Transfer{}, err
	}
	var data xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(raw.Value, &data); err != nil {
		return Transfer{}, malformed("transfer data: %v", err)
	}
	if data.Type == xdr.ScValTypeScvMap {
		m, ok := data.GetMap()
		if !ok || m == nil {
			return Transfer{}, malformed("transfer data map")
		}
		found := false
		for _, e := range *m {
			if k, ok := symbolOf(e.Key); ok && k == "amount" {
				data, found = e.Val, true
			}
		}
		if !found {
			return Transfer{}, malformed("transfer data without an amount")
		}
	}
	amount, err := i128Of(data)
	if err != nil {
		return Transfer{}, err
	}
	if amount.Sign() < 0 {
		return Transfer{}, malformed("negative transfer")
	}
	return Transfer{From: from, To: to, Amount: amount}, nil
}
