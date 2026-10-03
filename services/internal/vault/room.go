package vault

import (
	"math/big"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// The vault decides in the ledger a call lands in, not at its simulation, whether an exit is paid
// at once or queued, which IDs the queue's next exits take and which exits release pays, so a
// call simulated against one state of the exit queue may need entries of another. A call that
// touches an entry its footprint does not hold fails on the host's storage, so the calls on the
// exit queue are given these entries as read-write beyond their simulation.

// The resources the other path of a call on the exit queue may take beyond its simulation.
const (
	// ExitEntryBytes covers an exit or stranded exit entry with its key, about 330 bytes.
	ExitEntryBytes = 400
	// BalanceEntryBytes covers a contract's balance entry in the asset contract, about 225 bytes.
	BalanceEntryBytes = 256
	// SwitchInstructions covers paying an exit at once rather than queueing it, two transfers in
	// the asset contract that take about 200,000 instructions.
	SwitchInstructions = 1_000_000
	// SwitchEventBytes covers the events of paying at once rather than queueing, about 430 bytes
	// more.
	SwitchEventBytes = 512
	// EntryTTL is the TTL in ledgers the vault gives its entries when it writes them.
	EntryTTL = 30*17_280 + 720
)

// PayKeys are the entries a payment of the asset to an address writes: for lumens the account,
// for an issued asset the account's trustline and nothing for its issuer, and for a contract its
// balance in the asset contract. A muxed address pays its account.
func PayKeys(token, asset, address string) ([]xdr.LedgerKey, error) {
	account, err := AccountOf(address)
	if err != nil {
		return nil, err
	}
	var k xdr.LedgerKey
	switch {
	case strings.HasPrefix(account, "C"):
		k, err = BalanceKey(token, account)
	case asset == "native":
		k, err = AccountKey(account)
	case strings.HasSuffix(asset, ":"+account):
		return nil, nil
	default:
		k, err = TrustlineKey(account, asset)
	}
	return []xdr.LedgerKey{k}, err
}

// ExitKeys are the keys of the exits from first to first+k: those up to k exits queued ahead of a
// call in the same ledger leave for it.
func ExitKeys(vault string, first uint64, k uint32) ([]xdr.LedgerKey, error) {
	keys := make([]xdr.LedgerKey, 0, k+1)
	for id := first; id <= first+uint64(k); id++ {
		key, err := ExitKey(vault, id)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// TransactRoom are the entries a transact that pays anything is given beyond its simulation, in
// the order they are added: the vault's balance in the asset and the balances of the recipient,
// when it is paid, and of the relayer, when it is paid a fee, which paying at once writes; then
// the exits from tail to tail+k, one of which queueing writes. tail is the queue's tail the
// simulation saw.
func TransactRoom(vault, token, asset string, ext ExtData, tail uint64, k uint32) ([]xdr.LedgerKey, error) {
	payout := new(big.Int).Neg(ext.ExtAmount)
	if payout.Sign() <= 0 && ext.Fee.Sign() <= 0 {
		return nil, nil
	}
	own, err := BalanceKey(token, vault)
	if err != nil {
		return nil, err
	}
	keys := []xdr.LedgerKey{own}
	if payout.Sign() > 0 {
		paid, err := PayKeys(token, asset, ext.Recipient)
		if err != nil {
			return nil, err
		}
		keys = append(keys, paid...)
	}
	if ext.Fee.Sign() > 0 {
		paid, err := PayKeys(token, asset, ext.Relayer)
		if err != nil {
			return nil, err
		}
		keys = append(keys, paid...)
	}
	exits, err := ExitKeys(vault, tail, k)
	if err != nil {
		return nil, err
	}
	return append(keys, exits...), nil
}

// QueuedExit returns the ID of the exit a simulated footprint writes, the queue's tail when the
// simulation queued one, and whether it writes any.
func QueuedExit(vault string, fp xdr.LedgerFootprint) (uint64, bool) {
	var tail uint64
	found := false
	for _, k := range fp.ReadWrite {
		id, ok := exitID(vault, k)
		if ok && (!found || id > tail) {
			tail, found = id, true
		}
	}
	return tail, found
}

// exitID returns the ID of an exit entry's key of the vault.
func exitID(vault string, k xdr.LedgerKey) (uint64, bool) {
	if k.Type != xdr.LedgerEntryTypeContractData || k.ContractData == nil || k.ContractData.Contract.ContractId == nil {
		return 0, false
	}
	want, err := ScAddress(vault)
	if err != nil || want.ContractId == nil || *want.ContractId != *k.ContractData.Contract.ContractId {
		return 0, false
	}
	vec, ok := k.ContractData.Key.GetVec()
	if !ok || vec == nil || len(*vec) != 2 {
		return 0, false
	}
	if name, ok := symbolOf((*vec)[0]); !ok || name != "Exit" {
		return 0, false
	}
	id, ok := (*vec)[1].GetU64()
	return uint64(id), ok
}
