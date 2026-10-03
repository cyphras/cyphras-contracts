package vault

import (
	"github.com/stellar/go-stellar-sdk/xdr"
)

// The keys of the vault's persistent entries, the contracttype enum DataKey.

func enumKey(name string, args ...xdr.ScVal) xdr.ScVal {
	return Vec(append([]xdr.ScVal{Symbol(name)}, args...)...)
}

func contractData(contract string, key xdr.ScVal, durability xdr.ContractDataDurability) (xdr.LedgerKey, error) {
	addr, err := ScAddress(contract)
	if err != nil {
		return xdr.LedgerKey{}, err
	}
	if addr.Type != xdr.ScAddressTypeScAddressTypeContract {
		return xdr.LedgerKey{}, malformed("%q is not a contract", contract)
	}
	var k xdr.LedgerKey
	if err := k.SetContractData(addr, key, durability); err != nil {
		return xdr.LedgerKey{}, err
	}
	return k, nil
}

// InstanceKey is the contract instance entry, which holds the instance storage.
func InstanceKey(contract string) (xdr.LedgerKey, error) {
	return contractData(contract, xdr.ScVal{Type: xdr.ScValTypeScvLedgerKeyContractInstance}, xdr.ContractDataDurabilityPersistent)
}

// RootsKey is the root ring entry.
func RootsKey(vault string) (xdr.LedgerKey, error) {
	return contractData(vault, enumKey("Roots"), xdr.ContractDataDurabilityPersistent)
}

// FrontierKey is the tree frontier entry.
func FrontierKey(vault string) (xdr.LedgerKey, error) {
	return contractData(vault, enumKey("Frontier"), xdr.ContractDataDurabilityPersistent)
}

// NextLeafKey is the next leaf index entry.
func NextLeafKey(vault string) (xdr.LedgerKey, error) {
	return contractData(vault, enumKey("NextLeaf"), xdr.ContractDataDurabilityPersistent)
}

// NullifierKey is the marker entry of a spent nullifier.
func NullifierKey(vault string, nullifier [32]byte) (xdr.LedgerKey, error) {
	return contractData(vault, enumKey("Nullifier", U256(nullifier)), xdr.ContractDataDurabilityPersistent)
}

// PendingKey is the entry of a pending deposit.
func PendingKey(vault string, id uint64) (xdr.LedgerKey, error) {
	return contractData(vault, enumKey("Pending", U64(id)), xdr.ContractDataDurabilityPersistent)
}

// TreeKeys are the tree entries bump_ttl extends.
func TreeKeys(vault string) ([]xdr.LedgerKey, error) {
	var keys []xdr.LedgerKey
	for _, f := range []func(string) (xdr.LedgerKey, error){RootsKey, FrontierKey, NextLeafKey} {
		k, err := f(vault)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// CodeKey is the entry of an uploaded wasm.
func CodeKey(hash [32]byte) xdr.LedgerKey {
	var k xdr.LedgerKey
	_ = k.SetContractCode(xdr.Hash(hash))
	return k
}

// BalanceKey is the Stellar Asset Contract entry that holds a contract address's balance.
func BalanceKey(token, holder string) (xdr.LedgerKey, error) {
	h, err := Address(holder)
	if err != nil {
		return xdr.LedgerKey{}, err
	}
	return contractData(token, Vec(Symbol("Balance"), h), xdr.ContractDataDurabilityPersistent)
}

// AccountKey is the entry of a G account.
func AccountKey(account string) (xdr.LedgerKey, error) {
	id, err := xdr.AddressToAccountId(account)
	if err != nil {
		return xdr.LedgerKey{}, malformed("account %q", account)
	}
	var k xdr.LedgerKey
	if err := k.SetAccount(id); err != nil {
		return xdr.LedgerKey{}, err
	}
	return k, nil
}

// ConfigSettingKey is the entry of a network configuration setting.
func ConfigSettingKey(id xdr.ConfigSettingId) xdr.LedgerKey {
	var k xdr.LedgerKey
	_ = k.SetConfigSetting(id)
	return k
}
