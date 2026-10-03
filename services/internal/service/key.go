package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/stellar/go-stellar-sdk/network"
)

// forgeableTestnetSHA256 is the SHA-256 of the testnet verifying key. Its setup is public, so anyone
// can forge a proof that it accepts.
const forgeableTestnetSHA256 = "526f5befc2ff836621cc6f2f181fa50de3318a6865d6eca2121c678a225e2b9c"

// CheckVerifyingKey refuses a verifying key whose SHA-256 is not the pinned one, so a mount of the
// wrong key never checks proofs, and refuses the testnet key on the public network.
func CheckVerifyingKey(raw []byte, pinned, passphrase string) error {
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != strings.ToLower(strings.TrimSpace(pinned)) {
		return fmt.Errorf("the verifying key's SHA-256 is %s, not the pinned %q", got, pinned)
	}
	if passphrase == network.PublicNetworkPassphrase && got == forgeableTestnetSHA256 {
		return errors.New("the testnet verifying key, for which anyone can forge proofs, is refused on the public network")
	}
	return nil
}
