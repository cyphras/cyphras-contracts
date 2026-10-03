package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/config"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// CheckSigner refuses a key that cannot authorize the account on its own: its weight must meet
// the account's medium threshold, which a contract's require_auth asks of a classic account.
func CheckSigner(ctx context.Context, c rpc.Client, account string, key *keypair.Full) error {
	k, err := vault.AccountKey(account)
	if err != nil {
		return err
	}
	entry, _, err := rpc.One(ctx, c, k)
	if err != nil {
		return fmt.Errorf("read account %s: %w", account, err)
	}
	acct := entry.Data.Account
	if acct == nil {
		return fmt.Errorf("%s is not an account", account)
	}
	medium := uint32(acct.Thresholds[2])
	var weight uint32
	if key.Address() == account {
		weight = uint32(acct.Thresholds[0])
	}
	for _, s := range acct.Signers {
		if s.Key.Type == xdr.SignerKeyTypeSignerKeyTypeEd25519 {
			if addr, err := s.Key.GetAddress(); err == nil && addr == key.Address() {
				weight = uint32(s.Weight)
			}
		}
	}
	if weight == 0 || weight < medium {
		return fmt.Errorf("the key has weight %d on %s, which needs %d", weight, account, medium)
	}
	return nil
}

// Engine builds the submission engine from INCLUSION_FEE_CAP and RESOURCE_FEE_CAP, in stroops,
// and the defaults the services share.
func Engine(c rpc.Client, passphrase string) (*submit.Engine, error) {
	inclusionCap, err := config.Int("INCLUSION_FEE_CAP", 1_000_000)
	if err != nil {
		return nil, err
	}
	resourceCap, err := config.Int("RESOURCE_FEE_CAP", 50_000_000)
	if err != nil {
		return nil, err
	}
	if inclusionCap <= 0 || resourceCap <= 0 {
		return nil, errors.New("fee caps must be positive")
	}
	return &submit.Engine{
		RPC: c, Passphrase: passphrase, MaxInclusionFee: inclusionCap, MaxResourceFee: resourceCap, ResourceMarginPct: 15,
		Validity: 90 * time.Second, Poll: 2 * time.Second,
	}, nil
}
