package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// CheckHotSigner refuses a key that may not serve as the online signer of an account whose own
// key stays offline: the account's master key, which can do anything, or a signer whose weight
// reaches the account's high threshold, which can change the signers. Its weight must still meet
// the medium threshold a contract's require_auth asks.
func CheckHotSigner(ctx context.Context, c rpc.Client, account string, key *keypair.Full) error {
	if key.Address() == account {
		return fmt.Errorf("the key is the master key of %s, which must stay offline", account)
	}
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
	medium, high := uint32(acct.Thresholds[2]), uint32(acct.Thresholds[3])
	var weight uint32
	for _, s := range acct.Signers {
		if s.Key.Type == xdr.SignerKeyTypeSignerKeyTypeEd25519 {
			if addr, err := s.Key.GetAddress(); err == nil && addr == key.Address() {
				weight = uint32(s.Weight)
			}
		}
	}
	switch {
	case weight == 0 || weight < medium:
		return fmt.Errorf("the key has weight %d on %s, which needs %d", weight, account, medium)
	case weight >= high:
		return fmt.Errorf("the key has weight %d on %s, which reaches its high threshold %d", weight, account, high)
	}
	return nil
}

// ExitKeys reads EXIT_KEYS, how many exits queued or released ahead of a call on the exit queue in
// the ledger it lands in still leave its footprint room: 1 to 32, 4 when unset.
func ExitKeys() (uint32, error) {
	n, err := config.Int("EXIT_KEYS", 4)
	if err == nil && (n < 1 || n > 32) {
		err = errors.New("EXIT_KEYS must be 1 to 32")
	}
	return uint32(n), err
}

// The bounds of the fee caps, in stroops. An inclusion fee below 100 stroops is under the
// network's minimum. A transaction's fee field, a uint32 of about 429.5 XLM, holds its inclusion
// fee and its resource fee together, so the largest caps of the two must fit it together.
const (
	MinInclusionFeeCap = 100
	MaxInclusionFeeCap = 100_000_000
	MaxResourceFeeCap  = 4_000_000_000
)

// This fails to compile when the largest caps no longer fit a transaction's fee field together.
const _ uint32 = MaxInclusionFeeCap + MaxResourceFeeCap

// Engine builds the submission engine from INCLUSION_FEE_CAP and RESOURCE_FEE_CAP, in stroops,
// and the defaults the services share.
func Engine(c rpc.Client, passphrase string, log *slog.Logger) (*submit.Engine, error) {
	inclusionCap, err := config.Int("INCLUSION_FEE_CAP", 1_000_000)
	if err != nil {
		return nil, err
	}
	resourceCap, err := config.Int("RESOURCE_FEE_CAP", 50_000_000)
	if err != nil {
		return nil, err
	}
	if inclusionCap < MinInclusionFeeCap || inclusionCap > MaxInclusionFeeCap {
		return nil, fmt.Errorf("INCLUSION_FEE_CAP must be %d to %d stroops", MinInclusionFeeCap, MaxInclusionFeeCap)
	}
	if resourceCap <= 0 || resourceCap > MaxResourceFeeCap {
		return nil, fmt.Errorf("RESOURCE_FEE_CAP must be 1 to %d stroops", MaxResourceFeeCap)
	}
	return &submit.Engine{
		RPC: c, Passphrase: passphrase, MaxInclusionFee: inclusionCap, MaxResourceFee: resourceCap, ResourceMarginPct: 15,
		Validity: 90 * time.Second, Poll: 2 * time.Second, Log: log,
	}, nil
}
