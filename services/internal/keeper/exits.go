package keeper

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const secondsPerDay = 86_400

// readExits reads exit entries by ID in order and stops at the first one that is gone.
func (k *Keeper) readExits(ctx context.Context, ids []uint64, key func(string, uint64) (xdr.LedgerKey, error)) ([]vault.Exit, error) {
	keys := make([]xdr.LedgerKey, len(ids))
	for i, id := range ids {
		var err error
		if keys[i], err = key(k.cfg.Vault, id); err != nil {
			return nil, err
		}
	}
	entries, _, err := rpc.Entries(ctx, k.rpc, keys)
	if err != nil {
		return nil, err
	}
	var out []vault.Exit
	for i := range ids {
		s, _ := rpc.KeyString(keys[i])
		e, ok := entries[s]
		if !ok {
			break
		}
		v, err := rpc.ContractValue(e)
		if err != nil {
			return nil, err
		}
		x, err := vault.DecodeExit(v)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, nil
}

// window reads what is left of today's outflow window, and whether the vault takes payments now.
func (k *Keeper) window(ctx context.Context) (vault.Instance, *big.Int, bool, error) {
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return vault.Instance{}, nil, false, err
	}
	now, _, err := k.chainTime(ctx)
	if err != nil {
		return vault.Instance{}, nil, false, err
	}
	room := new(big.Int).Sub(inst.Limits.MaxDailyOutflow, inst.Status.OutflowOn(now/secondsPerDay))
	return inst, room, !inst.Status.Halted(now), nil
}

// Release pays queued exits in order while today's outflow window has room. It counts from the
// chain how many exits fit, and when none fits whole it still tries the head, which a vault that
// pays exits in parts will part pay. A release whose simulation handles no exit is not sent, so
// none is paid for in vain, and a batch the transaction limits refuse in simulation is halved.
func (k *Keeper) Release(ctx context.Context) error {
	batch := max(k.cfg.MaxReleases, 1)
	for range 100 {
		inst, room, open, err := k.window(ctx)
		if err != nil {
			return err
		}
		head, tail := inst.Status.ExitHead, inst.Status.ExitTail
		if !open || head >= tail || room.Sign() <= 0 {
			return nil
		}
		ids := make([]uint64, 0, batch)
		for id := head; id < tail && len(ids) < batch; id++ {
			ids = append(ids, id)
		}
		exits, err := k.readExits(ctx, ids, vault.ExitKey)
		if err != nil {
			return err
		}
		n := 0
		for _, e := range exits {
			outflow := new(big.Int).Add(e.Payout, e.Fee)
			if outflow.Cmp(room) > 0 {
				break
			}
			room.Sub(room, outflow)
			n++
		}
		n = max(n, 1)
		_, err = k.callWorth(ctx, fmt.Sprintf("release of %d exits", n), func() (txnbuild.Operation, error) {
			return k.invoke("release", vault.U32(uint32(n)))
		}, handledAny)
		switch {
		case errors.Is(err, submit.ErrNotWorth):
			return nil
		case errors.Is(err, submit.ErrSimulation) && n > 1:
			batch = n / 2
			continue
		case err != nil:
			return err
		}
	}
	return nil
}

// handledAny reports whether a simulated release handled at least one exit.
func handledAny(ret *xdr.ScVal) bool {
	if ret == nil {
		return true
	}
	n, ok := ret.GetU32()
	return !ok || n > 0
}

// claimRetry is how often a stranded exit is tried again although nothing its parties hold has
// changed: whether a contract may hold the asset also depends on the issuer's flags.
const claimRetry = time.Hour

// claimTry is the keeper's last claim of a stranded exit: the parties' entries it saw, and when.
type claimTry struct {
	seen string
	at   time.Time
}

// Claims moves stranded exits back into the exit queue once their recipient or relayer can
// receive again. It simulates claim for a stranded exit when an entry that decides whether a party
// it still owes can receive has changed since the last try, and at least every claimRetry, and
// sends the claims that would move a part; one that would move nothing fails in simulation and is
// not sent. A requeued exit waits behind every exit queued before it, so claims never compete
// with the queue for the window.
func (k *Keeper) Claims(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return err
	}
	now, _, err := k.chainTime(ctx)
	if err != nil || inst.Status.Halted(now) {
		return err
	}
	k.mu.RLock()
	ids := slices.Sorted(maps.Keys(k.state.Stranded))
	parties := make(map[uint64][]string, len(ids))
	for _, id := range ids {
		e := k.state.Stranded[id]
		if e.Payout.Sign() > 0 {
			parties[id] = append(parties[id], e.Recipient)
		}
		if e.Fee.Sign() > 0 {
			parties[id] = append(parties[id], e.Relayer)
		}
	}
	k.mu.RUnlock()
	keys := make(map[uint64][]string, len(ids))
	var all []xdr.LedgerKey
	known := map[string]bool{}
	for _, id := range ids {
		for _, p := range parties[id] {
			ks, err := k.receiveKeys(inst.Config.Token, p)
			if err != nil {
				return err
			}
			for _, key := range ks {
				s, err := rpc.KeyString(key)
				if err != nil {
					return err
				}
				keys[id] = append(keys[id], s)
				if !known[s] {
					known[s] = true
					all = append(all, key)
				}
			}
		}
	}
	entries, _, err := rpc.Entries(ctx, k.rpc, all)
	if err != nil {
		return err
	}
	at := k.now()
	for _, id := range ids {
		var seen strings.Builder
		for _, s := range keys[id] {
			if e, ok := entries[s]; ok {
				fmt.Fprintf(&seen, "%d,", e.LastModified)
			} else {
				seen.WriteString("-,")
			}
		}
		k.mu.Lock()
		last, tried := k.claims[id]
		due := !tried || last.seen != seen.String() || at.Sub(last.at) >= claimRetry
		if due {
			k.claims[id] = claimTry{seen: seen.String(), at: at}
		}
		k.mu.Unlock()
		if !due {
			continue
		}
		_, err := k.call(ctx, fmt.Sprintf("claim of exit %d", id), func() (txnbuild.Operation, error) {
			return k.invoke("claim", vault.U64(id))
		})
		if err != nil && !errors.Is(err, submit.ErrSimulation) {
			return err
		}
	}
	k.mu.Lock()
	for id := range k.claims {
		if _, ok := parties[id]; !ok {
			delete(k.claims, id)
		}
	}
	k.mu.Unlock()
	return nil
}

// receiveKeys are the entries that decide whether a party can receive the asset: for an account,
// the account and its trustline; for a contract, its balance in the asset contract.
func (k *Keeper) receiveKeys(token, address string) ([]xdr.LedgerKey, error) {
	account, err := vault.AccountOf(address)
	if err != nil {
		return nil, err
	}
	if account[0] != 'G' {
		key, err := vault.BalanceKey(token, account)
		return []xdr.LedgerKey{key}, err
	}
	return vault.ReceiveKeys(k.cfg.Asset, account)
}

// untilRelease is how long the release job sleeps: its interval, or until just after the next UTC
// midnight, when the window resets, if that comes first.
func untilRelease(now time.Time, every time.Duration) time.Duration {
	midnight := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	// A ledger closed after midnight must exist before release can use the new window.
	return min(every, midnight.Sub(now)+10*time.Second)
}
