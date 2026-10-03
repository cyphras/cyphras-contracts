package keeper

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"slices"
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

// Claim pays stranded exits whose recipient or relayer can receive again, oldest first, while
// today's window has room. A claim pays each part that fits on its own; one that would pay
// nothing fails in simulation and costs nothing.
func (k *Keeper) Claim(ctx context.Context) error {
	k.mu.RLock()
	ids := slices.Sorted(maps.Keys(k.state.Stranded))
	k.mu.RUnlock()
	for _, id := range ids {
		_, room, open, err := k.window(ctx)
		if err != nil || !open || room.Sign() <= 0 {
			return err
		}
		_, err = k.call(ctx, fmt.Sprintf("claim of exit %d", id), func() (txnbuild.Operation, error) {
			return k.invoke("claim", vault.U64(id))
		})
		if err != nil && !errors.Is(err, submit.ErrSimulation) {
			return err
		}
	}
	return nil
}

// untilRelease is how long the release job sleeps: its interval, or until just after the next UTC
// midnight, when the window resets, if that comes first.
func untilRelease(now time.Time, every time.Duration) time.Duration {
	midnight := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	// A ledger closed after midnight must exist before release can use the new window.
	return min(every, midnight.Sub(now)+10*time.Second)
}
