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

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
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

// outflowWindow is the state release works from: the vault, today's UTC day, what is left of the
// day's outflow window, what the vault can pay out, and whether the vault takes payments now.
type outflowWindow struct {
	inst  vault.Instance
	day   uint64
	room  *big.Int
	funds *big.Int
	open  bool
}

func (k *Keeper) window(ctx context.Context) (outflowWindow, error) {
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return outflowWindow{}, err
	}
	now, _, err := k.chainTime(ctx)
	if err != nil {
		return outflowWindow{}, err
	}
	funds, err := k.funds(ctx, inst.Config.Token)
	if err != nil {
		return outflowWindow{}, err
	}
	day := now / secondsPerDay
	room := new(big.Int).Sub(inst.Limits.MaxDailyOutflow, inst.Status.OutflowOn(day))
	return outflowWindow{inst: inst, day: day, room: room, funds: funds, open: !inst.Status.Halted(now)}, nil
}

// funds is what the vault can pay out as release judges it: its balance in the asset contract,
// and nothing while the issuer does not let it hold the asset.
func (k *Keeper) funds(ctx context.Context, token string) (*big.Int, error) {
	key, err := vault.BalanceKey(token, k.cfg.Vault)
	if err != nil {
		return nil, err
	}
	e, _, err := rpc.One(ctx, k.rpc, key)
	if errors.Is(err, rpc.ErrMissing) {
		return new(big.Int), nil
	}
	if err != nil {
		return nil, err
	}
	v, err := rpc.ContractValue(e)
	if err != nil {
		return nil, err
	}
	amount, authorized, err := vault.DecodeBalance(v)
	if err != nil || !authorized {
		return new(big.Int), err
	}
	return amount, nil
}

// releaseIdle is the state in which a release last handled no exit: the day, the room left in its
// window and the head of the queue.
type releaseIdle struct {
	day  uint64
	room string
	head uint64
}

// Release pays queued exits in order while today's outflow window has room. It counts from the
// chain how many exits fit the window and the vault's funds, and when none fits the window whole
// it still tries the head, which the vault pays in part. A release whose simulation handles no
// exit is not sent, so none is paid for in vain, and a batch the transaction limits refuse in
// simulation is halved. While the vault cannot pay the next step, which the watcher reports,
// nothing is tried. A release that handles no exit, as when the head would create an account and
// less than 1 XLM of the window is left, is not tried again until the day, the room left or the
// head changes.
func (k *Keeper) Release(ctx context.Context) error {
	batch := max(k.cfg.MaxReleases, 1)
	for range 100 {
		w, err := k.window(ctx)
		if err != nil {
			return err
		}
		head, tail := w.inst.Status.ExitHead, w.inst.Status.ExitTail
		if !w.open || head >= tail || w.room.Sign() <= 0 {
			return nil
		}
		state := releaseIdle{day: w.day, room: w.room.String(), head: head}
		k.mu.RLock()
		idle := k.idle != nil && *k.idle == state
		k.mu.RUnlock()
		if idle {
			return nil
		}
		// The exits past the batch are those it pays when others release as many first.
		ids := make([]uint64, 0, batch+int(k.cfg.ExitKeys))
		for id := head; id < tail && len(ids) < batch+int(k.cfg.ExitKeys); id++ {
			ids = append(ids, id)
		}
		exits, err := k.readExits(ctx, ids, vault.ExitKey)
		if err != nil {
			return err
		}
		room, funds := w.room, w.funds
		n := 0
		for _, e := range exits[:min(len(exits), batch)] {
			outflow := new(big.Int).Add(e.Payout, e.Fee)
			if outflow.Cmp(room) > 0 || outflow.Cmp(funds) > 0 {
				break
			}
			room.Sub(room, outflow)
			funds.Sub(funds, outflow)
			n++
		}
		if n == 0 && len(exits) > 0 {
			step := new(big.Int).Add(exits[0].Payout, exits[0].Fee)
			if step.Cmp(room) > 0 {
				step = room
			}
			if step.Cmp(funds) > 0 {
				return nil
			}
		}
		n = max(n, 1)
		res, err := k.callWorth(ctx, fmt.Sprintf("release of %d exits", n), func() (txnbuild.Operation, error) {
			return k.invoke("release", vault.U32(uint32(n)))
		}, handledAny, k.releaseRoom(w.inst.Config.Token, head, n, exits))
		switch {
		case errors.Is(err, submit.ErrNotWorth):
			k.setIdle(state)
			return nil
		case errors.Is(err, submit.ErrSimulation) && n > 1:
			batch = n / 2
			continue
		case err != nil:
			return err
		}
		if !handledAny(res.Return) {
			k.setIdle(state)
			return nil
		}
	}
	return nil
}

// releaseRoom gives a release of n exits from head room for the ledger it lands in: the stranded
// entries of its exits, which a payment the asset contract refuses writes, and the entries of the
// ExitKeys exits after them, which it pays instead when releases of others pay as many from the
// head first: those exits, their stranded entries and their payees' balances.
func (k *Keeper) releaseRoom(token string, head uint64, n int, exits []vault.Exit) submit.Extend {
	return func(context.Context, xdr.LedgerFootprint) (submit.Extra, error) {
		var keys []xdr.LedgerKey
		for id := head; id < head+uint64(n); id++ {
			key, err := vault.StrandedKey(k.cfg.Vault, id)
			if err != nil {
				return submit.Extra{}, err
			}
			keys = append(keys, key)
		}
		balances := 0
		for i, e := range exits[min(n, len(exits)):min(n+int(k.cfg.ExitKeys), len(exits))] {
			id := head + uint64(n+i)
			exit, err := vault.ExitKey(k.cfg.Vault, id)
			if err != nil {
				return submit.Extra{}, err
			}
			stranded, err := vault.StrandedKey(k.cfg.Vault, id)
			if err != nil {
				return submit.Extra{}, err
			}
			keys = append(keys, exit, stranded)
			for _, p := range []struct {
				party  string
				amount *big.Int
			}{{e.Recipient, e.Payout}, {e.Relayer, e.Fee}} {
				if p.amount.Sign() <= 0 {
					continue
				}
				paid, err := vault.PayKeys(token, k.cfg.Asset, p.party)
				if err != nil {
					return submit.Extra{}, err
				}
				for _, key := range paid {
					if key.Type == xdr.LedgerEntryTypeContractData {
						balances++
					}
				}
				keys = append(keys, paid...)
			}
		}
		written := uint32(vault.ExitEntryBytes + balances*vault.BalanceEntryBytes)
		return submit.Extra{ReadWrite: keys, Instructions: vault.SwitchInstructions, WriteBytes: written, NewBytes: written,
			RentLedgers: vault.EntryTTL, EventBytes: vault.SwitchEventBytes}, nil
	}
}

func (k *Keeper) setIdle(state releaseIdle) {
	k.mu.Lock()
	k.idle = &state
	k.mu.Unlock()
}

// handledAny reports whether a simulated release handled at least one exit.
func handledAny(ret *xdr.ScVal) bool {
	if ret == nil {
		return true
	}
	n, ok := ret.GetU32()
	return !ok || n > 0
}

const (
	// claimRetry is how often a stranded exit is tried again although nothing its parties hold has
	// changed: whether a contract may hold the asset also depends on the issuer's flags.
	claimRetry = time.Hour
	// claimRestMax caps how long an exit rests after it strands again or its claim fails on chain.
	claimRestMax = 24 * time.Hour
	// creatingReserveMax is the highest base reserve, in stroops, at which the 1 XLM the vault lets
	// create an account still covers the account's two reserves.
	creatingReserveMax = vault.MinNewAccountPayout / 2
)

// rest is how long an exit waits after its n-th setback in a row: an hour, doubling up to a day.
func rest(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return min(claimRetry<<min(n-1, 5), claimRestMax)
}

// claimTry is the keeper's last claim of a stranded exit: the parties' entries it saw, when, and
// how many of its claims in a row failed on chain.
type claimTry struct {
	seen     string
	at       time.Time
	failures int
}

// strandedExit is what Claims needs of a stranded exit.
type strandedExit struct {
	id         uint64
	parties    []string
	payout     *big.Int
	recipient  string
	strandedAt int64
}

// Claims moves stranded exits back into the exit queue once their recipient or relayer can
// receive again. It simulates claim for a stranded exit when an entry that decides whether a party
// it still owes can receive has changed since the last try, and at least every claimRetry, and
// sends the claims that would move a part; one that would move nothing fails in simulation and is
// not sent. A requeued exit waits behind every exit queued before it, so claims never compete
// with the queue for the window. An exit that strands again, or whose claim fails on chain, rests
// for an hour, doubling with each further setback up to a day. A claim whose payout would create
// an account waits while the base reserve is above 0.5 XLM: 1 XLM then no longer covers the
// account's two reserves, and the payout would only strand again.
func (k *Keeper) Claims(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return err
	}
	now, _, err := k.chainTime(ctx)
	if err != nil || inst.Status.Halted(now) {
		return err
	}
	k.mu.Lock()
	stranded := make([]strandedExit, 0, len(k.state.Stranded))
	for _, id := range slices.Sorted(maps.Keys(k.state.Stranded)) {
		e := k.state.Stranded[id]
		s := strandedExit{id: id, payout: new(big.Int).Set(e.Payout), recipient: e.Recipient, strandedAt: e.StrandedAt}
		if e.Payout.Sign() > 0 {
			s.parties = append(s.parties, e.Recipient)
		}
		if e.Fee.Sign() > 0 {
			s.parties = append(s.parties, e.Relayer)
		}
		stranded = append(stranded, s)
	}
	for id := range k.claims {
		if _, ok := k.state.Stranded[id]; !ok {
			delete(k.claims, id)
		}
	}
	k.mu.Unlock()
	if len(stranded) == 0 {
		return nil
	}
	ids := make([]uint64, len(stranded))
	for i, s := range stranded {
		ids[i] = s.id
	}
	strands, err := k.chain.Strands(ctx, ids)
	if err != nil {
		return err
	}
	keys := make(map[uint64][]string, len(stranded))
	var all []xdr.LedgerKey
	known := map[string]bool{}
	for _, s := range stranded {
		for _, p := range s.parties {
			ks, err := k.receiveKeys(inst.Config.Token, p)
			if err != nil {
				return err
			}
			for _, key := range ks {
				name, err := rpc.KeyString(key)
				if err != nil {
					return err
				}
				keys[s.id] = append(keys[s.id], name)
				if !known[name] {
					known[name] = true
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
	var reserve *int64
	var reserveErr error
	waiting := 0
	for _, s := range stranded {
		if n := strands[s.id]; n > 1 && now < uint64(s.strandedAt)+uint64(rest(n-1)/time.Second) {
			continue
		}
		creating, err := k.creates(s, entries)
		if err != nil {
			return err
		}
		if creating {
			if reserve == nil && reserveErr == nil {
				r, err := rpc.BaseReserve(ctx, k.rpc)
				reserve, reserveErr = &r, err
			}
			if reserveErr != nil || *reserve > creatingReserveMax {
				waiting++
				continue
			}
		}
		var seen strings.Builder
		for _, name := range keys[s.id] {
			if e, ok := entries[name]; ok {
				fmt.Fprintf(&seen, "%d,", e.LastModified)
			} else {
				seen.WriteString("-,")
			}
		}
		k.mu.Lock()
		last, tried := k.claims[s.id]
		due := !tried || last.seen != seen.String() || at.Sub(last.at) >= claimRetry
		if tried && at.Sub(last.at) < rest(last.failures) {
			due = false
		}
		if due {
			k.claims[s.id] = claimTry{seen: seen.String(), at: at, failures: last.failures}
		}
		k.mu.Unlock()
		if !due {
			continue
		}
		if err := k.claim(ctx, s.id); err != nil {
			return err
		}
	}
	switch {
	case waiting > 0 && reserveErr != nil:
		k.alerts.Raise(ctx, alert.Warning, "creating_claims_wait", "%d stranded exits that would create an account wait: the base reserve could not be read: %v", waiting, reserveErr)
	case waiting > 0:
		k.alerts.Raise(ctx, alert.Warning, "creating_claims_wait", "%d stranded exits that would create an account wait while the base reserve is %d stroops", waiting, *reserve)
	default:
		k.alerts.Clear(ctx, "creating_claims_wait", "no stranded exit waits for the base reserve")
	}
	return nil
}

// claim sends one claim. A claim that fails on chain, which anyone's claim of the same exit or a
// party that stops receiving between simulation and inclusion can cause, rests the exit and lets
// the other claims go ahead.
func (k *Keeper) claim(ctx context.Context, id uint64) error {
	what := fmt.Sprintf("claim of exit %d", id)
	res, err := k.attempt(ctx, what, func() (txnbuild.Operation, error) {
		return k.invoke("claim", vault.U64(id))
	}, nil, k.claimRoom)
	if errors.Is(err, submit.ErrSimulation) {
		return nil
	}
	k.mu.Lock()
	try := k.claims[id]
	if err == nil {
		try.failures = 0
	} else if res.Outcome == submit.Failed {
		try.failures++
	}
	k.claims[id] = try
	k.mu.Unlock()
	switch {
	case err == nil:
		return nil
	case res.Outcome == submit.Failed:
		k.log.Warn("claim failed on chain", "exit", id, "tx", res.Hash, "code", res.Code, "rest", rest(try.failures).String())
		k.alerts.Raise(ctx, alert.Warning, "claim_failed", "%s failed on chain with %s; the exit rests %s", what, res.Code, rest(try.failures))
		return nil
	default:
		k.alerts.Raise(ctx, alert.Critical, "call_failed", "%s failed after retries: %v", what, err)
		return err
	}
}

// claimRoom gives a claim the exits from the tail its simulation queued it at to ExitKeys past it,
// so as many exits queued ahead of it in the same ledger still leave it room.
func (k *Keeper) claimRoom(_ context.Context, fp xdr.LedgerFootprint) (submit.Extra, error) {
	tail, ok := vault.QueuedExit(k.cfg.Vault, fp)
	if !ok {
		return submit.Extra{}, nil
	}
	keys, err := vault.ExitKeys(k.cfg.Vault, tail, k.cfg.ExitKeys)
	return submit.Extra{ReadWrite: keys}, err
}

// creates reports whether claiming the exit would queue a payout that creates its recipient's
// account: a native payout of at least 1 XLM to an account that does not exist.
func (k *Keeper) creates(s strandedExit, entries map[string]rpc.Entry) (bool, error) {
	if k.cfg.Asset != "native" || s.payout.Cmp(big.NewInt(vault.MinNewAccountPayout)) < 0 {
		return false, nil
	}
	account, err := vault.AccountOf(s.recipient)
	if err != nil || account[0] != 'G' {
		return false, err
	}
	key, err := vault.AccountKey(account)
	if err != nil {
		return false, err
	}
	ks, err := rpc.KeyString(key)
	if err != nil {
		return false, err
	}
	_, ok := entries[ks]
	return !ok, nil
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
