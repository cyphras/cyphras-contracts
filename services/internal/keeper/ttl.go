package keeper

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// The vault's own writes extend an entry once it has less than 30 days left, at the cost of the
// transaction that writes it. The keeper renews every entry within renewWithin of expiry, a day
// before that, so that no user pays the vault's rent while the keeper runs, and pages for an entry
// within warnWithin of expiry that it could not extend.
const (
	renewWithin = 31 * ledgersPerDay
	warnWithin  = 14 * ledgersPerDay
	// renewStep is how far past renewWithin the vault's instance, code and tree entries, pending
	// deposits and exits are extended, so that each extension pays about a day of their rent rather
	// than months of it at once.
	renewStep = ledgersPerDay
	// minStep is the shortest extension a lone entry is given when the fee cap refuses a longer
	// one: an hourly cycle that adds less loses ground.
	minStep = ledgersPerDay / 24
)

// tracked is an entry the cycle looked at.
type tracked struct {
	name string
	key  xdr.LedgerKey
	// optional marks an entry that may be gone by the time it is read, such as a deposit admitted
	// or an exit paid since the list was made; a missing one is skipped rather than restored.
	optional bool
	missing  bool
	// liveUntil is nil when the entry is archived or missing.
	liveUntil *uint32
}

func (t tracked) gone() bool {
	return t.optional && t.missing
}

func (t tracked) due(latest uint32) bool {
	return !t.gone() && (t.liveUntil == nil || *t.liveUntil < latest+renewWithin)
}

func (t tracked) urgent(latest uint32) bool {
	return !t.gone() && (t.liveUntil == nil || *t.liveUntil < latest+warnWithin)
}

func (k *Keeper) read(ctx context.Context, items []tracked) ([]tracked, uint32, error) {
	keys := make([]xdr.LedgerKey, len(items))
	for i, it := range items {
		keys[i] = it.key
	}
	entries, latest, err := rpc.Entries(ctx, k.rpc, keys)
	if err != nil {
		return nil, 0, err
	}
	out := make([]tracked, len(items))
	for i, it := range items {
		s, _ := rpc.KeyString(it.key)
		e, ok := entries[s]
		it.liveUntil, it.missing = nil, !ok
		if ok && e.LiveUntil != nil && *e.LiveUntil >= latest {
			v := *e.LiveUntil
			it.liveUntil = &v
		}
		out[i] = it
	}
	return out, latest, nil
}

// TTLCycle reads the remaining life of every entry the vault depends on, restores the archived
// ones and extends each one within renewWithin of expiry. The vault's instance and code, the tree,
// pending deposits and queued and stranded exits are extended renewStep past renewWithin. The asset
// contract's instance, the vault's balance and the nullifiers are extended to the network's
// maximum: they are so small that the fee every extension pays to write a TTL is about a day of
// their rent.
func (k *Keeper) TTLCycle(ctx context.Context) error {
	maxTTL, err := rpc.MaxEntryTTL(ctx, k.rpc)
	if err != nil {
		return err
	}
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return err
	}
	var failures []string

	instanceKey, _ := vault.InstanceKey(k.cfg.Vault)
	group := []tracked{{name: "vault instance", key: instanceKey}, {name: "vault code", key: vault.CodeKey(inst.WasmHash)}}
	treeKeys, err := vault.TreeKeys(k.cfg.Vault)
	if err != nil {
		return err
	}
	for _, key := range treeKeys {
		group = append(group, tracked{name: "tree entry", key: key})
	}
	for _, id := range k.pendingIDs() {
		key, err := vault.PendingKey(k.cfg.Vault, id)
		if err != nil {
			return err
		}
		group = append(group, tracked{name: fmt.Sprintf("pending deposit %d", id), key: key, optional: true})
	}
	exits, err := k.exitEntries()
	if err != nil {
		return err
	}
	group, latest, err := k.read(ctx, append(group, exits...))
	if err != nil {
		return err
	}
	if err := k.extend(ctx, group, renewWithin+renewStep, latest); err != nil {
		failures = append(failures, err.Error())
	}

	tokenInstance, err := vault.InstanceKey(inst.Config.Token)
	if err != nil {
		return err
	}
	balance, err := vault.BalanceKey(inst.Config.Token, k.cfg.Vault)
	if err != nil {
		return err
	}
	// The vault has no balance entry until its first deposit.
	others, _, err := k.read(ctx, []tracked{{name: "asset contract", key: tokenInstance}, {name: "vault balance", key: balance, optional: true}})
	if err != nil {
		return err
	}
	if err := k.extend(ctx, others, maxTTL-1, latest); err != nil {
		failures = append(failures, err.Error())
	}
	nfFailures, err := k.nullifiers(ctx, maxTTL)
	if err != nil {
		return err
	}
	failures = append(failures, nfFailures...)

	urgent := 0
	for _, t := range append(group, others...) {
		if t.urgent(latest) {
			urgent++
		}
	}
	if len(failures) > 0 {
		if urgent > 0 {
			k.alerts.Raise(ctx, alert.Critical, "entry_expiring", "%d entries are within 14 days of expiry and could not be extended: %v", urgent, failures)
		}
		return fmt.Errorf("ttl cycle incomplete: %v", failures)
	}
	k.mu.Lock()
	k.lastCycle = k.now()
	k.mu.Unlock()
	k.alerts.Clear(ctx, "entry_expiring", "every entry is extended")
	k.alerts.Clear(ctx, "ttl_cycle_stale", "the TTL cycle completed")
	return nil
}

// restore restores archived entries, in batches.
func (k *Keeper) restore(ctx context.Context, archived []xdr.LedgerKey) error {
	return inBatches(archived, k.cfg.MaxExtensions, func(keys []xdr.LedgerKey) error {
		what := fmt.Sprintf("restore of %d entries", len(keys))
		if _, err := k.call(ctx, what, func() (txnbuild.Operation, error) {
			return &txnbuild.RestoreFootprint{Ext: footprint(nil, keys)}, nil
		}); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		return nil
	})
}

// extend restores the archived entries among items, then extends them and those within
// renewWithin of expiry to `to` ledgers past the ledger each extension lands in, in batches.
func (k *Keeper) extend(ctx context.Context, items []tracked, to, latest uint32) error {
	var archived []xdr.LedgerKey
	var due []tracked
	for _, t := range items {
		switch {
		case t.gone():
		case t.liveUntil == nil:
			archived = append(archived, t.key)
			due = append(due, t)
		case t.due(latest):
			due = append(due, t)
		}
	}
	restored := k.restore(ctx, archived)
	if restored != nil && !errors.Is(restored, submit.ErrSimulation) {
		return restored
	}
	return errors.Join(restored, inBatches(due, k.cfg.MaxExtensions, func(batch []tracked) error {
		return k.extendBatch(ctx, batch, to, latest)
	}))
}

// extendBatch extends a batch of entries to `to` ledgers past the ledger it lands in. A lone entry
// whose rent the fee cap refuses is extended half as far, down to minStep, so that rent grown past
// the cap takes more transactions rather than the entry.
func (k *Keeper) extendBatch(ctx context.Context, batch []tracked, to, latest uint32) error {
	keys := make([]xdr.LedgerKey, len(batch))
	for i, t := range batch {
		keys[i] = t.key
	}
	what := fmt.Sprintf("extension of %d entries", len(keys))
	if len(batch) == 1 {
		what = "extension of the " + batch[0].name
	}
	for {
		_, err := k.call(ctx, what, func() (txnbuild.Operation, error) {
			return &txnbuild.ExtendFootprintTtl{ExtendTo: to, Ext: footprint(keys, nil)}, nil
		})
		if err == nil {
			return nil
		}
		left := uint32(0)
		if until := batch[0].liveUntil; until != nil {
			left = *until - latest
		}
		if len(batch) > 1 || !errors.Is(err, submit.ErrFeeCap) || to <= left || (to-left)/2 < minStep {
			return fmt.Errorf("%s: %w", what, err)
		}
		to = left + (to-left)/2
	}
}

// inBatches runs items through run in batches of at most size. A batch the simulation refuses, as
// when its fee is above the cap or one of its entries was archived since it was read, is split in
// two, so that one entry cannot hold back the others; the refusal of a lone item is reported once
// every batch has run. Any other failure stops the run.
func inBatches[T any](items []T, size int, run func([]T) error) error {
	var refused []error
	var do func([]T) error
	do = func(batch []T) error {
		err := run(batch)
		if !errors.Is(err, submit.ErrSimulation) {
			return err
		}
		if len(batch) == 1 {
			refused = append(refused, err)
			return nil
		}
		if err := do(batch[:len(batch)/2]); err != nil {
			return err
		}
		return do(batch[len(batch)/2:])
	}
	for start := 0; start < len(items); start += size {
		if err := do(items[start:min(start+size, len(items))]); err != nil {
			return err
		}
	}
	switch len(refused) {
	case 0:
		return nil
	case 1:
		return refused[0]
	}
	return fmt.Errorf("%w; %d more entries refused alone", refused[0], len(refused)-1)
}

func footprint(readOnly, readWrite []xdr.LedgerKey) xdr.TransactionExt {
	return xdr.TransactionExt{V: 1, SorobanData: &xdr.SorobanTransactionData{
		Resources: xdr.SorobanResources{Footprint: xdr.LedgerFootprint{ReadOnly: readOnly, ReadWrite: readWrite}},
	}}
}

// nullifiers extends spent-nullifier entries. Each entry's last known end of life is kept, so
// only entries that may be due are read again.
func (k *Keeper) nullifiers(ctx context.Context, maxTTL uint32) ([]string, error) {
	_, latest, err := k.chainTime(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := k.chain.Pool.Query(ctx, `SELECT seq, nullifier FROM nullifiers
		WHERE live_until IS NULL OR live_until < $1 ORDER BY seq`, int64(latest+renewWithin+ledgersPerDay))
	if err != nil {
		return nil, err
	}
	type nf struct {
		seq int64
		key xdr.LedgerKey
	}
	var list []nf
	for rows.Next() {
		var seq int64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		e, err := fr.SetBytes([32]byte(raw))
		if err != nil {
			rows.Close()
			return nil, err
		}
		key, err := vault.NullifierKey(k.cfg.Vault, e.Bytes())
		if err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, nf{seq, key})
	}
	rows.Close()
	var failures []string
	const readBatch = 200
	for start := 0; start < len(list); start += readBatch {
		chunk := list[start:min(start+readBatch, len(list))]
		items := make([]tracked, len(chunk))
		for i, n := range chunk {
			items[i] = tracked{name: "nullifier", key: n.key}
		}
		items, latest, err := k.read(ctx, items)
		if err != nil {
			return nil, err
		}
		urgent := 0
		for _, t := range items {
			if t.urgent(latest) {
				urgent++
			}
		}
		if err := k.extend(ctx, items, maxTTL-1, latest); err != nil {
			failures = append(failures, err.Error())
			if urgent > 0 {
				k.alerts.Raise(ctx, alert.Critical, "entry_expiring", "%d nullifier entries are within 14 days of expiry and could not be extended", urgent)
			}
			continue
		}
		// Only the life of an entry left as it was is known: an extended one is read again in the
		// next cycle, as the fee cap may have let it get less far than the maximum.
		for i, t := range items {
			if t.due(latest) {
				continue
			}
			if _, err := k.chain.Pool.Exec(ctx, `UPDATE nullifiers SET live_until = $2 WHERE seq = $1`, chunk[i].seq, int64(*t.liveUntil)); err != nil {
				return nil, err
			}
		}
	}
	return failures, nil
}

// Watch pages when the last complete TTL cycle is more than two hours old.
func (k *Keeper) Watch(ctx context.Context) {
	k.mu.Lock()
	if k.lastCycle.IsZero() {
		// Staleness counts from the first watch until a cycle completes.
		k.lastCycle = k.now()
	}
	last := k.lastCycle
	k.mu.Unlock()
	if k.now().Sub(last) > 2*time.Hour {
		k.alerts.Raise(ctx, alert.Critical, "ttl_cycle_stale", "the last complete TTL cycle was %s ago", k.now().Sub(last).Round(time.Minute))
	}
}

// exitEntries lists the entries of the queued and stranded exits the keeper has ingested.
func (k *Keeper) exitEntries() ([]tracked, error) {
	k.mu.RLock()
	head, tail := k.state.ExitHead, k.state.ExitTail
	stranded := slices.Sorted(maps.Keys(k.state.Stranded))
	k.mu.RUnlock()
	var out []tracked
	for id := head; id < tail; id++ {
		key, err := vault.ExitKey(k.cfg.Vault, id)
		if err != nil {
			return nil, err
		}
		out = append(out, tracked{name: fmt.Sprintf("exit %d", id), key: key, optional: true})
	}
	for _, id := range stranded {
		key, err := vault.StrandedKey(k.cfg.Vault, id)
		if err != nil {
			return nil, err
		}
		out = append(out, tracked{name: fmt.Sprintf("stranded exit %d", id), key: key, optional: true})
	}
	return out, nil
}
