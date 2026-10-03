package keeper

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// An entry within renewWithin of expiry is extended; one within warnWithin pages.
const (
	renewWithin = 30 * ledgersPerDay
	warnWithin  = 14 * ledgersPerDay
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

// TTLCycle reads the remaining life of every entry the vault depends on and extends each one within
// 30 days of expiry to the network's maximum: the instance, the tree and pending deposits through
// bump_ttl, and the code, the asset contract's entries, queued and stranded exits and the
// nullifiers by footprint.
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

	// Entries bump_ttl extends.
	instanceKey, _ := vault.InstanceKey(k.cfg.Vault)
	group := []tracked{{name: "vault instance", key: instanceKey}}
	treeKeys, err := vault.TreeKeys(k.cfg.Vault)
	if err != nil {
		return err
	}
	for _, key := range treeKeys {
		group = append(group, tracked{name: "tree entry", key: key})
	}
	ids := k.pendingIDs()
	for _, id := range ids {
		key, err := vault.PendingKey(k.cfg.Vault, id)
		if err != nil {
			return err
		}
		group = append(group, tracked{name: fmt.Sprintf("pending deposit %d", id), key: key, optional: true})
	}
	group, latest, err := k.read(ctx, group)
	if err != nil {
		return err
	}
	bump := false
	var duePending []xdr.ScVal
	for i, t := range group {
		if !t.due(latest) {
			continue
		}
		bump = true
		if i >= 1+len(treeKeys) {
			duePending = append(duePending, vault.U64(ids[i-1-len(treeKeys)]))
		}
	}
	if bump {
		if _, err := k.call(ctx, "bump_ttl", func() (txnbuild.Operation, error) {
			return k.invoke("bump_ttl", vault.Vec(duePending...))
		}); err != nil {
			failures = append(failures, "bump_ttl")
		}
	}

	// Entries only a footprint extension reaches.
	codeKey := vault.CodeKey(inst.WasmHash)
	tokenInstance, err := vault.InstanceKey(inst.Config.Token)
	if err != nil {
		return err
	}
	balance, err := vault.BalanceKey(inst.Config.Token, k.cfg.Vault)
	if err != nil {
		return err
	}
	// The vault has no balance entry until its first deposit.
	others := []tracked{{name: "vault code", key: codeKey}, {name: "asset contract", key: tokenInstance}, {name: "vault balance", key: balance, optional: true}}
	exits, err := k.exitEntries()
	if err != nil {
		return err
	}
	others, _, err = k.read(ctx, append(others, exits...))
	if err != nil {
		return err
	}
	if err := k.extend(ctx, others, maxTTL, latest); err != nil {
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

// extend restores archived entries, then extends those within 30 days of expiry, in batches.
func (k *Keeper) extend(ctx context.Context, items []tracked, maxTTL, latest uint32) error {
	var archived, due []xdr.LedgerKey
	for _, t := range items {
		switch {
		case t.gone():
		case t.liveUntil == nil:
			archived = append(archived, t.key)
			due = append(due, t.key)
		case t.due(latest):
			due = append(due, t.key)
		}
	}
	for start := 0; start < len(archived); start += k.cfg.MaxExtensions {
		keys := archived[start:min(start+k.cfg.MaxExtensions, len(archived))]
		if _, err := k.call(ctx, fmt.Sprintf("restore of %d entries", len(keys)), func() (txnbuild.Operation, error) {
			return &txnbuild.RestoreFootprint{Ext: footprint(nil, keys)}, nil
		}); err != nil {
			return err
		}
	}
	for start := 0; start < len(due); start += k.cfg.MaxExtensions {
		keys := due[start:min(start+k.cfg.MaxExtensions, len(due))]
		if _, err := k.call(ctx, fmt.Sprintf("extension of %d entries", len(keys)), func() (txnbuild.Operation, error) {
			return &txnbuild.ExtendFootprintTtl{ExtendTo: maxTTL - 1, Ext: footprint(keys, nil)}, nil
		}); err != nil {
			return err
		}
	}
	return nil
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
		if err := k.extend(ctx, items, maxTTL, latest); err != nil {
			failures = append(failures, err.Error())
			if urgent > 0 {
				k.alerts.Raise(ctx, alert.Critical, "entry_expiring", "%d nullifier entries are within 14 days of expiry and could not be extended", urgent)
			}
			continue
		}
		for i, t := range items {
			until := int64(latest + maxTTL - 1)
			if !t.due(latest) {
				until = int64(*t.liveUntil)
			}
			if _, err := k.chain.Pool.Exec(ctx, `UPDATE nullifiers SET live_until = $2 WHERE seq = $1`, chunk[i].seq, until); err != nil {
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
