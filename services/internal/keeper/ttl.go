package keeper

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// The vault's own writes extend an entry once it has 30 days or less left, at the cost of the
// transaction that writes it, and every user transaction writes the vault's instance, which
// extends the code with it, and its tree entries. The keeper renews those within holdWithin of
// expiry, so that it may stop for two weeks before a user pays their rent, and every other entry
// within renewWithin. It pages for an entry within warnWithin of expiry that it could not extend.
const (
	holdWithin  = 45 * ledgersPerDay
	renewWithin = 31 * ledgersPerDay
	warnWithin  = 14 * ledgersPerDay
	// renewStep is how far past its threshold an entry is extended, unless it goes to the network's
	// maximum: each extension pays about a day of rent, whatever the threshold.
	renewStep = ledgersPerDay
	// minStep is the shortest extension tried for a lone entry whose longer ones the fee cap
	// refuses: an hourly cycle that adds less loses ground.
	minStep = ledgersPerDay / 24
	// cycleCaps is how many times the TTL fee cap the transactions of one cycle may be charged; the
	// entries left wait for the next cycle.
	cycleCaps = 10
)

// errCycleSpent stops a TTL cycle whose transactions have been charged cycleCaps times the fee cap.
var errCycleSpent = fmt.Errorf("the cycle's transactions were charged %d times the TTL fee cap", cycleCaps)

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

// treeNames names the entries vault.TreeKeys returns, in its order.
var treeNames = [...]string{"Roots", "Frontier", "NextLeaf"}

// TTLCycle reads the remaining life of every entry the vault depends on, restores the archived
// ones and extends those near expiry. The vault's instance and code and the tree entries are
// extended renewStep past holdWithin. Pending deposits and queued and stranded exits, whose rent is
// lost when the vault deletes them, are extended renewStep past renewWithin. The asset contract's
// instance, the vault's balance and the nullifiers go to the network's maximum: they are so small
// that the fee every extension pays to write a TTL is about a day of their rent.
func (k *Keeper) TTLCycle(ctx context.Context) error {
	maxTTL, err := rpc.MaxEntryTTL(ctx, k.rpc)
	if err != nil {
		return err
	}
	inst, _, _, err := rpc.VaultInstance(ctx, k.rpc, k.cfg.Vault)
	if err != nil {
		return err
	}
	k.charged = 0
	var failures []string
	fail := func(err error) {
		if err != nil {
			failures = append(failures, err.Error())
		}
	}

	instanceKey, _ := vault.InstanceKey(k.cfg.Vault)
	own := []tracked{{name: "vault instance", key: instanceKey}, {name: "vault code", key: vault.CodeKey(inst.WasmHash)}}
	treeKeys, err := vault.TreeKeys(k.cfg.Vault)
	if err != nil {
		return err
	}
	for i, key := range treeKeys {
		own = append(own, tracked{name: treeNames[i], key: key})
	}
	var queued []tracked
	for _, id := range k.pendingIDs() {
		key, err := vault.PendingKey(k.cfg.Vault, id)
		if err != nil {
			return err
		}
		queued = append(queued, tracked{name: fmt.Sprintf("pending deposit %d", id), key: key, optional: true})
	}
	exits, err := k.exitEntries()
	if err != nil {
		return err
	}
	queued = append(queued, exits...)
	n := len(own)
	read, latest, err := k.read(ctx, append(own, queued...))
	if err != nil {
		return err
	}
	own, err = k.extend(ctx, read[:n], holdWithin, holdWithin+renewStep, latest)
	fail(err)
	queued, err = k.extend(ctx, read[n:], renewWithin, renewWithin+renewStep, latest)
	fail(err)

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
	others, err = k.extend(ctx, others, renewWithin, maxTTL-1, latest)
	fail(err)
	nfFailures, err := k.nullifiers(ctx, maxTTL)
	if err != nil {
		fail(fmt.Errorf("nullifiers: %w", err))
	}
	failures = append(failures, nfFailures...)

	// An entry of the vault's own a day below holdWithin has missed a day of renewals, long before
	// the vault's writes would make users pay for it.
	var behind []string
	for _, t := range own {
		if t.liveUntil == nil || *t.liveUntil < latest+holdWithin-ledgersPerDay {
			behind = append(behind, t.name)
		}
	}
	if len(behind) > 0 {
		k.alerts.Raise(ctx, alert.Warning, "ttl_behind", "%s: more than a day below the %d days the keeper holds them at; users pay their rent below 30 days", strings.Join(behind, ", "), holdWithin/ledgersPerDay)
	} else {
		k.alerts.Clear(ctx, "ttl_behind", "the vault's instance, code and tree entries are held again")
	}
	urgent := 0
	for _, t := range slices.Concat(own, queued, others) {
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

// extend restores the archived entries among items, then extends them and those within renewAt of
// expiry to `to` ledgers past the ledger each extension lands in, in batches. An entry whose
// restoration fails is left out, and holds back no other. It returns items with the life their
// restoration or extension gave them, at the least.
func (k *Keeper) extend(ctx context.Context, items []tracked, renewAt, to, latest uint32) ([]tracked, error) {
	out := slices.Clone(items)
	var archived, due []*tracked
	for i := range out {
		t := &out[i]
		switch {
		case t.gone():
		case t.liveUntil == nil:
			archived = append(archived, t)
		case *t.liveUntil < latest+renewAt:
			due = append(due, t)
		}
	}
	restored := k.restore(ctx, archived)
	for _, t := range archived {
		if t.liveUntil != nil && *t.liveUntil < latest+renewAt {
			due = append(due, t)
		}
	}
	extended := inBatches(due, k.cfg.MaxExtensions, func(batch []*tracked) error {
		return k.extendBatch(ctx, batch, to, latest)
	})
	return out, errors.Join(restored, extended)
}

// restore restores archived entries, in batches, then reads the life the network gave the ones it
// restored: its least for a persistent entry, which differs between networks.
func (k *Keeper) restore(ctx context.Context, archived []*tracked) error {
	var restored []*tracked
	err := inBatches(archived, k.cfg.MaxExtensions, func(batch []*tracked) error {
		keys := keysOf(batch)
		what := fmt.Sprintf("restore of %d entries", len(keys))
		if err := k.ttlCall(ctx, what, func() (txnbuild.Operation, error) {
			return &txnbuild.RestoreFootprint{Ext: footprint(nil, keys)}, nil
		}); err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		restored = append(restored, batch...)
		return nil
	})
	if len(restored) == 0 {
		return err
	}
	items := make([]tracked, len(restored))
	for i, t := range restored {
		items[i] = *t
	}
	read, _, readErr := k.read(ctx, items)
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	for i, t := range restored {
		t.liveUntil = read[i].liveUntil
	}
	return err
}

// extendBatch extends a batch of entries to `to` ledgers past the ledger it lands in, and records
// the life that gives them. A lone entry whose rent the fee cap refuses is extended half as far,
// and at last exactly minStep past its life, so that rent grown past the cap takes more
// transactions rather than the entry.
func (k *Keeper) extendBatch(ctx context.Context, batch []*tracked, to, latest uint32) error {
	keys := keysOf(batch)
	what := fmt.Sprintf("extension of %d entries", len(keys))
	if len(batch) == 1 {
		what = "extension of the " + batch[0].name
	}
	for {
		err := k.ttlCall(ctx, what, func() (txnbuild.Operation, error) {
			return &txnbuild.ExtendFootprintTtl{ExtendTo: to, Ext: footprint(keys, nil)}, nil
		})
		if err == nil {
			life := latest + to
			for _, t := range batch {
				if *t.liveUntil < life {
					t.liveUntil = &life
				}
			}
			return nil
		}
		left := *batch[0].liveUntil - latest
		if len(batch) > 1 || !errors.Is(err, submit.ErrFeeCap) || to <= left+minStep {
			return fmt.Errorf("%s: %w", what, err)
		}
		to = left + max((to-left)/2, minStep)
	}
}

// ttlCall runs one extension or restoration, unless the transactions of the cycle have been
// charged cycleCaps times the fee cap of such transactions already.
func (k *Keeper) ttlCall(ctx context.Context, what string, build func() (txnbuild.Operation, error)) error {
	if limit := k.engine.TTLFeeCap(); limit > 0 && k.charged >= cycleCaps*limit {
		return errCycleSpent
	}
	res, err := k.call(ctx, what, build)
	k.charged += res.FeeCharged
	return err
}

func keysOf(batch []*tracked) []xdr.LedgerKey {
	keys := make([]xdr.LedgerKey, len(batch))
	for i, t := range batch {
		keys[i] = t.key
	}
	return keys
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
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
		items, err = k.extend(ctx, items, renewWithin, maxTTL-1, latest)
		if err != nil {
			failures = append(failures, err.Error())
			urgent := 0
			for _, t := range items {
				if t.urgent(latest) {
					urgent++
				}
			}
			if urgent > 0 {
				k.alerts.Raise(ctx, alert.Critical, "entry_expiring", "%d nullifier entries are within 14 days of expiry and could not be extended", urgent)
			}
		}
		// The life recorded for an extended entry is the least its extension gave it, so the entry
		// is read again no later than it is due.
		for i, t := range items {
			if t.liveUntil == nil {
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
