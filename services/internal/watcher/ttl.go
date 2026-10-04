package watcher

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// expiryWarning is how close to expiry an entry may come before the watcher pages.
const expiryWarning = 14 * ledgersPerDay

// writeWarning is how close to expiry the vault's instance, code and tree entries may come before
// the watcher warns: a day above the 30 days below which every user transaction, which writes
// them, also pays their rent. A keeper that renews them keeps them far above it.
const writeWarning = 31 * ledgersPerDay

// entry is a ledger entry the vault depends on. An optional one may be gone by the time it is
// read, such as a deposit admitted meanwhile. A written one is one that every user transaction
// extends once it has 30 days or less left: the vault's instance, its code or a tree entry.
type entry struct {
	name     string
	key      xdr.LedgerKey
	optional bool
	written  bool
}

// CheckTTL pages when any entry the vault depends on is archived or within 14 days of expiry: the
// instance, the tree, the code, the asset contract, the vault's balance, pending deposits, queued
// and stranded exits, and every spent nullifier. It warns when the instance, the code or a tree
// entry comes within writeWarning of expiry.
func (w *Watcher) CheckTTL(ctx context.Context) error {
	w.mu.RLock()
	inst := w.inst
	pending := slices.Sorted(maps.Keys(w.state.Pending))
	head, tail := w.state.ExitHead, w.state.ExitTail
	stranded := slices.Sorted(maps.Keys(w.state.Stranded))
	w.mu.RUnlock()
	if inst == nil {
		return nil
	}
	var entries []entry
	add := func(name string, optional bool, key xdr.LedgerKey, err error) error {
		if err != nil {
			return err
		}
		entries = append(entries, entry{name, key, optional, false})
		return nil
	}
	instKey, err := vault.InstanceKey(w.cfg.Vault)
	if err != nil {
		return err
	}
	tree, err := vault.TreeKeys(w.cfg.Vault)
	if err != nil {
		return err
	}
	entries = append(entries, entry{"vault instance", instKey, false, true}, entry{"vault code", vault.CodeKey(inst.WasmHash), false, true})
	for _, k := range tree {
		entries = append(entries, entry{"tree entry", k, false, true})
	}
	tokenKey, err := vault.InstanceKey(inst.Config.Token)
	if err := add("asset contract", false, tokenKey, err); err != nil {
		return err
	}
	balance, err := vault.BalanceKey(inst.Config.Token, w.cfg.Vault)
	if err := add("vault balance", true, balance, err); err != nil {
		return err
	}
	for _, id := range pending {
		k, err := vault.PendingKey(w.cfg.Vault, id)
		if err := add(fmt.Sprintf("pending deposit %d", id), true, k, err); err != nil {
			return err
		}
	}
	for id := head; id < tail; id++ {
		k, err := vault.ExitKey(w.cfg.Vault, id)
		if err := add(fmt.Sprintf("exit %d", id), true, k, err); err != nil {
			return err
		}
	}
	for _, id := range stranded {
		k, err := vault.StrandedKey(w.cfg.Vault, id)
		if err := add(fmt.Sprintf("stranded exit %d", id), true, k, err); err != nil {
			return err
		}
	}
	keys := make([]xdr.LedgerKey, len(entries))
	for i, e := range entries {
		keys[i] = e.key
	}
	found, latest, err := rpc.Entries(ctx, w.rpc, keys)
	if err != nil {
		return err
	}
	var expiring, unrenewed []string
	for _, e := range entries {
		got, ok := found[mustKeyString(e.key)]
		switch {
		case !ok && e.optional:
		case !ok:
			expiring = append(expiring, e.name+" is missing")
		case got.LiveUntil != nil && *got.LiveUntil < latest:
			expiring = append(expiring, e.name+" is archived")
		case got.LiveUntil != nil && *got.LiveUntil < latest+expiryWarning:
			expiring = append(expiring, fmt.Sprintf("%s expires in %d ledgers", e.name, *got.LiveUntil-latest))
		case e.written && got.LiveUntil != nil && *got.LiveUntil < latest+writeWarning:
			unrenewed = append(unrenewed, fmt.Sprintf("%s expires in %d ledgers", e.name, *got.LiveUntil-latest))
		}
	}
	if len(unrenewed) > 0 {
		w.alerts.Raise(ctx, alert.Warning, "renewal_late", "the keeper is not renewing the vault's entries, and below 30 days every user transaction pays their rent: %v", unrenewed)
	} else {
		w.alerts.Clear(ctx, "renewal_late", "the vault's instance, code and tree entries have more than 31 days left")
	}
	n, err := w.expiringNullifiers(ctx, latest)
	if err != nil {
		return err
	}
	if n > 0 {
		expiring = append(expiring, fmt.Sprintf("%d nullifier entries", n))
	}
	if len(expiring) > 0 {
		w.alerts.Raise(ctx, alert.Critical, "entry_expiring", "within 14 days of expiry or archived: %v", expiring)
	} else {
		w.alerts.Clear(ctx, "entry_expiring", "every entry has more than 14 days left")
	}
	return nil
}

// expiringNullifiers counts spent-nullifier entries within 14 days of expiry or archived. Each
// entry's last known end of life is kept, so only those that may be near it are read again.
func (w *Watcher) expiringNullifiers(ctx context.Context, latest uint32) (int, error) {
	rows, err := w.chain.Pool.Query(ctx, `SELECT seq, nullifier FROM nullifiers
		WHERE live_until IS NULL OR live_until < $1 ORDER BY seq`, int64(latest+expiryWarning+ledgersPerDay))
	if err != nil {
		return 0, err
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
			return 0, err
		}
		e, err := fr.SetBytes([32]byte(raw))
		if err != nil {
			rows.Close()
			return 0, err
		}
		key, err := vault.NullifierKey(w.cfg.Vault, e.Bytes())
		if err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, nf{seq, key})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	expiring := 0
	for start := 0; start < len(list); start += 200 {
		chunk := list[start:min(start+200, len(list))]
		keys := make([]xdr.LedgerKey, len(chunk))
		for i, n := range chunk {
			keys[i] = n.key
		}
		found, at, err := rpc.Entries(ctx, w.rpc, keys)
		if err != nil {
			return 0, err
		}
		for _, n := range chunk {
			e, ok := found[mustKeyString(n.key)]
			if !ok || e.LiveUntil == nil || *e.LiveUntil < at+expiryWarning {
				expiring++
				continue
			}
			if _, err := w.chain.Pool.Exec(ctx, `UPDATE nullifiers SET live_until = $2 WHERE seq = $1`, n.seq, int64(*e.LiveUntil)); err != nil {
				return 0, err
			}
		}
	}
	return expiring, nil
}
