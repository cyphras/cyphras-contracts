package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/follow"
	"github.com/cyphras/cyphras-contracts/services/internal/freeze"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// vaultKeys are the entries Reconcile reads: the instance, the next leaf, the root ring and the
// vault's balance in its asset contract.
func (w *Watcher) vaultKeys(token string) ([]xdr.LedgerKey, error) {
	inst, err := vault.InstanceKey(w.cfg.Vault)
	if err != nil {
		return nil, err
	}
	next, err := vault.NextLeafKey(w.cfg.Vault)
	if err != nil {
		return nil, err
	}
	roots, err := vault.RootsKey(w.cfg.Vault)
	if err != nil {
		return nil, err
	}
	balance, err := vault.BalanceKey(token, w.cfg.Vault)
	if err != nil {
		return nil, err
	}
	return []xdr.LedgerKey{inst, next, roots, balance}, nil
}

// Reconcile compares the watcher's own state with the vault's storage as the primary RPC reports
// it, checks the vault's balance against tvl, and compares the primary RPC with the second one.
func (w *Watcher) Reconcile(ctx context.Context) error {
	inst, _, _, err := rpc.VaultInstance(ctx, w.rpc, w.cfg.Vault)
	if err != nil {
		return err
	}
	keys, err := w.vaultKeys(inst.Config.Token)
	if err != nil {
		return err
	}
	entries, latest, err := rpc.Entries(ctx, w.rpc, keys)
	if err != nil {
		return err
	}
	health, err := w.rpc.GetHealth(ctx)
	if err != nil {
		return err
	}
	now := uint64(health.LatestLedgerCloseTime)
	w.mu.Lock()
	w.inst = &inst
	w.latest = max(w.latest, latest)
	cursor := w.cursor
	if e, ok := entries[mustKeyString(keys[0])]; ok {
		w.reads = append(w.reads, statusRead{inst: inst, from: e.LastModified, to: latest, now: now})
		if len(w.reads) > 16 {
			w.reads = w.reads[1:]
		}
	}
	w.mu.Unlock()

	if cursor+60 < latest {
		w.alerts.Raise(ctx, alert.Warning, "watcher_lagging", "the watcher has checked up to ledger %d of %d", cursor, latest)
	} else {
		w.alerts.Clear(ctx, "watcher_lagging", "the watcher caught up")
	}
	problems, compared := w.compareReads()
	nextEntry, ok1 := entries[mustKeyString(keys[1])]
	rootsEntry, ok2 := entries[mustKeyString(keys[2])]
	if !ok1 || !ok2 {
		problems = append(problems, "the vault's tree entries are missing")
	} else if p, ok := w.treeDiff(nextEntry, rootsEntry); ok {
		compared = true
		if p != "" {
			problems = append(problems, p)
		}
	}
	switch {
	case len(problems) > 0:
		w.alerts.Raise(ctx, alert.Critical, "state_mismatch", "at ledger %d: %s", cursor, strings.Join(problems, "; "))
	case compared:
		w.alerts.Clear(ctx, "state_mismatch", "the watcher agrees with the vault again")
	}

	balance, authorized := new(big.Int), true
	if e, ok := entries[mustKeyString(keys[3])]; ok {
		v, err := rpc.ContractValue(e)
		if err != nil {
			return err
		}
		if balance, authorized, err = vault.DecodeBalance(v); err != nil {
			return err
		}
	}
	w.checkAuthorization(ctx, authorized)
	if balance.Cmp(inst.Status.Tvl) < 0 {
		w.alerts.Raise(ctx, alert.Critical, "balance_below_tvl", "the vault holds %v of its asset but owes %v", balance, inst.Status.Tvl)
	} else {
		w.alerts.Clear(ctx, "balance_below_tvl", "the vault's balance covers tvl again")
	}
	if today := inst.Status.OutflowOn(now / secondsPerDay); today.Cmp(inst.Limits.MaxDailyOutflow) > 0 {
		w.alerts.Raise(ctx, alert.Critical, "outflow_over_cap", "the vault reports today's outflow %v above max_daily_outflow %v", today, inst.Limits.MaxDailyOutflow)
	}
	w.compareProviders(ctx, keys, entries, latest)
	w.crossCheckEvents(ctx)
	return nil
}

// checkAuthorization pages when the asset's issuer stops letting the vault hold the asset, which
// stops every payment out of it, and reports any change of that authorization.
func (w *Watcher) checkAuthorization(ctx context.Context, authorized bool) {
	w.mu.Lock()
	changed := w.authorized != nil && *w.authorized != authorized
	w.authorized = &authorized
	w.mu.Unlock()
	if changed {
		w.alerts.Raise(ctx, alert.Critical, fmt.Sprintf("vault_authorization_%t", authorized), "the issuer changed the vault's authorization to hold the asset to %t", authorized)
	}
	if !authorized {
		w.alerts.Raise(ctx, alert.Critical, "vault_deauthorized", "the issuer does not let the vault hold the asset: no exit can be paid")
	} else {
		w.alerts.Clear(ctx, "vault_deauthorized", "the vault may hold the asset again")
	}
}

// statusDiff lists the fields where the vault's status and the watcher's replay differ.
func statusDiff(inst vault.Instance, s snapshot, now uint64) []string {
	st, ours := inst.Status, s.status
	var out []string
	check := func(name string, equal bool, chain, replayed any) {
		if !equal {
			out = append(out, fmt.Sprintf("%s is %v on chain, %v replayed", name, chain, replayed))
		}
	}
	check("tvl", st.Tvl.Cmp(ours.Tvl) == 0, st.Tvl, ours.Tvl)
	check("pending_total", st.PendingTotal.Cmp(ours.PendingTotal) == 0, st.PendingTotal, ours.PendingTotal)
	check("queued_total", st.QueuedTotal.Cmp(ours.QueuedTotal) == 0, st.QueuedTotal, ours.QueuedTotal)
	check("exit_head", st.ExitHead == ours.ExitHead, st.ExitHead, ours.ExitHead)
	check("exit_tail", st.ExitTail == ours.ExitTail, st.ExitTail, ours.ExitTail)
	check("next_deposit_id", st.NextDepositID == ours.NextDepositID, st.NextDepositID, ours.NextDepositID)
	check("attested_up_to", st.AttestedUpTo == ours.AttestedUpTo, st.AttestedUpTo, ours.AttestedUpTo)
	check("deposits_paused", st.DepositsPaused == ours.DepositsPaused, st.DepositsPaused, ours.DepositsPaused)
	check("transfers_paused", st.TransfersPaused == ours.TransfersPaused, st.TransfersPaused, ours.TransfersPaused)
	check("halted_until", st.HaltedUntil == ours.HaltedUntil, st.HaltedUntil, ours.HaltedUntil)
	check("next_halt_at", st.NextHaltAt == ours.NextHaltAt, st.NextHaltAt, ours.NextHaltAt)
	day := now / secondsPerDay
	check("today's outflow", st.OutflowOn(day).Cmp(ours.OutflowOn(day)) == 0, st.OutflowOn(day), ours.OutflowOn(day))
	if s.limits != nil {
		check("limits", limitsText(*s.limits) == limitsText(inst.Limits), limitsText(inst.Limits), limitsText(*s.limits))
	}
	return out
}

// compareReads compares each read of the vault's status with the replayed state at a ledger the
// read is valid for, once the watcher has replayed that far, and drops reads too old to match.
func (w *Watcher) compareReads() ([]string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var problems []string
	compared := false
	keep := w.reads[:0]
	for _, r := range w.reads {
		var match *snapshot
		for i := len(w.snapshots) - 1; i >= 0; i-- {
			if l := w.snapshots[i].ledger; l >= r.from && l <= r.to {
				match = &w.snapshots[i]
				break
			}
		}
		switch {
		case match != nil:
			compared = true
			problems = append(problems, statusDiff(r.inst, *match, r.now)...)
		case r.to > w.cursor:
			keep = append(keep, r)
		}
	}
	w.reads = keep
	return problems, compared
}

// treeDiff compares the vault's current root with the watcher's root at the vault's leaf count;
// it reports false when the watcher has no root at that count yet.
func (w *Watcher) treeDiff(next, roots rpc.Entry) (string, bool) {
	nextVal, err := rpc.ContractValue(next)
	if err != nil {
		return "the next leaf entry is not contract data", true
	}
	n, ok := nextVal.GetU64()
	if !ok {
		return "the next leaf entry is not a u64", true
	}
	ringVal, err := rpc.ContractValue(roots)
	if err != nil {
		return "the root ring is not contract data", true
	}
	ring, err := vault.DecodeRootRing(ringVal)
	if err != nil {
		return "the root ring does not decode", true
	}
	w.mu.RLock()
	ours, known := w.roots[uint64(n)]
	w.mu.RUnlock()
	if !known {
		return "", false
	}
	if ring.Current() != ours {
		return fmt.Sprintf("at %d leaves the vault has root %s, the watcher %s", uint64(n), ring.Current().Hex(), ours.Hex()), true
	}
	return "", true
}

// compareProviders reads the same entries from the second RPC and pages when an entry that both
// report at the same last-modified ledger differs, or when the second falls far behind.
func (w *Watcher) compareProviders(ctx context.Context, keys []xdr.LedgerKey, primary map[string]rpc.Entry, latest uint32) {
	other, otherLatest, err := rpc.Entries(ctx, w.second, keys)
	if err != nil {
		w.secondFailed(ctx, err)
		return
	}
	w.secondAnswered(ctx)
	if otherLatest+60 < latest {
		w.alerts.Raise(ctx, alert.Warning, "second_rpc_lagging", "the second RPC is at ledger %d, the primary at %d", otherLatest, latest)
	} else {
		w.alerts.Clear(ctx, "second_rpc_lagging", "the second RPC caught up")
	}
	for _, k := range keys {
		s := mustKeyString(k)
		a, okA := primary[s]
		b, okB := other[s]
		if !okA || !okB || a.LastModified != b.LastModified {
			continue
		}
		ra, _ := xdr.MarshalBase64(a.Data)
		rb, _ := xdr.MarshalBase64(b.Data)
		if ra != rb {
			w.alerts.Raise(ctx, alert.Critical, "rpc_disagreement", "the two RPC providers report different contents for a vault entry last modified in ledger %d", a.LastModified)
		}
	}
}

func (w *Watcher) secondFailed(ctx context.Context, err error) {
	w.mu.Lock()
	w.crossFails++
	fails := w.crossFails
	w.mu.Unlock()
	if fails >= 3 {
		w.alerts.Raise(ctx, alert.Warning, "second_rpc_unavailable", "the second RPC failed %d times in a row: %v", fails, err)
	}
}

func (w *Watcher) secondAnswered(ctx context.Context) {
	w.mu.Lock()
	w.crossFails = 0
	w.mu.Unlock()
	w.alerts.Clear(ctx, "second_rpc_unavailable", "the second RPC answers again")
}

// crossCheckEvents reads each applied window again from the second RPC once it has reached it,
// and pages when the two disagree on any vault event.
func (w *Watcher) crossCheckEvents(ctx context.Context) {
	h, err := w.second.GetHealth(ctx)
	if err != nil {
		w.secondFailed(ctx, err)
		return
	}
	w.mu.Lock()
	var ready []follow.Batch
	keep := w.pendingCross[:0]
	for _, b := range w.pendingCross {
		if b.To <= h.LatestLedger {
			ready = append(ready, b)
		} else {
			keep = append(keep, b)
		}
	}
	w.pendingCross = keep
	w.mu.Unlock()
	src := follow.RPCSource{Client: w.second, Contract: w.cfg.Vault, PageLimit: 1000}
	for _, b := range ready {
		events, err := src.Events(ctx, b.From, b.To)
		if errors.Is(err, follow.ErrRetention) {
			continue
		}
		if err != nil {
			w.secondFailed(ctx, err)
			w.mu.Lock()
			w.pendingCross = append([]follow.Batch{b}, w.pendingCross...)
			w.mu.Unlock()
			return
		}
		if !slices.EqualFunc(events, b.Raw, sameEvent) {
			w.alerts.Raise(ctx, alert.Critical, fmt.Sprintf("rpc_disagreement_%d", b.To), "the two RPC providers report different vault events in ledgers %d to %d", b.From, b.To)
		}
	}
}

func sameEvent(a, b vault.RawEvent) bool {
	return a.Pos() == b.Pos() && a.TxHash == b.TxHash && a.Contract == b.Contract && a.Value == b.Value && slices.Equal(a.Topics, b.Topics)
}

// CheckIndexer compares the indexer's root with the watcher's root at the same leaf count.
func (w *Watcher) CheckIndexer(ctx context.Context) error {
	if w.cfg.IndexerURL == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(w.cfg.IndexerURL, "/")+"/v1/health", nil)
	if err != nil {
		return err
	}
	resp, err := w.http.Do(req)
	if err != nil {
		return errors.New("indexer unreachable")
	}
	defer resp.Body.Close()
	var h struct {
		LeafCount uint64 `json:"leaf_count"`
		Root      string `json:"root"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h); err != nil {
		return errors.New("indexer health unreadable")
	}
	w.mu.RLock()
	root, ok := w.roots[h.LeafCount]
	w.mu.RUnlock()
	if !ok {
		return nil
	}
	if root.Hex() != h.Root {
		w.alerts.Raise(ctx, alert.Critical, "indexer_root_mismatch", "at %d leaves the indexer serves root %s, the watcher has %s", h.LeafCount, h.Root, root.Hex())
	} else {
		w.alerts.Clear(ctx, "indexer_root_mismatch", "the indexer's root matches again")
	}
	return nil
}

// CheckHealth pages when a health endpoint fails twice in a row.
func (w *Watcher) CheckHealth(ctx context.Context) error {
	for i, u := range w.cfg.HealthURLs {
		code := fmt.Sprintf("health_failing_%d", i)
		ok := false
		if req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil); err == nil {
			if resp, err := w.http.Do(req); err == nil {
				ok = resp.StatusCode == http.StatusOK
				resp.Body.Close()
			}
		}
		w.mu.Lock()
		if ok {
			w.healthFails[u] = 0
		} else {
			w.healthFails[u]++
		}
		fails := w.healthFails[u]
		w.mu.Unlock()
		switch {
		case fails >= 2:
			w.alerts.Raise(ctx, alert.Warning, code, "%s failed %d health checks in a row", u, fails)
		case ok:
			w.alerts.Clear(ctx, code, "%s is healthy again", u)
		}
	}
	return nil
}

// CheckGovernanceAccounts pages, also publicly, when the signers or thresholds of the guardian or
// asp account change, or the code of either when it is a contract.
func (w *Watcher) CheckGovernanceAccounts(ctx context.Context) error {
	w.mu.RLock()
	inst := w.inst
	w.mu.RUnlock()
	if inst == nil {
		return nil
	}
	for _, a := range []struct{ role, address string }{{"guardian", inst.Config.Guardian}, {"asp", inst.Config.ASP}} {
		fp, err := w.fingerprint(ctx, a.address)
		if err != nil {
			return err
		}
		key := "fingerprint:" + a.address
		old, ok, err := w.db.meta(ctx, key)
		if err != nil {
			return err
		}
		if ok && old != fp {
			msg := fmt.Sprintf("the %s account %s changed: %s, was %s", a.role, a.address, fp, old)
			w.alerts.Raise(ctx, alert.Critical, "governance_account_"+a.role+"_"+fp, "%s", msg)
			w.public.Raise(ctx, alert.Info, "governance_account_"+a.role+"_"+fp, "%s", msg)
		}
		if !ok || old != fp {
			if err := w.db.setMeta(ctx, key, fp); err != nil {
				return err
			}
		}
	}
	return nil
}

// fingerprint describes what controls an address: an account's thresholds and signers, or a
// contract's executable.
func (w *Watcher) fingerprint(ctx context.Context, address string) (string, error) {
	if strings.HasPrefix(address, "C") {
		key, err := vault.InstanceKey(address)
		if err != nil {
			return "", err
		}
		e, _, err := rpc.One(ctx, w.rpc, key)
		if err != nil {
			return "", err
		}
		v, err := rpc.ContractValue(e)
		if err != nil {
			return "", err
		}
		inst, ok := v.GetInstance()
		if !ok {
			return "", errors.New("not a contract instance")
		}
		exe, err := xdr.MarshalBase64(inst.Executable)
		return "executable " + exe, err
	}
	key, err := vault.AccountKey(address)
	if err != nil {
		return "", err
	}
	e, _, err := rpc.One(ctx, w.rpc, key)
	if err != nil {
		return "", err
	}
	acct := e.Data.Account
	if acct == nil {
		return "", errors.New("not an account")
	}
	var signers []string
	for _, s := range acct.Signers {
		addr, err := s.Key.GetAddress()
		if err != nil {
			addr = "other"
		}
		signers = append(signers, fmt.Sprintf("%s:%d", addr, s.Weight))
	}
	slices.Sort(signers)
	t := acct.Thresholds
	return fmt.Sprintf("thresholds %d/%d/%d/%d signers [%s]", t[0], t[1], t[2], t[3], strings.Join(signers, " ")), nil
}

// CheckFreezes pages when a CAP-77 freeze touches the vault, its code, its asset contract or a
// service account.
func (w *Watcher) CheckFreezes(ctx context.Context) error {
	w.mu.RLock()
	inst := w.inst
	w.mu.RUnlock()
	if inst == nil {
		return nil
	}
	set, err := freeze.Read(ctx, w.rpc)
	if err != nil {
		return err
	}
	var touched []string
	for _, a := range append([]string{w.cfg.Vault, inst.Config.Token, inst.Config.Guardian, inst.Config.ASP}, w.cfg.ServiceAccounts...) {
		if set.Touches(a) {
			touched = append(touched, a)
		}
	}
	if set.Codes[inst.WasmHash] {
		touched = append(touched, fmt.Sprintf("the vault's code %x", inst.WasmHash))
	}
	if len(touched) > 0 {
		w.alerts.Raise(ctx, alert.Critical, "frozen", "a CAP-77 freeze touches %s", strings.Join(touched, ", "))
	} else {
		w.alerts.Clear(ctx, "frozen", "no freeze touches the vault or its services")
	}
	return nil
}

// CheckAdmissions pages when an attested, unflagged deposit is still pending ten minutes after it
// became eligible.
func (w *Watcher) CheckAdmissions(ctx context.Context) error {
	health, err := w.rpc.GetHealth(ctx)
	if err != nil {
		return err
	}
	now := uint64(health.LatestLedgerCloseTime)
	w.mu.RLock()
	inst := w.inst
	var due []*chainstate.Deposit
	for _, d := range w.state.Pending {
		if d.Flag == nil && d.ID <= w.state.AttestedUpTo {
			due = append(due, d)
		}
	}
	halted := w.state.HaltedUntil > now
	w.mu.RUnlock()
	if inst == nil || halted {
		return nil
	}
	var late []uint64
	for _, d := range due {
		delay, ok, err := w.delayOf(ctx, d.ID)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		eligible := vault.PendingDeposit{Amount: d.Amount, CreatedAt: d.CreatedAt, Delay: delay}.EligibleAt(inst.Config, inst.Limits)
		if now >= eligible+600 {
			late = append(late, d.ID)
		}
	}
	slices.Sort(late)
	if len(late) > 0 {
		w.alerts.Raise(ctx, alert.Warning, "admission_late", "deposits %v have been eligible for more than 10 minutes", late)
	} else {
		w.alerts.Clear(ctx, "admission_late", "every eligible deposit is admitted")
	}
	return nil
}

// The ages at which a part-paid head exit and a stranded exit page.
const (
	partPaidAge = 2 * secondsPerDay
	strandedAge = 7 * secondsPerDay
)

// CheckExitQueue pages when the exit queue grows long or its oldest exit waits too long, when the
// head exit has been paid in part for more than two days, and when an exit has stayed stranded for
// more than seven.
func (w *Watcher) CheckExitQueue(ctx context.Context) error {
	health, err := w.rpc.GetHealth(ctx)
	if err != nil {
		return err
	}
	now := uint64(health.LatestLedgerCloseTime)
	w.mu.RLock()
	length := w.state.ExitTail - w.state.ExitHead
	var oldest uint64
	partPaid := false
	if head := w.state.Exits[w.state.ExitHead]; head != nil {
		oldest = head.QueuedAt
		partPaid = head.Payout.Cmp(head.QueuedPayout) != 0 || head.Fee.Cmp(head.QueuedFee) != 0
	}
	var stuck []uint64
	for id, e := range w.state.Stranded {
		if now > uint64(e.StrandedAt) && now-uint64(e.StrandedAt) >= strandedAge {
			stuck = append(stuck, id)
		}
	}
	w.mu.RUnlock()
	age := uint64(0)
	if length > 0 && now > oldest {
		age = now - oldest
	}
	if length >= w.cfg.QueueLength {
		w.alerts.Raise(ctx, alert.Warning, "exit_queue_long", "%d exits wait in the exit queue", length)
	} else {
		w.alerts.Clear(ctx, "exit_queue_long", "the exit queue is short again")
	}
	if age >= uint64(w.cfg.QueueAge.Seconds()) && length > 0 {
		w.alerts.Raise(ctx, alert.Warning, "exit_queue_old", "the oldest queued exit has waited %d hours", age/3600)
	} else {
		w.alerts.Clear(ctx, "exit_queue_old", "no queued exit has waited too long")
	}
	if partPaid && age >= partPaidAge {
		w.alerts.Raise(ctx, alert.Warning, "exit_part_paid_old", "the exit at the head of the queue has been paid only in part for %d hours", age/3600)
	} else {
		w.alerts.Clear(ctx, "exit_part_paid_old", "no exit is paid only in part for long")
	}
	slices.Sort(stuck)
	if len(stuck) > 0 {
		w.alerts.Raise(ctx, alert.Warning, "exit_stranded_old", "exits %v have been stranded for more than seven days", stuck)
	} else {
		w.alerts.Clear(ctx, "exit_stranded_old", "no exit has been stranded for long")
	}
	return nil
}

// mustKeyString encodes a key the watcher built itself, which always encodes.
func mustKeyString(k xdr.LedgerKey) string {
	s, err := rpc.KeyString(k)
	if err != nil {
		panic(err)
	}
	return s
}
