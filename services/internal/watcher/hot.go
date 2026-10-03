package watcher

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// ownOperations are what a hot account does itself: Soroban calls and footprint upkeep. Anything
// else it sources, such as a payment, an offer or a change to its signers, thresholds or flags,
// means its key is used for something it never should be.
var ownOperations = map[string]bool{"invoke_host_function": true, "extend_footprint_ttl": true, "restore_footprint": true}

// CheckHotAccounts pages when a hot account is missing or below its floor, and when Horizon shows
// it sourcing anything but its own Soroban calls, an issuer changing its trustline flags, or its
// funds moving, whoever sourced the call. What others send it means nothing and is ignored, so
// nobody can flood the pager by paying it. Each account is checked on its own, and a page of its
// history raises at most one alert per account.
func (w *Watcher) CheckHotAccounts(ctx context.Context) error {
	var errs []error
	for _, h := range w.cfg.HotAccounts {
		if err := w.checkHot(ctx, h); err != nil {
			errs = append(errs, fmt.Errorf("the %s account: %w", h.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (w *Watcher) checkHot(ctx context.Context, h HotAccount) error {
	key, err := vault.AccountKey(h.Address)
	if err != nil {
		return err
	}
	missing := "hot_account_missing_" + h.Address
	e, _, err := rpc.One(ctx, w.rpc, key)
	switch {
	case errors.Is(err, rpc.ErrMissing):
		w.alerts.Raise(ctx, alert.Critical, missing, "the %s account %s does not exist: it was merged away or never funded", h.Name, h.Address)
		return nil
	case err != nil:
		return err
	}
	w.alerts.Clear(ctx, missing, "the %s account exists again", h.Name)
	if h.Floor > 0 {
		code := "hot_balance_low_" + h.Address
		if balance := int64(e.Data.Account.Balance); balance < h.Floor {
			w.alerts.Raise(ctx, alert.Warning, code, "the %s account %s holds %d stroops, below its floor of %d", h.Name, h.Address, balance, h.Floor)
		} else {
			w.alerts.Clear(ctx, code, "the %s account is above its floor again", h.Name)
		}
	}
	if w.horizon == nil {
		return nil
	}
	return w.operations(ctx, h)
}

// operations reads the account's new operations from its stored cursor. Each page is judged
// before the cursor moves past it, so a failed read of a later page loses nothing.
func (w *Watcher) operations(ctx context.Context, h HotAccount) error {
	key := "operations:" + h.Address
	cursor, ok, err := w.db.meta(ctx, key)
	if err != nil {
		return err
	}
	if !ok {
		// An earlier watcher read the account's effects; an effect's paging token is its
		// operation's followed by a dash and the effect's index.
		effects, found, err := w.db.meta(ctx, "effects:"+h.Address)
		if err != nil {
			return err
		}
		if found {
			cursor, _, _ = strings.Cut(effects, "-")
		}
	}
	for range 50 {
		list, err := w.horizon.Operations(ctx, h.Address, cursor)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			break
		}
		if cursor != "" {
			w.judgeOperations(ctx, h, list)
		}
		cursor = list[len(list)-1].PagingToken
		if err := w.db.setMeta(ctx, key, cursor); err != nil {
			return err
		}
	}
	return nil
}

// judgeOperations pages on the operations of a hot account it should never take part in.
func (w *Watcher) judgeOperations(ctx context.Context, h HotAccount, list []horizon.Operation) {
	counts := map[string]int{}
	var newest string
	for _, op := range list {
		var what string
		switch {
		case slices.ContainsFunc(op.Changes, func(c horizon.BalanceChange) bool { return c.From == h.Address }):
			what = op.Type + " moving its funds"
		case op.SourceAccount == h.Address && !ownOperations[op.Type]:
			what = op.Type
		case (op.Type == "set_trust_line_flags" || op.Type == "allow_trust") && op.Trustor == h.Address:
			what = op.Type
		default:
			continue
		}
		counts[what]++
		newest = op.ID
	}
	if len(counts) == 0 {
		return
	}
	var parts []string
	for _, t := range slices.Sorted(maps.Keys(counts)) {
		parts = append(parts, fmt.Sprintf("%d %s", counts[t], t))
	}
	w.alerts.Raise(ctx, alert.Critical, "hot_account_activity_"+h.Address, "the %s account %s took part in what it never should: %s, the newest operation %s",
		h.Name, h.Address, strings.Join(parts, ", "), newest)
}

// ParseHotAccounts reads one "name address floor" line per hot account, the floor in stroops;
// blank lines and lines starting with # are skipped.
func ParseHotAccounts(data []byte) ([]HotAccount, error) {
	var out []HotAccount
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("hot accounts line %d is not \"name address floor\"", n)
		}
		floor, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil || floor < 0 || !strkey.IsValidEd25519PublicKey(fields[1]) {
			return nil, fmt.Errorf("hot accounts line %d has a bad address or floor", n)
		}
		out = append(out, HotAccount{Name: fields[0], Address: fields[1], Floor: floor})
	}
	return out, sc.Err()
}
