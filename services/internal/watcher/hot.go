package watcher

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// quietEffects are the only effects a hot account should see: being created and receiving value.
// Fees are not effects, so any other effect is something the account did beyond paying the fee
// of its own transaction.
var quietEffects = map[string]bool{"account_created": true, "account_credited": true}

// outflowEffects move value out of the account.
var outflowEffects = map[string]bool{
	"account_debited": true, "account_removed": true, "trade": true, "liquidity_pool_deposited": true,
	"claimable_balance_created": true, "contract_debited": true,
}

// CheckHotAccounts pages when a hot account runs below its floor, and when Horizon shows it doing
// anything but receiving value.
func (w *Watcher) CheckHotAccounts(ctx context.Context) error {
	for _, h := range w.cfg.HotAccounts {
		if h.Floor > 0 {
			key, err := vault.AccountKey(h.Address)
			if err != nil {
				return err
			}
			e, _, err := rpc.One(ctx, w.rpc, key)
			if err != nil {
				return fmt.Errorf("read the %s account: %w", h.Name, err)
			}
			code := "hot_balance_low_" + h.Address
			if balance := int64(e.Data.Account.Balance); balance < h.Floor {
				w.alerts.Raise(ctx, alert.Warning, code, "the %s account %s holds %d stroops, below its floor of %d", h.Name, h.Address, balance, h.Floor)
			} else {
				w.alerts.Clear(ctx, code, "the %s account is above its floor again", h.Name)
			}
		}
		if w.horizon != nil {
			if err := w.effects(ctx, h); err != nil {
				return fmt.Errorf("effects of the %s account: %w", h.Name, err)
			}
		}
	}
	return nil
}

// effects reads the account's new effects from its stored cursor.
func (w *Watcher) effects(ctx context.Context, h HotAccount) error {
	key := "effects:" + h.Address
	cursor, _, err := w.db.meta(ctx, key)
	if err != nil {
		return err
	}
	for range 50 {
		list, err := w.horizon.Effects(ctx, h.Address, cursor)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return nil
		}
		if cursor != "" {
			for _, e := range list {
				switch {
				case outflowEffects[e.Type]:
					w.alerts.Raise(ctx, alert.Critical, "hot_account_outflow_"+e.ID, "the %s account %s paid out %s (%s) at %s, which is not the fee of its own transaction",
						h.Name, h.Address, e.Amount, e.Type, e.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
				case !quietEffects[e.Type]:
					w.alerts.Raise(ctx, alert.Critical, "hot_account_change_"+e.ID, "the %s account %s shows %s at %s", h.Name, h.Address, e.Type, e.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
				}
			}
		}
		cursor = list[len(list)-1].PagingToken
		if err := w.db.setMeta(ctx, key, cursor); err != nil {
			return err
		}
	}
	return nil
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
