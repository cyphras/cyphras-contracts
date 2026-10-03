package watcher

import (
	"context"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const (
	// patternWindow is how far back deposits and payouts are matched.
	patternWindow = 7 * secondsPerDay
	// funderWindow is how far back the senders of value to an address count as its funders.
	funderWindow = 30 * secondsPerDay
)

// sources returns an address and the accounts that funded it, from the cache when it is fresh.
// Lookups are forgotten after the pattern window, so the watcher keeps no lasting map of who
// funds whom.
func (w *Watcher) sources(ctx context.Context, address string, now int64) (map[string]bool, error) {
	account, err := vault.AccountOf(address)
	if err != nil {
		return nil, err
	}
	funders, ok, err := w.db.funders(ctx, account, now-secondsPerDay)
	if err != nil {
		return nil, err
	}
	if !ok {
		if funders, _, err = w.horizon.Funders(ctx, account, time.Unix(now-funderWindow, 0)); err != nil {
			return nil, err
		}
		if err := w.db.setFunders(ctx, account, funders, now); err != nil {
			return nil, err
		}
	}
	out := map[string]bool{account: true}
	for _, f := range funders {
		// Every recipient of a payout was funded by the vault itself.
		if f != w.cfg.Vault && !w.cfg.IgnoreFunders[f] {
			out[f] = true
		}
	}
	return out, nil
}

// CheckPatterns looks for capital that cycles through the vault: payouts whose recipients share a
// funding source with earlier deposits, again and again, and a day's outflow window filled soon
// after midnight by recipients that share one.
func (w *Watcher) CheckPatterns(ctx context.Context) error {
	if w.horizon == nil {
		return nil
	}
	health, err := w.rpc.GetHealth(ctx)
	if err != nil {
		return err
	}
	now := health.LatestLedgerCloseTime
	if err := w.db.forgetFunders(ctx, now-patternWindow); err != nil {
		return err
	}
	if err := w.roundTrips(ctx, now); err != nil {
		return err
	}
	return w.earlySaturation(ctx, now)
}

func (w *Watcher) roundTrips(ctx context.Context, now int64) error {
	deposits, err := w.db.depositsSince(ctx, now-patternWindow)
	if err != nil {
		return err
	}
	payouts, err := w.db.payoutsSince(ctx, now-patternWindow)
	if err != nil {
		return err
	}
	if len(deposits) == 0 || len(payouts) == 0 {
		return nil
	}
	depositSources := make([]map[string]bool, len(deposits))
	for i, d := range deposits {
		if depositSources[i], err = w.sources(ctx, d.address, now); err != nil {
			return err
		}
	}
	trips := map[string]int{}
	amounts := map[string]*big.Int{}
	for _, p := range payouts {
		ps, err := w.sources(ctx, p.address, now)
		if err != nil {
			return err
		}
		linked := map[string]bool{}
		for i, d := range deposits {
			if d.at >= p.at {
				break
			}
			for s := range ps {
				if depositSources[i][s] {
					linked[s] = true
				}
			}
		}
		for s := range linked {
			trips[s]++
			if amounts[s] == nil {
				amounts[s] = new(big.Int)
			}
			amounts[s].Add(amounts[s], p.amount)
		}
	}
	for s, n := range trips {
		if n >= w.cfg.RoundTrips {
			w.alerts.Raise(ctx, alert.Warning, "round_trip_"+s, "%d payouts totalling %v in 7 days went to recipients that share the funding source %s with earlier depositors", n, amounts[s], s)
		}
	}
	return nil
}

func (w *Watcher) earlySaturation(ctx context.Context, now int64) error {
	limits := w.limits()
	dayStart := now - now%secondsPerDay
	if limits == nil || now-dayStart > int64(w.cfg.EarlyWindow.Seconds()) {
		return nil
	}
	payouts, err := w.db.payoutsSince(ctx, dayStart-1)
	if err != nil {
		return err
	}
	used := new(big.Int)
	bySource := map[string]*big.Int{}
	for _, p := range payouts {
		used.Add(used, p.amount)
		ps, err := w.sources(ctx, p.address, now)
		if err != nil {
			return err
		}
		for s := range ps {
			if bySource[s] == nil {
				bySource[s] = new(big.Int)
			}
			bySource[s].Add(bySource[s], p.amount)
		}
	}
	threshold := new(big.Int).Div(new(big.Int).Mul(limits.MaxDailyOutflow, big.NewInt(w.cfg.EarlyShare)), big.NewInt(100))
	if used.Cmp(threshold) < 0 {
		return nil
	}
	sources := make([]string, 0, len(bySource))
	for s := range bySource {
		sources = append(sources, s)
	}
	slices.Sort(sources)
	for _, s := range sources {
		// A source behind at least half of what the window paid today is the same capital.
		if new(big.Int).Mul(bySource[s], big.NewInt(2)).Cmp(used) >= 0 {
			w.alerts.Raise(ctx, alert.Warning, fmt.Sprintf("window_saturated_early_%d", dayStart/secondsPerDay),
				"%v of today's outflow window of %v was paid within %s of midnight UTC, %v of it to recipients that share the source %s",
				used, limits.MaxDailyOutflow, time.Duration(now-dayStart)*time.Second, bySource[s], s)
			return nil
		}
	}
	return nil
}
