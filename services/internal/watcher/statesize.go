package watcher

import (
	"context"
	"fmt"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
)

// stateLevels are the shares of the network's target Soroban state size, in percent, at which the
// watcher alerts. Rent rises with the state's size and, above the target, grows steeply, so every
// write to the vault, a shield first, costs more and may pass the fee caps of wallets and relayers.
// The lowest leaves weeks of notice at the growth seen on mainnet.
var stateLevels = []int64{70, 85, 95, 100}

// stateMargin is how many percentage points under a level the state must fall before that level
// clears, and so may page again.
const stateMargin = 2

func stateCode(level int64) string {
	return fmt.Sprintf("state_size_%d", level)
}

func stateSeverity(level int64) alert.Severity {
	if level >= 100 {
		return alert.Critical
	}
	return alert.Warning
}

// CheckStateSize alerts when the network's average live Soroban state passes a level of
// stateLevels, and clears a level once the state is stateMargin points under it. A level pages
// once until it clears, so a state that hovers around a level does not page again and again.
func (w *Watcher) CheckStateSize(ctx context.Context) error {
	if w.cfg.SkipStateSize {
		return nil
	}
	st, err := rpc.ReadSorobanState(ctx, w.rpc)
	if err != nil {
		return err
	}
	permille := st.Average * 1000 / st.Target
	var level int64
	for _, l := range stateLevels {
		if permille >= l*10 {
			level = l
		}
	}
	w.mu.Lock()
	reached := w.stateLevel
	held := reached
	if level > reached {
		held = level
	}
	var cleared []int64
	for i := len(stateLevels) - 1; i >= 0; i-- {
		l := stateLevels[i]
		if l > held || permille >= (l-stateMargin)*10 {
			continue
		}
		cleared = append(cleared, l)
		held = 0
		if i > 0 {
			held = stateLevels[i-1]
		}
	}
	w.stateLevel = held
	w.mu.Unlock()
	if level > reached {
		w.alerts.Raise(ctx, stateSeverity(level), stateCode(level),
			"the network's live Soroban state averages %.3f GB, %d.%d%% of its %.3f GB target; 1 KiB of persistent state now rents for %d stroops a period, against %d at the target and growing %d times as fast above it, so shields and every other vault write cost more and may pass the fee caps of wallets and relayers",
			float64(st.Average)/1e9, permille/10, permille%10, float64(st.Target)/1e9, st.Rent1KB, st.TargetRent1KB, st.Growth)
	}
	for _, l := range cleared {
		w.alerts.Clear(ctx, stateCode(l), "the network's live Soroban state averages %d.%d%% of its target again, under %d%%", permille/10, permille%10, l-stateMargin)
	}
	return nil
}
