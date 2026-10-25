package watcher

import (
	"context"
	"fmt"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc"
)

// stateLevels are the shares of the network's target Soroban state size, in percent, at which the
// watcher warns. Rent rises with the state's size and, above the target, grows steeply, so every
// write to the vault, a shield first, costs more and may pass the fee caps of wallets and relayers.
var stateLevels = []int64{85, 95, 100}

func stateCode(level int64) string {
	return fmt.Sprintf("state_size_%d", level)
}

// CheckStateSize warns when the network's average live Soroban state passes each of stateLevels,
// and clears the warnings once it is back under the lowest. Each level pages once until then, so a
// state that hovers around a level does not page again and again.
func (w *Watcher) CheckStateSize(ctx context.Context) error {
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
	if level > reached || level == 0 {
		w.stateLevel = level
	}
	w.mu.Unlock()
	switch {
	case level > reached:
		w.alerts.Raise(ctx, alert.Warning, stateCode(level),
			"the network's live Soroban state averages %.3f GB, %d.%d%% of its %.3f GB target; 1 KiB of persistent state now rents for %d stroops a period, against %d at the target and growing %d times as fast above it, so shields and every other vault write cost more and may pass the fee caps of wallets and relayers",
			float64(st.Average)/1e9, permille/10, permille%10, float64(st.Target)/1e9, st.Rent1KB, st.TargetRent1KB, st.Growth)
	case level == 0 && reached > 0:
		for _, l := range stateLevels {
			w.alerts.Clear(ctx, stateCode(l), "the network's live Soroban state averages %d.%d%% of its target again, under %d%%", permille/10, permille%10, stateLevels[0])
		}
	}
	return nil
}
