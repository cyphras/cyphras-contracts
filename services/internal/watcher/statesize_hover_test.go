package watcher

import (
	"context"
	"testing"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
)

// A state whose window average wobbles a tenth of a percent around the lowest level, as it does
// while it grows with deletions in between, pages that level once, not at every crossing, with the
// watcher's own cooldown in place.
func TestAStateHoveringAtTheLowestLevelPagesItOnce(t *testing.T) {
	w, fake, pages := stateWatcher(rpctest.Mainnet)
	now := time.Unix(1_761_350_000, 0)
	w.alerts.Cooldown = time.Hour
	w.alerts.Now = func() time.Time { return now }
	ctx := context.Background()
	// Mainnet's target is 3 GB: 85.0% and 84.9%, one check every 10 minutes.
	for _, average := range []uint64{2_550_000_000, 2_547_000_000, 2_550_000_000, 2_547_000_000, 2_550_000_000, 2_547_000_000} {
		setWindow(fake, average)
		if err := w.CheckStateSize(ctx); err != nil {
			t.Fatal(err)
		}
		now = now.Add(10 * time.Minute)
	}
	raised := 0
	for _, a := range pages.all() {
		if a.Code == "state_size_85" && a.Severity == alert.Warning {
			raised++
		}
	}
	if raised != 1 {
		t.Fatalf("state_size_85 paged %d times in an hour of hovering: %v", raised, codesOf(pages.all()))
	}
}

func codesOf(all []alert.Alert) []string {
	out := make([]string, len(all))
	for i, a := range all {
		out[i] = a.Code
	}
	return out
}
