package relayer

import (
	"context"
	"math/big"
	"sync"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
)

// lossWindow is how many ledgers the loss budget covers, about a day.
const lossWindow = 17_280

// losses keeps, by ledger, what confirmed relays were charged above the fees they paid, in the
// asset's smallest units.
type losses struct {
	mu      sync.Mutex
	latest  uint32
	entries []lossEntry
}

type lossEntry struct {
	ledger uint32
	amount *big.Int
}

func (l *losses) add(ledger uint32, amount *big.Int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, lossEntry{ledger: ledger, amount: amount})
	l.latest = max(l.latest, ledger)
}

// sum returns the losses of the lossWindow ledgers up to the newest ledger seen, latest or a
// loss's, and forgets older ones.
func (l *losses) sum(latest uint32) *big.Int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.latest = max(l.latest, latest)
	keep := l.entries[:0]
	total := new(big.Int)
	for _, e := range l.entries {
		if e.ledger+lossWindow > l.latest {
			keep = append(keep, e)
			total.Add(total, e.amount)
		}
	}
	l.entries = keep
	return total
}

// loss is what a confirmed relay was charged above the fee it paid, or nil.
func (r *Relayer) loss(charged int64, fee string) *big.Int {
	paid, ok := new(big.Int).SetString(fee, 10)
	if !ok {
		return nil
	}
	over := new(big.Int).Sub(r.cfg.Pricing.ToAsset(charged), paid)
	if over.Sign() <= 0 {
		return nil
	}
	return over
}

// loadLosses reads the losses of the last day from the relay records once.
func (r *Relayer) loadLosses(ctx context.Context, latest uint32) error {
	if r.lossesLoaded {
		return nil
	}
	since := uint32(0)
	if latest > lossWindow {
		since = latest - lossWindow
	}
	charges, err := r.db.recentCharges(ctx, since)
	if err != nil {
		return err
	}
	for _, c := range charges {
		if over := r.loss(c.networkFee, c.fee); over != nil {
			r.losses.add(c.ledger, over)
		}
	}
	r.lossesLoaded = true
	return nil
}

// overBudget reports whether confirmed relays were charged more than LossBudget above their fees
// within the last day.
func (r *Relayer) overBudget() bool {
	_, latest, _ := r.view()
	return r.losses.sum(latest).Cmp(r.cfg.Pricing.ToAsset(r.cfg.LossBudget)) > 0
}

// chargedAbove records a confirmed relay charged more than the fee it paid, which happens only
// when the call took a path its simulation did not, or the RPC misreported its costs, and alerts.
func (r *Relayer) chargedAbove(res submit.Result, fee string) {
	over := r.loss(res.FeeCharged, fee)
	if over == nil {
		return
	}
	r.losses.add(res.Ledger, over)
	_, latest, _ := r.view()
	total := r.losses.sum(latest)
	r.log.Warn("charged above its fee", "tx", res.Hash, "network_fee", res.FeeCharged, "fee", fee)
	r.alerts.Raise(r.ctx, alert.Warning, "relay_below_cost", "relayed transaction %s was charged %d stroops, %v more than the fee %s it paid; %v within the last day, against a budget of %d",
		res.Hash, res.FeeCharged, over, fee, total, r.cfg.LossBudget)
	if r.overBudget() {
		r.alerts.Raise(r.ctx, alert.Warning, "relay_loss_budget", "relays were charged %v above their fees within the last day, more than the budget of %d; until that falls under it, the network fee check takes each envelope's whole fee, so most relays are refused with network_fee_high",
			total, r.cfg.LossBudget)
	}
}
