package relayer

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/submit"
)

const (
	// lossWindow is how many ledgers the loss budget covers, about a day.
	lossWindow = 17_280
	// lossAge is how long a loss is kept at least, whatever ledger an RPC reports, so one tip far
	// ahead cannot drop the day's losses.
	lossAge = 24 * time.Hour
)

// losses keeps, by transaction, what confirmed relays were charged above the fees they paid, in
// the asset's smallest units. A loss is dropped once it is both lossWindow ledgers behind the tip
// and lossAge old.
type losses struct {
	mu  sync.Mutex
	now func() time.Time
	by  map[string]lossEntry
}

type lossEntry struct {
	ledger uint32
	at     time.Time
	amount *big.Int
}

func (l *losses) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// add records a transaction's loss once, however often it is seen.
func (l *losses) add(hash string, ledger uint32, amount *big.Int) {
	l.addAt(hash, ledger, time.Time{}, amount)
}

// addAt is add for a loss seen at a known time; a zero time is now.
func (l *losses) addAt(hash string, ledger uint32, at time.Time, amount *big.Int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.by == nil {
		l.by = map[string]lossEntry{}
	}
	if at.IsZero() {
		at = l.clock()
	}
	if _, ok := l.by[hash]; !ok {
		l.by[hash] = lossEntry{ledger: ledger, at: at, amount: amount}
	}
}

// sum returns the losses not yet dropped at the tip latest, and drops the others.
func (l *losses) sum(latest uint32) *big.Int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	total := new(big.Int)
	for hash, e := range l.by {
		if uint64(e.ledger)+lossWindow <= uint64(latest) && now.Sub(e.at) >= lossAge {
			delete(l.by, hash)
			continue
		}
		total.Add(total, e.amount)
	}
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

// loadLosses reads the losses of the last day from the relay records once. The day is the
// records' own, the window of ledgers up to the newest recorded and each loss's time, so no tip an
// RPC reports, however far ahead, makes a restart forget it. A loss already followed in this run,
// a relay resumed before the first refresh, is not counted again.
func (r *Relayer) loadLosses(ctx context.Context) error {
	if r.lossesLoaded {
		return nil
	}
	charges, err := r.db.recentCharges(ctx)
	if err != nil {
		return err
	}
	for _, c := range charges {
		if over := r.loss(c.networkFee, c.fee); over != nil {
			var at time.Time
			if c.finishedAt > 0 {
				at = time.Unix(c.finishedAt, 0)
			}
			r.losses.addAt(c.hash, c.ledger, at, over)
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
// when the call took a path its simulation did not, used more refundable resources than it saw,
// or the RPC misreported its costs, and alerts.
func (r *Relayer) chargedAbove(res submit.Result, fee string) {
	over := r.loss(res.FeeCharged, fee)
	if over == nil {
		return
	}
	r.losses.add(res.Hash, res.Ledger, over)
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

const (
	// belowCostRequests requests paying the published quote, with no note in common, refused for
	// their network fee within belowCostWindow, mean the quote no longer covers what relays cost.
	belowCostRequests = 3
	belowCostWindow   = time.Hour
)

// belowCost remembers the nullifiers of requests that paid the published quote and were refused
// for their network fee, so the same notes, under any number of proofs, count once.
type belowCost struct {
	mu   sync.Mutex
	seen map[fr.Element]time.Time
	hits []time.Time
}

// refusedAtQuote counts a request that paid the published quote and was refused for its network
// fee, and alerts once belowCostRequests of them, with no note in common, came within the window.
func (r *Relayer) refusedAtQuote(req Request, cost int64) {
	b := &r.belowCost
	now := r.now()
	b.mu.Lock()
	if b.seen == nil {
		b.seen = map[fr.Element]time.Time{}
	}
	for nf, at := range b.seen {
		if now.Sub(at) >= belowCostWindow {
			delete(b.seen, nf)
		}
	}
	keep := b.hits[:0]
	for _, at := range b.hits {
		if now.Sub(at) < belowCostWindow {
			keep = append(keep, at)
		}
	}
	b.hits = keep
	_, known0 := b.seen[req.Proof.Nullifiers[0]]
	_, known1 := b.seen[req.Proof.Nullifiers[1]]
	b.seen[req.Proof.Nullifiers[0]], b.seen[req.Proof.Nullifiers[1]] = now, now
	if !known0 && !known1 {
		b.hits = append(b.hits, now)
	}
	hits := len(b.hits)
	b.mu.Unlock()
	if hits >= belowCostRequests {
		r.alerts.Raise(r.ctx, alert.Warning, "quote_below_cost", "%d requests paying the published quote were refused for their network fee within %s, the last at %d stroops: the quote no longer covers what relays cost; it moves only with confirmed relays, so set QUOTE_FLOOR or wait for costs to fall",
			hits, belowCostWindow, cost)
	}
}
