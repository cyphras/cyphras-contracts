// Package relayer submits transfers and unshields as the transaction source, so the user's account
// never appears in them, for a fee that covers the cost and is paid in the pool asset.
package relayer

import (
	"errors"
	"math/big"
	"slices"
	"sync"
	"time"
)

// Samples is how many confirmed transactions the cost estimate learns from.
const Samples = 50

// QuoteLifetime is how long a quote stays acceptable.
const QuoteLifetime = 5 * time.Minute

// MaxMarginBps caps the margin over cost.
const MaxMarginBps = 1000

// Pricing turns a cost in stroops into a fee in the pool asset.
type Pricing struct {
	// Native is set for the XLM vault, where the conversion is the identity.
	Native bool
	// PerStroopNum/PerStroopDen is the asset's smallest units per stroop.
	PerStroopNum, PerStroopDen *big.Int
	MarginBps                  int64
	Tier                       *big.Int
}

// Validate checks the configuration.
func (p Pricing) Validate() error {
	if p.MarginBps < 0 || p.MarginBps > MaxMarginBps {
		return errors.New("relayer: the margin must be between 0 and 1000 basis points")
	}
	if p.Tier == nil || p.Tier.Sign() <= 0 {
		return errors.New("relayer: the fee tier must be positive")
	}
	if !p.Native && (p.PerStroopNum == nil || p.PerStroopDen == nil || p.PerStroopNum.Sign() <= 0 || p.PerStroopDen.Sign() <= 0) {
		return errors.New("relayer: a non-native vault needs a price")
	}
	return nil
}

func ceilDiv(a, b *big.Int) *big.Int {
	q, r := new(big.Int).QuoRem(a, b, new(big.Int))
	if r.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// ToAsset converts a cost in stroops to the pool asset's smallest units, rounded up.
func (p Pricing) ToAsset(costStroops int64) *big.Int {
	cost := big.NewInt(costStroops)
	if !p.Native {
		cost = ceilDiv(new(big.Int).Mul(cost, p.PerStroopNum), p.PerStroopDen)
	}
	return cost
}

// Quote is roundUp(toAsset(cost) * (10000 + margin) / 10000, tier).
func (p Pricing) Quote(costStroops int64) *big.Int {
	return p.QuoteAt(costStroops, p.MarginBps)
}

// QuoteAt is Quote with another margin, capped at MaxMarginBps.
func (p Pricing) QuoteAt(costStroops, marginBps int64) *big.Int {
	cost := p.ToAsset(costStroops)
	margin := min(marginBps, MaxMarginBps)
	withMargin := ceilDiv(new(big.Int).Mul(cost, big.NewInt(10_000+margin)), big.NewInt(10_000))
	return new(big.Int).Mul(ceilDiv(withMargin, p.Tier), p.Tier)
}

// SampleMultiple bounds a sample at that many times the median of a full window, or of the
// bootstrap value before, so dear relays a client pays for cannot lift the quote past twice the
// median: lifting the median itself takes half the window, 25 relays, for each doubling.
const SampleMultiple = 2

// Costs learns the resource fee from the relayer's own confirmed transactions only, so nobody can
// move the quote by sending requests that are simulated or refused. A sample is the resource fee
// the relay was expected to be charged when it was sent, the measure the network fee check takes,
// so a relay that costs what the samples did passes the check at the quote.
type Costs struct {
	mu        sync.Mutex
	bootstrap int64
	samples   []int64
}

// NewCosts starts from the stored samples, newest last, and the bootstrap value. A full window is
// held against its own median, as the running relayer held it, not against the bootstrap value,
// which a quote learned after it rose no longer has anything to do with.
func NewCosts(bootstrap int64, stored []int64) *Costs {
	c := &Costs{bootstrap: bootstrap}
	if len(stored) < Samples {
		for _, s := range stored {
			c.Add(s)
		}
		return c
	}
	stored = stored[len(stored)-Samples:]
	sorted := slices.Clone(stored)
	slices.Sort(sorted)
	median := sorted[len(sorted)/2]
	for _, s := range stored {
		if s > 0 {
			c.samples = append(c.samples, min(s, SampleMultiple*median))
		}
	}
	return c
}

// Add records the resource fee of a confirmed transaction, within SampleMultiple of the median.
// A sample of 0, from a confirmation that reported no fee, is not taken.
func (c *Costs) Add(resourceFee int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if resourceFee <= 0 {
		return
	}
	reference := c.bootstrap
	if len(c.samples) >= Samples {
		sorted := slices.Clone(c.samples)
		slices.Sort(sorted)
		reference = sorted[len(sorted)/2]
	}
	c.samples = append(c.samples, min(resourceFee, SampleMultiple*reference))
	if len(c.samples) > Samples {
		c.samples = c.samples[len(c.samples)-Samples:]
	}
}

// ResourceFee is the p90 of the last 50 samples, or the bootstrap value until there are 50.
func (c *Costs) ResourceFee() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.samples) < Samples {
		return c.bootstrap
	}
	sorted := slices.Clone(c.samples)
	slices.Sort(sorted)
	// The nearest-rank p90 of 50 samples is the 45th.
	return sorted[(len(sorted)*9+9)/10-1]
}

// quotes remembers what was quoted, so a fee is accepted at or above the lowest quote of the last
// five minutes: the fee of a payment the vault pays at once, and the fee of one it queues, nil
// when that is above max_fee.
type quotes struct {
	mu      sync.Mutex
	history []quoted
}

type quoted struct {
	at          time.Time
	fee, queued *big.Int
}

func (q *quotes) publish(now time.Time, fee, queued *big.Int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.history = append(q.history, quoted{at: now, fee: fee, queued: queued})
	cutoff := now.Add(-QuoteLifetime)
	i := 0
	for i < len(q.history) && q.history[i].at.Before(cutoff) {
		i++
	}
	q.history = q.history[i:]
}

// newest returns the latest quote published since a time, with its queued fee.
func (q *quotes) newest(since time.Time) (fee, queued *big.Int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n := len(q.history); n > 0 && !q.history[n-1].at.Before(since) {
		return q.history[n-1].fee, q.history[n-1].queued
	}
	return nil, nil
}

// lowestQueued returns the lowest queued fee quoted within the lifetime, or nil.
func (q *quotes) lowestQueued(now time.Time) *big.Int {
	q.mu.Lock()
	defer q.mu.Unlock()
	cutoff := now.Add(-QuoteLifetime)
	var low *big.Int
	for _, h := range q.history {
		if !h.at.Before(cutoff) && h.queued != nil && (low == nil || h.queued.Cmp(low) < 0) {
			low = h.queued
		}
	}
	return low
}

// lowest returns the lowest fee quoted within the lifetime, or nil.
func (q *quotes) lowest(now time.Time) *big.Int {
	q.mu.Lock()
	defer q.mu.Unlock()
	cutoff := now.Add(-QuoteLifetime)
	var low *big.Int
	for _, h := range q.history {
		if !h.at.Before(cutoff) && (low == nil || h.fee.Cmp(low) < 0) {
			low = h.fee
		}
	}
	return low
}
