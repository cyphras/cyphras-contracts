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

// Quote is roundUp(toAsset(cost) * (10000 + margin) / 10000, tier).
func (p Pricing) Quote(costStroops int64) *big.Int {
	cost := big.NewInt(costStroops)
	if !p.Native {
		cost = ceilDiv(new(big.Int).Mul(cost, p.PerStroopNum), p.PerStroopDen)
	}
	withMargin := ceilDiv(new(big.Int).Mul(cost, big.NewInt(10_000+p.MarginBps)), big.NewInt(10_000))
	return new(big.Int).Mul(ceilDiv(withMargin, p.Tier), p.Tier)
}

// Costs learns the resource fee from the relayer's own confirmed transactions only, so nobody can
// move the quote by sending requests that are simulated or refused.
type Costs struct {
	mu        sync.Mutex
	bootstrap int64
	samples   []int64
}

// NewCosts starts from the stored samples, newest last, and the bootstrap value.
func NewCosts(bootstrap int64, stored []int64) *Costs {
	c := &Costs{bootstrap: bootstrap}
	for _, s := range stored {
		c.Add(s)
	}
	return c
}

// Add records the resource fee charged to a confirmed transaction.
func (c *Costs) Add(resourceFee int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.samples = append(c.samples, resourceFee)
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
// five minutes.
type quotes struct {
	mu      sync.Mutex
	history []quoted
}

type quoted struct {
	at  time.Time
	fee *big.Int
}

func (q *quotes) publish(now time.Time, fee *big.Int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.history = append(q.history, quoted{at: now, fee: fee})
	cutoff := now.Add(-QuoteLifetime)
	i := 0
	for i < len(q.history) && q.history[i].at.Before(cutoff) {
		i++
	}
	q.history = q.history[i:]
}

// lowest returns the lowest fee quoted within the lifetime, or nil.
// newest returns the latest quote published since a time.
func (q *quotes) newest(since time.Time) *big.Int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if n := len(q.history); n > 0 && !q.history[n-1].at.Before(since) {
		return q.history[n-1].fee
	}
	return nil
}

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
