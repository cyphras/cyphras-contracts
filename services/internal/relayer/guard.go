package relayer

import (
	"math"
	"sync"
	"time"
)

// cooldowns refuses the nullifiers and destinations of relayed transactions that failed on chain.
// A transaction that passed simulation and then failed costs the relayer its fee, and the same
// notes or destination failing again is how that is repeated at will.
type cooldowns struct {
	mu    sync.Mutex
	until map[string]int64
}

func nullifierKey(hex string) string { return "nullifier:" + hex }

func destinationKey(account string) string { return "destination:" + account }

func (c *cooldowns) add(keys []string, until int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.until == nil {
		c.until = map[string]int64{}
	}
	for _, k := range keys {
		c.until[k] = max(c.until[k], until)
	}
}

// cooling reports whether any key is still refused at now, and forgets those that are not.
func (c *cooldowns) cooling(now int64, keys ...string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit := false
	for _, k := range keys {
		until, ok := c.until[k]
		switch {
		case !ok:
		case until > now:
			hit = true
		default:
			delete(c.until, k)
		}
	}
	return hit
}

// breaker stops relaying for a while once too many relayed transactions failed on chain within a
// window, since each failure costs a fee and a run of them means the checks before sending miss
// something.
type breaker struct {
	failures int
	window   time.Duration
	pause    time.Duration

	mu        sync.Mutex
	recent    []time.Time
	openUntil time.Time
}

// failed records a failure and reports whether it opened the breaker.
func (b *breaker) failed(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := b.recent[:0]
	for _, t := range b.recent {
		if now.Sub(t) < b.window {
			keep = append(keep, t)
		}
	}
	b.recent = append(keep, now)
	if b.failures <= 0 || len(b.recent) < b.failures || now.Before(b.openUntil) {
		return false
	}
	// The failures that opened it are spent, so the next window starts afresh.
	b.recent, b.openUntil = nil, now.Add(b.pause)
	return true
}

func (b *breaker) open(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return now.Before(b.openUntil)
}

// outcomes remembers whether each recent relay that reached the chain succeeded, so the fee can
// carry what failures cost.
type outcomes struct {
	mu   sync.Mutex
	last []bool
}

// outcomeSamples is how many relays the failure rate is taken over.
const outcomeSamples = 200

func (o *outcomes) add(success bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.last = append(o.last, success)
	if len(o.last) > outcomeSamples {
		o.last = o.last[len(o.last)-outcomeSamples:]
	}
}

// failureBps is the share of failures in basis points. Fewer than 100 relays count as 100, so a
// single early failure does not set the price on its own.
func (o *outcomes) failureBps() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	failed := 0
	for _, ok := range o.last {
		if !ok {
			failed++
		}
	}
	return int64(failed) * 10_000 / int64(max(len(o.last), 100))
}

// ledgerClock estimates when ledgers close from the ledgers it has seen, so a time is turned into
// a ledger at the pace the network keeps rather than a fixed one.
type ledgerClock struct {
	fallback float64

	mu      sync.Mutex
	samples []ledgerSample
}

type ledgerSample struct {
	ledger uint32
	at     int64
}

// clockSpan is how far back the samples reach.
const clockSpan = 30 * 60

// observe records a ledger and its close time.
func (c *ledgerClock) observe(ledger uint32, at int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := len(c.samples); n > 0 && ledger <= c.samples[n-1].ledger {
		return
	}
	c.samples = append(c.samples, ledgerSample{ledger, at})
	for len(c.samples) > 2 && at-c.samples[0].at > clockSpan {
		c.samples = c.samples[1:]
	}
}

// secondsPerLedger is the mean close time over the samples, or the fallback until they span 60
// ledgers.
func (c *ledgerClock) secondsPerLedger() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pace()
}

func (c *ledgerClock) pace() float64 {
	n := len(c.samples)
	if n < 2 || c.samples[n-1].ledger-c.samples[0].ledger < 60 {
		return c.fallback
	}
	first, last := c.samples[0], c.samples[n-1]
	return max(float64(last.at-first.at)/float64(last.ledger-first.ledger), 1)
}

// ledgerAt estimates the latest ledger at time t.
func (c *ledgerClock) ledgerAt(t int64) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.samples)
	if n == 0 {
		return 0
	}
	last := c.samples[n-1]
	if t <= last.at {
		return last.ledger
	}
	return last.ledger + uint32(math.Ceil(float64(t-last.at)/c.pace()))
}
