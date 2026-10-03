package relayer

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"sync"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
)

// cooldowns refuses the nullifiers and destinations of relayed transactions that failed on chain
// because of what the request carried. A transaction that passed simulation and then failed costs
// the relayer its fee, and the same notes or destination failing again is how that is repeated
// at will.
type cooldowns struct {
	mu    sync.Mutex
	until map[string]int64
	// strikes counts a destination's receive failures in a row.
	strikes map[string]int
}

func nullifierKey(hex string) string { return "nullifier:" + hex }

// destinationKey names a destination by its full address, a muxed one included, so that one
// failure cannot rest every other user of the same account.
func destinationKey(address string) string { return "destination:" + address }

// requestKey names one request by its proof, so a request that failed on chain is not sent
// again, whatever the cause.
func requestKey(req Request) string {
	k := proofKey(req)
	return "request:" + hex.EncodeToString(k[:])
}

// strikeMemory is how long after its rest a destination's failures still count toward the next
// rest.
const strikeMemory = 24 * 60 * 60

// destinationRest is how long a destination rests after its n-th receive failure in a row: ten
// minutes, doubling up to a day.
func destinationRest(n int) time.Duration {
	return min(10*time.Minute<<min(max(n, 1)-1, 8), 24*time.Hour)
}

func (c *cooldowns) init() {
	if c.until == nil {
		c.until, c.strikes = map[string]int64{}, map[string]int{}
	}
}

func (c *cooldowns) add(keys []string, until int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	for _, k := range keys {
		c.until[k] = max(c.until[k], until)
	}
}

// restore puts back a stored cooldown with its strikes.
func (c *cooldowns) restore(key string, until int64, strikes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	c.until[key], c.strikes[key] = max(c.until[key], until), max(c.strikes[key], strikes)
}

// strike rests a destination after a receive failure, longer for each failure that follows one
// within a day, and returns the end of the rest and the strikes counted.
func (c *cooldowns) strike(key string, now int64) (int64, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.init()
	n := 1
	if until, ok := c.until[key]; ok && now < until+strikeMemory {
		n = c.strikes[key] + 1
	}
	c.until[key] = max(c.until[key], now+int64(destinationRest(n).Seconds()))
	c.strikes[key] = n
	return c.until[key], n
}

// cooling reports whether any key is still refused at now. A key is forgotten a day after its
// rest ended, once its strikes no longer count.
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
		case until+strikeMemory <= now:
			delete(c.until, k)
			delete(c.strikes, k)
		}
	}
	return hit
}

// spentSet holds nullifiers known to be spent: those of this relayer's own successful relays and
// those the vault's events name, so a proof that was already used is refused before it costs
// anything. It keeps the newest ones up to its bound; an older spend is still found by the read
// of the chain that follows.
type spentSet struct {
	max int

	mu    sync.Mutex
	seen  map[fr.Element]bool
	order []fr.Element
}

func (s *spentSet) add(nfs ...fr.Element) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[fr.Element]bool{}
	}
	for _, nf := range nfs {
		if s.seen[nf] {
			continue
		}
		s.seen[nf] = true
		s.order = append(s.order, nf)
	}
	if over := len(s.order) - s.max; s.max > 0 && over > 0 {
		for _, nf := range s.order[:over] {
			delete(s.seen, nf)
		}
		s.order = append([]fr.Element(nil), s.order[over:]...)
	}
}

func (s *spentSet) any(nfs [2]fr.Element) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen[nfs[0]] || s.seen[nfs[1]]
}

// verdicts remembers for a while how a proof was refused once it had cost the network, so the same
// proof sent again is answered from memory.
type verdicts struct {
	ttl time.Duration
	max int

	mu    sync.Mutex
	by    map[[32]byte]verdict
	order [][32]byte
}

type verdict struct {
	f  failure
	at time.Time
}

// proofKey identifies a proof by everything it commits to.
func proofKey(req Request) [32]byte {
	p := req.Proof
	h := sha256.New()
	h.Write(p.A[:])
	h.Write(p.B[:])
	h.Write(p.C[:])
	for _, e := range []fr.Element{p.Root, p.PublicAmount, p.ExtDataHash, p.Nullifiers[0], p.Nullifiers[1], p.Commitments[0], p.Commitments[1]} {
		b := e.Bytes()
		h.Write(b[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (v *verdicts) remember(key [32]byte, f failure, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.by == nil {
		v.by = map[[32]byte]verdict{}
	}
	if _, ok := v.by[key]; !ok {
		v.order = append(v.order, key)
	}
	v.by[key] = verdict{f: f, at: now}
	if over := len(v.order) - v.max; v.max > 0 && over > 0 {
		for _, k := range v.order[:over] {
			delete(v.by, k)
		}
		v.order = append([][32]byte(nil), v.order[over:]...)
	}
}

func (v *verdicts) recall(key [32]byte, now time.Time) *failure {
	v.mu.Lock()
	defer v.mu.Unlock()
	if r, ok := v.by[key]; ok && now.Sub(r.at) < v.ttl {
		f := r.f
		return &f
	}
	return nil
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
