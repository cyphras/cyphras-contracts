package screening

import (
	"context"
	"sync"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

// CachedInflows keeps inflow lookups for a few minutes, so an address asked about again, by a
// deposit or a relayed unshield, costs no new requests. It holds addresses only in memory.
type CachedInflows struct {
	Inner Inflows
	TTL   time.Duration
	Now   func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]cachedInflows
}

type cacheKey struct {
	account string
	hour    int64
}

type cachedInflows struct {
	at      time.Time
	inflows []Inflow
	gap     Gap
}

// maxCached bounds the cache; past it, expired entries are dropped first and then all of them.
const maxCached = 10_000

// Inflows implements Inflows. Lookups that start within the same hour share an entry, which looks
// back from the start of that hour.
func (c *CachedInflows) Inflows(ctx context.Context, account string, since time.Time) ([]Inflow, Gap, error) {
	now := c.Now()
	key := cacheKey{account, since.Unix() / 3600}
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Sub(e.at) < c.TTL {
		c.mu.Unlock()
		return e.inflows, e.gap, nil
	}
	c.mu.Unlock()
	inflows, gap, err := c.Inner.Inflows(ctx, account, time.Unix(key.hour*3600, 0))
	if err != nil {
		return nil, 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[cacheKey]cachedInflows{}
	}
	if len(c.entries) >= maxCached {
		for k, e := range c.entries {
			if now.Sub(e.at) >= c.TTL {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxCached {
			clear(c.entries)
		}
	}
	c.entries[key] = cachedInflows{at: now, inflows: inflows, gap: gap}
	return inflows, gap, nil
}

// BudgetedInflows spends a fixed budget of lookups, so the screening that requests drive cannot use
// up the Horizon quota deposit screening needs. A lookup over budget is unavailable, and the
// request it serves fails closed.
type BudgetedInflows struct {
	Inner  Inflows
	Budget *httpapi.Limiter
}

// Inflows implements Inflows.
func (b BudgetedInflows) Inflows(ctx context.Context, account string, since time.Time) ([]Inflow, Gap, error) {
	if !b.Budget.Allow() {
		return nil, 0, ErrUnavailable
	}
	return b.Inner.Inflows(ctx, account, since)
}
