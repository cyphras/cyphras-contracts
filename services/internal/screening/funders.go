package screening

import (
	"context"
	"sync"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

// CachedFunders keeps funder lookups for a few minutes, so an address asked about again, by a
// deposit or a relayed unshield, costs no new requests. It holds addresses only in memory.
type CachedFunders struct {
	Inner Funders
	TTL   time.Duration
	Now   func() time.Time

	mu      sync.Mutex
	entries map[cacheKey]cachedFunders
}

type cacheKey struct {
	account string
	hour    int64
}

type cachedFunders struct {
	at       time.Time
	funders  []string
	complete bool
}

// maxCached bounds the cache; past it, expired entries are dropped first and then all of them.
const maxCached = 10_000

// Funders implements Funders. Lookups that start within the same hour share an entry, which looks
// back from the start of that hour.
func (c *CachedFunders) Funders(ctx context.Context, account string, since time.Time) ([]string, bool, error) {
	now := c.Now()
	key := cacheKey{account, since.Unix() / 3600}
	c.mu.Lock()
	if e, ok := c.entries[key]; ok && now.Sub(e.at) < c.TTL {
		c.mu.Unlock()
		return e.funders, e.complete, nil
	}
	c.mu.Unlock()
	funders, complete, err := c.Inner.Funders(ctx, account, time.Unix(key.hour*3600, 0))
	if err != nil {
		return nil, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[cacheKey]cachedFunders{}
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
	c.entries[key] = cachedFunders{at: now, funders: funders, complete: complete}
	return funders, complete, nil
}

// BudgetedFunders spends a fixed budget of lookups, so the screening that requests drive cannot
// use up the Horizon quota deposit screening needs. A lookup over budget is unavailable, and the
// request it serves fails closed.
type BudgetedFunders struct {
	Inner  Funders
	Budget *httpapi.Limiter
}

// Funders implements Funders.
func (b BudgetedFunders) Funders(ctx context.Context, account string, since time.Time) ([]string, bool, error) {
	if !b.Budget.Allow() {
		return nil, false, ErrUnavailable
	}
	return b.Inner.Funders(ctx, account, since)
}
