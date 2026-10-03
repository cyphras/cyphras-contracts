package indexer

import (
	"bytes"
	"net/http"
	"sync"
	"time"
)

// memoAge is how long a bulk response is served from memory while the indexer has not moved.
const memoAge = 5 * time.Second

type memoEntry struct {
	mu     sync.Mutex
	ledger uint32
	at     time.Time
	header http.Header
	body   []byte
}

// responseCopy keeps a handler's response so it can be served again.
type responseCopy struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *responseCopy) Header() http.Header         { return r.header }
func (r *responseCopy) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *responseCopy) WriteHeader(status int)      { r.status = status }

// memo serves a bulk response from memory for a few seconds while the indexer has not moved, so a
// burst of requests costs one database read. Only successful responses are kept; requests for the
// same endpoint wait for the one that builds it.
func (ix *Indexer) memo(key string, next http.HandlerFunc) http.HandlerFunc {
	ix.memoMu.Lock()
	e, ok := ix.memos[key]
	if !ok {
		e = &memoEntry{}
		ix.memos[key] = e
	}
	ix.memoMu.Unlock()
	return func(w http.ResponseWriter, r *http.Request) {
		// A copy never outlives readiness: a mismatch stops serving at once.
		if !ix.Health().Ready {
			next(w, r)
			return
		}
		ledger := ix.Cursor()
		e.mu.Lock()
		defer e.mu.Unlock()
		if e.body == nil || e.ledger != ledger || ix.now().Sub(e.at) >= memoAge {
			rec := &responseCopy{header: http.Header{}, status: http.StatusOK}
			next(rec, r)
			if rec.status != http.StatusOK {
				for k, v := range rec.header {
					w.Header()[k] = v
				}
				w.WriteHeader(rec.status)
				_, _ = w.Write(rec.body.Bytes())
				return
			}
			e.ledger, e.at, e.header, e.body = ledger, ix.now(), rec.header, rec.body.Bytes()
		}
		for k, v := range e.header {
			w.Header()[k] = v
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(e.body)
	}
}
