package indexer

import (
	"sync"
)

// Wake is what a stream subscriber learns about a ledger that changed the vault.
type Wake struct {
	Ledger         uint32 `json:"ledger"`
	LeafCount      uint64 `json:"leaf_count"`
	NullifierCount uint64 `json:"nullifier_count"`
}

// hub fans wake events out to stream subscribers. A slow subscriber misses wakes rather than
// holding up the others; it resyncs from its next wake anyway.
type hub struct {
	mu   sync.Mutex
	max  int
	subs map[chan Wake]struct{}
}

func newHub(max int) *hub {
	return &hub{max: max, subs: map[chan Wake]struct{}{}}
}

func (h *hub) subscribe() (chan Wake, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= h.max {
		return nil, false
	}
	ch := make(chan Wake, 4)
	h.subs[ch] = struct{}{}
	return ch, true
}

func (h *hub) unsubscribe(ch chan Wake) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, ch)
}

func (h *hub) publish(w Wake) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- w:
		default:
		}
	}
}
