package indexer

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/tree"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// resolvedWindow is how long resolved deposits stay in the deposits response.
const resolvedWindow = 7 * 24 * time.Hour

// Handler serves the read-only API. No endpoint takes a commitment, nullifier, leaf index or note:
// clients download whole pages and sets and test membership locally.
func (ix *Indexer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", ix.health)
	mux.HandleFunc("GET /v1/leaves", ix.leaves)
	mux.HandleFunc("GET /v1/nullifiers", ix.nullifiers)
	mux.HandleFunc("GET /v1/deposits", ix.memo("deposits", ix.deposits))
	mux.HandleFunc("GET /v1/exits", ix.memo("exits", ix.exits))
	mux.HandleFunc("GET /v1/stats", ix.memo("stats", ix.stats))
	mux.HandleFunc("GET /v1/stream", ix.stream)
	return httpapi.Public(mux)
}

func (ix *Indexer) health(w http.ResponseWriter, _ *http.Request) {
	h := ix.Health()
	status := http.StatusOK
	if !h.Ready {
		status = http.StatusServiceUnavailable
	}
	httpapi.JSON(w, status, h)
}

// serving answers with the not-ready code unless the data may be served.
func (ix *Indexer) serving(w http.ResponseWriter) (Health, bool) {
	h := ix.Health()
	if !h.Ready {
		httpapi.Fail(w, http.StatusServiceUnavailable, h.Code)
	}
	return h, h.Ready
}

func uintParam(r *http.Request, name string, max uint64) (uint64, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil || n > max || strconv.FormatUint(n, 10) != v {
		return 0, false
	}
	return n, true
}

func (ix *Indexer) leaves(w http.ResponseWriter, r *http.Request) {
	page, ok := uintParam(r, "page", tree.Capacity/PageSize-1)
	if !ok {
		httpapi.Fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	h, ok := ix.serving(w)
	if !ok {
		return
	}
	ix.mu.RLock()
	vouched := ix.vouched
	ix.mu.RUnlock()
	leaves, err := ix.db.leaves(r.Context(), page, h.IngestedLedger)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	complete := len(leaves) == PageSize
	if complete && (page+1)*PageSize <= vouched {
		// A full page the chain has vouched for never changes.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"page": page, "leaves": leaves, "complete": complete, "ingested_ledger": h.IngestedLedger,
	})
}

func (ix *Indexer) nullifiers(w http.ResponseWriter, r *http.Request) {
	since, ok1 := uintParam(r, "since_ledger", 1<<32-1)
	cursor, ok2 := uintParam(r, "cursor", 1<<62)
	if !ok1 || !ok2 {
		httpapi.Fail(w, http.StatusBadRequest, "bad_request")
		return
	}
	h, ok := ix.serving(w)
	if !ok {
		return
	}
	list, next, err := ix.db.nullifiers(r.Context(), uint32(since), h.IngestedLedger, cursor)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	var nextCursor *string
	if next != "" {
		nextCursor = &next
	}
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"nullifiers": list, "next_cursor": nextCursor, "complete_to": h.IngestedLedger,
	})
}

func (ix *Indexer) deposits(w http.ResponseWriter, r *http.Request) {
	if _, ok := ix.serving(w); !ok {
		return
	}
	upTo, attested, pending := ix.pendingDeposits()
	resolved, err := ix.db.resolved(r.Context(), ix.now().Add(-resolvedWindow).Unix(), upTo)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"pending": pending, "resolved": resolved, "attested_up_to": attested, "complete_to": upTo,
	})
}

// pendingDeposits lists the entry queue from the state in memory, with the ledger it describes, at
// which the resolved deposits are cut.
func (ix *Indexer) pendingDeposits() (uint32, uint64, []PendingDeposit) {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	attested := ix.state.AttestedUpTo
	pending := make([]PendingDeposit, 0, len(ix.state.Pending))
	for _, d := range ix.state.Pending {
		p := PendingDeposit{ID: d.ID, Depositor: d.Depositor, Amount: d.Amount.String(), CreatedAt: d.CreatedAt, Attested: d.ID <= attested}
		if d.Flag != nil {
			p.FlagReason, p.FlaggedAt = ptr(*d.Flag), ptr(d.FlaggedAt)
		}
		if delay, ok := ix.delays[d.ID]; ok && ix.instance != nil {
			eligible := vault.PendingDeposit{Amount: new(big.Int).Set(d.Amount), CreatedAt: d.CreatedAt, Delay: delay}.EligibleAt(ix.instance.Config, ix.instance.Limits)
			p.EarliestAdmission = &eligible
		}
		pending = append(pending, p)
	}
	slices.SortFunc(pending, func(a, b PendingDeposit) int { return cmp.Compare(a.ID, b.ID) })
	return ix.cursor, attested, pending
}

func (ix *Indexer) stats(w http.ResponseWriter, r *http.Request) {
	h, ok := ix.serving(w)
	if !ok {
		return
	}
	st, err := ix.db.stats(r.Context(), h.IngestedLedger)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	st.LeafCount = h.LeafCount
	httpapi.JSON(w, http.StatusOK, st)
}

func (ix *Indexer) stream(w http.ResponseWriter, r *http.Request) {
	ch, ok := ix.hub.subscribe()
	if !ok {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	defer ix.hub.unsubscribe(ch)
	rc := http.NewResponseController(w)
	// The stream outlives the server's write timeout.
	_ = rc.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "retry: 5000\n\n")
	_ = rc.Flush()
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case wake := <-ch:
			data, _ := json.Marshal(wake)
			if _, err := fmt.Fprintf(w, "event: wake\ndata: %s\n\n", data); err != nil {
				return
			}
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}
