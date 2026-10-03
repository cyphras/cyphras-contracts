package indexer

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
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
	mux.HandleFunc("GET /v1/deposits", ix.deposits)
	mux.HandleFunc("GET /v1/exits", ix.exits)
	mux.HandleFunc("GET /v1/stats", ix.stats)
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
	leaves, err := ix.db.leaves(r.Context(), page, h.IngestedLedger)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	complete := len(leaves) == PageSize
	if complete {
		// A full page never changes.
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
	h, ok := ix.serving(w)
	if !ok {
		return
	}
	ix.mu.RLock()
	inst := ix.instance
	attested := ix.state.AttestedUpTo
	delays := make(map[uint64]uint64, len(ix.delays))
	for id, d := range ix.delays {
		delays[id] = d
	}
	ix.mu.RUnlock()
	rows, err := ix.db.pending(r.Context(), h.IngestedLedger)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	pending := make([]PendingDeposit, 0, len(rows))
	for _, d := range rows {
		p := PendingDeposit{ID: uint64(d.id), Depositor: d.depositor, Amount: d.amount, CreatedAt: uint64(d.createdAt), Attested: uint64(d.id) <= attested}
		if d.flag != nil {
			reason := uint32(*d.flag)
			p.FlagReason = &reason
		}
		if d.flaggedAt != nil {
			at := uint64(*d.flaggedAt)
			p.FlaggedAt = &at
		}
		if delay, ok := delays[p.ID]; ok && inst != nil {
			amount, _ := new(big.Int).SetString(d.amount, 10)
			eligible := vault.PendingDeposit{Amount: amount, CreatedAt: p.CreatedAt, Delay: delay}.EligibleAt(inst.Config, inst.Limits)
			p.EarliestAdmission = &eligible
		}
		pending = append(pending, p)
	}
	resolved, err := ix.db.resolved(r.Context(), ix.now().Add(-resolvedWindow).Unix(), h.IngestedLedger)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"pending": pending, "resolved": resolved, "attested_up_to": attested, "complete_to": h.IngestedLedger,
	})
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
