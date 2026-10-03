package relayer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

// Handler serves the relayer API. Nothing about a request is logged. Per-client limits live in
// nginx; the budgets here guard only what costs the network or the database, after the checks
// that cost nothing.
func (r *Relayer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, req *http.Request) {
		inst, _, _ := r.view()
		paused := r.brk.open(r.now())
		body := map[string]any{
			"ready": inst != nil && r.channels.ready() > 0 && !paused, "vault": r.cfg.Vault, "network_id": hex.EncodeToString(r.cfg.NetworkID[:]),
			"fee_address": r.cfg.FeeAddress, "ready_channels": r.channels.ready(), "channels": r.channels.total, "paused": paused,
			"guarded": r.guarded(),
		}
		status := http.StatusOK
		if inst == nil {
			status = http.StatusServiceUnavailable
		} else {
			body["max_fee"] = inst.Limits.MaxFee.String()
			// The largest exit, payout and fee together, the vault accepts; larger ones are split.
			body["max_daily_outflow"] = inst.Limits.MaxDailyOutflow.String()
		}
		if r.channels.ready() == 0 || paused {
			status = http.StatusServiceUnavailable
		}
		httpapi.JSON(w, status, body)
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, req *http.Request) {
		fee, err := r.CurrentQuote(req.Context())
		if err != nil {
			httpapi.Fail(w, http.StatusServiceUnavailable, CodeUnavailable)
			return
		}
		httpapi.JSON(w, http.StatusOK, map[string]any{
			"fee": fee.String(), "asset": r.cfg.Asset, "tier": r.cfg.Pricing.Tier.String(), "margin_bps": r.Margin(),
			"valid_until": r.now().Add(QuoteLifetime).Unix(), "fee_address": r.cfg.FeeAddress, "vault": r.cfg.Vault,
			"network_id": hex.EncodeToString(r.cfg.NetworkID[:]),
		})
	})
	mux.HandleFunc("POST /v1/submit", func(w http.ResponseWriter, req *http.Request) {
		// Sending can wait for a channel and for the network to take the transaction, longer than
		// the server's write timeout allows any other answer.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(sendWait + 30*time.Second))
		var body SubmitBody
		if err := httpapi.ReadJSON(w, req, 16<<10, &body); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, CodeBadRequest)
			return
		}
		parsed, err := body.Parse()
		if err != nil {
			httpapi.Fail(w, http.StatusBadRequest, CodeBadRequest)
			return
		}
		accepted, f := r.Submit(req.Context(), parsed)
		if f != nil {
			if f.reason != nil {
				httpapi.JSON(w, f.status, map[string]any{"error": f.code, "reason": *f.reason})
				return
			}
			httpapi.Fail(w, f.status, f.code)
			return
		}
		httpapi.JSON(w, http.StatusAccepted, accepted)
	})
	mux.HandleFunc("GET /v1/tx/{hash}", func(w http.ResponseWriter, req *http.Request) {
		hash := req.PathValue("hash")
		if _, err := lowerHex(hash, 32); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, CodeBadRequest)
			return
		}
		s, ok, err := r.Status(req.Context(), hash)
		switch {
		case errors.Is(err, errLookupBudget):
			httpapi.Fail(w, http.StatusTooManyRequests, CodeRateLimited)
			return
		case err != nil:
			httpapi.Fail(w, http.StatusServiceUnavailable, CodeUnavailable)
			return
		case !ok:
			httpapi.Fail(w, http.StatusNotFound, "not_found")
			return
		}
		httpapi.JSON(w, http.StatusOK, s)
	})
	mux.HandleFunc("DELETE /v1/held/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		if _, err := lowerHex(id, 16); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, CodeBadRequest)
			return
		}
		if !r.CancelHeld(id) {
			httpapi.Fail(w, http.StatusNotFound, "not_found")
			return
		}
		httpapi.JSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
	})
	mux.HandleFunc("GET /v1/held/{id}", func(w http.ResponseWriter, req *http.Request) {
		id := req.PathValue("id")
		if _, err := lowerHex(id, 16); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, CodeBadRequest)
			return
		}
		s, hash, reason, ok := r.HeldStatus(req.Context(), id)
		if !ok {
			httpapi.Fail(w, http.StatusNotFound, "not_found")
			return
		}
		body := map[string]any{"status": s.Status}
		if hash != "" {
			body["hash"] = hash
		}
		if s.Code != "" {
			body["code"] = s.Code
		}
		if reason != nil {
			body["reason"] = *reason
		}
		if s.ExitID != nil {
			body["exit_id"] = *s.ExitID
		}
		httpapi.JSON(w, http.StatusOK, body)
	})
	return httpapi.Public(mux)
}

// Run keeps the vault state, the quote and the spent nullifiers fresh until the context ends.
func (r *Relayer) Run(every time.Duration) {
	for r.ctx.Err() == nil {
		if err := r.Refresh(r.ctx); err != nil {
			r.log.Warn("refresh failed", "error", fmt.Sprint(err))
		}
		if err := r.FollowNullifiers(r.ctx); err != nil {
			r.log.Warn("nullifier follow failed", "error", fmt.Sprint(err))
		}
		t := time.NewTimer(every)
		select {
		case <-r.ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}
