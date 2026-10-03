package relayer

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

// Handler serves the relayer API. Nothing about a request is logged.
func (r *Relayer) Handler() http.Handler {
	quoteLimit, statusLimit := httpapi.NewLimiter(600, 60), httpapi.NewLimiter(600, 60)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, req *http.Request) {
		inst, _, _ := r.view()
		body := map[string]any{
			"ready": inst != nil && r.channels.ready() > 0, "vault": r.cfg.Vault, "network_id": hex.EncodeToString(r.cfg.NetworkID[:]),
			"fee_address": r.cfg.FeeAddress, "ready_channels": r.channels.ready(), "channels": r.channels.total,
		}
		status := http.StatusOK
		if inst == nil {
			status = http.StatusServiceUnavailable
		} else {
			body["max_fee"] = inst.Limits.MaxFee.String()
		}
		if r.channels.ready() == 0 {
			status = http.StatusServiceUnavailable
		}
		httpapi.JSON(w, status, body)
	})
	mux.HandleFunc("GET /v1/quote", func(w http.ResponseWriter, req *http.Request) {
		if !quoteLimit.Allow() {
			httpapi.Fail(w, http.StatusTooManyRequests, CodeRateLimited)
			return
		}
		fee, err := r.Quote(req.Context())
		if err != nil {
			httpapi.Fail(w, http.StatusServiceUnavailable, CodeUnavailable)
			return
		}
		httpapi.JSON(w, http.StatusOK, map[string]any{
			"fee": fee.String(), "asset": r.cfg.Asset, "tier": r.cfg.Pricing.Tier.String(), "margin_bps": r.cfg.Pricing.MarginBps,
			"valid_until": r.now().Add(QuoteLifetime).Unix(), "fee_address": r.cfg.FeeAddress, "vault": r.cfg.Vault,
			"network_id": hex.EncodeToString(r.cfg.NetworkID[:]),
		})
	})
	mux.HandleFunc("POST /v1/submit", func(w http.ResponseWriter, req *http.Request) {
		if !r.submitLimit.Allow() {
			httpapi.Fail(w, http.StatusTooManyRequests, CodeRateLimited)
			return
		}
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
		if !statusLimit.Allow() {
			httpapi.Fail(w, http.StatusTooManyRequests, CodeRateLimited)
			return
		}
		hash := req.PathValue("hash")
		if _, err := lowerHex(hash, 32); err != nil {
			httpapi.Fail(w, http.StatusBadRequest, CodeBadRequest)
			return
		}
		s, ok := r.Status(req.Context(), hash)
		if !ok {
			httpapi.Fail(w, http.StatusNotFound, "not_found")
			return
		}
		httpapi.JSON(w, http.StatusOK, s)
	})
	return httpapi.Public(mux)
}

// Run keeps the vault state and the quote fresh until the context ends.
func (r *Relayer) Run(every time.Duration) {
	for r.ctx.Err() == nil {
		if err := r.Refresh(r.ctx); err != nil {
			r.log.Warn("refresh failed", "error", fmt.Sprint(err))
		}
		t := time.NewTimer(every)
		select {
		case <-r.ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}
