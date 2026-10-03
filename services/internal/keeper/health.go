package keeper

import (
	"net/http"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

// Handler serves the keeper's health: how far it has followed the vault and the state of its
// alert channels, by name, so the watcher can tell when none of them takes the keeper's pages.
func (k *Keeper) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		httpapi.JSON(w, http.StatusOK, map[string]any{
			"vault": k.cfg.Vault, "ingested_ledger": k.Cursor(), "alert_lanes": k.alerts.Lanes(k.now()),
		})
	})
	return mux
}
