package follow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

func TestTheLedgerArchiveStopsAskingForFilesAfterTheFirstFailure(t *testing.T) {
	var files atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".config.json") {
			_, _ = w.Write([]byte(`{"networkPassphrase":"` + passphrase + `","compression":"zstd","ledgersPerBatch":1,"batchesPerPartition":64000}`))
			return
		}
		files.Add(1)
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	a := &LedgerArchive{BaseURL: srv.URL + "/pubnet", Passphrase: passphrase, Vault: vaulttest.Vault, Workers: 4}
	if _, err := a.Events(context.Background(), 1_000, 1_000+17_279); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("a store that refuses every file: %v", err)
	}
	if n := files.Load(); n > 100 {
		t.Fatalf("%d files were asked for after the first refusal", n)
	}
}
