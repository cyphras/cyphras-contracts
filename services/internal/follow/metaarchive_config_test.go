package follow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

func TestALayoutThePublicArchiveCouldNotHaveIsRefusedWithoutPanicking(t *testing.T) {
	for _, layout := range [][2]uint64{{65536, 65536}, {4294967295, 4294967295}, {0, 1}, {65, 1}, {1, 0}, {1, 64001}} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/pubnet/.config.json" {
				fmt.Fprintf(w, `{"networkPassphrase":%q,"compression":"zstd","ledgersPerBatch":%d,"batchesPerPartition":%d}`, passphrase, layout[0], layout[1])
				return
			}
			http.NotFound(w, r)
		}))
		a := &LedgerArchive{BaseURL: srv.URL + "/pubnet", Passphrase: passphrase, Vault: vaulttest.Vault}
		if _, err := a.Events(context.Background(), 5, 5); err == nil {
			t.Fatalf("layout %v was accepted", layout)
		}
		srv.Close()
	}
}

func TestObjectKeysOfTheLargestLayoutDoNotWrapAround(t *testing.T) {
	s := archiveSchema{LedgersPerBatch: 65536, BatchesPerPartition: 65536}
	if got, want := s.objectKey(1), "FFFFFFFF--0-4294967295/FFFFFFFF--0-65535.xdr.zst"; got != want {
		t.Fatalf("key %s, want %s", got, want)
	}
}

func TestAnErrorNamesTheObjectAndNotTheURLOfTheArchive(t *testing.T) {
	a := &LedgerArchive{BaseURL: "http://127.0.0.1:1/token-s3cret", Passphrase: passphrase, Vault: vaulttest.Vault}
	_, err := a.Events(context.Background(), 5, 5)
	if err == nil || strings.Contains(err.Error(), "s3cret") || !strings.Contains(err.Error(), ".config.json") {
		t.Fatalf("error %v", err)
	}
}
