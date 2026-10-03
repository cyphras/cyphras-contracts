package keeper

import (
	"context"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTheQueuedUnflagsAreReadWithTheKeepersToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"deposits": [{"id": 4, "until": 1700000000}, {"id": 9, "until": 1700000600}]}`))
	}))
	defer srv.Close()
	got, err := UnflagsFrom(srv.URL, "secret", srv.Client())(context.Background())
	if err != nil || !maps.Equal(got, map[uint64]uint64{4: 1_700_000_000, 9: 1_700_000_600}) {
		t.Fatalf("%v, %v", got, err)
	}
	if _, err := UnflagsFrom(srv.URL, "wrong", srv.Client())(context.Background()); err == nil {
		t.Fatal("a refused read went through")
	}
}
