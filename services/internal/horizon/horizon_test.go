package horizon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	clean    = "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH"
	thief    = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
	funder   = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
	grandpa  = "GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO"
	contract = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"
)

func TestFundersAreTheIncomingSenders(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/accounts/"+clean) {
			http.NotFound(w, r)
			return
		}
		records := []map[string]any{
			{"type": "payment", "created_at": now, "from": funder, "to": clean},
			{"type": "payment", "created_at": now, "from": clean, "to": thief},
			{"type": "invoke_host_function", "created_at": now, "asset_balance_changes": []map[string]string{{"from": contract, "to": clean}}},
			{"type": "create_account", "created_at": now.Add(-40 * 24 * time.Hour), "funder": grandpa, "account": clean},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": records}})
	}))
	defer srv.Close()
	h := Client{URL: srv.URL, HTTP: srv.Client(), MaxPages: 3}
	got, complete, err := h.Funders(context.Background(), clean, now.Add(-30*24*time.Hour))
	if err != nil || !complete {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != funder || got[1] != contract {
		t.Fatalf("funders %v", got)
	}
	got, complete, err = h.Funders(context.Background(), thief, now.Add(-30*24*time.Hour))
	if err != nil || !complete || len(got) != 0 {
		t.Fatalf("missing account: %v %v", got, err)
	}
}

func TestEffectsStartFromTheNewestAndFollowTheCursor(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		records := []map[string]any{{"id": "1-1", "paging_token": "11", "type": "account_debited", "amount": "5.0000000"}}
		_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": records}})
	}))
	defer srv.Close()
	h := Client{URL: srv.URL + "/key/SECRET", HTTP: srv.Client()}
	if _, err := h.Effects(context.Background(), clean, ""); err != nil {
		t.Fatal(err)
	}
	got, err := h.Effects(context.Background(), clean, "11")
	if err != nil || len(got) != 1 || got[0].Type != "account_debited" || got[0].PagingToken != "11" {
		t.Fatalf("effects %+v, %v", got, err)
	}
	if queries[0] != "order=desc&limit=1" || queries[1] != "order=asc&limit=200&cursor=11" {
		t.Fatalf("queries %v", queries)
	}
	srv.Close()
	if _, err := h.Effects(context.Background(), clean, "11"); err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), clean) {
		t.Fatalf("error %v", err)
	}
}
