package horizon

import (
	"context"
	"encoding/json"
	"fmt"
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

func TestOperationsStartFromTheNewestAndFollowTheCursor(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Path+"?"+r.URL.RawQuery)
		records := []map[string]any{{"id": "1", "paging_token": "11", "type": "payment", "source_account": clean}}
		_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": records}})
	}))
	defer srv.Close()
	h := Client{URL: srv.URL + "/key/SECRET", HTTP: srv.Client()}
	if _, err := h.Operations(context.Background(), clean, ""); err != nil {
		t.Fatal(err)
	}
	got, err := h.Operations(context.Background(), clean, "11")
	if err != nil || len(got) != 1 || got[0].Type != "payment" || got[0].SourceAccount != clean || got[0].PagingToken != "11" {
		t.Fatalf("operations %+v, %v", got, err)
	}
	if queries[0] != "/key/SECRET/accounts/"+clean+"/operations?order=desc&limit=1" || queries[1] != "/key/SECRET/accounts/"+clean+"/operations?order=asc&limit=200&cursor=11" {
		t.Fatalf("queries %v", queries)
	}
	srv.Close()
	if _, err := h.Operations(context.Background(), clean, "11"); err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), clean) {
		t.Fatalf("error %v", err)
	}
}

func TestInflowsCarryAmountsAndComeFromEffectsToo(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var records []map[string]any
		switch {
		case r.URL.Path == "/accounts/"+clean+"/payments":
			records = []map[string]any{
				{"type": "payment", "created_at": now, "from": funder, "to": clean, "amount": "12.5", "asset_type": "native"},
				{"type": "payment", "created_at": now, "from": thief, "to": clean, "amount": "3.0000000", "asset_type": "credit_alphanum4", "asset_code": "USDC", "asset_issuer": grandpa},
				{"type": "account_merge", "created_at": now, "account": thief, "into": clean},
			}
		case r.URL.Path == "/accounts/"+clean+"/effects":
			records = []map[string]any{
				{"type": "claimable_balance_claimed", "created_at": now, "balance_id": "00ab", "asset": "native", "amount": "1.0000000"},
				{"type": "claimable_balance_claimed", "created_at": now, "balance_id": "00cd", "asset": "native", "amount": "2.0000000"},
				{"type": "trade", "created_at": now, "seller": grandpa, "bought_amount": "0.0000001", "bought_asset_type": "native"},
				{"type": "liquidity_pool_withdrew", "created_at": now, "reserves_received": []map[string]string{{"asset": "native", "amount": "4"}}},
				{"type": "account_credited", "created_at": now, "amount": "99"},
			}
		case r.URL.Path == "/claimable_balances/00ab/operations":
			records = []map[string]any{{"type": "create_claimable_balance", "source_account": thief}}
		default:
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": records}})
	}))
	defer srv.Close()
	h := Client{URL: srv.URL, HTTP: srv.Client(), MaxPages: 3}
	got, complete, err := h.Inflows(context.Background(), clean, now.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	// The second claimable balance has no creator Horizon knows, so the history is incomplete.
	if complete {
		t.Fatal("an unnamed sender left the history complete")
	}
	want := []string{
		funder + " native 125000000", thief + " USDC:" + grandpa + " 30000000", thief + " native <nil>",
		thief + " native 10000000", grandpa + " native 1", " native 40000000",
	}
	if len(got) != len(want) {
		t.Fatalf("inflows %+v", got)
	}
	for i, in := range got {
		if s := in.From + " " + in.Asset + " " + fmt.Sprint(in.Amount); s != want[i] {
			t.Fatalf("inflow %d is %q, want %q", i, s, want[i])
		}
	}
}

func TestAHistoryLongerThanThePagesReadIsIncomplete(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		records := make([]map[string]any, pageSize)
		for i := range records {
			records[i] = map[string]any{"type": "payment", "created_at": now, "from": funder, "to": clean, "amount": "1", "asset_type": "native"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"_links":    map[string]any{"next": map[string]string{"href": "http://" + r.Host + r.URL.Path + "?cursor=next"}},
			"_embedded": map[string]any{"records": records},
		})
	}))
	defer srv.Close()
	h := Client{URL: srv.URL, HTTP: srv.Client(), MaxPages: 2}
	if _, complete, err := h.Inflows(context.Background(), clean, now.Add(-time.Hour)); err != nil || complete {
		t.Fatalf("complete %v, %v", complete, err)
	}
}
