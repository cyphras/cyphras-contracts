package screening

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"

	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
)

// history serves one account's history as Horizon does, through the pages page answers: by the
// kind of page and how many of that kind were asked for before. Any other account has none.
func history(t *testing.T, account string, page func(kind string, n int) any) *horizon.Client {
	t.Helper()
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kind := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if strings.Contains(r.URL.Path, "/accounts/") && !strings.Contains(r.URL.Path, account) {
			_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": []any{}}})
			return
		}
		asked[kind]++
		switch p := page(kind, asked[kind]).(type) {
		case string:
			_, _ = w.Write([]byte(p))
		default:
			_ = json.NewEncoder(w).Encode(p)
		}
	}))
	t.Cleanup(srv.Close)
	return &horizon.Client{URL: srv.URL, HTTP: srv.Client(), MaxPages: 2, Floors: map[string]*big.Int{"native": big.NewInt(100_000_000)}}
}

func records(next string, rs ...map[string]any) map[string]any {
	return map[string]any{"_links": map[string]any{"next": map[string]string{"href": next}}, "_embedded": map[string]any{"records": rs}}
}

func TestAHistoryHorizonCannotServeSendsTheDepositToAPerson(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	unreadable := `{"_embedded": {"records": [` + strings.Repeat(" ", 9<<20) + `]}}`
	for name, page := range map[string]func(string, int) any{
		"its payments": func(kind string, _ int) any {
			if kind == "payments" {
				return unreadable
			}
			return records("")
		},
		"its effects": func(kind string, _ int) any {
			if kind == "effects" {
				return "<html>busy</html>"
			}
			return records("")
		},
		"the creator of a balance it claimed": func(kind string, _ int) any {
			switch kind {
			case "effects":
				return records("", map[string]any{"type": "claimable_balance_claimed", "created_at": now, "balance_id": "00ab", "asset": "native", "amount": "100.0000000"})
			case "operations":
				return unreadable
			}
			return records("")
		},
	} {
		h := newHarness(t)
		h.now = now
		victim := keypair.MustRandom().Address()
		h.s.check.Inflows = history(t, victim, page)
		id := h.shield(victim, 10_000_000)
		h.tick()
		if reviews, err := h.s.Reviews(context.Background()); err != nil || len(reviews) != 1 || reviews[0].ID != id {
			t.Fatalf("%s unreadable: reviews %v, %v", name, reviews, err)
		}
		if got := h.sent(); len(got) != 0 {
			t.Fatalf("%s unreadable: sent %v", name, got)
		}
	}
}

func TestATaintedFunderBehindPagesOfDustIsFound(t *testing.T) {
	h := newHarness(t)
	depositor := keypair.MustRandom().Address()
	dust := make([]map[string]any, 200)
	for i := range dust {
		dust[i] = map[string]any{"type": "payment", "created_at": h.now, "from": keypair.MustRandom().Address(), "to": depositor, "amount": "0.0000001", "asset_type": "native"}
	}
	var next string
	h.s.check.Inflows = history(t, depositor, func(kind string, n int) any {
		if kind != "payments" {
			return records("")
		}
		if n <= 2 {
			return records(next, dust...)
		}
		return records("", map[string]any{"type": "payment", "created_at": h.now, "from": thief, "to": depositor, "amount": "100.0000000", "asset_type": "native"})
	})
	next = h.s.check.Inflows.(*horizon.Client).URL + "/accounts/" + depositor + "/payments?cursor=next"
	h.s.check.Dust = Dust{ShareBps: 100, Floors: map[string]*big.Int{"native": big.NewInt(100_000_000)}}
	h.shield(depositor, 10_000_000)
	h.tick()
	// Two pages of dust do not use up the two pages of value read: the funder behind them is
	// found, rather than a history too long to read.
	rows, err := h.s.db.pending(context.Background())
	if err != nil || len(rows) != 1 || !slices.Contains(rows[0].findings, "funder:"+thief+":exploits") {
		t.Fatalf("rows %+v, %v", rows, err)
	}
}
