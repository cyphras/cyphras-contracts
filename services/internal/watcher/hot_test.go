package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

const (
	hotAccount = "GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO"
	thief      = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
)

// operationsServer serves an account's operations as Horizon pages them, and fails the reads
// numbered in failOn.
type operationsServer struct {
	mu       sync.Mutex
	ops      []map[string]any
	requests int
	failOn   map[int]bool
}

func (f *operationsServer) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	if f.failOn[f.requests] {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var page []map[string]any
	after, _ := strconv.Atoi(r.URL.Query().Get("cursor"))
	for _, op := range f.ops {
		if token, _ := strconv.Atoi(op["paging_token"].(string)); token > after && len(page) < 200 {
			page = append(page, op)
		}
	}
	if r.URL.Query().Get("order") == "desc" && len(page) > 0 {
		page = page[len(page)-1:]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"_embedded": map[string]any{"records": page}})
}

func (f *operationsServer) add(ops ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = append(f.ops, ops...)
}

func hotHarness(t *testing.T, f *operationsServer) *harness {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	h := newHarness(t, func(c *Config) {
		c.HotAccounts = []HotAccount{{Name: "channel-1", Address: hotAccount, Floor: 100}}
	})
	h.w.horizon = &horizon.Client{URL: srv.URL, HTTP: srv.Client(), MaxPages: 2}
	key := mustKey(vault.AccountKey(hotAccount))
	h.primary.SetEntry(key, xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeAccount, Account: &xdr.AccountEntry{AccountId: key.MustAccount().AccountId, Balance: 1_000_000_000}}, 1, nil)
	return h
}

func op(id int, typ, source string, extra ...any) map[string]any {
	m := map[string]any{"id": fmt.Sprint(id), "paging_token": fmt.Sprint(id), "type": typ, "source_account": source}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i].(string)] = extra[i+1]
	}
	return m
}

func (h *harness) hotAlerts() []string {
	var out []string
	for _, a := range h.pages.alerts {
		if a.Code == "hot_account_activity_"+hotAccount {
			out = append(out, a.Message)
		}
	}
	return out
}

func TestAMovementOfAHotAccountsFundsPagesWhoeverSourcedIt(t *testing.T) {
	f := &operationsServer{ops: []map[string]any{op(1, "invoke_host_function", hotAccount)}}
	h := hotHarness(t, f)
	ctx := context.Background()
	if err := h.w.CheckHotAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	out := []map[string]string{{"asset_type": "native", "from": hotAccount, "to": thief, "amount": "99.0000000", "type": "transfer"}}
	in := []map[string]string{{"asset_type": "native", "from": thief, "to": hotAccount, "amount": "1.0000000", "type": "transfer"}}
	f.add(
		// Its own call and what others send it are nothing.
		op(2, "invoke_host_function", hotAccount),
		op(3, "invoke_host_function", thief, "asset_balance_changes", in),
		// A thief with its key drains it through the asset contract, in a call it sources or one
		// another account sources with its authorization.
		op(4, "invoke_host_function", hotAccount, "asset_balance_changes", out),
		op(5, "invoke_host_function", thief, "asset_balance_changes", out),
	)
	if err := h.w.CheckHotAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	if got := h.hotAlerts(); len(got) != 1 || !strings.Contains(got[0], "2 invoke_host_function moving its funds") || !strings.Contains(got[0], "operation 5") {
		t.Fatalf("alerts %v", got)
	}
}

func TestAHotAccountPageIsRaisedBeforeALaterPageFails(t *testing.T) {
	f := &operationsServer{ops: []map[string]any{op(1, "invoke_host_function", hotAccount)}}
	h := hotHarness(t, f)
	ctx := context.Background()
	if err := h.w.CheckHotAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	// The thief pays itself, then pushes payments into the account so its history spans two
	// pages, and the read of the second one fails.
	f.add(op(2, "payment", hotAccount, "to", thief))
	for i := range 250 {
		f.add(op(10+i, "payment", thief, "to", hotAccount))
	}
	f.mu.Lock()
	f.failOn = map[int]bool{f.requests + 2: true}
	f.mu.Unlock()
	if err := h.w.CheckHotAccounts(ctx); err == nil {
		t.Fatal("the failed page went unreported")
	}
	if got := h.hotAlerts(); len(got) != 1 || !strings.Contains(got[0], "1 payment") {
		t.Fatalf("alerts %v", got)
	}
	if err := h.w.CheckHotAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	if cursor, _, _ := h.w.db.meta(ctx, "operations:"+hotAccount); cursor != "259" {
		t.Fatalf("cursor %s", cursor)
	}
}

func TestTheOperationsReaderStartsWhereTheEffectsReaderStopped(t *testing.T) {
	f := &operationsServer{}
	for i := 1; i <= 10; i++ {
		typ := "invoke_host_function"
		if i == 3 || i == 7 {
			typ = "payment"
		}
		f.add(op(i, typ, hotAccount))
	}
	h := hotHarness(t, f)
	ctx := context.Background()
	if err := h.w.db.setMeta(ctx, "effects:"+hotAccount, "5-2"); err != nil {
		t.Fatal(err)
	}
	if err := h.w.CheckHotAccounts(ctx); err != nil {
		t.Fatal(err)
	}
	// The payment before the effects cursor was the earlier reader's to judge.
	if got := h.hotAlerts(); len(got) != 1 || !strings.Contains(got[0], "1 payment, the newest operation 7") {
		t.Fatalf("alerts %v", got)
	}
}

// hotTransfer puts a native asset event of the hot account's in a ledger of its own.
func (h *harness) hotTransfer(name string, topics ...xdr.ScVal) {
	h.t.Helper()
	c := h.chain
	c.NextLedger(5)
	sym := xdr.ScSymbol(name)
	asset := xdr.ScString("native")
	all := append([]xdr.ScVal{{Type: xdr.ScValTypeScvSymbol, Sym: &sym}}, topics...)
	all = append(all, xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &asset})
	var encoded []string
	for _, v := range all {
		s, err := xdr.MarshalBase64(v)
		if err != nil {
			h.t.Fatal(err)
		}
		encoded = append(encoded, s)
	}
	amount, err := vault.I128(big.NewInt(990_000_000))
	if err != nil {
		h.t.Fatal(err)
	}
	value, err := xdr.MarshalBase64(amount)
	if err != nil {
		h.t.Fatal(err)
	}
	c.Events = append(c.Events, vault.RawEvent{
		Ledger: c.Ledger, ClosedAt: c.ClosedAt, TxHash: strings.Repeat(fmt.Sprintf("%02x", c.Ledger%256), 32), Contract: vaulttest.Token, Topics: encoded, Value: value,
	})
	c.NextLedger(5)
}

func address(t *testing.T, a string) xdr.ScVal {
	t.Helper()
	v, err := vault.Address(a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestALumenTransferOutOfAHotAccountPages(t *testing.T) {
	h := newHarness(t, func(c *Config) {
		c.HotAccounts = []HotAccount{{Name: "channel-1", Address: hotAccount}}
		c.Lumens = vaulttest.Token
	})
	h.activity()
	// What it is sent and the fees it pays are its own flow.
	h.hotTransfer("transfer", address(t, thief), address(t, hotAccount))
	h.hotTransfer("fee", address(t, hotAccount))
	h.sync()
	if h.pages.has("hot_account_transfer") {
		t.Fatalf("pages %v", h.pages.codes())
	}
	h.hotTransfer("transfer", address(t, hotAccount), address(t, thief))
	h.sync()
	var got []string
	for _, a := range h.pages.alerts {
		if strings.HasPrefix(a.Code, "hot_account_transfer_") {
			got = append(got, a.Message)
		}
	}
	if len(got) != 1 || !strings.Contains(got[0], "990000000 stroops to "+thief) {
		t.Fatalf("pages %v", got)
	}
}
