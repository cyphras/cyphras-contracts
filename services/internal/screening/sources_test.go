package screening

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
)

const (
	clean    = "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH"
	thief    = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"
	funder   = "GA53HZCSOZI5ZUDYCMYXXUGHO7XEZSM3BYW4M5FGSTYGKWMGVL7QLFB3"
	grandpa  = "GCFK3MDGB4MMH3YCPF42DWOQ47JSAMITMIO3UEHYE62XJAJA4KPERZGO"
	contract = "CCVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKUD2U"
)

func writeList(t *testing.T, entries string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.json")
	doc := fmt.Sprintf(`{"version": "7", "updated_at": "2026-10-01T00:00:00Z", "entries": [%s]}`, entries)
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheCuratedListIsValidated(t *testing.T) {
	s := NewFileSource("exploits", writeList(t, `{"address": "`+thief+`", "reason": 2, "source": "https://incident.example/1"}`), 30*24*time.Hour)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h, ok := s.Lookup(thief); !ok || h.Reason != ReasonExploit || h.Detail != "https://incident.example/1" {
		t.Fatalf("lookup %+v", h)
	}
	if st := s.Status(); st.Version != "7" || st.FetchedAt.Year() != 2026 {
		t.Fatalf("status %+v", st)
	}
	for _, bad := range []string{
		`{"address": "GABC", "reason": 2}`,
		`{"address": "` + thief + `", "reason": 3}`,
		`{"address": "` + thief + `", "reason": 5}`,
		`{"address": "` + thief + `", "reason": 0}`,
	} {
		s := NewFileSource("exploits", writeList(t, bad), time.Hour)
		if err := s.Refresh(context.Background()); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestTheSanctionsListKeepsStellarAddresses(t *testing.T) {
	csv := `36,"SOME PERSON","individual","SDGT",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - XBT 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa; Digital Currency Address - XLM ` + thief + `; Digital Currency Address - ETH 0xabc."`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(csv)) }))
	defer srv.Close()
	s := NewOFACSource(srv.URL, 48*time.Hour)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h, ok := s.Lookup(thief); !ok || h.Reason != ReasonSanctions {
		t.Fatal("sanctioned Stellar address missed")
	}
	if _, ok := s.Lookup("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"); ok {
		t.Fatal("another chain's address kept")
	}
}

func TestTheDirectoryIsDownloadedWhole(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.RawQuery)
		tag := r.URL.Query().Get("tag[]")
		page := directoryPage{}
		switch {
		case tag == "malicious" && r.URL.Query().Get("cursor") == "":
			for range directoryPageSize - 1 {
				page.Embedded.Records = append(page.Embedded.Records, struct {
					Address string   `json:"address"`
					Name    string   `json:"name"`
					Tags    []string `json:"tags"`
				}{Address: "GBAD", Name: "invalid address"})
			}
			page.Embedded.Records = append(page.Embedded.Records, struct {
				Address string   `json:"address"`
				Name    string   `json:"name"`
				Tags    []string `json:"tags"`
			}{Address: thief, Name: "Scam"})
			page.Links.Next.Href = "/explorer/directory?tag[]=malicious&limit=200&cursor=x"
		case tag == "malicious":
			page.Embedded.Records = append(page.Embedded.Records, struct {
				Address string   `json:"address"`
				Name    string   `json:"name"`
				Tags    []string `json:"tags"`
			}{Address: contract, Name: "Drainer"})
		case tag == "unsafe":
			page.Embedded.Records = append(page.Embedded.Records, struct {
				Address string   `json:"address"`
				Name    string   `json:"name"`
				Tags    []string `json:"tags"`
			}{Address: funder, Name: "Old"}, struct {
				Address string   `json:"address"`
				Name    string   `json:"name"`
				Tags    []string `json:"tags"`
			}{Address: thief, Name: "Scam"})
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	defer srv.Close()
	s := NewDirectorySource(srv.URL, 24*time.Hour)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 3 {
		t.Fatalf("%d requests", len(requests))
	}
	if h, _ := s.Lookup(thief); h.Reason != ReasonExploit || h.Refer {
		t.Fatalf("malicious account %+v", h)
	}
	if h, _ := s.Lookup(contract); h.Reason != ReasonExploit {
		t.Fatal("tagged contract missed")
	}
	if h, ok := s.Lookup(funder); !ok || !h.Refer {
		t.Fatal("an unsafe account is referred")
	}
	for _, q := range requests {
		if strings.Contains(q, clean) {
			t.Fatal("a screened address reached the directory")
		}
	}
}

type staticSource struct {
	list
}

func (s *staticSource) Refresh(context.Context) error { return nil }

func static(name string, fetched time.Time, entries map[string]Hit) *staticSource {
	s := &staticSource{list{name: name, maxAge: time.Hour}}
	s.set(entries, "1", fetched)
	return s
}

type funderMap map[string][]string

func (f funderMap) Funders(_ context.Context, account string, _ time.Time) ([]string, bool, error) {
	if account == "unreachable" {
		return nil, false, errors.New("down")
	}
	return f[account], true, nil
}

func TestTheCheckerFollowsFunders(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	src := static("exploits", now, map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}})
	c := &Checker{Sources: []Source{src}, Funders: funderMap{clean: {funder}, funder: {thief}}, MaxFunders: 10, Now: func() time.Time { return now }}
	ctx := context.Background()
	v, err := c.Check(ctx, clean, 1, now)
	if err != nil || v.Refused {
		t.Fatalf("one hop: %+v %v", v, err)
	}
	v, err = c.Check(ctx, clean, 2, now)
	if err != nil || !v.Refused || v.Reason != ReasonExploit || !strings.Contains(v.Detail, thief) || !strings.Contains(v.Detail, "2 hop") {
		t.Fatalf("two hops: %+v %v", v, err)
	}
	v, _ = c.Check(ctx, thief, 0, now)
	if !v.Refused {
		t.Fatal("direct hit missed")
	}
	if _, err := c.Check(ctx, "nonsense", 1, now); err == nil {
		t.Fatal("invalid address accepted")
	}

	c.Now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := c.Check(ctx, clean, 1, now); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stale source: %v", err)
	}
	c.Now = func() time.Time { return now }
	c.Funders = funderMap{}
	c.Sources = []Source{src, static("refer", now, map[string]Hit{funder: {Source: "refer", Refer: true}})}
	c.Funders = funderMap{clean: {funder}}
	if v, _ := c.Check(ctx, clean, 1, now); v.Refused || !v.Refer {
		t.Fatalf("referral %+v", v)
	}
}

func TestHorizonFundersAreTheIncomingSenders(t *testing.T) {
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
	h := Horizon{URL: srv.URL, HTTP: srv.Client(), MaxPages: 3}
	got, complete, err := h.Funders(context.Background(), clean, now.Add(-FunderWindow))
	if err != nil || !complete {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != funder || got[1] != contract {
		t.Fatalf("funders %v", got)
	}
	got, complete, err = h.Funders(context.Background(), thief, now.Add(-FunderWindow))
	if err != nil || !complete || len(got) != 0 {
		t.Fatalf("missing account: %v %v", got, err)
	}
}

func TestSEP53SignaturesAreVerified(t *testing.T) {
	kp := keypair.MustRandom()
	msg := SelfReportMessage("testnet", kp.Address(), "2026-10-03")
	if msg != "Cyphras compromised address report\nNetwork: testnet\nAddress: "+kp.Address()+"\nDate: 2026-10-03" {
		t.Fatal("message layout")
	}
	sig, err := kp.Sign(sep53Digest(msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySEP53(kp.Address(), msg, sig); err != nil {
		t.Fatal(err)
	}
	if VerifySEP53(kp.Address(), msg+"x", sig) == nil || VerifySEP53(clean, msg, sig) == nil || VerifySEP53(kp.Address(), msg, sig[:10]) == nil {
		t.Fatal("bad signature accepted")
	}
}
