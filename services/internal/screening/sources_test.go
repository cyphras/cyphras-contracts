package screening

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
		var records []directoryRecord
		page := directoryPage{}
		switch {
		case tag == "malicious" && r.URL.Query().Get("cursor") == "":
			for range directoryPageSize - 1 {
				records = append(records, directoryRecord{Address: "GBAD", Name: "invalid address"})
			}
			records = append(records, directoryRecord{Address: thief, Name: "Scam"})
			page.Links.Next.Href = "/explorer/directory?tag[]=malicious&limit=200&cursor=x"
		case tag == "malicious":
			records = append(records, directoryRecord{Address: contract, Name: "Drainer"})
		case tag == "unsafe":
			records = append(records, directoryRecord{Address: funder, Name: "Old"}, directoryRecord{Address: thief, Name: "Scam"})
		}
		page.Embedded = &struct {
			Records *[]directoryRecord `json:"records"`
		}{Records: &records}
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

// funderMap gives each account its funders, each having sent 100 XLM, enough to matter.
type funderMap map[string][]string

func (f funderMap) Inflows(_ context.Context, account string, _ time.Time) ([]Inflow, Gap, error) {
	if account == "unreachable" {
		return nil, 0, errors.New("down")
	}
	var out []Inflow
	for _, from := range f[account] {
		out = append(out, Inflow{From: from, Asset: "native", Amount: big.NewInt(1_000_000_000)})
	}
	return out, 0, nil
}

func TestTheCheckerFollowsFunders(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	src := static("exploits", now, map[string]Hit{thief: {Source: "exploits", Reason: ReasonExploit}})
	c := &Checker{Sources: []Source{src}, Inflows: funderMap{clean: {funder}, funder: {thief}}, MaxFunders: 10, Now: func() time.Time { return now }}
	ctx := context.Background()
	v, err := c.Check(ctx, clean, 1, now)
	if err != nil || !v.Clear() {
		t.Fatalf("one hop: %+v %v", v, err)
	}
	// A listed funder two hops back refers the address to a person; it never refuses it.
	v, err = c.Check(ctx, clean, 2, now)
	if err != nil || v.Refused || !v.Refer || !strings.Contains(v.Detail, thief) || !strings.Contains(v.Detail, "2 hop") || !strings.Contains(v.Detail, "reason 2") {
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
	c.Sources = []Source{src, static("refer", now, map[string]Hit{funder: {Source: "refer", Refer: true}})}
	c.Inflows = funderMap{clean: {funder}}
	if v, _ := c.Check(ctx, clean, 1, now); v.Refused || !v.Refer || len(v.Findings) != 1 {
		t.Fatalf("referral %+v", v)
	}
}

// inflowList answers every account with the same inflows.
type inflowList struct {
	inflows []Inflow
	gap     Gap
}

func (l inflowList) Inflows(context.Context, string, time.Time) ([]Inflow, Gap, error) {
	return l.inflows, l.gap, nil
}

func TestASelfReportNeverReachesThePayeesOfTheReportedKey(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	attacker, honest := keypair.MustRandom().Address(), keypair.MustRandom().Address()
	reports := &ReportSource{list: list{name: "self_reports", maxAge: time.Hour}, load: func(context.Context) ([]string, error) { return []string{attacker}, nil }, now: func() time.Time { return now }}
	if err := reports.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fraud := static("curated_list", now, map[string]Hit{thief: {Source: "curated_list", Reason: ReasonFraud, Detail: "victim report"}})
	for name, inflows := range map[string][]Inflow{
		"dust":        {{From: attacker, Asset: "native", Amount: big.NewInt(1)}, {From: funder, Asset: "native", Amount: big.NewInt(1_000_000_000)}},
		"a real gift": {{From: attacker, Asset: "native", Amount: big.NewInt(50_000_000_000)}},
	} {
		c := &Checker{Sources: []Source{reports, fraud}, Inflows: inflowList{inflows, 0}, MaxFunders: 25, Now: func() time.Time { return now },
			Dust: Dust{ShareBps: 100, Floors: map[string]*big.Int{"native": big.NewInt(100_000_000)}}}
		v, err := c.Check(context.Background(), honest, 1, now.Add(-FunderWindow))
		if err != nil || !v.Clear() {
			t.Fatalf("%s from a self-reported key: %+v %v", name, v, err)
		}
	}
	// A victim's report about a funder sends the payee to review, never to a public reason 4.
	c := &Checker{Sources: []Source{reports, fraud}, Inflows: inflowList{[]Inflow{{From: thief, Asset: "native", Amount: big.NewInt(1_000_000_000)}}, 0},
		MaxFunders: 25, Now: func() time.Time { return now }}
	if v, _ := c.Check(context.Background(), honest, 1, now.Add(-FunderWindow)); v.Refused || !v.Refer {
		t.Fatalf("a reported funder: %+v", v)
	}
	// The reported address itself is refused with reason 4.
	if v, _ := c.Check(context.Background(), attacker, 1, now.Add(-FunderWindow)); !v.Refused || v.Reason != ReasonFraud {
		t.Fatalf("the reported address: %+v", v)
	}
}

func TestFundersBelowBothTheShareAndTheFloorAreDust(t *testing.T) {
	d := Dust{ShareBps: 100, Floors: map[string]*big.Int{"native": big.NewInt(100_000_000)}}
	n := big.NewInt
	usdc := "USDC:" + grandpa
	got := d.matter([]Inflow{
		{From: funder, Asset: "native", Amount: n(9_000_000_000)},
		// 0.5 XLM of 90 XLM: below 1 percent and below 10 XLM.
		{From: thief, Asset: "native", Amount: n(5_000_000)},
		// Below the floor but above 1 percent of a small total.
		{From: grandpa, Asset: "native", Amount: n(99_000_000)},
		// An asset without a floor always matters.
		{From: clean, Asset: usdc, Amount: n(1)},
		// So does an amount Horizon does not give, even beside a known amount that is dust.
		{From: contract, Asset: "native"},
		{From: contract, Asset: "native", Amount: n(1)},
		// Value out of a pool names nobody.
		{Asset: "native", Amount: n(1_000)},
	})
	if strings.Join(got, ",") != strings.Join([]string{funder, grandpa, clean, contract}, ",") {
		t.Fatalf("funders that matter %v", got)
	}
}

func TestAHistoryNotReadInFullNeverPasses(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	listed := keypair.MustRandom().Address()
	src := static("exploits", now, map[string]Hit{listed: {Source: "exploits", Reason: ReasonExploit}})
	var inflows []Inflow
	for range 25 {
		inflows = append(inflows, Inflow{From: keypair.MustRandom().Address(), Asset: "native", Amount: big.NewInt(1_000_000_000)})
	}
	// The listed funder comes last, past the cap, as the oldest of a newest-first history.
	inflows = append(inflows, Inflow{From: listed, Asset: "native", Amount: big.NewInt(1_000_000_000)})
	c := &Checker{Sources: []Source{src}, Inflows: inflowList{inflows, 0}, MaxFunders: 25, Now: func() time.Time { return now }}
	v, err := c.Check(context.Background(), clean, 1, now.Add(-FunderWindow))
	if err != nil || v.Clear() || !v.Incomplete || !strings.Contains(v.Detail, "25 of the 26 funders") {
		t.Fatalf("over the cap: %+v %v", v, err)
	}
	c.Inflows = inflowList{inflows[:3], GapVolume}
	if v, _ := c.Check(context.Background(), clean, 1, now.Add(-FunderWindow)); v.Clear() || !v.Incomplete || !strings.Contains(v.Detail, "longer than a check reads") {
		t.Fatalf("a partial history: %+v", v)
	}
	c.Exempt = map[string]bool{clean: true}
	if v, _ := c.Check(context.Background(), clean, 1, now.Add(-FunderWindow)); !v.Clear() {
		t.Fatalf("an exempt address: %+v", v)
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

func TestASuspectListUpdateIsRefusedAndTheOldOneKept(t *testing.T) {
	var entries []string
	for range 10 {
		entries = append(entries, `{"address": "`+keypair.MustRandom().Address()+`", "reason": 2, "source": "incident"}`)
	}
	path := writeList(t, strings.Join(entries, ","))
	s := NewFileSource("curated_list", path, 30*24*time.Hour)
	s.Guard(&Guard{MaxShrinkPct: 20, Canaries: []string{thief}})
	write := func(list []string) {
		doc := fmt.Sprintf(`{"version": "8", "updated_at": "2026-10-02T00:00:00Z", "entries": [%s]}`, strings.Join(list, ","))
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	canary := `{"address": "` + thief + `", "reason": 2, "source": "incident"}`
	write(append(slices.Clone(entries), canary))
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Losing three of eleven entries is a shrink of more than 20 percent.
	write(append(slices.Clone(entries[:7]), canary))
	if err := s.Refresh(context.Background()); !errors.Is(err, ErrSuspect) {
		t.Fatalf("a shrunk list: %v", err)
	}
	if _, ok := s.Lookup(entries[9][13:69]); !ok {
		t.Fatal("the previous list was dropped")
	}
	write(entries)
	if err := s.Refresh(context.Background()); !errors.Is(err, ErrSuspect) || !strings.Contains(err.Error(), "canary") {
		t.Fatalf("a list without its canary: %v", err)
	}
	for _, bad := range []string{
		`{"version": "9", "updated_at": "2026-10-02T00:00:00Z", "entries": [], "extra": 1}`,
		`{"version": "9", "updated_at": "2026-10-02T00:00:00Z"}`,
		`{"version": "9", "updated_at": "2026-10-02T00:00:00Z", "entries": [{"address": "` + thief + `", "reason": 2}]}`,
	} {
		if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := s.Refresh(context.Background()); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestTheSanctionsListMustBeTheSDNList(t *testing.T) {
	row := `36,"SOME PERSON","individual","SDGT",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,"Digital Currency Address - XLM ` + thief + `."`
	for name, c := range map[string]struct {
		body string
		ok   bool
	}{
		"plain":           {row + "\n37,\"OTHER\",\"entity\",\"CYBER2\",-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- ,-0- \n\x1a", true},
		"with its header": {"ent_num,SDN_Name,SDN_Type,Program,Title,Call_Sign,Vess_type,Tonnage,GRT,Vess_flag,Vess_owner,Remarks\n" + row, true},
		"a web page":      {"<html><body>maintenance, back soon</body></html>", false},
		"short records":   {"36,\"SOME PERSON\",\"individual\"", false},
		"no entity":       {strings.Replace(row, "36,", "x,", 1), false},
		"empty":           {"", false},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(c.body)) }))
		err := NewOFACSource(srv.URL, time.Hour).Refresh(context.Background())
		srv.Close()
		if (err == nil) != c.ok {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestADirectoryPageWithoutRecordsIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"error": "rate limited"}`)) }))
	defer srv.Close()
	if err := NewDirectorySource(srv.URL, time.Hour).Refresh(context.Background()); err == nil {
		t.Fatal("a page without records was read as an empty directory")
	}
}
