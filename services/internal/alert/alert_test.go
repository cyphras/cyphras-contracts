package alert

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type recorder struct {
	mu   sync.Mutex
	sent []Alert
}

func (r *recorder) Send(_ context.Context, a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, a)
	return nil
}

func TestAlertsAreSentOncePerCooldownAndResolved(t *testing.T) {
	now := time.Unix(1_728_000_000, 0)
	one, two := &recorder{}, &recorder{}
	a := &Alerter{Service: "keeper", Channels: []Channel{one, two}, Cooldown: 10 * time.Minute, Now: func() time.Time { return now }}
	ctx := context.Background()
	a.Raise(ctx, Critical, "ttl_cycle_stale", "last cycle %d hours ago", 3)
	a.Raise(ctx, Critical, "ttl_cycle_stale", "again")
	if len(one.sent) != 1 || len(two.sent) != 1 || one.sent[0].Message != "last cycle 3 hours ago" {
		t.Fatalf("sent %+v", one.sent)
	}
	now = now.Add(11 * time.Minute)
	a.Raise(ctx, Critical, "ttl_cycle_stale", "still")
	if len(one.sent) != 2 || !a.Open("ttl_cycle_stale") {
		t.Fatal("alert not repeated after the cooldown")
	}
	a.Clear(ctx, "ttl_cycle_stale", "cycle completed")
	a.Clear(ctx, "ttl_cycle_stale", "cycle completed")
	if len(one.sent) != 3 || one.sent[2].Code != "ttl_cycle_stale_resolved" || a.Open("ttl_cycle_stale") {
		t.Fatalf("resolution %+v", one.sent)
	}
}

func TestWebhookFormats(t *testing.T) {
	var got []string
	var mu sync.Mutex
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	channels, err := ParseWebhooks([]byte("# pager\n\nslack " + srv.URL + "/s\ndiscord " + srv.URL + "/d\ntelegram " + srv.URL + "/bot1/sendMessage?chat_id=42\ntext " + srv.URL + "/t\njson " + srv.URL + "/j\n"))
	if err != nil {
		t.Fatal(err)
	}
	a := Alert{Service: "watcher", Severity: Warning, Code: "root_mismatch", Message: "m"}
	for _, ch := range channels {
		w := ch.(Webhook)
		w.HTTP = srv.Client()
		if err := w.Send(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{`/s {"text":"[WARNING] watcher root_mismatch: m"}`, `/d {"content"`, `/bot1/sendMessage {"chat_id":"42"`, `/t [WARNING]`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	var decoded Alert
	for _, line := range got {
		if strings.HasPrefix(line, "/j ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "/j ")), &decoded); err != nil || decoded.Code != "root_mismatch" {
				t.Fatalf("json body %q", line)
			}
		}
	}
	for _, bad := range []string{"slack", "pager https://x", "slack ftp://x", "slack https://", "slack http://hooks.example/x"} {
		if _, err := ParseWebhooks([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestAnUnreachableWebhookDoesNotLeakItsURL(t *testing.T) {
	w := Webhook{Format: "slack", URL: "http://127.0.0.1:1/hooks/SECRET-TOKEN"}
	err := w.Send(context.Background(), Alert{})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("error %v", err)
	}
}

func TestAMessageIsCutToWhatItsChannelTakes(t *testing.T) {
	long := strings.Repeat("m", 5000)
	for format, limit := range map[string]int{"discord": 2000, "telegram": 4096, "slack": 4000, "text": 4096} {
		a := fit(format, Alert{Service: "watcher", Severity: Warning, Code: "root_mismatch", Message: long})
		if len(a.text()) != limit || !strings.HasSuffix(a.Message, " [truncated]") {
			t.Fatalf("%s sends %d bytes, not %d", format, len(a.text()), limit)
		}
	}
	if a := fit("json", Alert{Code: "root_mismatch", Message: long}); len(a.Message) != 4096 {
		t.Fatalf("json sends a message of %d bytes", len(a.Message))
	}
	short := Alert{Code: "root_mismatch", Message: strings.Repeat("m", 1980)}
	if fit("discord", short) != short {
		t.Fatal("a message that fits was cut")
	}
	// The cut falls inside a two-byte character, which goes rather than half of it.
	a := fit("discord", Alert{Severity: Info, Code: "c", Message: strings.Repeat("\u00e9", 1500)})
	if !utf8.ValidString(a.Message) || len(a.text()) > 2000 {
		t.Fatalf("cut to %d bytes, valid %v", len(a.text()), utf8.ValidString(a.Message))
	}
}

func TestOnlyAnAnswerThatWouldRepeatRefusesACopy(t *testing.T) {
	for status, refused := range map[int]bool{400: true, 401: true, 403: true, 404: true, 413: true, 408: false, 429: false, 500: false, 502: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		err := Webhook{Format: "json", URL: srv.URL, HTTP: srv.Client()}.Send(context.Background(), Alert{})
		srv.Close()
		if err == nil || errors.As(err, new(Refused)) != refused {
			t.Fatalf("%d: %v", status, err)
		}
	}
}

func TestAWebhookIsNamedWithoutItsToken(t *testing.T) {
	w := Webhook{Format: "discord", URL: "https://discord.example/api/webhooks/1/SECRET-TOKEN"}
	other := Webhook{Format: "discord", URL: w.URL + "2"}
	if n := w.Name(); !strings.HasPrefix(n, "discord-") || len(n) != len("discord-")+16 || strings.Contains(n, "SECRET") || n == other.Name() {
		t.Fatalf("named %q", n)
	}
}
