package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPublicAnswersPreflightAndHidesPanics(t *testing.T) {
	h := Public(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("database password in a message")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, "/v1/submit", nil))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("preflight %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "password") || !strings.Contains(rec.Body.String(), `"internal"`) {
		t.Fatalf("panic answered %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" || rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("credentials allowed")
	}
}

func TestReadJSONIsStrict(t *testing.T) {
	type body struct {
		A int `json:"a"`
	}
	for input, ok := range map[string]bool{
		`{"a":1}`:                             true,
		`{"a":1}` + "\n":                      true,
		`{"a":1,"b":2}`:                       false,
		`{"a":1}{"a":2}`:                      false,
		`{"a":1} x`:                           false,
		`{"a":1}]`:                            false,
		`{"a":1,"a":2}`:                       false,
		`{"A":1}`:                             false,
		strings.Repeat(" ", 2048) + `{"a":1}`: false,
	} {
		var b body
		err := ReadJSON(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", strings.NewReader(input)), 1024, &b)
		if (err == nil) != ok {
			t.Fatalf("%q: %v", input, err)
		}
	}
}

func TestTheLimiterRefillsOverTime(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(60, 2)
	l.now = func() time.Time { return now }
	if !l.Allow() || !l.Allow() || l.Allow() {
		t.Fatal("burst of two")
	}
	now = now.Add(time.Second)
	if !l.Allow() || l.Allow() {
		t.Fatal("one token a second")
	}
}
