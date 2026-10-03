// Package alert pages an operator through webhooks. Alerts carry only public chain data and the
// service's own state, never anything about a client request.
package alert

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Severity orders alerts.
type Severity string

// The severities.
const (
	Critical Severity = "critical"
	Warning  Severity = "warning"
	Info     Severity = "info"
)

// Alert is one notification.
type Alert struct {
	Service  string    `json:"service"`
	Severity Severity  `json:"severity"`
	Code     string    `json:"code"`
	Message  string    `json:"message"`
	Time     time.Time `json:"time"`
}

func (a Alert) text() string {
	return fmt.Sprintf("[%s] %s %s: %s", strings.ToUpper(string(a.Severity)), a.Service, a.Code, a.Message)
}

// Channel delivers alerts.
type Channel interface {
	Send(ctx context.Context, a Alert) error
}

// Webhook posts alerts to a URL in one of the formats json, text, slack, discord or telegram.
type Webhook struct {
	Format string
	URL    string
	HTTP   *http.Client
}

// Send implements Channel.
func (w Webhook) Send(ctx context.Context, a Alert) error {
	target := w.URL
	var body []byte
	contentType := "application/json"
	switch w.Format {
	case "json":
		body, _ = json.Marshal(a)
	case "text":
		body, contentType = []byte(a.text()), "text/plain; charset=utf-8"
	case "slack":
		body, _ = json.Marshal(map[string]string{"text": a.text()})
	case "discord":
		body, _ = json.Marshal(map[string]string{"content": a.text()})
	case "telegram":
		u, err := url.Parse(w.URL)
		if err != nil {
			return err
		}
		chat := u.Query().Get("chat_id")
		u.RawQuery = ""
		target = u.String()
		body, _ = json.Marshal(map[string]string{"chat_id": chat, "text": a.text()})
	default:
		return fmt.Errorf("alert: unknown format %q", w.Format)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	client := w.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		// The URL holds a token, so the error, which repeats it, is not passed on.
		return fmt.Errorf("alert: %s webhook unreachable", w.Format)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("alert: %s webhook answered %d", w.Format, resp.StatusCode)
	}
	return nil
}

// ParseWebhooks reads one "format url" pair per line; blank lines and lines starting with # are
// skipped.
func ParseWebhooks(data []byte) ([]Channel, error) {
	var out []Channel
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		format, target, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("alert: line %d is not \"format url\"", n)
		}
		switch format {
		case "json", "text", "slack", "discord", "telegram":
		default:
			return nil, fmt.Errorf("alert: line %d has unknown format %q", n, format)
		}
		// The URL carries the channel's token, so it only travels encrypted.
		u, err := url.Parse(strings.TrimSpace(target))
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("alert: line %d has no valid https URL", n)
		}
		out = append(out, Webhook{Format: format, URL: u.String()})
	}
	return out, sc.Err()
}

// Alerter raises alerts on every channel, at most once per code within the cooldown, and reports
// when an open alert clears.
type Alerter struct {
	Service  string
	Channels []Channel
	Log      *slog.Logger
	Cooldown time.Duration
	Now      func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
	open map[string]bool
}

func (a *Alerter) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Raise sends an alert unless the same code was sent within the cooldown.
func (a *Alerter) Raise(ctx context.Context, sev Severity, code, format string, args ...any) {
	a.mu.Lock()
	if a.last == nil {
		a.last, a.open = map[string]time.Time{}, map[string]bool{}
	}
	now := a.now()
	a.open[code] = true
	if t, ok := a.last[code]; ok && now.Sub(t) < a.Cooldown {
		a.mu.Unlock()
		return
	}
	a.last[code] = now
	if len(a.last) > 256 {
		// Codes unique to one event would otherwise accumulate; a condition that persists is
		// raised again well within a day.
		for c, t := range a.last {
			if now.Sub(t) > max(a.Cooldown, 24*time.Hour) {
				delete(a.last, c)
				delete(a.open, c)
			}
		}
	}
	a.mu.Unlock()
	a.deliver(ctx, Alert{Service: a.Service, Severity: sev, Code: code, Message: fmt.Sprintf(format, args...), Time: now.UTC()})
}

// Clear reports that the condition behind an open alert has ended.
func (a *Alerter) Clear(ctx context.Context, code, format string, args ...any) {
	a.mu.Lock()
	wasOpen := a.open[code]
	delete(a.open, code)
	delete(a.last, code)
	a.mu.Unlock()
	if wasOpen {
		a.deliver(ctx, Alert{Service: a.Service, Severity: Info, Code: code + "_resolved", Message: fmt.Sprintf(format, args...), Time: a.now().UTC()})
	}
}

// Open reports whether an alert with the code is open.
func (a *Alerter) Open(code string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.open[code]
}

func (a *Alerter) deliver(ctx context.Context, al Alert) {
	if a.Log != nil {
		a.Log.Log(ctx, level(al.Severity), "alert", "code", al.Code, "severity", al.Severity, "message", al.Message)
	}
	var wg sync.WaitGroup
	for _, ch := range a.Channels {
		wg.Go(func() {
			sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
			defer cancel()
			if err := ch.Send(sendCtx, al); err != nil && a.Log != nil {
				a.Log.Error("alert delivery failed", "code", al.Code, "error", err.Error())
			}
		})
	}
	wg.Wait()
}

func level(s Severity) slog.Level {
	switch s {
	case Critical:
		return slog.LevelError
	case Warning:
		return slog.LevelWarn
	}
	return slog.LevelInfo
}
