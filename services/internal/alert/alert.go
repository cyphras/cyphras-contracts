// Package alert pages an operator through webhooks. Alerts carry only public chain data and the
// service's own state, never anything about a client request.
package alert

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
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

// Name implements Named: the webhook's format and the start of a hash of its URL, which holds a
// token and is never shown.
func (w Webhook) Name() string {
	sum := sha256.Sum256([]byte(w.Format + " " + w.URL))
	return fmt.Sprintf("%s-%x", w.Format, sum[:8])
}

// Send implements Channel.
func (w Webhook) Send(ctx context.Context, a Alert) error {
	a = fit(w.Format, a)
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
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return RetryAfter{Wait: retryAfter(resp)}
	case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusRequestTimeout:
		return Refused{Format: w.Format, Status: resp.StatusCode}
	case resp.StatusCode >= 300:
		return fmt.Errorf("alert: %s webhook answered %d", w.Format, resp.StatusCode)
	}
	return nil
}

// Refused is a channel's refusal of one alert, a 4xx answer other than 408 or 429: sending the
// same alert again would be refused again.
type Refused struct {
	Format string
	Status int
}

func (r Refused) Error() string {
	return fmt.Sprintf("alert: %s webhook answered %d", r.Format, r.Status)
}

// maxText is how long a message each format takes, as the services behind them accept it.
var maxText = map[string]int{"discord": 2000, "telegram": 4096, "slack": 4000, "json": 4096, "text": 4096}

// fit shortens an alert's message so that what a format sends of it is no longer than it takes.
func fit(format string, a Alert) Alert {
	limit := maxText[format]
	text := a.text()
	if format == "json" {
		text = a.Message
	}
	if limit == 0 || len(text) <= limit {
		return a
	}
	const mark = " [truncated]"
	keep := max(len(a.Message)-(len(text)-limit)-len(mark), 0)
	a.Message = strings.ToValidUTF8(a.Message[:keep], "") + mark // the cut may split a character
	return a
}

// RetryAfter is a channel's refusal that says how long to wait before the next send, as a 429
// answer does.
type RetryAfter struct {
	Wait time.Duration
}

func (r RetryAfter) Error() string {
	return fmt.Sprintf("alert: rate limited for %s", r.Wait)
}

// retryAfter reads how long a 429 answer asks to wait: its Retry-After header, in seconds or as a
// date, or the retry_after member of its body, as Discord sends it at the top and Telegram in
// parameters. Without either it is 30 seconds, and it is never more than an hour.
func retryAfter(resp *http.Response) time.Duration {
	wait := 30 * time.Second
	if h := resp.Header.Get("Retry-After"); h != "" {
		if n, err := strconv.ParseFloat(h, 64); err == nil && n >= 0 {
			wait = seconds(n)
		} else if at, err := http.ParseTime(h); err == nil {
			wait = time.Until(at)
		}
	} else {
		var body struct {
			RetryAfter *float64 `json:"retry_after"`
			Parameters struct {
				RetryAfter *float64 `json:"retry_after"`
			} `json:"parameters"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) == nil {
			switch {
			case body.RetryAfter != nil:
				wait = seconds(*body.RetryAfter)
			case body.Parameters.RetryAfter != nil:
				wait = seconds(*body.Parameters.RetryAfter)
			}
		}
	}
	return min(max(wait, time.Second), time.Hour)
}

// seconds converts a wait in seconds, bounded first, since a float too large for a Duration
// converts to a different value on each architecture.
func seconds(n float64) time.Duration {
	return time.Duration(min(n, time.Hour.Seconds()) * float64(time.Second))
}

// ParseWebhooks reads one "format url" pair per line; blank lines and lines starting with # are
// skipped. A URL listed twice, however it is written, is refused, as a channel's copies are kept
// under its name.
func ParseWebhooks(data []byte) ([]Channel, error) {
	var out []Channel
	seen := map[string]int{}
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
		normal := normalize(u)
		if first, ok := seen[normal]; ok {
			return nil, fmt.Errorf("alert: line %d repeats the URL of line %d", n, first)
		}
		seen[normal] = n
		out = append(out, Webhook{Format: format, URL: normal})
	}
	return out, sc.Err()
}

// normalize writes a URL one way however it was spelled: the host in lower case without the
// default port, no fragment, and the query sorted. The path, which may hold a token, is kept as
// it is.
func normalize(u *url.URL) string {
	n := *u
	n.Host = strings.ToLower(strings.TrimSuffix(n.Host, ":443"))
	n.Fragment, n.RawFragment = "", ""
	n.RawQuery = n.Query().Encode()
	return n.String()
}

// Alerter raises alerts on every channel, at most once per code within the cooldown, and reports
// when an open alert clears. Every alert is logged, a repeat within the cooldown too. With a
// Queue, delivery runs in the background and Raise returns at once; without one, Raise waits for
// the channels.
type Alerter struct {
	Service  string
	Channels []Channel
	Log      *slog.Logger
	Cooldown time.Duration
	Now      func() time.Time
	Queue    *Queue

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
		if a.Log != nil {
			a.Log.Log(ctx, level(sev), "alert repeated", "code", code, "severity", sev, "message", fmt.Sprintf(format, args...))
		}
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
	if a.Queue != nil {
		a.Queue.Put(al)
		return
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
