// Package httpapi holds what the services' HTTP APIs share. Nothing here records a client address,
// a path, a parameter or a request time; per-client rate limits live in the proxy, which does not
// pass the client address on.
package httpapi

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// JSON writes v with the status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Fail writes a fixed error code, never an internal message.
func Fail(w http.ResponseWriter, status int, code string) {
	JSON(w, status, map[string]string{"error": code})
}

// Public serves an API to any origin without credentials, and turns a panic into a generic error.
func Public(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE")
		h.Set("Access-Control-Allow-Headers", "Content-Type")
		h.Set("Access-Control-Max-Age", "600")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		defer func() {
			if recover() != nil {
				Fail(w, http.StatusInternalServerError, "internal")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ReadJSON decodes a body of at most limit bytes into v. Member names must match exactly and
// appear once, unknown members are refused, and nothing may follow the value, so a body has one
// reading only.
func ReadJSON(w http.ResponseWriter, r *http.Request, limit int64, v any) error {
	return jsonv2.UnmarshalRead(http.MaxBytesReader(w, r.Body, limit), v, jsonv2.RejectUnknownMembers(true))
}

// Limiter is a token bucket shared by every client of an endpoint.
type Limiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// NewLimiter allows perMinute requests a minute with bursts of burst.
func NewLimiter(perMinute, burst int) *Limiter {
	return &Limiter{rate: float64(perMinute) / 60, burst: float64(burst), tokens: float64(burst), now: time.Now}
}

// Allow takes a token if one is left.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.last.IsZero() {
		l.tokens = min(l.burst, l.tokens+now.Sub(l.last).Seconds()*l.rate)
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// Serve runs the handler on addr until ctx ends. The server's error log is discarded because Go
// writes client addresses into it.
func Serve(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
