package main

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// answers serves the statuses in order, then 200, and counts the requests.
func answers(t *testing.T, header http.Header, statuses ...int) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(calls.Add(1)) - 1
		if n < len(statuses) {
			for k, v := range header {
				w.Header()[k] = v
			}
			w.WriteHeader(statuses[n])
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func clientOf(r retrying) *http.Client {
	if r.next == nil {
		r.next = http.DefaultTransport
	}
	if r.delay == 0 {
		r.delay = time.Millisecond
	}
	return &http.Client{Transport: r}
}

func TestOnlyWhatSaysToComeBackLaterIsRetried(t *testing.T) {
	for status, retried := range map[int]bool{
		429: true, 502: true, 503: true, 504: true,
		500: false, 501: false, 505: false, 404: false, 403: false, 400: false,
	} {
		srv, calls := answers(t, nil, status)
		resp, err := clientOf(retrying{}).Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if retried != (calls.Load() == 2) || (retried && resp.StatusCode != 200) || (!retried && resp.StatusCode != status) {
			t.Fatalf("status %d: %d requests, final %d", status, calls.Load(), resp.StatusCode)
		}
	}
	srv, calls := answers(t, nil, 503, 503, 503, 503, 503, 503)
	resp, err := clientOf(retrying{}).Get(srv.URL)
	if err != nil || resp.StatusCode != 503 || calls.Load() != attempts {
		t.Fatalf("a store that stays busy: %d requests, %v", calls.Load(), err)
	}
	resp.Body.Close()
}

func TestARetryAfterIsObeyedUpToACap(t *testing.T) {
	srv, _ := answers(t, http.Header{"Retry-After": {"1"}}, 429)
	start := time.Now()
	resp, err := clientOf(retrying{}).Get(srv.URL)
	if err != nil || resp.StatusCode != 200 || time.Since(start) < time.Second {
		t.Fatalf("a Retry-After of one second: %v after %v", err, time.Since(start))
	}
	resp.Body.Close()

	srv, _ = answers(t, http.Header{"Retry-After": {"3600"}}, 503)
	start = time.Now()
	resp, err = clientOf(retrying{maxWait: 50 * time.Millisecond}).Get(srv.URL)
	if err != nil || resp.StatusCode != 200 || time.Since(start) > 10*time.Second {
		t.Fatalf("a Retry-After of an hour: %v after %v", err, time.Since(start))
	}
	resp.Body.Close()
}

type failing struct {
	errs  []error
	calls atomic.Int32
}

func (f *failing) RoundTrip(req *http.Request) (*http.Response, error) {
	n := int(f.calls.Add(1)) - 1
	if n < len(f.errs) {
		return nil, f.errs[n]
	}
	return http.DefaultTransport.RoundTrip(req)
}

type timeout struct{}

func (timeout) Error() string   { return "i/o timeout" }
func (timeout) Timeout() bool   { return true }
func (timeout) Temporary() bool { return true }

func TestOnlyATransportErrorThatCanRecoverIsRetried(t *testing.T) {
	srv, _ := answers(t, nil)
	reset := &net.OpError{Op: "read", Err: syscall.ECONNRESET}
	for name, c := range map[string]struct {
		err     error
		retried bool
	}{
		"a connection reset":       {reset, true},
		"a timeout":                {timeout{}, true},
		"an unexpected EOF":        {io.ErrUnexpectedEOF, true},
		"a certificate":            {x509.UnknownAuthorityError{}, false},
		"a name that is not there": {&net.DNSError{Err: "no such host", IsNotFound: true}, false},
		"a refused connection":     {&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, false},
	} {
		f := &failing{errs: []error{c.err}}
		resp, err := clientOf(retrying{next: f}).Get(srv.URL)
		if c.retried != (err == nil) || (c.retried && f.calls.Load() != 2) || (!c.retried && f.calls.Load() != 1) {
			t.Fatalf("%s: %d tries, %v", name, f.calls.Load(), err)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}

func TestAStalledAnswerGivesUpAfterTheAttemptTimeoutNotTheClientTimeout(t *testing.T) {
	stall := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "start")
		w.(http.Flusher).Flush()
		<-stall
	}))
	defer srv.Close()
	defer close(stall)
	start := time.Now()
	resp, err := clientOf(retrying{attemptTimeout: 200 * time.Millisecond}).Get(srv.URL)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("a body that stalls: %v after %v", err, time.Since(start))
	}
	if d := patientClient.Timeout; d != 0 {
		t.Fatalf("the client has a timeout of %v that spans every try", d)
	}
}

func TestAnAnswerThatDropsPartWayThroughItsBodyIsRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "start")
			return
		}
		_, _ = io.WriteString(w, "whole answer")
	}))
	defer srv.Close()
	resp, err := clientOf(retrying{}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "whole answer" || calls.Load() != 3 {
		t.Fatalf("%d requests, body %q, %v", calls.Load(), body, err)
	}
}

func TestAnAnswerThatAlwaysDropsGivesUpAfterTheAttempts(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "start")
	}))
	defer srv.Close()
	resp, err := clientOf(retrying{}).Get(srv.URL)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil || calls.Load() != attempts {
		t.Fatalf("%d requests, %v", calls.Load(), err)
	}
}

func TestAnAnswerLargerThanWhatIsKeptForRetryIsStillReadWhole(t *testing.T) {
	big := make([]byte, 24<<20)
	for i := range big {
		big[i] = byte(i)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()
	resp, err := clientOf(retrying{}).Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != string(big) {
		t.Fatalf("%d bytes of %d, %v", len(body), len(big), err)
	}
}
