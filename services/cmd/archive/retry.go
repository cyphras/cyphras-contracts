package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"syscall"
	"time"
)

// patientClient retries what an object store answers when it is busy, since one failed request
// would otherwise cost a whole window of ledger files that a rebuild fetches again.
var patientClient = &http.Client{Transport: retrying{next: http.DefaultTransport, delay: 500 * time.Millisecond}}

const (
	// attempts is the number of tries a request gets.
	attempts = 5
	// defaultMaxWait bounds how long a server's Retry-After is obeyed.
	defaultMaxWait = 30 * time.Second
	// defaultAttemptTimeout bounds one try, its body included, so a stalled object holds a worker
	// for minutes and not for as long as a window takes.
	defaultAttemptTimeout = 2 * time.Minute
	// bufferedBytes is how much of an answer is read inside the try, so that a connection that
	// drops part way through it is tried again. A ledger file or a window is far smaller; a
	// larger answer is passed on as it arrives.
	bufferedBytes = 8 << 20
)

type retrying struct {
	next http.RoundTripper
	// delay is the wait after the first failure; it doubles for each one after it.
	delay          time.Duration
	maxWait        time.Duration
	attemptTimeout time.Duration
}

func (r retrying) RoundTrip(req *http.Request) (*http.Response, error) {
	maxWait, timeout := r.maxWait, r.attemptTimeout
	if maxWait == 0 {
		maxWait = defaultMaxWait
	}
	if timeout == 0 {
		timeout = defaultAttemptTimeout
	}
	var wait time.Duration
	for try := range attempts {
		if try > 0 {
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(wait):
			}
		}
		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		resp, err := r.next.RoundTrip(req.WithContext(ctx))
		last := try == attempts-1
		if err == nil && !busy(resp.StatusCode) {
			err = buffer(resp)
		}
		switch {
		case err == nil && (!busy(resp.StatusCode) || last):
			resp.Body = &cancelOnClose{ReadCloser: resp.Body, cancel: cancel}
			return resp, nil
		case err != nil && (req.Context().Err() != nil || !recoverable(err) || last):
			cancel()
			return nil, err
		}
		wait = r.delay << try
		if err == nil {
			if told, ok := retryAfter(resp); ok {
				wait = min(told, maxWait)
			}
			resp.Body.Close()
		}
		cancel()
	}
	panic("unreachable")
}

// buffer reads the first bufferedBytes of the answer's body, so a read that fails is the try's
// failure and not the caller's. It closes the body when it fails.
func buffer(resp *http.Response) error {
	head, err := io.ReadAll(io.LimitReader(resp.Body, bufferedBytes+1))
	if err != nil {
		resp.Body.Close()
		return err
	}
	if len(head) > bufferedBytes {
		resp.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
		return nil
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(head))
	return nil
}

// busy reports the answers that say to come back later.
func busy(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// recoverable reports a transport error that a new try can get past: a timeout or a connection
// the other side dropped. A certificate, a name that does not exist or a refused connection will
// be the same next time.
func recoverable(err error) bool {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return true
	}
	for _, dropped := range []error{syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, io.EOF, io.ErrUnexpectedEOF} {
		if errors.Is(err, dropped) {
			return true
		}
	}
	return false
}

func retryAfter(resp *http.Response) (time.Duration, bool) {
	v := resp.Header.Get("Retry-After")
	if seconds, err := strconv.ParseUint(v, 10, 31); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second, true
	}
	if at, err := http.ParseTime(v); err == nil {
		if d := time.Until(at); d > 0 {
			return d, true
		}
	}
	return 0, false
}

// cancelOnClose ends the try's context when its body is closed, which is also what bounds a
// body that stalls.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}
