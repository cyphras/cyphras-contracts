package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/cyphras/cyphras-contracts/services/internal/config"
)

// Heartbeat pings a dead-man switch, such as a monitoring service's check URL, after each healthy
// cycle, so a monitor elsewhere notices when the service stops or goes blind. The URL carries the
// check's token, so it is read from the file HEARTBEAT_URL_FILE names.
type Heartbeat struct {
	URL  string
	HTTP *http.Client
}

// LoadHeartbeat returns the configured heartbeat, or nil when HEARTBEAT_URL_FILE is not set.
func LoadHeartbeat() (*Heartbeat, error) {
	if os.Getenv("HEARTBEAT_URL_FILE") == "" {
		return nil, nil
	}
	raw, err := config.SecretString("HEARTBEAT_URL")
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("HEARTBEAT_URL must be an https URL")
	}
	return &Heartbeat{URL: u.String(), HTTP: &http.Client{Timeout: 10 * time.Second}}, nil
}

// Ping reports one healthy cycle.
func (h *Heartbeat) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.URL, nil)
	if err != nil {
		return errors.New("heartbeat: bad URL")
	}
	resp, err := h.HTTP.Do(req)
	if err != nil {
		// The URL holds a token, so the error, which repeats it, is not passed on.
		return errors.New("heartbeat unreachable")
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat answered %d", resp.StatusCode)
	}
	return nil
}
