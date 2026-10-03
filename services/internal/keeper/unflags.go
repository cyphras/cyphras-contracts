package keeper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// UnflagsFrom reads the deposits an operator's queued unflag waits to correct from the screening
// service's internal endpoint at url, with the keeper's token.
func UnflagsFrom(url, token string, client *http.Client) func(context.Context) (map[uint64]uint64, error) {
	return func(ctx context.Context) (map[uint64]uint64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("screening unreachable: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("screening answered %d", resp.StatusCode)
		}
		var body struct {
			Deposits []struct {
				ID    uint64 `json:"id"`
				Until uint64 `json:"until"`
			} `json:"deposits"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return nil, fmt.Errorf("screening answered: %w", err)
		}
		out := make(map[uint64]uint64, len(body.Deposits))
		for _, d := range body.Deposits {
			out[d.ID] = d.Until
		}
		return out, nil
	}
}
