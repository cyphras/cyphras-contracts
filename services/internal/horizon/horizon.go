// Package horizon reads account history from a Horizon server: who funded an account, and what
// an account's own operations did. Errors never carry the server's URL, which may hold a key, nor
// the account asked about.
package horizon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client reads one Horizon server.
type Client struct {
	URL  string
	HTTP *http.Client
	// MaxPages bounds how far back a funder lookup reads.
	MaxPages int
}

const pageSize = 200

var errUnreachable = errors.New("horizon unreachable")

// get reads one page into v; a 404 reports found false.
func (c Client) get(ctx context.Context, target string, v any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, errUnreachable
	}
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, errUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("horizon answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v); err != nil {
		return false, errors.New("horizon sent an unreadable page")
	}
	return true, nil
}

func (c Client) accountURL(account, collection, query string) string {
	return fmt.Sprintf("%s/accounts/%s/%s?%s", strings.TrimSuffix(c.URL, "/"), url.PathEscape(account), collection, query)
}

type paymentsPage struct {
	Links struct {
		Next struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
	Embedded struct {
		Records []struct {
			Type      string    `json:"type"`
			CreatedAt time.Time `json:"created_at"`
			From      string    `json:"from"`
			To        string    `json:"to"`
			Funder    string    `json:"funder"`
			Account   string    `json:"account"`
			Into      string    `json:"into"`
			Changes   []struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"asset_balance_changes"`
		} `json:"records"`
	} `json:"_embedded"`
}

// Funders returns the accounts that sent value to account since a time, newest first, and whether
// the history was read in full. A missing account has none.
func (c Client) Funders(ctx context.Context, account string, since time.Time) ([]string, bool, error) {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a != "" && a != account && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	next := c.accountURL(account, "payments", fmt.Sprintf("order=desc&limit=%d", pageSize))
	for page := 0; next != ""; page++ {
		if page == c.MaxPages {
			return out, false, nil
		}
		var p paymentsPage
		found, err := c.get(ctx, next, &p)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return out, true, nil
		}
		for _, r := range p.Embedded.Records {
			if r.CreatedAt.Before(since) {
				return out, true, nil
			}
			switch r.Type {
			case "payment", "path_payment_strict_receive", "path_payment_strict_send":
				if r.To == account {
					add(r.From)
				}
			case "create_account":
				if r.Account == account {
					add(r.Funder)
				}
			case "account_merge":
				if r.Into == account {
					add(r.Account)
				}
			case "invoke_host_function":
				for _, ch := range r.Changes {
					if ch.To == account {
						add(ch.From)
					}
				}
			}
		}
		next = ""
		if len(p.Embedded.Records) == pageSize {
			next = p.Links.Next.Href
		}
	}
	return out, true, nil
}

// Effect is one effect on an account, as Horizon reports it.
type Effect struct {
	ID          string    `json:"id"`
	PagingToken string    `json:"paging_token"`
	Type        string    `json:"type"`
	CreatedAt   time.Time `json:"created_at"`
	Amount      string    `json:"amount"`
}

type effectsPage struct {
	Embedded struct {
		Records []Effect `json:"records"`
	} `json:"_embedded"`
}

// Effects returns the account's effects after the cursor, oldest first, at most one page. An empty
// cursor returns only the newest effect, so a new reader starts from now.
func (c Client) Effects(ctx context.Context, account, cursor string) ([]Effect, error) {
	query := fmt.Sprintf("order=asc&limit=%d&cursor=%s", pageSize, url.QueryEscape(cursor))
	if cursor == "" {
		query = "order=desc&limit=1"
	}
	var p effectsPage
	found, err := c.get(ctx, c.accountURL(account, "effects", query), &p)
	if err != nil || !found {
		return nil, err
	}
	return p.Embedded.Records, nil
}
