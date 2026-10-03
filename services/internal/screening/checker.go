package screening

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// FunderWindow is how far back the accounts that sent value to an address count as its funders.
const FunderWindow = 30 * 24 * time.Hour

// Funders finds the accounts that sent value to an account since a time.
type Funders interface {
	// Funders returns the senders and whether the history was read in full.
	Funders(ctx context.Context, account string, since time.Time) ([]string, bool, error)
}

// Horizon reads payment history from a Horizon server.
type Horizon struct {
	URL      string
	HTTP     *http.Client
	MaxPages int
}

type horizonPage struct {
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

const horizonPageSize = 200

// Funders implements Funders.
func (h Horizon) Funders(ctx context.Context, account string, since time.Time) ([]string, bool, error) {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a != "" && a != account && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	next := fmt.Sprintf("%s/accounts/%s/payments?order=desc&limit=%d", strings.TrimSuffix(h.URL, "/"), url.PathEscape(account), horizonPageSize)
	for page := 0; next != ""; page++ {
		if page == h.MaxPages {
			return out, false, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return nil, false, err
		}
		resp, err := h.HTTP.Do(req)
		if err != nil {
			return nil, false, errors.New("horizon unreachable")
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return out, true, nil
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, false, fmt.Errorf("horizon answered %d", resp.StatusCode)
		}
		var p horizonPage
		err = json.NewDecoder(resp.Body).Decode(&p)
		resp.Body.Close()
		if err != nil {
			return nil, false, fmt.Errorf("horizon: %w", err)
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
				for _, c := range r.Changes {
					if c.To == account {
						add(c.From)
					}
				}
			}
		}
		next = ""
		if len(p.Embedded.Records) == horizonPageSize {
			next = p.Links.Next.Href
		}
	}
	return out, true, nil
}

// ErrUnavailable reports that a check could not run: a source is stale or unreachable. Screening
// fails closed on it.
var ErrUnavailable = errors.New("screening: a required source is unavailable")

// Verdict is the outcome of one check.
type Verdict struct {
	// Refused is set with the reason of the first refusing hit.
	Refused bool
	Reason  uint32
	// Refer is set when the check passed but a person must review the deposit.
	Refer   bool
	Detail  string
	Sources []SourceStatus
}

// Checker checks an address and its funders against every source.
type Checker struct {
	Sources []Source
	Funders Funders
	// MaxFunders bounds how many funders are checked at each hop.
	MaxFunders int
	Now        func() time.Time
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Statuses returns the status of every source.
func (c *Checker) Statuses() []SourceStatus {
	out := make([]SourceStatus, 0, len(c.Sources))
	for _, s := range c.Sources {
		out = append(out, s.Status())
	}
	return out
}

// Fresh reports an error when any source is older than its maximum age.
func (c *Checker) Fresh() error {
	now := c.now()
	for _, s := range c.Sources {
		st := s.Status()
		if st.FetchedAt.IsZero() || now.Sub(st.FetchedAt) > time.Duration(st.MaxAge)*time.Second {
			return fmt.Errorf("%w: %s", ErrUnavailable, st.Name)
		}
	}
	return nil
}

func (c *Checker) lookup(address string) (Hit, bool) {
	var referral *Hit
	for _, s := range c.Sources {
		if h, ok := s.Lookup(address); ok {
			if !h.Refer {
				return h, true
			}
			referral = &h
		}
	}
	if referral != nil {
		return *referral, true
	}
	return Hit{}, false
}

// Check screens an address and the funders of its funders up to hops back, counting only value
// received since the given time. A muxed address is screened as its account.
func (c *Checker) Check(ctx context.Context, address string, hops int, since time.Time) (Verdict, error) {
	if err := c.Fresh(); err != nil {
		return Verdict{}, err
	}
	account, err := vault.AccountOf(address)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Sources: c.Statuses()}
	level := []string{account}
	checked := map[string]bool{}
	for hop := 0; hop <= hops && len(level) > 0; hop++ {
		var next []string
		for _, a := range level {
			if checked[a] {
				continue
			}
			checked[a] = true
			if h, ok := c.lookup(a); ok {
				who := "the address"
				if hop > 0 {
					who = fmt.Sprintf("a funder %d hop(s) back, %s,", hop, a)
				}
				if !h.Refer {
					v.Refused, v.Reason, v.Detail = true, h.Reason, fmt.Sprintf("%s matched %s: %s", who, h.Source, h.Detail)
					return v, nil
				}
				v.Refer, v.Detail = true, fmt.Sprintf("%s matched %s: %s", who, h.Source, h.Detail)
			}
			if hop == hops || !strkey.IsValidEd25519PublicKey(a) {
				continue
			}
			funders, complete, err := c.Funders.Funders(ctx, a, since)
			if err != nil {
				return Verdict{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			if !complete || len(funders) > c.MaxFunders {
				v.Refer, v.Detail = true, fmt.Sprintf("the funders of %s were too many to check in full", a)
				funders = funders[:min(len(funders), c.MaxFunders)]
			}
			next = append(next, funders...)
		}
		level = next
	}
	return v, nil
}
