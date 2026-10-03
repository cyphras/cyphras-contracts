// Package horizon reads account history from a Horizon server: what an account received and from
// whom, and what an account's own operations did. Errors never carry the server's URL, which may hold a key, nor
// the account asked about.
package horizon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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

type assetFields struct {
	AssetType   string `json:"asset_type"`
	AssetCode   string `json:"asset_code"`
	AssetIssuer string `json:"asset_issuer"`
}

func (a assetFields) name() string {
	if a.AssetType == "native" {
		return "native"
	}
	if a.AssetCode == "" {
		return ""
	}
	return a.AssetCode + ":" + a.AssetIssuer
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
			Amount    string    `json:"amount"`
			Starting  string    `json:"starting_balance"`
			assetFields
			Changes []struct {
				From   string `json:"from"`
				To     string `json:"to"`
				Amount string `json:"amount"`
				assetFields
			} `json:"asset_balance_changes"`
		} `json:"records"`
	} `json:"_embedded"`
}

type inflowEffectsPage struct {
	Links struct {
		Next struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
	Embedded struct {
		Records []struct {
			Type      string    `json:"type"`
			CreatedAt time.Time `json:"created_at"`
			BalanceID string    `json:"balance_id"`
			Asset     string    `json:"asset"`
			Amount    string    `json:"amount"`
			Seller    string    `json:"seller"`
			Bought    string    `json:"bought_amount"`
			BoughtTyp string    `json:"bought_asset_type"`
			BoughtCod string    `json:"bought_asset_code"`
			BoughtIss string    `json:"bought_asset_issuer"`
			Reserves  []struct {
				Asset  string `json:"asset"`
				Amount string `json:"amount"`
			} `json:"reserves_received"`
		} `json:"records"`
	} `json:"_embedded"`
}

// Inflow is value an account received. From names the sender; it is empty for value out of a
// liquidity pool, which mixes everyone's deposits and names nobody. Amount is in the asset's
// smallest unit, and nil when the record does not say, as for an account merge.
type Inflow struct {
	From   string
	Asset  string
	Amount *big.Int
}

// stroops reads a Horizon amount, a decimal with up to seven places.
func stroops(s string) *big.Int {
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" || len(frac) > 7 || strings.HasPrefix(whole, "-") {
		return nil
	}
	n, ok := new(big.Int).SetString(whole+frac+strings.Repeat("0", 7-len(frac)), 10)
	if !ok {
		return nil
	}
	return n
}

// maxClaims bounds the claimable balances whose creators one lookup asks for.
const maxClaims = 50

// Inflows returns what the account received since a time, newest first, and whether its history
// was read in full: payments, path payments, account creations and merges and contract transfers
// from its payments, and the claimable balances it claimed, the trades that paid it and its
// withdrawals from liquidity pools from its effects. A missing account received nothing.
func (c Client) Inflows(ctx context.Context, account string, since time.Time) ([]Inflow, bool, error) {
	var out []Inflow
	complete := true
	next := c.accountURL(account, "payments", fmt.Sprintf("order=desc&limit=%d", pageSize))
	for page := 0; next != ""; page++ {
		if page == c.MaxPages {
			complete = false
			break
		}
		var p paymentsPage
		found, err := c.get(ctx, next, &p)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, true, nil
		}
		next = ""
		for _, r := range p.Embedded.Records {
			if r.CreatedAt.Before(since) {
				break
			}
			switch r.Type {
			case "payment", "path_payment_strict_receive", "path_payment_strict_send":
				if r.To == account && r.From != account {
					out = append(out, Inflow{From: r.From, Asset: r.name(), Amount: stroops(r.Amount)})
				}
			case "create_account":
				if r.Account == account {
					out = append(out, Inflow{From: r.Funder, Asset: "native", Amount: stroops(r.Starting)})
				}
			case "account_merge":
				if r.Into == account {
					out = append(out, Inflow{From: r.Account, Asset: "native"})
				}
			case "invoke_host_function":
				for _, ch := range r.Changes {
					if ch.To == account && ch.From != account {
						out = append(out, Inflow{From: ch.From, Asset: ch.name(), Amount: stroops(ch.Amount)})
					}
				}
			}
		}
		if n := len(p.Embedded.Records); n == pageSize && !p.Embedded.Records[n-1].CreatedAt.Before(since) {
			next = p.Links.Next.Href
		}
	}
	claims := 0
	next = c.accountURL(account, "effects", fmt.Sprintf("order=desc&limit=%d", pageSize))
	for page := 0; next != ""; page++ {
		if page == c.MaxPages {
			complete = false
			break
		}
		var p inflowEffectsPage
		found, err := c.get(ctx, next, &p)
		if err != nil {
			return nil, false, err
		}
		if !found {
			break
		}
		next = ""
		for _, r := range p.Embedded.Records {
			if r.CreatedAt.Before(since) {
				break
			}
			switch r.Type {
			case "claimable_balance_claimed":
				claims++
				if claims > maxClaims {
					complete = false
					continue
				}
				from, err := c.creator(ctx, r.BalanceID)
				if err != nil {
					return nil, false, err
				}
				if from == "" {
					// A sender that cannot be named cannot be screened.
					complete = false
					continue
				}
				out = append(out, Inflow{From: from, Asset: r.Asset, Amount: stroops(r.Amount)})
			case "trade":
				bought := assetFields{AssetType: r.BoughtTyp, AssetCode: r.BoughtCod, AssetIssuer: r.BoughtIss}
				out = append(out, Inflow{From: r.Seller, Asset: bought.name(), Amount: stroops(r.Bought)})
			case "liquidity_pool_withdrew":
				for _, res := range r.Reserves {
					out = append(out, Inflow{Asset: res.Asset, Amount: stroops(res.Amount)})
				}
			}
		}
		if n := len(p.Embedded.Records); n == pageSize && !p.Embedded.Records[n-1].CreatedAt.Before(since) {
			next = p.Links.Next.Href
		}
	}
	return out, complete, nil
}

type operationsPage struct {
	Embedded struct {
		Records []struct {
			Type          string `json:"type"`
			SourceAccount string `json:"source_account"`
		} `json:"records"`
	} `json:"_embedded"`
}

// creator returns the account that created a claimable balance, or "" when Horizon does not know.
func (c Client) creator(ctx context.Context, balanceID string) (string, error) {
	if balanceID == "" {
		return "", nil
	}
	target := fmt.Sprintf("%s/claimable_balances/%s/operations?order=asc&limit=1", strings.TrimSuffix(c.URL, "/"), url.PathEscape(balanceID))
	var p operationsPage
	found, err := c.get(ctx, target, &p)
	if err != nil || !found || len(p.Embedded.Records) == 0 || p.Embedded.Records[0].Type != "create_claimable_balance" {
		return "", err
	}
	return p.Embedded.Records[0].SourceAccount, nil
}

// Funders returns the accounts that sent value to account since a time, newest first, and whether
// the history was read in full.
func (c Client) Funders(ctx context.Context, account string, since time.Time) ([]string, bool, error) {
	inflows, complete, err := c.Inflows(ctx, account, since)
	if err != nil {
		return nil, false, err
	}
	seen := map[string]bool{}
	var out []string
	for _, in := range inflows {
		if in.From != "" && !seen[in.From] {
			seen[in.From] = true
			out = append(out, in.From)
		}
	}
	return out, complete, nil
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
