package screening

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"

	"github.com/cyphras/cyphras-contracts/services/internal/horizon"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// FunderWindow is how far back the accounts that sent value to an address count as its funders.
const FunderWindow = 30 * 24 * time.Hour

// Inflow is value an address received, with its sender when one can be named.
type Inflow = horizon.Inflow

// Inflows finds what an account received since a time; horizon.Client is one.
type Inflows interface {
	// Inflows returns what the account received and whether its history was read in full.
	Inflows(ctx context.Context, account string, since time.Time) ([]Inflow, bool, error)
}

// ErrUnavailable reports that a check could not run: a source is stale or unreachable. Screening
// fails closed on it.
var ErrUnavailable = errors.New("screening: a required source is unavailable")

// Verdict is the outcome of one check.
type Verdict struct {
	// Refused is set, with the reason, when the address itself matched a list that refuses.
	Refused bool
	Reason  uint32
	// Refer is set when a person must decide: a list refers the address, or a funder matched a
	// list. A funder never refuses on its own, since anyone can send value to anyone.
	Refer bool
	// Incomplete is set when not every funder that matters could be checked: the history was read
	// only in part, or more funders mattered than are checked. Screening never allows on it.
	Incomplete bool
	// Findings name each match and each gap, so a later check can tell what is new.
	Findings []string
	Detail   string
	Sources  []SourceStatus
}

// Clear reports a verdict that lets the address through on its own.
func (v Verdict) Clear() bool {
	return !v.Refused && !v.Refer && !v.Incomplete
}

// Dust decides which funders are too small to matter. A funder is left out when, for every asset
// it sent, it is below both ShareBps of what the address received of that asset and the asset's
// floor, in its smallest unit. An asset without a floor, and an inflow of unknown amount, always
// matter.
type Dust struct {
	ShareBps int64
	Floors   map[string]*big.Int
}

// matter returns the senders that matter, in the order the inflows name them.
func (d Dust) matter(inflows []Inflow) []string {
	totals := map[string]*big.Int{}
	type sent struct {
		amounts map[string]*big.Int
		unknown bool
	}
	by := map[string]*sent{}
	var order []string
	add := func(m map[string]*big.Int, asset string, amount *big.Int) {
		if m[asset] == nil {
			m[asset] = new(big.Int)
		}
		m[asset].Add(m[asset], amount)
	}
	for _, in := range inflows {
		if in.Amount != nil && in.Asset != "" {
			add(totals, in.Asset, in.Amount)
		}
		if in.From == "" {
			continue
		}
		s := by[in.From]
		if s == nil {
			s = &sent{amounts: map[string]*big.Int{}}
			by[in.From] = s
			order = append(order, in.From)
		}
		if in.Amount == nil || in.Asset == "" {
			s.unknown = true
		} else {
			add(s.amounts, in.Asset, in.Amount)
		}
	}
	var out []string
	for _, f := range order {
		if s := by[f]; s.unknown || !d.dust(s.amounts, totals) {
			out = append(out, f)
		}
	}
	return out
}

func (d Dust) dust(amounts, totals map[string]*big.Int) bool {
	if len(amounts) == 0 {
		return false
	}
	for asset, amount := range amounts {
		floor := d.Floors[asset]
		if floor == nil || amount.Cmp(floor) >= 0 {
			return false
		}
		share := new(big.Int).Mul(totals[asset], big.NewInt(d.ShareBps))
		if new(big.Int).Mul(amount, big.NewInt(10_000)).Cmp(share) >= 0 {
			return false
		}
	}
	return true
}

// Checker checks an address against every source, and the funders of its funders up to a number
// of hops back.
type Checker struct {
	Sources []Source
	Inflows Inflows
	// MaxFunders bounds how many funders that matter are checked for each address.
	MaxFunders int
	Dust       Dust
	// Exempt are addresses whose funders are not read, such as an exchange's deposit account, whose
	// inflows are too many to read; each is still checked against every list.
	Exempt map[string]bool
	Now    func() time.Time
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

// directOnly is a source that names only the addresses it lists, never their payees: a
// self-report says a key was compromised, not that whoever it paid is.
type directOnly interface {
	directOnly() bool
}

func (c *Checker) lookup(address string, funder bool) (Hit, bool) {
	var referral *Hit
	for _, s := range c.Sources {
		if d, ok := s.(directOnly); ok && funder && d.directOnly() {
			continue
		}
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

// Check screens an address, and up to hops back the funders that sent it value since the given
// time. A muxed address is screened as its account. Only the address itself can be refused; a
// funder's match, or a funder history that could not be read in full, is left to a person.
func (c *Checker) Check(ctx context.Context, address string, hops int, since time.Time) (Verdict, error) {
	if err := c.Fresh(); err != nil {
		return Verdict{}, err
	}
	account, err := vault.AccountOf(address)
	if err != nil {
		return Verdict{}, err
	}
	v := Verdict{Sources: c.Statuses()}
	var notes []string
	note := func(finding, text string) {
		v.Findings = append(v.Findings, finding)
		notes = append(notes, text)
	}
	if h, ok := c.lookup(account, false); ok {
		if !h.Refer {
			v.Refused, v.Reason = true, h.Reason
			v.Detail = fmt.Sprintf("the address matched %s: %s", h.Source, h.Detail)
			return v, nil
		}
		v.Refer = true
		note("address:"+h.Source, fmt.Sprintf("the address matched %s: %s", h.Source, h.Detail))
	}
	level, checked := []string{account}, map[string]bool{account: true}
	for hop := 1; hop <= hops; hop++ {
		var next []string
		for _, a := range level {
			if !strkey.IsValidEd25519PublicKey(a) || c.Exempt[a] {
				continue
			}
			inflows, complete, err := c.Inflows.Inflows(ctx, a, since)
			if err != nil {
				return Verdict{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			if !complete {
				v.Incomplete = true
				note("partial:"+a, fmt.Sprintf("the history of %s was read only in part", a))
			}
			funders := c.Dust.matter(inflows)
			if len(funders) > c.MaxFunders {
				v.Incomplete = true
				note("truncated:"+a, fmt.Sprintf("%d of the %d funders of %s that matter were checked", c.MaxFunders, len(funders), a))
				funders = funders[:c.MaxFunders]
			}
			for _, f := range funders {
				if checked[f] {
					continue
				}
				checked[f] = true
				if h, ok := c.lookup(f, true); ok {
					v.Refer = true
					what := "a referral"
					if !h.Refer {
						what = fmt.Sprintf("reason %d", h.Reason)
					}
					note("funder:"+f+":"+h.Source, fmt.Sprintf("a funder %d hop(s) back, %s, matched %s (%s): %s", hop, f, h.Source, what, h.Detail))
				}
				next = append(next, f)
			}
		}
		level = next
	}
	v.Detail = strings.Join(notes, "; ")
	return v, nil
}
