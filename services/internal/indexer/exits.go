package indexer

import (
	"cmp"
	"math/big"
	"net/http"
	"slices"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

const secondsPerDay = 86_400

// QueuedExit is an exit waiting in the exit queue; position 0 is the head. EarliestRelease is the
// earliest time a release can pay it, counting today's use of the window and every exit ahead of
// it, if each is released as soon as it fits.
type QueuedExit struct {
	ID              uint64 `json:"id"`
	Position        uint64 `json:"position"`
	Payout          string `json:"payout"`
	Fee             string `json:"fee"`
	Recipient       string `json:"recipient"`
	Relayer         string `json:"relayer"`
	QueuedAt        uint64 `json:"queued_at"`
	QueuedLedger    uint32 `json:"queued_ledger"`
	TxHash          string `json:"tx_hash"`
	EarliestRelease uint64 `json:"earliest_release"`
}

// StrandedExit is a released exit with parts the asset contract refused; Payout and Fee are what is
// still owed, which claim pays.
type StrandedExit struct {
	ID        uint64 `json:"id"`
	Payout    string `json:"payout"`
	Fee       string `json:"fee"`
	Recipient string `json:"recipient"`
	Relayer   string `json:"relayer"`
	QueuedAt  uint64 `json:"queued_at"`
}

// Window is the day's outflow window: what it has paid and when it resets.
type Window struct {
	Day      uint64 `json:"day"`
	Used     string `json:"used"`
	ResetsAt uint64 `json:"resets_at"`
}

// releaseSchedule gives each queued exit, in queue order, the earliest time a release can pay it.
// A release pays exits in order while each fits what is left of a day's window, which resets at
// each UTC midnight, and nothing is released during a halt. Claims of stranded exits use the
// window too and are not foreseen, so the times are a lower bound.
func releaseSchedule(outflows []*big.Int, now, haltedUntil uint64, usedToday, maxDaily *big.Int) []uint64 {
	start := max(now, haltedUntil)
	d := start / secondsPerDay
	used := new(big.Int)
	if d == now/secondsPerDay {
		used.Set(usedToday)
	}
	at := start
	out := make([]uint64, len(outflows))
	for i, o := range outflows {
		if new(big.Int).Add(used, o).Cmp(maxDaily) > 0 {
			d++
			at = d * secondsPerDay
			used.SetInt64(0)
		}
		used.Add(used, o)
		out[i] = at
	}
	return out
}

// exits serves the whole exit queue and every stranded exit, so a client finds its own exit by the
// ID its transaction emitted without asking for it.
func (ix *Indexer) exits(w http.ResponseWriter, _ *http.Request) {
	h, ok := ix.serving(w)
	if !ok {
		return
	}
	now := uint64(ix.now().Unix())
	ix.mu.RLock()
	s := ix.state
	var maxDaily *big.Int
	switch {
	case ix.instance != nil:
		maxDaily = new(big.Int).Set(ix.instance.Limits.MaxDailyOutflow)
	case s.Limits != nil:
		maxDaily = new(big.Int).Set(s.Limits.MaxDailyOutflow)
	}
	head, tail, haltedUntil := s.ExitHead, s.ExitTail, s.HaltedUntil
	queuedTotal, used := s.QueuedTotal.String(), s.OutflowOn(now/secondsPerDay)
	queued := make([]QueuedExit, 0, len(s.Exits))
	var outflows []*big.Int
	for id := head; id < tail; id++ {
		e := s.Exits[id]
		queued = append(queued, QueuedExit{
			ID: id, Position: id - head, Payout: e.Payout.String(), Fee: e.Fee.String(), Recipient: e.Recipient,
			Relayer: e.Relayer, QueuedAt: e.QueuedAt, QueuedLedger: e.Ledger, TxHash: e.TxHash,
		})
		outflows = append(outflows, e.Outflow())
	}
	stranded := make([]StrandedExit, 0, len(s.Stranded))
	for _, e := range s.Stranded {
		stranded = append(stranded, StrandedExit{ID: e.ID, Payout: e.Payout.String(), Fee: e.Fee.String(), Recipient: e.Recipient, Relayer: e.Relayer, QueuedAt: e.QueuedAt})
	}
	ix.mu.RUnlock()
	if maxDaily == nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	for i, at := range releaseSchedule(outflows, now, haltedUntil, used, maxDaily) {
		queued[i].EarliestRelease = at
	}
	slices.SortFunc(stranded, func(a, b StrandedExit) int { return cmp.Compare(a.ID, b.ID) })
	today := now / secondsPerDay
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"head": head, "tail": tail, "queued_total": queuedTotal, "max_daily_outflow": maxDaily.String(),
		"window":       Window{Day: today, Used: used.String(), ResetsAt: (today + 1) * secondsPerDay},
		"halted_until": haltedUntil, "queued": queued, "stranded": stranded, "complete_to": h.IngestedLedger,
	})
}
