package indexer

import (
	"cmp"
	"math/big"
	"net/http"
	"slices"

	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

const secondsPerDay = 86_400

// QueuedExit is an exit waiting in the exit queue; position 0 is the head. Payout and Fee are what
// it still owes, less any part payment. EarliestPaidAt is the earliest time releases can have paid
// all of it.
type QueuedExit struct {
	ID             uint64 `json:"id"`
	Position       uint64 `json:"position"`
	Payout         string `json:"payout"`
	Fee            string `json:"fee"`
	Recipient      string `json:"recipient"`
	Relayer        string `json:"relayer"`
	QueuedAt       uint64 `json:"queued_at"`
	QueuedLedger   uint32 `json:"queued_ledger"`
	TxHash         string `json:"tx_hash"`
	EarliestPaidAt uint64 `json:"earliest_paid_at"`
}

// StrandedExit is a released exit with parts the asset contract refused; Payout and Fee are what is
// still owed, which claim pays. TxHash is the transaction that queued it, StrandedTx the release
// that stranded it.
type StrandedExit struct {
	ID             uint64 `json:"id"`
	Payout         string `json:"payout"`
	Fee            string `json:"fee"`
	Recipient      string `json:"recipient"`
	Relayer        string `json:"relayer"`
	QueuedAt       uint64 `json:"queued_at"`
	TxHash         string `json:"tx_hash"`
	StrandedLedger uint32 `json:"stranded_ledger"`
	StrandedAt     uint64 `json:"stranded_at"`
	StrandedTx     string `json:"stranded_tx"`
}

// Window is the day's outflow window: what it has paid and when it resets.
type Window struct {
	Day      uint64 `json:"day"`
	Used     string `json:"used"`
	ResetsAt uint64 `json:"resets_at"`
}

// paidBy gives each queued exit, in queue order, the earliest time releases can have paid all it
// still owes. Releases pay the queue in order out of each day's window, which resets at midnight
// UTC, and pay nothing during a halt. A vault that pays an exit in parts uses each window in full;
// one that pays only whole exits, or claims of stranded exits, can take longer, so the times are a
// lower bound.
func paidBy(owed []*big.Int, now, haltedUntil uint64, usedToday, maxDaily *big.Int) []uint64 {
	start := max(now, haltedUntil)
	d := start / secondsPerDay
	room := new(big.Int).Set(maxDaily)
	if d == now/secondsPerDay {
		room.Sub(room, usedToday)
		if room.Sign() < 0 {
			room.SetInt64(0)
		}
	}
	out := make([]uint64, len(owed))
	total := new(big.Int)
	for i, o := range owed {
		total.Add(total, o)
		if total.Cmp(room) <= 0 || maxDaily.Sign() <= 0 {
			out[i] = start
			continue
		}
		over := new(big.Int).Sub(total, room)
		days := new(big.Int).Div(over.Add(over, new(big.Int).Sub(maxDaily, big.NewInt(1))), maxDaily)
		out[i] = (d + days.Uint64()) * secondsPerDay
	}
	return out
}

// exits serves the whole exit queue, every stranded exit and the exits paid in full in the last
// week, so a client finds its own exit by the ID its transaction emitted without asking for it.
func (ix *Indexer) exits(w http.ResponseWriter, r *http.Request) {
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
	var owed []*big.Int
	for id := head; id < tail; id++ {
		e := s.Exits[id]
		queued = append(queued, QueuedExit{
			ID: id, Position: id - head, Payout: e.Payout.String(), Fee: e.Fee.String(), Recipient: e.Recipient,
			Relayer: e.Relayer, QueuedAt: e.QueuedAt, QueuedLedger: e.Ledger, TxHash: e.TxHash,
		})
		owed = append(owed, e.Outflow())
	}
	stranded := make([]StrandedExit, 0, len(s.Stranded))
	for _, e := range s.Stranded {
		stranded = append(stranded, StrandedExit{
			ID: e.ID, Payout: e.Payout.String(), Fee: e.Fee.String(), Recipient: e.Recipient, Relayer: e.Relayer, QueuedAt: e.QueuedAt,
			TxHash: e.TxHash, StrandedLedger: e.StrandedLedger, StrandedAt: uint64(e.StrandedAt), StrandedTx: e.StrandedTx,
		})
	}
	ix.mu.RUnlock()
	if maxDaily == nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	resolved, err := ix.db.resolvedExits(r.Context(), ix.now().Add(-resolvedWindow).Unix(), h.IngestedLedger)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	for i, at := range paidBy(owed, now, haltedUntil, used, maxDaily) {
		queued[i].EarliestPaidAt = at
	}
	slices.SortFunc(stranded, func(a, b StrandedExit) int { return cmp.Compare(a.ID, b.ID) })
	today := now / secondsPerDay
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"head": head, "tail": tail, "queued_total": queuedTotal, "max_daily_outflow": maxDaily.String(),
		"window":       Window{Day: today, Used: used.String(), ResetsAt: (today + 1) * secondsPerDay},
		"halted_until": haltedUntil, "queued": queued, "stranded": stranded, "resolved": resolved, "complete_to": h.IngestedLedger,
	})
}
