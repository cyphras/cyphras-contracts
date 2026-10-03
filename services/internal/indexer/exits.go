package indexer

import (
	"cmp"
	"math/big"
	"net/http"
	"slices"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
)

const secondsPerDay = 86_400

// The states of an exit.
const (
	ExitQueued     = "queued"
	ExitPaidInPart = "paid_in_part"
	ExitStranded   = "stranded"
	ExitSettled    = "settled"
)

// Exit is one exit of the vault's exit queue as the API shows it. Payout and Fee are what it owed
// when transact queued it; the paid and left amounts split that into what reached the recipient
// and relayer so far and what the vault still owes. Position and PaidBy are set while the exit is
// in the queue, the stranded fields once a release stranded it, and the settled fields once it was
// paid in full.
type Exit struct {
	ID             uint64  `json:"id"`
	State          string  `json:"state"`
	Position       *uint64 `json:"position,omitempty"`
	Payout         string  `json:"payout"`
	Fee            string  `json:"fee"`
	PayoutPaid     string  `json:"payout_paid"`
	FeePaid        string  `json:"fee_paid"`
	PayoutLeft     string  `json:"payout_left"`
	FeeLeft        string  `json:"fee_left"`
	Recipient      string  `json:"recipient"`
	Relayer        string  `json:"relayer"`
	QueuedAt       uint64  `json:"queued_at"`
	QueuedLedger   uint32  `json:"queued_ledger"`
	TxHash         string  `json:"tx_hash"`
	PaidBy         *uint64 `json:"paid_by,omitempty"`
	StrandedLedger *uint32 `json:"stranded_ledger,omitempty"`
	StrandedAt     *uint64 `json:"stranded_at,omitempty"`
	StrandedTx     *string `json:"stranded_tx,omitempty"`
	SettledLedger  *uint32 `json:"settled_ledger,omitempty"`
	SettledAt      *uint64 `json:"settled_at,omitempty"`
	SettledTx      *string `json:"settled_tx,omitempty"`
}

// Window is the day's outflow window: what it has paid and when it resets.
type Window struct {
	Day      uint64 `json:"day"`
	Used     string `json:"used"`
	ResetsAt uint64 `json:"resets_at"`
}

func ptr[T any](v T) *T { return &v }

func fromState(e *chainstate.Exit, state string) Exit {
	payoutPaid, feePaid := e.Paid()
	return Exit{
		ID: e.ID, State: state, Payout: e.QueuedPayout.String(), Fee: e.QueuedFee.String(),
		PayoutPaid: payoutPaid.String(), FeePaid: feePaid.String(), PayoutLeft: e.Payout.String(), FeeLeft: e.Fee.String(),
		Recipient: e.Recipient, Relayer: e.Relayer, QueuedAt: e.QueuedAt, QueuedLedger: e.Ledger, TxHash: e.TxHash,
	}
}

// paidBy gives each queued exit, in queue order, the end of the UTC day by which it is paid in full
// at the latest: from the day of max(now, haltedUntil), ceil((V + x) / M) more days, with V what
// the exits ahead still owe, x what it still owes and M max_daily_outflow. Releases use every
// window in full, so only claims of stranded exits, which the keeper pays first at each midnight,
// or a new halt can make it later.
func paidBy(owed []*big.Int, now, haltedUntil uint64, maxDaily *big.Int) []*uint64 {
	out := make([]*uint64, len(owed))
	if maxDaily.Sign() <= 0 {
		return out
	}
	day := max(now, haltedUntil) / secondsPerDay
	total := new(big.Int)
	for i, o := range owed {
		total.Add(total, o)
		days := new(big.Int).Div(new(big.Int).Add(total, new(big.Int).Sub(maxDaily, big.NewInt(1))), maxDaily)
		out[i] = ptr((day+days.Uint64()+1)*secondsPerDay - 1)
	}
	return out
}

// exits serves the whole exit queue, every stranded exit and the exits settled in the last week,
// so a client finds its own exit by the ID or the transaction hash its transaction gave it,
// without asking for it.
func (ix *Indexer) exits(w http.ResponseWriter, r *http.Request) {
	if _, ok := ix.serving(w); !ok {
		return
	}
	now := uint64(ix.now().Unix())
	ix.mu.RLock()
	// The stored rows are cut at the ledger of the state in memory, so neither shows an exit the
	// other has moved on.
	s, upTo := ix.state, ix.cursor
	var maxDaily *big.Int
	switch {
	case ix.instance != nil:
		maxDaily = new(big.Int).Set(ix.instance.Limits.MaxDailyOutflow)
	case s.Limits != nil:
		maxDaily = new(big.Int).Set(s.Limits.MaxDailyOutflow)
	}
	head, tail, haltedUntil := s.ExitHead, s.ExitTail, s.HaltedUntil
	queuedTotal, used := s.QueuedTotal.String(), s.OutflowOn(now/secondsPerDay)
	var list []Exit
	var owed []*big.Int
	for id := head; id < tail; id++ {
		e := s.Exits[id]
		state := ExitQueued
		if e.Payout.Cmp(e.QueuedPayout) != 0 || e.Fee.Cmp(e.QueuedFee) != 0 {
			state = ExitPaidInPart
		}
		x := fromState(e, state)
		x.Position = ptr(id - head)
		list = append(list, x)
		owed = append(owed, e.Outflow())
	}
	queued := len(list)
	for _, e := range s.Stranded {
		x := fromState(e, ExitStranded)
		x.StrandedLedger, x.StrandedAt, x.StrandedTx = ptr(e.StrandedLedger), ptr(uint64(e.StrandedAt)), ptr(e.StrandedTx)
		list = append(list, x)
	}
	ix.mu.RUnlock()
	if maxDaily == nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	for i, at := range paidBy(owed, now, haltedUntil, maxDaily) {
		list[i].PaidBy = at
	}
	settled, err := ix.db.settledExits(r.Context(), ix.now().Add(-resolvedWindow).Unix(), upTo)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	list = append(list, settled...)
	slices.SortFunc(list[queued:], func(a, b Exit) int { return cmp.Compare(a.ID, b.ID) })
	if list == nil {
		list = []Exit{}
	}
	today := now / secondsPerDay
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"head": head, "tail": tail, "queued_total": queuedTotal, "max_daily_outflow": maxDaily.String(),
		"window":       Window{Day: today, Used: used.String(), ResetsAt: (today + 1) * secondsPerDay},
		"halted_until": haltedUntil, "exits": list, "complete_to": upTo,
	})
}
