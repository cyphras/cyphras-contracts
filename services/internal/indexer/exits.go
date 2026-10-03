package indexer

import (
	"cmp"
	"math/big"
	"net/http"
	"slices"

	"github.com/cyphras/cyphras-contracts/services/internal/chainstate"
	"github.com/cyphras/cyphras-contracts/services/internal/httpapi"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

const secondsPerDay = 86_400

// The states of an exit.
const (
	ExitQueued     = "queued"
	ExitPaidInPart = "paid_in_part"
	ExitStranded   = "stranded"
	ExitRequeued   = "requeued"
	ExitSettled    = "settled"
)

// Exit is one exit of the vault's exit queue as the API shows it. Payout and Fee are what it owed
// when it was queued; the paid, requeued and left amounts split that into what reached the
// recipient and relayer so far, what claims moved back into the queue as the exits RequeuedTo, and
// what the vault still owes under this ID. Position and PaidBy are set while the exit is in the
// queue, RequeuedFrom when a claim queued it from a stranded exit, the stranded fields once a
// release stranded it, the requeued fields once claims moved all it still owed, and the settled
// fields once it was paid in full.
type Exit struct {
	ID             uint64   `json:"id"`
	State          string   `json:"state"`
	Position       *uint64  `json:"position,omitempty"`
	Payout         string   `json:"payout"`
	Fee            string   `json:"fee"`
	PayoutPaid     string   `json:"payout_paid"`
	FeePaid        string   `json:"fee_paid"`
	PayoutRequeued string   `json:"payout_requeued"`
	FeeRequeued    string   `json:"fee_requeued"`
	PayoutLeft     string   `json:"payout_left"`
	FeeLeft        string   `json:"fee_left"`
	Recipient      string   `json:"recipient"`
	Relayer        string   `json:"relayer"`
	QueuedAt       uint64   `json:"queued_at"`
	QueuedLedger   uint32   `json:"queued_ledger"`
	TxHash         string   `json:"tx_hash"`
	RequeuedFrom   *uint64  `json:"requeued_from,omitempty"`
	PaidBy         *uint64  `json:"paid_by,omitempty"`
	StrandedLedger *uint32  `json:"stranded_ledger,omitempty"`
	StrandedAt     *uint64  `json:"stranded_at,omitempty"`
	StrandedTx     *string  `json:"stranded_tx,omitempty"`
	RequeuedTo     []uint64 `json:"requeued_to,omitempty"`
	RequeuedLedger *uint32  `json:"requeued_ledger,omitempty"`
	RequeuedAt     *uint64  `json:"requeued_at,omitempty"`
	RequeuedTx     *string  `json:"requeued_tx,omitempty"`
	SettledLedger  *uint32  `json:"settled_ledger,omitempty"`
	SettledAt      *uint64  `json:"settled_at,omitempty"`
	SettledTx      *string  `json:"settled_tx,omitempty"`
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
	x := Exit{
		ID: e.ID, State: state, Payout: e.QueuedPayout.String(), Fee: e.QueuedFee.String(),
		PayoutPaid: payoutPaid.String(), FeePaid: feePaid.String(), PayoutRequeued: e.MovedPayout.String(), FeeRequeued: e.MovedFee.String(),
		PayoutLeft: e.Payout.String(), FeeLeft: e.Fee.String(),
		Recipient: e.Recipient, Relayer: e.Relayer, QueuedAt: e.QueuedAt, QueuedLedger: e.Ledger, TxHash: e.TxHash,
		RequeuedTo: slices.Clone(e.RequeuedTo),
	}
	if e.RequeuedFrom != nil {
		x.RequeuedFrom = ptr(*e.RequeuedFrom)
	}
	return x
}

// paidBy gives each queued exit, in queue order, the end of the UTC day by which it is paid in full
// at the latest: from the day of max(now, haltedUntil), ceil((V + x) / M) more days, with V what
// the exits ahead take from the windows, x what it takes and M max_daily_outflow. The keeper
// releases every window in full and a claim queues behind it, so only a new halt, or a vault that
// cannot pay, makes it later.
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

// takes is what an exit can take from the windows: what it owes and, in a vault of the native
// asset, the rest of a window that release leaves unused rather than pay a first part below
// MinNewAccountPayout to an account that may not exist yet. That happens at most once an exit, as
// the first part paid creates the account.
func (ix *Indexer) takes(e *chainstate.Exit) *big.Int {
	t := e.Outflow()
	first := e.Payout.Sign() > 0 && e.Payout.Cmp(e.QueuedPayout) == 0
	if ix.cfg.Native && first && (e.Recipient[0] == 'G' || e.Recipient[0] == 'M') {
		t.Add(t, big.NewInt(vault.MinNewAccountPayout-1))
	}
	return t
}

// exits serves the whole exit queue, every stranded exit and the exits resolved in the last week,
// so a client finds its own exit by the ID or the transaction hash its transaction gave it, and
// follows it across claims by requeued_to, without asking for it.
func (ix *Indexer) exits(w http.ResponseWriter, r *http.Request) {
	if _, ok := ix.serving(w); !ok {
		return
	}
	now := uint64(ix.now().Unix())
	q := ix.queue(now)
	if q.maxDaily == nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	list := q.list
	for i, at := range paidBy(q.owed, now, q.haltedUntil, q.maxDaily) {
		list[i].PaidBy = at
	}
	resolved, err := ix.db.resolvedExits(r.Context(), ix.now().Add(-resolvedWindow).Unix(), q.upTo)
	if err != nil {
		httpapi.Fail(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	list = append(list, resolved...)
	slices.SortFunc(list[len(q.owed):], func(a, b Exit) int { return cmp.Compare(a.ID, b.ID) })
	if list == nil {
		list = []Exit{}
	}
	today := now / secondsPerDay
	httpapi.JSON(w, http.StatusOK, map[string]any{
		"head": q.head, "tail": q.tail, "queued_total": q.queuedTotal, "max_daily_outflow": q.maxDaily.String(),
		"window":       Window{Day: today, Used: q.used.String(), ResetsAt: (today + 1) * secondsPerDay},
		"halted_until": q.haltedUntil, "exits": list, "complete_to": q.upTo,
	})
}

// exitQueue is what the exits response takes from the state in memory: the queue in order, with
// what each queued exit takes from the windows, then the stranded exits.
type exitQueue struct {
	upTo                    uint32
	head, tail, haltedUntil uint64
	queuedTotal             string
	used, maxDaily          *big.Int
	list                    []Exit
	owed                    []*big.Int
}

// queue reads the exit queue from the state in memory. The stored rows the response adds are cut at
// the same ledger, so neither shows an exit the other has moved on.
func (ix *Indexer) queue(now uint64) exitQueue {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	s := ix.state
	q := exitQueue{
		upTo: ix.cursor, head: s.ExitHead, tail: s.ExitTail, haltedUntil: s.HaltedUntil,
		queuedTotal: s.QueuedTotal.String(), used: s.OutflowOn(now / secondsPerDay),
	}
	switch {
	case ix.instance != nil:
		q.maxDaily = new(big.Int).Set(ix.instance.Limits.MaxDailyOutflow)
	case s.Limits != nil:
		q.maxDaily = new(big.Int).Set(s.Limits.MaxDailyOutflow)
	}
	for id := q.head; id < q.tail; id++ {
		e := s.Exits[id]
		state := ExitQueued
		if e.Payout.Cmp(e.QueuedPayout) != 0 || e.Fee.Cmp(e.QueuedFee) != 0 {
			state = ExitPaidInPart
		}
		x := fromState(e, state)
		x.Position = ptr(id - q.head)
		q.list = append(q.list, x)
		q.owed = append(q.owed, ix.takes(e))
	}
	for _, e := range s.Stranded {
		x := fromState(e, ExitStranded)
		x.StrandedLedger, x.StrandedAt, x.StrandedTx = ptr(e.StrandedLedger), ptr(uint64(e.StrandedAt)), ptr(e.StrandedTx)
		q.list = append(q.list, x)
	}
	return q
}
