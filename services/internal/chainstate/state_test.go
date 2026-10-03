package chainstate

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

type fixtureStep struct {
	Name   string `json:"name"`
	Call   string `json:"call"`
	Caller string `json:"caller"`
	IDs    []uint64
	Ext    struct {
		ExtAmount string `json:"ext_amount"`
		Fee       string `json:"fee"`
		Recipient string `json:"recipient"`
		Relayer   string `json:"relayer"`
	} `json:"ext"`
	Proof struct {
		Nullifiers  []string `json:"input_nullifiers"`
		Commitments []string `json:"output_commitments"`
	} `json:"proof"`
	RootAfter string `json:"root_after"`
}

func field(t *testing.T, s string) fr.Element {
	t.Helper()
	e, err := fr.SetHex(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func amount(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatal(s)
	}
	return n
}

func fixtureSteps(t *testing.T) []fixtureStep {
	t.Helper()
	raw, err := os.ReadFile("../vault/testdata/proofs.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Steps []fixtureStep `json:"steps"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Steps
}

const ciphertextLen = vault.CiphertextLen

func nullifiers(t *testing.T, s fixtureStep) [2]vault.NewNullifier {
	return [2]vault.NewNullifier{{Nullifier: field(t, s.Proof.Nullifiers[0])}, {Nullifier: field(t, s.Proof.Nullifiers[1])}}
}

func outputs(t *testing.T, s fixtureStep, index uint64) [2]vault.NewCommitment {
	return [2]vault.NewCommitment{
		{Index: index, Commitment: field(t, s.Proof.Commitments[0]), Ciphertext: make([]byte, ciphertextLen)},
		{Index: index + 1, Commitment: field(t, s.Proof.Commitments[1]), Ciphertext: make([]byte, ciphertextLen)},
	}
}

// replay turns the vault's fixture flow into the transactions its events describe.
func replay(t *testing.T) ([]vault.Tx, map[string]string) {
	t.Helper()
	var txs []vault.Tx
	roots := map[string]string{}
	var deposits []fixtureStep
	ledger := uint32(1000)
	at := int64(1_728_000_000)
	for _, s := range fixtureSteps(t) {
		ledger++
		at += 5
		tx := vault.Tx{Ledger: ledger, ClosedAt: at, Hash: s.Name}
		switch s.Call {
		case "shield":
			deposits = append(deposits, s)
			tx.Calls = []any{vault.Shield{
				Nullifiers: nullifiers(t, s),
				Deposit: vault.DepositPending{
					ID: uint64(len(deposits)), Depositor: s.Caller, Amount: amount(t, s.Ext.ExtAmount),
					Commitment0: field(t, s.Proof.Commitments[0]), Commitment1: field(t, s.Proof.Commitments[1]),
					CreatedAt: uint64(at),
				},
			}}
		case "admit":
			tx.Calls = append(tx.Calls, vault.Attested{UpTo: uint64(len(deposits))})
			for i, d := range deposits {
				index := uint64(2 * i)
				tx.Calls = append(tx.Calls, vault.Admission{
					Outputs:  outputs(t, d, index),
					Admitted: vault.DepositAdmitted{ID: uint64(i + 1), LeafIndex0: index, LeafIndex1: index + 1},
				})
			}
		case "transact":
			index := uint64(0)
			for _, prev := range txs {
				for _, c := range prev.Calls {
					switch c.(type) {
					case vault.Admission, vault.Transact:
						index += 2
					}
				}
			}
			tx.Calls = []any{vault.Transact{
				Nullifiers: nullifiers(t, s),
				Outputs:    outputs(t, s, index),
				Settled:    &vault.Settled{ExtAmount: amount(t, s.Ext.ExtAmount), Fee: amount(t, s.Ext.Fee), Recipient: s.Ext.Recipient, Relayer: s.Ext.Relayer},
			}}
		}
		txs = append(txs, tx)
		roots[s.Name] = s.RootAfter
	}
	return txs, roots
}

func TestTheVaultFixtureFlowReplaysToTheVaultRoots(t *testing.T) {
	txs, roots := replay(t)
	s := New()
	for _, tx := range txs {
		d, err := s.Apply([]vault.Tx{tx})
		if err != nil {
			t.Fatal(err)
		}
		if want := roots[tx.Hash]; want != "" && s.Tree.Root() != field(t, want) {
			t.Fatalf("%s: root %s, want %s", tx.Hash, s.Tree.Root().Hex(), want)
		}
		if tx.Hash == "admit" && (len(d.Resolved) != 2 || len(d.Leaves) != 4 || d.Resolved[1].LeafIndex0 != 2) {
			t.Fatalf("admission delta %+v", d)
		}
		if len(d.Roots) != len(d.Leaves)/2 || (len(d.Roots) > 0 && (d.Roots[len(d.Roots)-1].Root != s.Tree.Root() || d.Roots[len(d.Roots)-1].LeafCount != s.Tree.Len())) {
			t.Fatalf("%s: roots %+v", tx.Hash, d.Roots)
		}
	}
	if s.Tree.Len() != 12 || s.NullifierCount != 12 || len(s.Pending) != 0 {
		t.Fatalf("leaves %d, nullifiers %d, pending %d", s.Tree.Len(), s.NullifierCount, len(s.Pending))
	}
	// The same value the vault's own end-to-end test ends with.
	if s.Tvl.Int64() != 90_000_000 {
		t.Fatalf("tvl %v", s.Tvl)
	}
	if s.Outflow.Int64() != 15_000_000+700_000_000+695_000_000 {
		t.Fatalf("outflow %v", s.Outflow)
	}
}

func apply(t *testing.T, s *State, calls ...any) (Delta, error) {
	t.Helper()
	return s.Apply([]vault.Tx{{Ledger: 7, ClosedAt: 1_728_000_000, Hash: "tx", Calls: calls}})
}

func shield(id uint64, nf uint64, amount int64) vault.Shield {
	return vault.Shield{
		Nullifiers: [2]vault.NewNullifier{{Nullifier: fr.SetUint64(nf)}, {Nullifier: fr.SetUint64(nf + 1)}},
		Deposit: vault.DepositPending{
			ID: id, Depositor: "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH", Amount: big.NewInt(amount),
			Commitment0: fr.SetUint64(100 + 2*id), Commitment1: fr.SetUint64(101 + 2*id), CreatedAt: 1_728_000_000,
		},
	}
}

func admission(id, index uint64) vault.Admission {
	return vault.Admission{
		Outputs: [2]vault.NewCommitment{
			{Index: index, Commitment: fr.SetUint64(100 + 2*id), Ciphertext: make([]byte, ciphertextLen)},
			{Index: index + 1, Commitment: fr.SetUint64(101 + 2*id), Ciphertext: make([]byte, ciphertextLen)},
		},
		Admitted: vault.DepositAdmitted{ID: id, LeafIndex0: index, LeafIndex1: index + 1},
	}
}

func TestTheEntryQueueFollowsTheVaultRules(t *testing.T) {
	s := New()
	if _, err := apply(t, s, shield(1, 10, 50), shield(2, 20, 70), shield(3, 30, 90)); err != nil {
		t.Fatal(err)
	}
	reason := uint32(4)
	d, err := apply(t, s, vault.DepositFlagged{ID: 2, Reason: reason}, vault.Attested{UpTo: 3}, admission(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Updated) != 1 || *d.Updated[0].Flag != 4 || d.Updated[0].FlaggedAt != 1_728_000_000 {
		t.Fatalf("flag delta %+v", d.Updated)
	}
	// A second flag replaces the reason but keeps the time of the first.
	if _, err := s.Apply([]vault.Tx{{ClosedAt: 1_728_000_100, Calls: []any{vault.DepositFlagged{ID: 2, Reason: 1}}}}); err != nil {
		t.Fatal(err)
	}
	if s.Pending[2].FlaggedAt != 1_728_000_000 || *s.Pending[2].Flag != 1 {
		t.Fatal("re-flag changed the flag time")
	}
	d, err = s.Apply([]vault.Tx{{Ledger: 9, ClosedAt: 1_728_000_000 + 86_400, Hash: "c", Calls: []any{vault.DepositRefunded{ID: 2, Reason: 1}, vault.DepositRefunded{ID: 3, Reason: 0}}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Resolved[0].Outcome != Refunded || d.Resolved[1].Outcome != Cancelled || s.Tvl.Int64() != 50 {
		t.Fatalf("resolutions %+v, tvl %v", d.Resolved, s.Tvl)
	}

	failures := map[string][]any{
		"skipped deposit id":       {shield(5, 40, 1)},
		"admitted twice":           {admission(1, 2)},
		"refunded after admission": {vault.DepositRefunded{ID: 1, Reason: 0}},
		"attestation backwards":    {vault.Attested{UpTo: 2}},
		"attestation ahead":        {shield(4, 50, 1), vault.Attested{UpTo: 5}},
		"refund without that flag": {shield(4, 50, 1), vault.DepositRefunded{ID: 4, Reason: 2}},
		"unflag of unflagged":      {shield(4, 50, 1), vault.DepositUnflagged{ID: 4, Reason: 1}},
		"admission not attested":   {shield(4, 50, 1), admission(4, 2)},
		"admission while flagged":  {shield(4, 50, 1), vault.Attested{UpTo: 4}, vault.DepositFlagged{ID: 4, Reason: 1}, admission(4, 2)},
		"admission with a gap":     {shield(4, 50, 1), vault.Attested{UpTo: 4}, admission(4, 4)},
		"nullifier spent twice":    {shield(4, 10, 1)},
	}
	for name, calls := range failures {
		c := s.Clone()
		if name == "nullifier spent twice" {
			// The store catches repeats across windows; within one window the state does.
			calls = append([]any{shield(4, 70, 1)}, shield(5, 70, 1))
		}
		if _, err := apply(t, c, calls...); !errors.Is(err, ErrInconsistent) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestHaltsAndLimitsAreTracked(t *testing.T) {
	s := New()
	limits := vault.Limits{MaxFee: big.NewInt(5)}
	if _, err := apply(t, s, shield(1, 1, 5), vault.Attested{UpTo: 1},
		vault.Paused{Deposits: true},
		vault.Halted{Until: 1_728_100_000},
		vault.LimitsQueued{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: 9}},
	); err != nil {
		t.Fatal(err)
	}
	if !s.DepositsPaused || s.HaltedUntil != 1_728_100_000 || s.NextHaltAt != 1_728_100_000+7*86_400 || s.Queued == nil {
		t.Fatal("pause, halt or queue not recorded")
	}
	for name, call := range map[string]any{
		"admission while halted":   admission(1, 0),
		"deposit while halted":     shield(2, 3, 5),
		"attestation while halted": vault.Attested{UpTo: 1},
	} {
		if _, err := apply(t, s.Clone(), call); !errors.Is(err, ErrInconsistent) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	d, err := apply(t, s, vault.Resumed{NextHaltAt: 1_728_604_800}, vault.LimitsApplied{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: 9}})
	if err != nil {
		t.Fatal(err)
	}
	if s.HaltedUntil != 1_728_000_000 || s.Queued != nil || s.Limits == nil || len(d.Notices) != 2 {
		t.Fatal("resume or applied loosening not recorded")
	}
	if _, err := apply(t, s.Clone(), shield(2, 3, 5)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("deposit while deposits are paused: %v", err)
	}
}

const relayer = "GBA3WCGVHQ5U5HNWIJXBSLCBLB5JWZH4HVWBZMU3ZLF6U4NH7OIZH3XH"

func spendPair(nf, leaf uint64) ([2]vault.NewNullifier, [2]vault.NewCommitment) {
	return [2]vault.NewNullifier{{Nullifier: fr.SetUint64(nf)}, {Nullifier: fr.SetUint64(nf + 1)}},
		[2]vault.NewCommitment{
			{Index: leaf, Commitment: fr.SetUint64(900 + leaf), Ciphertext: make([]byte, ciphertextLen)},
			{Index: leaf + 1, Commitment: fr.SetUint64(901 + leaf), Ciphertext: make([]byte, ciphertextLen)},
		}
}

func paidAtOnce(nf, leaf uint64, extAmount, fee int64) vault.Transact {
	n, o := spendPair(nf, leaf)
	return vault.Transact{Nullifiers: n, Outputs: o, Settled: &vault.Settled{ExtAmount: big.NewInt(extAmount), Fee: big.NewInt(fee), Recipient: relayer, Relayer: relayer}}
}

func queued(nf, leaf, id uint64, extAmount, fee int64) vault.Transact {
	n, o := spendPair(nf, leaf)
	return vault.Transact{Nullifiers: n, Outputs: o, Queued: &vault.ExitQueued{ID: id, ExtAmount: big.NewInt(extAmount), Fee: big.NewInt(fee), Recipient: relayer, Relayer: relayer}}
}

func release(id uint64, extAmount, fee int64) vault.ExitSettled {
	return vault.ExitSettled{Settled: vault.Settled{ExtAmount: big.NewInt(extAmount), Fee: big.NewInt(fee), Recipient: relayer, Relayer: relayer, ExitID: &id}}
}

func applyAt(s *State, at int64, calls ...any) (Delta, error) {
	return s.Apply([]vault.Tx{{Ledger: 9, ClosedAt: at, Hash: "tx", Calls: calls}})
}

func TestAPartPaymentFillsTheWindowAndLeavesTheRestAtTheHead(t *testing.T) {
	const day1, day2 = 1_728_000_000, 1_728_000_000 + 86_400
	big1 := big.NewInt(1_000_000)
	limits := vault.Limits{
		MinDeposit: big.NewInt(1), MaxDeposit: big1, MaxDailyPerDepositor: big1, TvlCap: big1,
		MaxDailyOutflow: big.NewInt(600), MaxFee: big.NewInt(50), LargeDepositThreshold: big1,
	}
	s := New()
	if _, err := applyAt(s, day1, shield(1, 1, 2000), vault.Attested{UpTo: 1}, admission(1, 0),
		vault.LimitsApplied{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: day1}},
		paidAtOnce(10, 2, -500, 0), queued(20, 4, 1, -580, 20)); err != nil {
		t.Fatal(err)
	}
	// 100 is left today: the payout takes it all and the fee waits.
	part := vault.ExitPaid{ID: 1, PayoutPaid: big.NewInt(100), FeePaid: new(big.Int), PayoutLeft: big.NewInt(480), FeeLeft: big.NewInt(20)}
	wrong := part
	wrong.PayoutPaid, wrong.PayoutLeft = big.NewInt(90), big.NewInt(490)
	if _, err := applyAt(s.Clone(), day1, wrong); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("a part payment that leaves room: %v", err)
	}
	d, err := applyAt(s, day1, part)
	if err != nil {
		t.Fatal(err)
	}
	if s.ExitHead != 1 || s.Exits[1].Payout.Int64() != 480 || s.QueuedTotal.Int64() != 500 || s.Outflow.Int64() != 600 || len(d.PartPaid) != 1 || len(d.Settlements) != 1 {
		t.Fatalf("after a part payment: head %d, exit %+v, queued %v, outflow %v", s.ExitHead, s.Exits[1], s.QueuedTotal, s.Outflow)
	}
	// The next day the rest completes it.
	if _, err := applyAt(s, day2, release(1, -480, 20)); err != nil {
		t.Fatal(err)
	}
	if s.ExitHead != 2 || s.QueuedTotal.Sign() != 0 || s.Outflow.Int64() != 500 {
		t.Fatalf("after the rest: head %d, queued %v, outflow %v", s.ExitHead, s.QueuedTotal, s.Outflow)
	}
}

func TestAStrandedExitLeavesTheQueueAndIsClaimedLater(t *testing.T) {
	const day1, day2 = 1_728_000_000, 1_728_000_000 + 86_400
	big1 := big.NewInt(1_000_000)
	limits := vault.Limits{
		MinDeposit: big.NewInt(1), MaxDeposit: big1, MaxDailyPerDepositor: big1, TvlCap: big1,
		MaxDailyOutflow: big.NewInt(600), MaxFee: big.NewInt(50), LargeDepositThreshold: big1,
	}
	s := New()
	if _, err := applyAt(s, day1, shield(1, 1, 2000), vault.Attested{UpTo: 1}, admission(1, 0),
		vault.LimitsApplied{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: day1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := applyAt(s.Clone(), day1, queued(10, 2, 1, -400, 10)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("an exit queued while it fit: %v", err)
	}
	for name, call := range map[string]vault.Transact{"fee above max_fee": paidAtOnce(10, 2, -10, 51), "exit above the daily window": queued(10, 2, 1, -600, 1)} {
		if _, err := applyAt(s.Clone(), day1, call); !errors.Is(err, ErrInconsistent) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// 410 is paid at once; 305 more would pass the window of 600, so it waits, and so does the
	// exit behind it.
	if _, err := applyAt(s, day1, paidAtOnce(10, 2, -400, 10), queued(20, 4, 1, -300, 5), queued(30, 6, 2, -100, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := applyAt(s.Clone(), day1, release(1, -300, 5)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("release beyond the window: %v", err)
	}
	for name, left := range map[string][2]int64{"part of a payout": {100, 0}, "more than owed": {301, 5}, "nothing refused": {0, 0}} {
		if _, err := applyAt(s.Clone(), day2, vault.ExitStranded{ID: 1, Payout: big.NewInt(left[0]), Fee: big.NewInt(left[1])}); !errors.Is(err, ErrInconsistent) {
			t.Fatalf("stranded with %s: %v", name, err)
		}
	}
	// The next day the recipient of exit 1 cannot receive: its fee is paid, its payout stranded,
	// and exit 2 behind it is paid.
	d, err := applyAt(s, day2, vault.ExitStranded{ID: 1, Payout: big.NewInt(300), Fee: new(big.Int)}, release(2, -100, 0))
	if err != nil {
		t.Fatal(err)
	}
	if s.ExitHead != 3 || len(s.Exits) != 0 || s.Stranded[1] == nil || s.Stranded[1].Payout.Int64() != 300 || s.Stranded[1].Fee.Sign() != 0 {
		t.Fatalf("after the release: head %d, stranded %+v", s.ExitHead, s.Stranded)
	}
	if s.QueuedTotal.Int64() != 300 || s.Outflow.Int64() != 105 || s.Tvl.Int64() != 2000-410-105 {
		t.Fatalf("queued %v, outflow %v, tvl %v", s.QueuedTotal, s.Outflow, s.Tvl)
	}
	if len(d.Released) != 2 || d.Released[0].UnpaidPayout.Int64() != 300 || len(d.Settlements) != 2 || d.Settlements[0].Fee.Int64() != 5 || d.Settlements[0].ExtAmount.Sign() != 0 {
		t.Fatalf("delta %+v", d)
	}
	if _, err := applyAt(s.Clone(), day2, paidAtOnce(40, 8, -300, 0), release(1, -300, 0)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("a claim beyond the window: %v", err)
	}
	if _, err := applyAt(s.Clone(), day2, release(1, -300, 5)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("a claim of more than is owed: %v", err)
	}
	d, err = applyAt(s, day2, release(1, -300, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Stranded) != 0 || s.QueuedTotal.Sign() != 0 || s.Outflow.Int64() != 405 || len(d.Claimed) != 1 || d.Notices[0].Name != "exit_claimed" {
		t.Fatalf("after the claim: stranded %+v, queued %v, outflow %v", s.Stranded, s.QueuedTotal, s.Outflow)
	}
}

func TestTheExitQueuePaysInOrderOutOfTheValueItHolds(t *testing.T) {
	s := New()
	if _, err := apply(t, s, shield(1, 1, 1000), shield(2, 3, 50), vault.Attested{UpTo: 1}, admission(1, 0)); err != nil {
		t.Fatal(err)
	}
	d, err := apply(t, s, paidAtOnce(10, 2, -100, 5), queued(20, 4, 1, -300, 5), queued(30, 6, 2, -200, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Queued) != 2 || len(d.Settlements) != 1 || s.ExitTail != 3 || s.QueuedTotal.Int64() != 505 {
		t.Fatalf("queue %+v, queued total %v", d.Queued, s.QueuedTotal)
	}
	// Queued exits are still held: only the immediate payment left the vault and its window.
	if s.Tvl.Int64() != 1050-105 || s.Outflow.Int64() != 105 {
		t.Fatalf("tvl %v, outflow %v", s.Tvl, s.Outflow)
	}
	failures := map[string][]any{
		"release out of turn":             {release(2, -200, 0)},
		"release differently from queued": {release(1, -300, 0)},
		"paid at once past the queue":     {paidAtOnce(40, 8, -1, 0)},
		"exit beyond the admitted notes":  {queued(40, 8, 3, -1000, 0)},
		"queued with the wrong id":        {queued(40, 8, 7, -1, 0)},
		"transfer to another recipient": {vault.Transact{
			Nullifiers: [2]vault.NewNullifier{{Nullifier: fr.SetUint64(40)}, {Nullifier: fr.SetUint64(41)}},
			Outputs:    [2]vault.NewCommitment{{Index: 8, Commitment: fr.SetUint64(1)}, {Index: 9, Commitment: fr.SetUint64(2)}},
			Settled:    &vault.Settled{ExtAmount: big.NewInt(0), Fee: big.NewInt(0), Recipient: "GD4NLSV522CTT6POVXWGVHSW2LXLH4SCJ66S2N7OEQRSW3YO2P7YYAAH", Relayer: relayer},
		}},
	}
	for name, calls := range failures {
		if _, err := apply(t, s.Clone(), calls...); !errors.Is(err, ErrInconsistent) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A transfer that pays nothing does not wait behind the queue.
	if _, err := apply(t, s.Clone(), paidAtOnce(40, 8, 0, 0)); err != nil {
		t.Fatalf("free transfer: %v", err)
	}
	d, err = apply(t, s, release(1, -300, 5), release(2, -200, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Released) != 2 || s.ExitHead != 3 || s.QueuedTotal.Sign() != 0 || s.Tvl.Int64() != 1050-610 || s.Outflow.Int64() != 610 {
		t.Fatalf("after release: head %d, queued %v, tvl %v", s.ExitHead, s.QueuedTotal, s.Tvl)
	}
}

func TestARefundWaitsADayAfterTheFlag(t *testing.T) {
	s := New()
	if _, err := apply(t, s, shield(1, 1, 5), vault.DepositFlagged{ID: 1, Reason: 2}); err != nil {
		t.Fatal(err)
	}
	early := []vault.Tx{{Ledger: 8, ClosedAt: 1_728_000_000 + 86_399, Hash: "b", Calls: []any{vault.DepositRefunded{ID: 1, Reason: 2}}}}
	if _, err := s.Clone().Apply(early); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("early refund: %v", err)
	}
	early[0].ClosedAt++
	if _, err := s.Apply(early); err != nil {
		t.Fatal(err)
	}
}

func TestACloneIsIndependent(t *testing.T) {
	s := New()
	if _, err := apply(t, s, shield(1, 1, 5), vault.DepositFlagged{ID: 1, Reason: 2}); err != nil {
		t.Fatal(err)
	}
	c := s.Clone()
	if _, err := apply(t, c, vault.DepositFlagged{ID: 1, Reason: 3}, shield(2, 3, 5)); err != nil {
		t.Fatal(err)
	}
	if *s.Pending[1].Flag != 2 || len(s.Pending) != 1 || s.Tvl.Int64() != 5 {
		t.Fatal("clone shares state with its original")
	}
}
