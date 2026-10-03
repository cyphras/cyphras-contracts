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
				Settled:    vault.Settled{ExtAmount: amount(t, s.Ext.ExtAmount), Fee: amount(t, s.Ext.Fee), Recipient: s.Ext.Recipient, Relayer: s.Ext.Relayer},
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
			{Index: index, Commitment: fr.SetUint64(100 + 2*id)},
			{Index: index + 1, Commitment: fr.SetUint64(101 + 2*id)},
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
	d, err = apply(t, s, vault.DepositRefunded{ID: 2, Reason: 1}, vault.DepositRefunded{ID: 3, Reason: 0})
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
	if _, err := apply(t, s,
		vault.Paused{Deposits: true},
		vault.Halted{Until: 1_728_100_000},
		vault.LimitsQueued{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: 9}},
	); err != nil {
		t.Fatal(err)
	}
	if !s.DepositsPaused || s.HaltedUntil != 1_728_100_000 || s.Queued == nil {
		t.Fatal("pause, halt or queue not recorded")
	}
	if _, err := apply(t, s, shield(1, 1, 5), vault.Attested{UpTo: 1}, admission(1, 0)); !errors.Is(err, ErrInconsistent) {
		t.Fatalf("admission while halted: %v", err)
	}
	d, err := apply(t, s, vault.Resumed{NextHaltAt: 1_728_604_800}, vault.LimitsApplied{LimitsChange: vault.LimitsChange{Limits: limits, ReadyAt: 9}})
	if err != nil {
		t.Fatal(err)
	}
	if s.HaltedUntil != 1_728_000_000 || s.Queued != nil || s.Limits == nil || len(d.Notices) != 2 {
		t.Fatal("resume or applied loosening not recorded")
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
