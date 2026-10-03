package vault

import (
	"fmt"
)

// Shield is the event shape of one shield: two nullifiers, then the pending deposit.
type Shield struct {
	Nullifiers [2]NewNullifier
	Deposit    DepositPending
}

// Transact is the event shape of one transact: two nullifiers, the two outputs, then settled when
// it paid at once or exit_queued when its payment waits in the exit queue.
type Transact struct {
	Nullifiers [2]NewNullifier
	Outputs    [2]NewCommitment
	Settled    *Settled
	Queued     *ExitQueued
}

// ExitSettled is a settled event that carries an exit ID: a queued exit release paid in full, or
// the unpaid parts of a stranded exit that claim paid.
type ExitSettled struct {
	Settled Settled
}

// Admission is the event shape of one admitted deposit: its two outputs, then deposit_admitted.
type Admission struct {
	Outputs  [2]NewCommitment
	Admitted DepositAdmitted
}

// Tx is the vault's part of one transaction. A transaction can reach the vault more than once
// through another contract, so it holds a sequence of calls.
type Tx struct {
	Ledger   uint32
	ClosedAt int64
	Hash     string
	// Calls holds Shield, Transact, Admission and ExitSettled values, and the bodies of the other
	// single events, such as an ExitStranded of a release.
	Calls []any
}

// ParseTxs groups events in chain order by transaction and checks that each transaction's events
// are a sequence of the shapes the vault emits.
func ParseTxs(events []Event) ([]Tx, error) {
	var txs []Tx
	for start := 0; start < len(events); {
		first := events[start].Raw
		end := start + 1
		for end < len(events) && events[end].Raw.Ledger == first.Ledger && events[end].Raw.TxHash == first.TxHash {
			end++
		}
		for i := start + 1; i < end; i++ {
			if !events[i-1].Raw.Pos().Less(events[i].Raw.Pos()) {
				return nil, malformed("events of %s out of order", first.TxHash)
			}
		}
		if start > 0 && !events[start-1].Raw.Pos().Less(first.Pos()) {
			return nil, malformed("transaction %s out of order", first.TxHash)
		}
		calls, err := parseCalls(events[start:end])
		if err != nil {
			return nil, fmt.Errorf("transaction %s in ledger %d: %w", first.TxHash, first.Ledger, err)
		}
		txs = append(txs, Tx{Ledger: first.Ledger, ClosedAt: first.ClosedAt, Hash: first.TxHash, Calls: calls})
		start = end
	}
	seen := make(map[string]bool, len(txs))
	for _, tx := range txs {
		if seen[tx.Hash] {
			return nil, malformed("transaction %s split", tx.Hash)
		}
		seen[tx.Hash] = true
	}
	return txs, nil
}

func parseCalls(events []Event) ([]any, error) {
	var calls []any
	for i := 0; i < len(events); {
		switch first := events[i].Body.(type) {
		case NewNullifier:
			second, ok := at[NewNullifier](events, i+1)
			if !ok {
				return nil, malformed("a nullifier without its pair")
			}
			if deposit, ok := at[DepositPending](events, i+2); ok {
				calls = append(calls, Shield{Nullifiers: [2]NewNullifier{first, second}, Deposit: deposit})
				i += 3
				continue
			}
			outputs, err := outputPair(events, i+2)
			if err != nil {
				return nil, err
			}
			t := Transact{Nullifiers: [2]NewNullifier{first, second}, Outputs: outputs}
			if settled, ok := at[Settled](events, i+4); ok && settled.ExitID == nil {
				t.Settled = &settled
			} else if queued, ok := at[ExitQueued](events, i+4); ok {
				t.Queued = &queued
			} else {
				return nil, malformed("spent nullifiers without a deposit, a settlement or a queued exit")
			}
			calls = append(calls, t)
			i += 5
		case NewCommitment:
			outputs, err := outputPair(events, i)
			if err != nil {
				return nil, err
			}
			admitted, ok := at[DepositAdmitted](events, i+2)
			if !ok {
				return nil, malformed("outputs without a settlement or an admission")
			}
			if admitted.LeafIndex0 != outputs[0].Index || admitted.LeafIndex1 != outputs[1].Index {
				return nil, malformed("deposit %d admitted at leaves %d, %d but inserted at %d, %d",
					admitted.ID, admitted.LeafIndex0, admitted.LeafIndex1, outputs[0].Index, outputs[1].Index)
			}
			calls = append(calls, Admission{Outputs: outputs, Admitted: admitted})
			i += 3
		case Settled:
			if first.ExitID == nil {
				return nil, malformed("a settlement without its transact")
			}
			calls = append(calls, ExitSettled{Settled: first})
			i++
		case DepositPending, DepositAdmitted, ExitQueued:
			return nil, malformed("%s out of place", events[i].Name)
		default:
			calls = append(calls, first)
			i++
		}
	}
	return calls, nil
}

func at[T any](events []Event, i int) (T, bool) {
	var zero T
	if i >= len(events) {
		return zero, false
	}
	v, ok := events[i].Body.(T)
	return v, ok
}

// outputPair reads the two new_commitment events of one inserted pair, which takes an even index
// and the one after it.
func outputPair(events []Event, i int) ([2]NewCommitment, error) {
	left, ok := at[NewCommitment](events, i)
	if !ok {
		return [2]NewCommitment{}, malformed("missing output")
	}
	right, ok := at[NewCommitment](events, i+1)
	if !ok {
		return [2]NewCommitment{}, malformed("an output without its pair")
	}
	if left.Index%2 != 0 || right.Index != left.Index+1 {
		return [2]NewCommitment{}, malformed("outputs at leaves %d and %d", left.Index, right.Index)
	}
	return [2]NewCommitment{left, right}, nil
}
