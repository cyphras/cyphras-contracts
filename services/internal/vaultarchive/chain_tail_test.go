package vaultarchive

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cyphras/cyphras-contracts/services/internal/fr"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
	"github.com/cyphras/cyphras-contracts/services/internal/vault/vaulttest"
)

// afterTheArchive is the vault's history after the three windows of good: pairs admissions, one
// pair each, in ledgers of the open window, continuing the archive's eight leaves.
func afterTheArchive(pairs int) []vault.RawEvent {
	c := vaulttest.New(3*WindowLedgers+10, 1_730_000_000)
	c.NextLeaf = 8
	for i := range pairs {
		c.NextLedger(5)
		c.Admit(uint64(100 + i))
	}
	return c.Events
}

func commitmentsOf(t *testing.T, events []vault.RawEvent) []fr.Element {
	t.Helper()
	var out []fr.Element
	for _, e := range events {
		d, err := vault.Decode(e)
		if err != nil {
			t.Fatal(err)
		}
		if n, ok := d.Body.(vault.NewCommitment); ok {
			out = append(out, n.Commitment)
		}
	}
	return out
}

// chainWithTail is a vault that took the events after the archive's last ledger, and an RPC that
// still keeps them.
func chainWithTail(t *testing.T, c *Contents, tail []vault.RawEvent) *rpctest.Fake {
	t.Helper()
	all := &Contents{Manifest: c.Manifest, Commitments: append(append([]fr.Element(nil), c.Commitments...), commitmentsOf(t, tail)...), Nullifiers: c.Nullifiers}
	f := chainOf(t, all)
	for _, e := range tail {
		f.AddEvent(rpctest.EventInfo(e))
	}
	return f
}

func TestAnArchiveFarBehindTheVaultIsCheckedAgainstTheEventsAfterIt(t *testing.T) {
	ctx := context.Background()
	c := loaded(t)
	tail := afterTheArchive(vault.RootHistory + 44)
	f := chainWithTail(t, c, tail)

	report, err := VerifyChain(ctx, f, pinOf(c), c)
	if err != nil {
		t.Fatalf("an archive %d pairs behind with the events after it available: %v", vault.RootHistory+44, err)
	}
	if want := uint64(8 + 2*(vault.RootHistory+44)); report.Leaves != 8 || report.ChainLeaves != want {
		t.Fatalf("report %+v, want the vault at %d leaves", report, want)
	}
}

func TestTheEventsAfterTheArchiveAreOnlyReadWhenTheRootRingCannotConfirmIt(t *testing.T) {
	ctx := context.Background()
	c := loaded(t)
	for name, pairs := range map[string]int{"the last pair the ring keeps": vault.RootHistory - 1, "one pair past it": vault.RootHistory} {
		f := chainWithTail(t, c, afterTheArchive(pairs))
		if _, err := VerifyChain(ctx, f, pinOf(c), c); err != nil {
			t.Fatalf("%s (%d pairs): %v", name, pairs, err)
		}
		if got, want := f.CallCount("getEvents") > 0, pairs >= vault.RootHistory; got != want {
			t.Fatalf("%s (%d pairs): getEvents asked %v, want %v", name, pairs, got, want)
		}
	}
}

func TestAnArchiveFarBehindTheVaultIsRefusedWhenAnythingBetweenItAndTheVaultIsOff(t *testing.T) {
	ctx := context.Background()
	c := loaded(t)
	tail := afterTheArchive(vault.RootHistory + 10)

	forged := append([]vault.RawEvent(nil), tail...)
	for i, e := range forged {
		if d, err := vault.Decode(e); err == nil {
			if n, ok := d.Body.(vault.NewCommitment); ok && n.Index == 8+2*100 {
				forged[i] = forgedLeaf(t, e, 424242)
			}
		}
	}

	var dropped []vault.RawEvent
	for _, e := range tail {
		if d, _ := vault.Decode(e); d.Body != nil {
			if n, ok := d.Body.(vault.NewCommitment); ok && (n.Index == 8+2*50 || n.Index == 8+2*50+1) {
				continue
			}
		}
		dropped = append(dropped, e)
	}

	replayed := append(append([]vault.RawEvent(nil), tail...), tail[len(tail)-4:]...)

	honest := chainWithTail(t, c, tail)
	for name, served := range map[string][]vault.RawEvent{
		"a leaf the RPC reports other than the vault holds": forged,
		"a pair the RPC leaves out":                         dropped,
		"events the RPC repeats":                            replayed,
		"no events at all":                                  nil,
	} {
		f := chainWithTail(t, c, tail)
		f.Events = nil
		for _, e := range served {
			f.AddEvent(rpctest.EventInfo(e))
		}
		if _, err := VerifyChain(ctx, f, pinOf(c), c); !errors.Is(err, ErrChain) {
			t.Errorf("%s: %v", name, err)
		}
	}

	tampered := &Contents{Manifest: c.Manifest, Commitments: append([]fr.Element(nil), c.Commitments...), Nullifiers: c.Nullifiers}
	tampered.Commitments[3] = fr.SetUint64(31337)
	if _, err := VerifyChain(ctx, honest, pinOf(tampered), tampered); !errors.Is(err, ErrChain) {
		t.Errorf("a tampered leaf in the archive, the events after it honest: %v", err)
	}
}

func forgedLeaf(t *testing.T, e vault.RawEvent, n uint64) vault.RawEvent {
	t.Helper()
	d, err := vault.Decode(e)
	if err != nil {
		t.Fatal(err)
	}
	body := d.Body.(vault.NewCommitment)
	e.Value = encodeNewCommitment(body.Index, fr.SetUint64(n))
	return e
}

func encodeNewCommitment(index uint64, commitment fr.Element) string {
	c := vaulttest.New(1, 0)
	c.NextLeaf = index
	c.Tx()
	c.Emit("new_commitment",
		vault.Field{Name: "index", Value: vault.U64(index)},
		vault.Field{Name: "commitment", Value: vaulttest.Field(commitment)},
		vault.Field{Name: "encrypted_output", Value: vault.Bytes(make([]byte, vault.CiphertextLen))},
	)
	return c.Events[0].Value
}

func TestAnArchiveFarBehindTheVaultSaysSoWhenTheRPCNoLongerKeepsTheEventsAfterIt(t *testing.T) {
	c := loaded(t)
	f := chainWithTail(t, c, afterTheArchive(vault.RootHistory+10))
	f.Oldest = 3*WindowLedgers + 5_000
	_, err := VerifyChain(context.Background(), f, pinOf(c), c)
	if !errors.Is(err, ErrChain) || !strings.Contains(err.Error(), "ahead of the archive") || !strings.Contains(err.Error(), "older than the source keeps") {
		t.Fatalf("an RPC that dropped the ledgers after the archive: %v", err)
	}
}

func TestEveryRPCMustGiveTheEventsAfterAnArchiveFarBehindTheVault(t *testing.T) {
	ctx := context.Background()
	dir, _ := good(t)
	c := loaded(t)
	tail := afterTheArchive(vault.RootHistory + 3)
	one, two := chainWithTail(t, c, tail), chainWithTail(t, c, tail)
	if _, _, err := VerifyArchive(ctx, DirFetcher(dir), pinOf(c), one, two); err != nil {
		t.Fatal(err)
	}
	forgetful := chainWithTail(t, c, tail)
	forgetful.Events = nil
	if _, _, err := VerifyArchive(ctx, DirFetcher(dir), pinOf(c), one, forgetful); !errors.Is(err, ErrChain) {
		t.Fatalf("the second RPC has no events: %v", err)
	}
}

func TestEventsOfAnotherContractAreNotTakenForTheVaultsTail(t *testing.T) {
	c := loaded(t)
	tail := afterTheArchive(vault.RootHistory + 3)
	f := chainWithTail(t, c, tail)
	f.Events = nil
	for _, e := range tail {
		e.Contract = vaulttest.Token
		f.AddEvent(rpctest.EventInfo(e))
	}
	if _, err := VerifyChain(context.Background(), f, pinOf(c), c); !errors.Is(err, ErrChain) {
		t.Fatalf("events of another contract: %v", err)
	}
}
