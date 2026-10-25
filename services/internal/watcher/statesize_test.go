package watcher

import (
	"context"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/cyphras/cyphras-contracts/services/internal/alert"
	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
	"github.com/cyphras/cyphras-contracts/services/internal/vault"
)

// stateWatcher is a watcher with only what the state size check reads: an RPC that publishes
// settings and an alerter without a cooldown, so any repeat would reach the recorder.
func stateWatcher(settings rpctest.Settings) (*Watcher, *rpctest.Fake, *recorder) {
	fake := rpctest.New(passphrase, 9)
	fake.SetSettings(settings)
	pages := &recorder{}
	return &Watcher{rpc: fake, alerts: &alert.Alerter{Service: "watcher", Channels: []alert.Channel{pages}}}, fake, pages
}

// setWindow publishes the network's window of live Soroban state sizes.
func setWindow(fake *rpctest.Fake, samples ...uint64) {
	window := make([]xdr.Uint64, len(samples))
	for i, s := range samples {
		window[i] = xdr.Uint64(s)
	}
	c := xdr.ConfigSettingEntry{ConfigSettingId: xdr.ConfigSettingIdConfigSettingLiveSorobanStateSizeWindow, LiveSorobanStateSizeWindow: &window}
	fake.SetEntry(vault.ConfigSettingKey(c.ConfigSettingId), xdr.LedgerEntryData{Type: xdr.LedgerEntryTypeConfigSetting, ConfigSetting: &c}, 1, nil)
}

func (r *recorder) all() []alert.Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.alerts)
}

func TestTheStateSizeAlertsOnceAtEachLevelAndClearsAMarginUnderIt(t *testing.T) {
	w, fake, pages := stateWatcher(rpctest.Mainnet)
	ctx := context.Background()
	// Mainnet's target is 3 GB; each step is the window's average, in bytes.
	steps := []struct {
		average uint64
		want    []string
	}{
		{1_612_000_000, nil},
		{2_099_999_999, nil},
		{2_100_000_000, []string{"state_size_70"}},
		{2_160_000_000, nil},
		{2_050_000_000, nil},
		{2_550_000_000, []string{"state_size_85"}},
		{2_490_000_000, nil},
		{2_850_000_000, []string{"state_size_95"}},
		{3_009_000_000, []string{"state_size_100"}},
		{2_950_000_000, nil},
		{2_930_000_000, []string{"state_size_100_resolved"}},
		{3_000_000_000, []string{"state_size_100"}},
		{2_480_000_000, []string{"state_size_100_resolved", "state_size_95_resolved", "state_size_85_resolved"}},
		{2_030_000_000, []string{"state_size_70_resolved"}},
		{2_000_000_000, nil},
		{2_200_000_000, []string{"state_size_70"}},
	}
	seen := 0
	for i, s := range steps {
		// Samples around the average, as the network's window holds them.
		setWindow(fake, s.average-1_000, s.average, s.average+1_000)
		if err := w.CheckStateSize(ctx); err != nil {
			t.Fatal(err)
		}
		got := pages.all()[seen:]
		seen += len(got)
		var codes []string
		for _, a := range got {
			codes = append(codes, a.Code)
		}
		if !slices.Equal(codes, s.want) {
			t.Fatalf("step %d at %d bytes: alerts %v, want %v", i, s.average, codes, s.want)
		}
		for _, a := range got {
			want := alert.Warning
			switch {
			case strings.HasSuffix(a.Code, "_resolved"):
				want = alert.Info
			case a.Code == "state_size_100":
				want = alert.Critical
			}
			if a.Severity != want {
				t.Fatalf("step %d: %s is %s", i, a.Code, a.Severity)
			}
		}
	}
	all := pages.all()
	if msg := all[3].Message; !strings.Contains(msg, "3.009 GB, 100.3% of its 3.000 GB target") || !strings.Contains(msg, "rents for 415000 stroops a period, against 10000 at the target") {
		t.Fatalf("message %q", msg)
	}
	if msg := all[4].Message; !strings.Contains(msg, "97.6%") || !strings.Contains(msg, "under 98%") {
		t.Fatalf("resolved message %q", msg)
	}
}

// Testnet's state passed its 4 GB target: the first check raises the highest level alone.
func TestAStateAlreadyAboveItsTargetRaisesTheHighestLevelAlone(t *testing.T) {
	testnet := rpctest.Mainnet
	testnet.StateTarget, testnet.StateSize = 4_000_000_000, 4_011_000_000
	w, _, pages := stateWatcher(testnet)
	for range 3 {
		if err := w.CheckStateSize(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	all := pages.all()
	if len(all) != 1 || all[0].Code != "state_size_100" || all[0].Severity != alert.Critical || !strings.Contains(all[0].Message, "4.011 GB, 100.2% of its 4.000 GB target") {
		t.Fatalf("alerts %+v", all)
	}
}

func TestTheStateSizeCheckFailsWithoutTheNetworksSettings(t *testing.T) {
	w, fake, pages := stateWatcher(rpctest.Mainnet)
	setWindow(fake)
	if err := w.CheckStateSize(context.Background()); err == nil {
		t.Fatal("an empty window was read")
	}
	fake.DeleteEntry(vault.ConfigSettingKey(xdr.ConfigSettingIdConfigSettingContractLedgerCostV0))
	setWindow(fake, 1)
	if err := w.CheckStateSize(context.Background()); err == nil {
		t.Fatal("a missing target was read")
	}
	if len(pages.all()) != 0 {
		t.Fatal("a failed read raised an alert")
	}
}

// A window no network can hold is an error, which the check's failure count pages, and clears
// nothing that is open.
func TestAnImplausibleStateSizeIsAnErrorAndClearsNothing(t *testing.T) {
	w, fake, pages := stateWatcher(rpctest.Mainnet)
	setWindow(fake, 2_550_000_000)
	if err := w.CheckStateSize(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, window := range [][]uint64{{math.MaxUint64, 1}, {10_000_000_000_001}, {math.MaxUint64 / 2, math.MaxUint64 / 2}} {
		setWindow(fake, window...)
		if err := w.CheckStateSize(context.Background()); err == nil {
			t.Fatalf("window %v was read", window)
		}
	}
	if codes := codesOf(pages.all()); !slices.Equal(codes, []string{"state_size_70"}) && !slices.Equal(codes, []string{"state_size_85"}) {
		t.Fatalf("alerts %v", codes)
	}
}

// A watcher that leaves the state size to another one of its network reads nothing for it.
func TestAWatcherThatSkipsTheStateSizeReadsNothing(t *testing.T) {
	testnet := rpctest.Mainnet
	testnet.StateTarget, testnet.StateSize = 4_000_000_000, 4_011_000_000
	w, fake, pages := stateWatcher(testnet)
	w.cfg.SkipStateSize = true
	reads := fake.CallCount("getLedgerEntries")
	if err := w.CheckStateSize(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.CallCount("getLedgerEntries") != reads || len(pages.all()) != 0 {
		t.Fatal("a skipping watcher checked the state size")
	}
}
