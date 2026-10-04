package main

import (
	"maps"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"

	"github.com/cyphras/cyphras-contracts/services/internal/rpc/rpctest"
)

func TestOnlyACourtOrderIsHeldFromRefundsByDefault(t *testing.T) {
	t.Setenv("HOLD_REASONS", "")
	hold, err := holdReasons()
	if err != nil || !maps.Equal(hold, map[uint32]bool{100: true}) {
		t.Fatalf("held by default: %v, %v", hold, err)
	}
	t.Setenv("HOLD_REASONS", "100, 7,")
	if hold, err := holdReasons(); err != nil || !maps.Equal(hold, map[uint32]bool{100: true, 7: true}) {
		t.Fatalf("held: %v, %v", hold, err)
	}
	t.Setenv("HOLD_REASONS", "100,court")
	if _, err := holdReasons(); err == nil {
		t.Fatal("a reason that is not a number was taken")
	}
	t.Setenv("HOLD_REASONS", "100, 6")
	if _, err := holdReasons(); err == nil {
		t.Fatal("the screening hold's reason was taken")
	}
}

func TestTheEngineCapsExtensionsAtTheTTLFeeCap(t *testing.T) {
	fake := rpctest.New(network.TestNetworkPassphrase, 1)
	t.Setenv("TTL_FEE_CAP", "")
	if e, err := newEngine(fake, network.TestNetworkPassphrase, nil); err != nil || e.MaxTTLFee != 50_000_000 || e.MaxResourceFee != 50_000_000 {
		t.Fatalf("by default: %+v, %v", e, err)
	}
	t.Setenv("TTL_FEE_CAP", "100000000")
	if e, err := newEngine(fake, network.TestNetworkPassphrase, nil); err != nil || e.MaxTTLFee != 100_000_000 || e.TTLFeeCap() != 100_000_000 {
		t.Fatalf("set: %+v, %v", e, err)
	}
	for _, ok := range []string{"100000", "4000000000"} {
		t.Setenv("TTL_FEE_CAP", ok)
		if _, err := newEngine(fake, network.TestNetworkPassphrase, nil); err != nil {
			t.Fatalf("%q was refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "-1", "99999", "4000000001", "5 XLM"} {
		t.Setenv("TTL_FEE_CAP", bad)
		if _, err := newEngine(fake, network.TestNetworkPassphrase, nil); err == nil {
			t.Fatalf("%q was taken", bad)
		}
	}
	// Nor may the inclusion fee cap leave the fee field too little room for the TTL fee cap.
	t.Setenv("TTL_FEE_CAP", "4000000000")
	t.Setenv("INCLUSION_FEE_CAP", "100000001")
	if _, err := newEngine(fake, network.TestNetworkPassphrase, nil); err == nil {
		t.Fatal("an inclusion fee cap above 10 XLM was taken")
	}
}
