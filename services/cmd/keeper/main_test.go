package main

import (
	"maps"
	"testing"
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

func TestTheTTLFeeCapIsFiveLumensUnlessSetToAPositiveFee(t *testing.T) {
	t.Setenv("TTL_FEE_CAP", "")
	if limit, err := ttlFeeCap(); err != nil || limit != 50_000_000 {
		t.Fatalf("by default: %d, %v", limit, err)
	}
	t.Setenv("TTL_FEE_CAP", "100000000")
	if limit, err := ttlFeeCap(); err != nil || limit != 100_000_000 {
		t.Fatalf("set: %d, %v", limit, err)
	}
	for _, bad := range []string{"0", "-1", "5 XLM"} {
		t.Setenv("TTL_FEE_CAP", bad)
		if _, err := ttlFeeCap(); err == nil {
			t.Fatalf("%q was taken", bad)
		}
	}
}
