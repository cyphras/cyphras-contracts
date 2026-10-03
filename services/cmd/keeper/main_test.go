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
}
