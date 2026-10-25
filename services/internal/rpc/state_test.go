package rpc

import (
	"math"
	"testing"
)

func TestRentSaturatesFarAboveTheTarget(t *testing.T) {
	// The product passes int64 here, the fee does not.
	if got := RentPerKB(10_000_000_000_000, -17_000, 10_000, 3_000_000_000, 5_000); got != 449_865_010_000 {
		t.Fatalf("rent %d", got)
	}
	if got := RentPerKB(1_000_000_000_000, -17_000, 10_000, 1, 5_000); got != math.MaxInt64 {
		t.Fatalf("rent %d", got)
	}
	if got := RentPerKB(3_009_000_000, -17_000, 10_000, 3_000_000_000, 5_000); got != 415_000 {
		t.Fatalf("rent %d", got)
	}
	if got := RentPerKB(1_614_568_461, -17_000, 10_000, 3_000_000_000, 5_000); got != 1_000 {
		t.Fatalf("rent at the floor %d", got)
	}
}
