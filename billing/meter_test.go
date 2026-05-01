package billing

import (
	"testing"
)

// TestTickMath verifies the per-tick charge formula in isolation. The actual
// TickUser also touches the DB; this test pulls the math out so it can be
// exercised without database setup.
//
// Formula (spec §3.2):
//
//	billable_bytes        = max(0, total_storage_bytes - free_baseline_bytes)
//	tick_charge_microcents = (billable_bytes * rate_microcents_per_gib_per_hour) >> 30
//
// The right-shift is integer division by 2^30 (binary GiB) and truncates the
// fractional remainder. We verify edge cases at the free baseline, one byte
// over, and well over.
func TestTickMath(t *testing.T) {
	const (
		rateMicrocentsPerGiBPerHour = int64(1356) // $10.00/TiB/month
		freeBaselineBytes           = int64(1_181_116_006)
		oneGiBBytes                 = int64(1) << 30
	)

	cases := []struct {
		name              string
		totalStorageBytes int64
		wantBillable      int64
		wantTickCharge    int64
	}{
		{
			name:              "exactly at baseline -> no charge",
			totalStorageBytes: freeBaselineBytes,
			wantBillable:      0,
			wantTickCharge:    0,
		},
		{
			name:              "below baseline -> no charge",
			totalStorageBytes: freeBaselineBytes - 1,
			wantBillable:      0,
			wantTickCharge:    0,
		},
		{
			name:              "1 byte over baseline -> truncates to zero charge",
			totalStorageBytes: freeBaselineBytes + 1,
			wantBillable:      1,
			// (1 * 1356) >> 30 = 0 (truncated)
			wantTickCharge: 0,
		},
		{
			name:              "1 GiB over baseline -> 1356 microcents/hour",
			totalStorageBytes: freeBaselineBytes + oneGiBBytes,
			wantBillable:      oneGiBBytes,
			// (oneGiBBytes * 1356) >> 30 = 1356 exactly
			wantTickCharge: 1356,
		},
		{
			name:              "100 GiB over baseline -> 135600 microcents/hour",
			totalStorageBytes: freeBaselineBytes + 100*oneGiBBytes,
			wantBillable:      100 * oneGiBBytes,
			wantTickCharge:    100 * 1356,
		},
		{
			name:              "0 total storage (deleted user) -> no charge",
			totalStorageBytes: 0,
			wantBillable:      0,
			wantTickCharge:    0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			billable := tc.totalStorageBytes - freeBaselineBytes
			if billable < 0 {
				billable = 0
			}
			if billable != tc.wantBillable {
				t.Errorf("billable = %d, want %d", billable, tc.wantBillable)
			}

			tickCharge := (billable * rateMicrocentsPerGiBPerHour) >> 30
			if tickCharge != tc.wantTickCharge {
				t.Errorf("tickCharge = %d microcents, want %d", tickCharge, tc.wantTickCharge)
			}
		})
	}
}
