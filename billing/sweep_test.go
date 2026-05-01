package billing

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

// TestSettlementMetadata_PrivacyInvariant is a regression guard: the JSON shape
// of SettlementMetadata must contain ONLY the five fields specified in §3.5
// of the design doc. Adding `avg_billable_bytes` (or any field that lets an
// observer reconstruct per-day storage history) would be a privacy disclosure.
//
// This test fails if a future change adds extra fields to SettlementMetadata.
func TestSettlementMetadata_PrivacyInvariant(t *testing.T) {
	m := SettlementMetadata{
		DrainedMicrocents:           600,
		RateMicrocentsPerGiBPerHour: 1356,
		PeriodStart:                 time.Date(2026, 4, 30, 0, 15, 0, 0, time.UTC),
		PeriodEnd:                   time.Date(2026, 5, 1, 0, 15, 0, 0, time.UTC),
		TicksCount:                  24,
	}
	bytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	allowedKeys := map[string]bool{
		"drained_microcents":               true,
		"rate_microcents_per_gib_per_hour": true,
		"period_start":                     true,
		"period_end":                       true,
		"ticks_count":                      true,
	}
	for k := range decoded {
		if !allowedKeys[k] {
			t.Errorf("SettlementMetadata contains forbidden key %q -- privacy regression. Only these keys are allowed: %v", k, keysOf(allowedKeys))
		}
	}
	if len(decoded) != len(allowedKeys) {
		t.Errorf("SettlementMetadata has %d keys, expected exactly %d (the §3.5-allowed set). Got: %v",
			len(decoded), len(allowedKeys), keysOf(decoded))
	}

	// Explicit per-key check that `avg_billable_bytes` is absent. This single
	// hard-coded assertion is the one that future engineers most need to see
	// in a failing test name.
	if _, present := decoded["avg_billable_bytes"]; present {
		t.Error("SettlementMetadata contains avg_billable_bytes -- privacy regression. See spec §3.5.")
	}
}

// keysOf returns the keys of a map[string]X as a slice, for error message diagnostics.
func keysOf(m interface{}) []string {
	out := []string{}
	switch v := m.(type) {
	case map[string]bool:
		for k := range v {
			out = append(out, k)
		}
	case map[string]interface{}:
		for k := range v {
			out = append(out, k)
		}
	}
	return out
}

func TestComputeSettlementPeriod_FirstSweepDefaults(t *testing.T) {
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	start, end, ticks := computeSettlementPeriod(sql.NullString{}, now)

	if !end.Equal(now) {
		t.Errorf("end = %v, want %v", end, now)
	}
	wantStart := now.Add(-24 * time.Hour)
	if !start.Equal(wantStart) {
		t.Errorf("start = %v, want %v (24h before now)", start, wantStart)
	}
	if ticks != 24 {
		t.Errorf("ticks = %d, want 24 (default for first sweep)", ticks)
	}
}

func TestComputeSettlementPeriod_NormalDay(t *testing.T) {
	now := time.Date(2026, 4, 30, 0, 15, 0, 0, time.UTC)
	last := sql.NullString{String: "2026-04-29 00:15:00", Valid: true}

	start, end, ticks := computeSettlementPeriod(last, now)
	if !end.Equal(now) {
		t.Errorf("end = %v, want %v", end, now)
	}
	wantStart := time.Date(2026, 4, 29, 0, 15, 0, 0, time.UTC)
	if !start.Equal(wantStart) {
		t.Errorf("start = %v, want %v", start, wantStart)
	}
	if ticks != 24 {
		t.Errorf("ticks = %d, want 24", ticks)
	}
}

func TestComputeSettlementPeriod_SkippedDay(t *testing.T) {
	// last_billed_at is 2 days ago; sweep at noon today. Period spans ~48h.
	now := time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)
	last := sql.NullString{String: "2026-04-28 12:00:00", Valid: true}

	_, _, ticks := computeSettlementPeriod(last, now)
	if ticks < 47 || ticks > 49 {
		t.Errorf("ticks for ~48h span = %d, want ~48", ticks)
	}
}
