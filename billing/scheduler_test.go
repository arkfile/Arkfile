package billing

import (
	"testing"
	"time"
)

func TestNextTickBoundary(t *testing.T) {
	cases := []struct {
		name     string
		now      time.Time
		interval time.Duration
		want     time.Time
	}{
		{
			name:     "mid-hour aligns to next top-of-hour",
			now:      time.Date(2026, 4, 30, 14, 23, 17, 0, time.UTC),
			interval: time.Hour,
			want:     time.Date(2026, 4, 30, 15, 0, 0, 0, time.UTC),
		},
		{
			name:     "exact hour rolls forward to next hour",
			now:      time.Date(2026, 4, 30, 15, 0, 0, 0, time.UTC),
			interval: time.Hour,
			want:     time.Date(2026, 4, 30, 16, 0, 0, 0, time.UTC),
		},
		{
			name:     "mid-minute with 1m interval aligns to next minute",
			now:      time.Date(2026, 4, 30, 14, 23, 17, 0, time.UTC),
			interval: time.Minute,
			want:     time.Date(2026, 4, 30, 14, 24, 0, 0, time.UTC),
		},
		{
			name:     "across UTC day boundary",
			now:      time.Date(2026, 4, 30, 23, 45, 0, 0, time.UTC),
			interval: time.Hour,
			want:     time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nextTickBoundary(tc.now, tc.interval)
			if !got.Equal(tc.want) {
				t.Errorf("nextTickBoundary(%v, %v) = %v, want %v", tc.now, tc.interval, got, tc.want)
			}
		})
	}
}

func TestShouldRunSweep(t *testing.T) {
	now := time.Date(2026, 4, 30, 12, 30, 0, 0, time.UTC)
	today := "2026-04-30"
	yesterday := "2026-04-29"

	cases := []struct {
		name      string
		sweepAt   string
		lastDate  string
		wantSweep bool
	}{
		{"already swept today", "00:15", today, false},
		{"crossed boundary, not yet swept today", "00:15", yesterday, true},
		{"boundary in future today", "23:00", yesterday, false},
		{"unparseable HH:MM returns false", "bogus", yesterday, false},
		{"empty HH:MM returns false", "", yesterday, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRunSweep(now, tc.sweepAt, tc.lastDate, today)
			if got != tc.wantSweep {
				t.Errorf("shouldRunSweep(now=%v, sweepAt=%q, lastDate=%q, today=%q) = %t, want %t",
					now, tc.sweepAt, tc.lastDate, today, got, tc.wantSweep)
			}
		})
	}
}

func TestParseHHMM(t *testing.T) {
	cases := []struct {
		in     string
		wantH  int
		wantM  int
		wantOK bool
	}{
		{"00:00", 0, 0, true},
		{"00:15", 0, 15, true},
		{"23:59", 23, 59, true},
		{"12:34", 12, 34, true},
		{"24:00", 0, 0, false}, // hour out of range
		{"00:60", 0, 0, false}, // minute out of range
		{"0:15", 0, 0, false},  // missing leading zero on hour
		{"00-15", 0, 0, false}, // wrong separator
		{"abcde", 0, 0, false},
		{"", 0, 0, false},
		{"00:1", 0, 0, false}, // wrong length
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			h, m, ok := parseHHMM(tc.in)
			if ok != tc.wantOK {
				t.Errorf("parseHHMM(%q) ok = %t, want %t", tc.in, ok, tc.wantOK)
			}
			if ok && (h != tc.wantH || m != tc.wantM) {
				t.Errorf("parseHHMM(%q) = (%d, %d), want (%d, %d)", tc.in, h, m, tc.wantH, tc.wantM)
			}
		})
	}
}
