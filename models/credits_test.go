package models

import (
	"testing"
)

// Pure-function tests for the microcent formatting and parsing helpers.
// DB-touching tests (GetUserCredits, AddCredits, etc.) live in integration-style
// tests against rqlite; this file focuses on the deterministic value layer.

func TestFormatCreditsUSD(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "$0.0000"},
		{1, "$0.0000"},                  // sub-tenth-of-microcent rounds to zero in display
		{10_000, "$0.0001"},             // smallest visible four-decimal increment
		{100_000_000, "$1.0000"},        // exactly one dollar
		{500_000_000, "$5.0000"},        // five dollars
		{12_345_678, "$0.1234"},         // mid-fraction
		{199_900_000_000, "$1999.0000"}, // four-figure dollars
		{-1, "-$0.0000"},                // negative below display threshold still shows minus
		{-10_000, "-$0.0001"},           // negative one tenth-thousandth
		{-12_345_678, "-$0.1234"},       // negative mid-fraction
		{-500_000_000, "-$5.0000"},      // negative five dollars
		{-600, "-$0.0000"},              // negative sub-tenth-of-microcent: minus sign is honest
	}
	for _, tc := range cases {
		got := FormatCreditsUSD(tc.in)
		if got != tc.want {
			t.Errorf("FormatCreditsUSD(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseCreditsFromUSD(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		cases := []struct {
			in   string
			want int64
		}{
			{"0", 0},
			{"0.00", 0},
			{"5", 500_000_000},
			{"5.00", 500_000_000},
			{"5.0", 500_000_000},
			{"$5.00", 500_000_000},
			{"+5.00", 500_000_000},
			{"19.99", 1_999_000_000},
			{"-19.99", -1_999_000_000},
			{"-$0.1234", -12_340_000},
			{"0.0001", 10_000},
			{"10.0000", 1_000_000_000},
			{"  10.00  ", 1_000_000_000}, // whitespace tolerated
		}
		for _, tc := range cases {
			got, err := ParseCreditsFromUSD(tc.in)
			if err != nil {
				t.Errorf("ParseCreditsFromUSD(%q) unexpected error: %v", tc.in, err)
				continue
			}
			if got != tc.want {
				t.Errorf("ParseCreditsFromUSD(%q) = %d, want %d", tc.in, got, tc.want)
			}
		}
	})

	t.Run("invalid", func(t *testing.T) {
		invalids := []string{
			"",
			"abc",
			"10.001a",
			"10.00001", // too many decimal places
			"$$10.00",  // double dollar sign
			"10..00",   // malformed decimal
			".",        // bare dot, no digits
			"-",        // bare minus
		}
		for _, in := range invalids {
			if _, err := ParseCreditsFromUSD(in); err == nil {
				t.Errorf("ParseCreditsFromUSD(%q) expected error, got nil", in)
			}
		}
	})
}

func TestFormatParseRoundTrip(t *testing.T) {
	// FormatCreditsUSD truncates below 10_000 microcents (one tenth-thousandth
	// of a dollar). For values that are exact multiples of 10_000, Format then
	// Parse must round-trip.
	cases := []int64{
		0,
		10_000,
		500_000_000,
		1_999_000_000,
		-12_340_000, // -$0.1234
		100_000_000_000,
	}
	for _, v := range cases {
		formatted := FormatCreditsUSD(v)
		parsed, err := ParseCreditsFromUSD(formatted)
		if err != nil {
			t.Errorf("round-trip parse error for %d (formatted=%q): %v", v, formatted, err)
			continue
		}
		if parsed != v {
			t.Errorf("round-trip mismatch: %d -> %q -> %d", v, formatted, parsed)
		}
	}
}

func TestMicrocentsPerUSD(t *testing.T) {
	// Sanity: the spec depends on this exact value. If it ever changes, every
	// downstream calculation breaks.
	if MicrocentsPerUSD != 100_000_000 {
		t.Fatalf("MicrocentsPerUSD = %d, want 100000000 (1 USD = 100 cents = 100M microcents)",
			MicrocentsPerUSD)
	}
}

func TestTransactionTypeConstants(t *testing.T) {
	// Spec §3.2 + §3.5: the daily storage sweep writes 'usage'; admin gifts
	// write 'gift'. These string values are observed by the audit log and
	// e2e test assertions, so they must remain stable.
	if TransactionTypeUsage != "usage" {
		t.Errorf("TransactionTypeUsage = %q, want \"usage\"", TransactionTypeUsage)
	}
	if TransactionTypeGift != "gift" {
		t.Errorf("TransactionTypeGift = %q, want \"gift\"", TransactionTypeGift)
	}
	if TransactionTypeAdjustment != "adjustment" {
		t.Errorf("TransactionTypeAdjustment = %q, want \"adjustment\"", TransactionTypeAdjustment)
	}
}
