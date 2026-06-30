package models

import "testing"

func TestScanBool(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want bool
	}{
		{"nil", nil, false},
		{"bool true", true, true},
		{"bool false", false, false},
		{"int one", 1, true},
		{"int zero", 0, false},
		{"int64 one", int64(1), true},
		{"float64 one", float64(1), true},
		{"string one", "1", true},
		{"string true", "true", true},
		{"string TRUE", "TRUE", true},
		{"string false", "false", false},
		{"string empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScanBool(tc.in); got != tc.want {
				t.Fatalf("ScanBool(%#v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestScanInt64(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want int64
	}{
		{"nil", nil, 0},
		{"int", 500, 500},
		{"int64", int64(268435456000), 268435456000},
		{"float64", float64(268435456000), 268435456000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScanInt64(tc.in); got != tc.want {
				t.Fatalf("ScanInt64(%#v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
