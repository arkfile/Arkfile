package main

import "testing"

func TestSanitizeDisplayText(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"caf\u00e9 \u65e5\u672c.txt", "caf\u00e9 \u65e5\u672c.txt"},
		{"\x1b[2Jcleared", "?[2Jcleared"},
		{"\x1b]0;title\x07", "?]0;title?"},
		{"\u009b31mred", "?31mred"},
		{"line\r\nbreak", "line??break"},
		{"tab\there", "tab?here"},
		{"del\x7f", "del?"},
		{"nul\x00", "nul?"},
		{"photo\u202egpj.exe", "photo?gpj.exe"},
		{"isolate\u2066x\u2069", "isolate?x?"},
		{"mark\u200e", "mark?"},
	}
	for _, tc := range cases {
		if got := sanitizeDisplayText(tc.in); got != tc.want {
			t.Errorf("sanitizeDisplayText(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
