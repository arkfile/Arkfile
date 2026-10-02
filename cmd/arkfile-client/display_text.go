// display_text.go - Terminal-safe rendering of untrusted text.

package main

import (
	"strings"
	"unicode"
)

// isUnsafeDisplayRune reports whether r can manipulate a terminal or reorder
// displayed text: C0 and C1 control characters (including ESC and the
// single-byte CSI), DEL, and Unicode bidirectional controls.
func isUnsafeDisplayRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
}

// sanitizeDisplayText replaces unsafe runes with '?' so user-authored strings
// such as filenames, tags, and hints print as inert text.
func sanitizeDisplayText(s string) string {
	return strings.Map(func(r rune) rune {
		if isUnsafeDisplayRune(r) {
			return '?'
		}
		return r
	}, s)
}
