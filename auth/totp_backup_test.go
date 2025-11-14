package auth

import (
	"testing"
)

func TestBackupCodeRandomness(t *testing.T) {
	// Generate multiple sets of backup codes
	const numSets = 5
	const codesPerSet = 10

	allCodes := make(map[string]bool)

	for set := 0; set < numSets; set++ {
		codes := generateBackupCodes(codesPerSet)

		// Check that we got the right number of codes
		if len(codes) != codesPerSet {
			t.Errorf("Set %d: Expected %d codes, got %d", set, codesPerSet, len(codes))
		}

		// Check each code
		for i, code := range codes {
			// Check length
			if len(code) != BackupCodeLength {
				t.Errorf("Set %d, Code %d: Expected length %d, got %d", set, i, BackupCodeLength, len(code))
			}

			// Check for valid characters
			for _, char := range code {
				if !containsChar(BackupCodeCharset, byte(char)) {
					t.Errorf("Set %d, Code %d: Invalid character '%c' in code '%s'", set, i, char, code)
				}
			}

			// Check for duplicates across all sets
			if allCodes[code] {
				t.Errorf("Set %d, Code %d: Duplicate code found: '%s'", set, i, code)
			}
			allCodes[code] = true

			// Log the code for manual inspection
			t.Logf("Set %d, Code %d: %s", set, i, code)
		}
	}

	// Statistical check: with proper randomness, we should have mostly unique codes
	totalCodes := numSets * codesPerSet
	uniqueCodes := len(allCodes)

	// We expect at least 95% unique codes (allowing for some birthday paradox collisions)
	minExpected := int(float64(totalCodes) * 0.95)
	if uniqueCodes < minExpected {
		t.Errorf("Insufficient randomness: got %d unique codes out of %d total (expected at least %d)",
			uniqueCodes, totalCodes, minExpected)
	}

	t.Logf("Randomness check: %d unique codes out of %d total (%.1f%%)",
		uniqueCodes, totalCodes, float64(uniqueCodes)/float64(totalCodes)*100)
}

func TestSingleBackupCodeRandomness(t *testing.T) {
	// Generate many codes and check for patterns
	const numCodes = 100
	codes := make([]string, numCodes)

	for i := 0; i < numCodes; i++ {
		codes[i] = generateSingleBackupCode()
		t.Logf("Code %d: %s", i, codes[i])
	}

	// Check for sequential patterns (like ABCDEFGHIJ, KLMNOPQRST)
	sequential := 0
	for _, code := range codes {
		if isSequential(code) {
			sequential++
			t.Logf("WARNING: Sequential code detected: %s", code)
		}
	}

	if sequential > 0 {
		t.Errorf("Found %d sequential codes out of %d - this indicates a serious randomness failure!", sequential, numCodes)
	}
}

// Helper function to check if a code is sequential in the charset
func isSequential(code string) bool {
	if len(code) < 3 {
		return false
	}

	// Check if characters follow the charset order
	for i := 0; i < len(code)-2; i++ {
		idx1 := indexInCharset(code[i])
		idx2 := indexInCharset(code[i+1])
		idx3 := indexInCharset(code[i+2])

		if idx1 >= 0 && idx2 >= 0 && idx3 >= 0 {
			// Check if they're consecutive in the charset (with wrapping)
			charsetLen := len(BackupCodeCharset)
			if (idx2 == (idx1+1)%charsetLen) && (idx3 == (idx2+1)%charsetLen) {
				return true
			}
		}
	}

	return false
}

func indexInCharset(char byte) int {
	for i := 0; i < len(BackupCodeCharset); i++ {
		if BackupCodeCharset[i] == char {
			return i
		}
	}
	return -1
}

func containsChar(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
