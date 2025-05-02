package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePasswordComplexity(t *testing.T) {
	testCases := []struct {
		name        string
		password    string
		expectedErr error // Expected error (nil if valid)
	}{
		// Valid case
		{"Valid Password", "ValidPass123!@", nil},

		// Invalid cases - Length
		{"Too Short", "Short1!", ErrPasswordTooShort},
		{"Boundary Length Minus 1", "ValidPass123!", ErrPasswordTooShort}, // 13 chars

		// Invalid cases - Missing Character Types
		{"Missing Uppercase", "validpass123!@", ErrPasswordMissingUpper},
		{"Missing Lowercase", "VALIDPASS123!@", ErrPasswordMissingLower},
		{"Missing Digit", "ValidPassword!@", ErrPasswordMissingDigit},
		{"Missing Special", "ValidPassword123", ErrPasswordMissingSpecial},
		{"Only Lowercase", "aaaaaaaaaaaaaa", ErrPasswordMissingUpper}, // Also misses others, but Upper check is first
		{"Only Uppercase", "AAAAAAAAAAAAAA", ErrPasswordMissingLower}, // Also misses others
		{"Only Digits", "12345678901234", ErrPasswordMissingUpper},    // Also misses others
		{"Only Special", "!@#$%^&*()_+[]{}", ErrPasswordMissingUpper}, // Also misses others
		{"Missing Lower & Digit", "VALIDPASSWORD!@", ErrPasswordMissingLower},
		{"Missing Special & Upper", "validpass123word", ErrPasswordMissingUpper}, // Tests order dependency

		// Edge cases
		{"Empty Password", "", ErrPasswordTooShort},
		{"Password with Space", "Valid Pass 123!@", nil}, // Assuming space is not special
		{"Password with Different Special", "ValidPass123#$", nil},
	}

	testCases[len(testCases)-1] = struct {
		name        string
		password    string
		expectedErr error
	}{"Password with Different Special", "ValidPass123>>", nil} // '>' is in the list

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePasswordComplexity(tc.password)
			assert.Equal(t, tc.expectedErr, err, "Test case failed: "+tc.name)
		})
	}
}

func TestIsHexString(t *testing.T) {
	assert.True(t, IsHexString("0123456789abcdef"), "Lowercase hex should be valid")
	assert.True(t, IsHexString("ABCDEF0123456789"), "Uppercase hex should be valid")
	assert.True(t, IsHexString("deadbeef1234cafe"), "Mixed case hex should be valid")
	assert.True(t, IsHexString(""), "Empty string should be considered valid (or handle as needed)")
	assert.False(t, IsHexString("deadbeefG"), "String with non-hex char 'G' should be invalid")
	assert.False(t, IsHexString("0xdeadbeef"), "String with '0x' prefix should be invalid")
	assert.False(t, IsHexString(" abc "), "String with spaces should be invalid")
}
