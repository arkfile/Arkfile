package utils

import (
	"errors"
	"strings"
	"unicode"
)

// IsHexString checks if a string contains only hexadecimal characters
func IsHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Password validation errors
var (
	ErrPasswordTooShort       = errors.New("password must be at least 14 characters long")
	ErrPasswordMissingUpper   = errors.New("password must contain at least one uppercase letter")
	ErrPasswordMissingLower   = errors.New("password must contain at least one lowercase letter")
	ErrPasswordMissingDigit   = errors.New("password must contain at least one digit")
	ErrPasswordMissingSpecial = errors.New("password must contain at least one special character: `~!@#$%^&*()-_=+[]{}|;:,.<>?")
)

// ValidatePasswordComplexity checks if a password meets complexity requirements.
// Requirements: 14+ chars, 1+ upper, 1+ lower, 1+ digit, 1+ special.
func ValidatePasswordComplexity(password string) error {
	if len(password) < 14 {
		return ErrPasswordTooShort
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	specialChars := "`~!@#$%^&*()-_=+[]{}|;:,.<>?" // set of special characters

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case strings.ContainsRune(specialChars, char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return ErrPasswordMissingUpper
	}
	if !hasLower {
		return ErrPasswordMissingLower
	}
	if !hasDigit {
		return ErrPasswordMissingDigit
	}
	if !hasSpecial {
		return ErrPasswordMissingSpecial
	}

	return nil // Password meets all criteria
}
