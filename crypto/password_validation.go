package crypto

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
)

// PasswordValidationResult contains validation results
type PasswordValidationResult struct {
	Valid       bool     `json:"valid"`
	Entropy     float64  `json:"entropy"`
	Message     string   `json:"message,omitempty"`
	Suggestions []string `json:"suggestions,omitempty"`
	Score       int      `json:"score"` // 0-4 strength score
}

// ValidatePasswordEntropy calculates true entropy with pattern detection
func ValidatePasswordEntropy(password string, passwordType string) PasswordValidationResult {
	// Base requirements
	minLength := 14
	if passwordType == "share" {
		minLength = 18
	}

	if len(password) < minLength {
		return PasswordValidationResult{
			Valid:   false,
			Message: fmt.Sprintf("Password must be at least %d characters", minLength),
			Score:   0,
		}
	}

	// Calculate true entropy with pattern detection
	entropy := calculateTrueEntropy(password)
	score := calculateStrengthScore(entropy)

	if entropy < 60.0 {
		return PasswordValidationResult{
			Valid:       false,
			Entropy:     entropy,
			Message:     fmt.Sprintf("Password entropy too low (%.1f bits). Need 60+ bits.", entropy),
			Suggestions: generateSuggestions(password, entropy),
			Score:       score,
		}
	}

	return PasswordValidationResult{
		Valid:   true,
		Entropy: entropy,
		Message: fmt.Sprintf("Strong password (%.1f bits entropy)", entropy),
		Score:   score,
	}
}

// calculateTrueEntropy computes entropy with pattern penalties
func calculateTrueEntropy(password string) float64 {
	baseEntropy := calculateCharsetEntropy(password)
	penalty := 1.0

	// Apply pattern detection penalties
	if hasRepeatingChars(password, 3) {
		penalty *= 0.1 // 90% penalty for extreme repetition (e.g., "aaa")
	}

	if hasSequentialChars(password) {
		penalty *= 0.3 // 70% penalty for sequences (e.g., "abc", "123")
	}

	if hasCommonPatterns(password) {
		penalty *= 0.3 // 70% penalty for common patterns
	}

	if hasDictionaryWords(password) {
		penalty *= 0.3 // 70% penalty for dictionary words
	}

	if hasKeyboardPatterns(password) {
		penalty *= 0.5 // 50% penalty for keyboard patterns (e.g., "qwerty")
	}

	return baseEntropy * penalty
}

// calculateCharsetEntropy calculates base entropy from character set analysis
func calculateCharsetEntropy(password string) float64 {
	charsetSize := 0

	// Determine character set size based on actual characters used
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		if unicode.IsLower(char) {
			hasLower = true
		} else if unicode.IsUpper(char) {
			hasUpper = true
		} else if unicode.IsDigit(char) {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}

	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigit {
		charsetSize += 10
	}
	if hasSpecial {
		charsetSize += 32 // Estimate for common special characters
	}

	if charsetSize == 0 {
		return 0
	}

	// Base entropy: log2(charset^length)
	return float64(len(password)) * math.Log2(float64(charsetSize))
}

// hasRepeatingChars detects repeated character sequences
func hasRepeatingChars(password string, minRepeats int) bool {
	if len(password) < minRepeats {
		return false
	}

	for i := 0; i <= len(password)-minRepeats; i++ {
		char := password[i]
		count := 1

		for j := i + 1; j < len(password) && password[j] == char; j++ {
			count++
		}

		if count >= minRepeats {
			return true
		}
	}

	return false
}

// hasSequentialChars detects sequential character patterns
func hasSequentialChars(password string) bool {
	sequences := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"9876543210",
		"zyxwvutsrqponmlkjihgfedcba",
		"ZYXWVUTSRQPONMLKJIHGFEDCBA",
	}

	lowerPassword := strings.ToLower(password)

	for _, seq := range sequences {
		for i := 0; i <= len(seq)-3; i++ {
			if strings.Contains(lowerPassword, seq[i:i+3]) {
				return true
			}
		}
	}

	return false
}

// hasCommonPatterns detects common password patterns
func hasCommonPatterns(password string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)password`),
		regexp.MustCompile(`(?i)admin`),
		regexp.MustCompile(`(?i)login`),
		regexp.MustCompile(`(?i)user`),
		regexp.MustCompile(`\d{4}`),                                                 // 4 consecutive digits (years, etc.)
		regexp.MustCompile(`(?i)(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)`), // Months
		regexp.MustCompile(`(?i)(monday|tuesday|wednesday|thursday|friday|saturday|sunday|mon|tue|wed|thu|fri|sat|sun)`), // Days
	}

	for _, pattern := range patterns {
		if pattern.MatchString(password) {
			return true
		}
	}

	return false
}

// hasDictionaryWords detects common dictionary words
func hasDictionaryWords(password string) bool {
	// Common weak passwords and dictionary words
	commonWords := []string{
		"password", "admin", "user", "login", "welcome", "hello", "world",
		"test", "demo", "sample", "example", "default", "guest", "public",
		"private", "secret", "key", "pass", "word", "code", "access",
		"security", "system", "computer", "internet", "email", "website",
		"server", "database", "network", "wireless", "router", "modem",
		"love", "family", "friend", "home", "work", "school", "office",
		"music", "movie", "book", "game", "sport", "food", "travel",
	}

	lowerPassword := strings.ToLower(password)

	for _, word := range commonWords {
		if strings.Contains(lowerPassword, word) {
			return true
		}
	}

	return false
}

// hasKeyboardPatterns detects keyboard layout patterns
func hasKeyboardPatterns(password string) bool {
	patterns := []string{
		"qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
		"123456", "1234567890", "098765", "0987654321",
		"!@#$%^", "!@#$%^&*()",
	}

	lowerPassword := strings.ToLower(password)

	for _, pattern := range patterns {
		if strings.Contains(lowerPassword, pattern) {
			return true
		}
	}

	return false
}

// calculateStrengthScore converts entropy to 0-4 strength score
func calculateStrengthScore(entropy float64) int {
	if entropy < 30 {
		return 0 // Very Weak
	} else if entropy < 50 {
		return 1 // Weak
	} else if entropy < 60 {
		return 2 // Fair
	} else if entropy < 80 {
		return 3 // Good
	} else {
		return 4 // Excellent
	}
}

// generateSuggestions provides improvement suggestions based on password analysis
func generateSuggestions(password string, entropy float64) []string {
	suggestions := []string{}

	if hasRepeatingChars(password, 3) {
		suggestions = append(suggestions, "Avoid repeating the same character multiple times")
	}

	if hasSequentialChars(password) {
		suggestions = append(suggestions, "Avoid sequential characters like 'abc' or '123'")
	}

	if hasCommonPatterns(password) {
		suggestions = append(suggestions, "Avoid common words and patterns")
	}

	if hasDictionaryWords(password) {
		suggestions = append(suggestions, "Use less predictable words or combine multiple unrelated words")
	}

	if hasKeyboardPatterns(password) {
		suggestions = append(suggestions, "Avoid keyboard patterns like 'qwerty' or '123456'")
	}

	if entropy < 60 {
		suggestions = append(suggestions, "Consider using a longer password or more character variety")
		suggestions = append(suggestions, "Mix uppercase, lowercase, numbers, and special characters")
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Consider adding more length or character variety for even better security")
	}

	return suggestions
}

// GetStrengthLevel returns human-readable strength level
func GetStrengthLevel(entropy float64) string {
	score := calculateStrengthScore(entropy)
	levels := []string{"Very Weak", "Weak", "Fair", "Good", "Excellent"}
	return levels[score]
}
