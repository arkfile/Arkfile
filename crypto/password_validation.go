package crypto

import (
	"math"

	"github.com/trustelem/zxcvbn"
)

// PasswordValidationResult represents the result of password validation
type PasswordValidationResult struct {
	Entropy          float64  `json:"entropy"`
	StrengthScore    int      `json:"strength_score"`
	Feedback         []string `json:"feedback"`
	MeetsRequirement bool     `json:"meets_requirements"`
	PatternPenalties []string `json:"pattern_penalties,omitempty"`
}

// ValidatePasswordEntropy performs comprehensive password entropy validation using zxcvbn
func ValidatePasswordEntropy(password string, minEntropy float64) *PasswordValidationResult {
	if password == "" {
		return &PasswordValidationResult{
			Entropy:          0,
			StrengthScore:    0,
			Feedback:         []string{"Password cannot be empty"},
			MeetsRequirement: false,
		}
	}

	// Use zxcvbn for comprehensive password analysis
	result := zxcvbn.PasswordStrength(password, nil)

	// Convert zxcvbn guesses to entropy bits: log2(guesses)
	entropyBits := 0.0
	if result.Guesses > 0 {
		entropyBits = math.Log2(result.Guesses)
	}

	// Generate user-friendly feedback based on zxcvbn score and analysis
	feedback := make([]string, 0)

	// Add feedback based on zxcvbn score
	switch result.Score {
	case 0:
		feedback = append(feedback, "This is a very weak password")
	case 1:
		feedback = append(feedback, "This is a weak password")
	case 2:
		feedback = append(feedback, "This is a fair password")
	}

	// Add length recommendation if password is short
	if len(password) < 14 {
		feedback = append(feedback, "Consider using 14+ characters for better security")
	}

	// Add entropy feedback if below threshold
	if entropyBits < minEntropy {
		feedback = append(feedback, "Password entropy is too low - add more varied characters")
	}

	// Extract pattern penalties from zxcvbn sequence analysis
	penalties := make([]string, 0)
	for _, seq := range result.Sequence {
		if seq.Pattern == "dictionary" {
			penalties = append(penalties, "Contains common dictionary words")
		} else if seq.Pattern == "spatial" {
			penalties = append(penalties, "Contains keyboard patterns")
		} else if seq.Pattern == "repeat" {
			penalties = append(penalties, "Contains repeated characters")
		} else if seq.Pattern == "sequence" {
			penalties = append(penalties, "Contains sequential patterns")
		}
	}

	// Positive feedback for strong passwords
	if entropyBits >= minEntropy && len(feedback) == 0 {
		feedback = append(feedback, "Strong password!")
	}

	return &PasswordValidationResult{
		Entropy:          entropyBits,
		StrengthScore:    result.Score, // zxcvbn already provides 0-4 scale
		Feedback:         feedback,
		MeetsRequirement: entropyBits >= minEntropy,
		PatternPenalties: penalties,
	}
}

// ValidateAccountPassword validates account passwords with 60+ bit entropy requirement
func ValidateAccountPassword(password string) *PasswordValidationResult {
	return ValidatePasswordEntropy(password, 60.0)
}

// ValidateSharePassword validates share passwords with 60+ bit entropy requirement
func ValidateSharePassword(password string) *PasswordValidationResult {
	return ValidatePasswordEntropy(password, 60.0)
}

// ValidateCustomPassword validates custom passwords with 60+ bit entropy requirement
func ValidateCustomPassword(password string) *PasswordValidationResult {
	return ValidatePasswordEntropy(password, 60.0)
}
