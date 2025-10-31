package crypto

import (
	"fmt"
	"math"

	"github.com/trustelem/zxcvbn"
)

// PasswordValidationResult represents the result of password validation
type PasswordValidationResult struct {
	Entropy          float64           `json:"entropy"`
	StrengthScore    int               `json:"strength_score"`
	Feedback         []string          `json:"feedback"`
	MeetsRequirement bool              `json:"meets_requirements"`
	PatternPenalties []string          `json:"pattern_penalties,omitempty"`
	Requirements     RequirementChecks `json:"requirements"`
	Suggestions      []string          `json:"suggestions"`
}

// RequirementChecks tracks individual password requirements
type RequirementChecks struct {
	Length    RequirementStatus `json:"length"`
	Uppercase RequirementStatus `json:"uppercase"`
	Lowercase RequirementStatus `json:"lowercase"`
	Number    RequirementStatus `json:"number"`
	Special   RequirementStatus `json:"special"`
}

// RequirementStatus represents the status of a single requirement
type RequirementStatus struct {
	Met     bool   `json:"met"`
	Current int    `json:"current,omitempty"`
	Needed  int    `json:"needed,omitempty"`
	Message string `json:"message"`
}

// checkPasswordRequirements checks individual password requirements
func checkPasswordRequirements(password string, minLength int) RequirementChecks {
	length := len(password)
	hasUpper := false
	hasLower := false
	hasNumber := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case char >= '!' && char <= '/' || char >= ':' && char <= '@' || char >= '[' && char <= '`' || char >= '{' && char <= '~':
			hasSpecial = true
		}
	}

	checks := RequirementChecks{
		Length: RequirementStatus{
			Met:     length >= minLength,
			Current: length,
			Needed:  minLength,
		},
		Uppercase: RequirementStatus{
			Met: hasUpper,
		},
		Lowercase: RequirementStatus{
			Met: hasLower,
		},
		Number: RequirementStatus{
			Met: hasNumber,
		},
		Special: RequirementStatus{
			Met: hasSpecial,
		},
	}

	// Set messages
	if checks.Length.Met {
		checks.Length.Message = "Length requirement met (14+ characters)"
	} else {
		remaining := minLength - length
		checks.Length.Message = fmt.Sprintf("Add %d more characters (currently %d/%d)", remaining, length, minLength)
	}

	if checks.Uppercase.Met {
		checks.Uppercase.Message = "Uppercase letter present"
	} else {
		checks.Uppercase.Message = "Missing: uppercase letter (A-Z)"
	}

	if checks.Lowercase.Met {
		checks.Lowercase.Message = "Lowercase letter present"
	} else {
		checks.Lowercase.Message = "Missing: lowercase letter (a-z)"
	}

	if checks.Number.Met {
		checks.Number.Message = "Number present"
	} else {
		checks.Number.Message = "Missing: number (0-9)"
	}

	if checks.Special.Met {
		checks.Special.Message = "Special character present"
	} else {
		checks.Special.Message = "Missing: special character"
	}

	return checks
}

// ValidatePasswordEntropy performs comprehensive password entropy validation using zxcvbn
func ValidatePasswordEntropy(password string, minEntropy float64) *PasswordValidationResult {
	if password == "" {
		return &PasswordValidationResult{
			Entropy:          0,
			StrengthScore:    0,
			Feedback:         []string{"Password cannot be empty"},
			MeetsRequirement: false,
			Requirements:     checkPasswordRequirements(password, 14),
			Suggestions:      []string{"Enter a password (minimum 14 characters)"},
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

	// Check individual requirements
	requirements := checkPasswordRequirements(password, 14)

	// Build suggestions based on what's missing
	suggestions := make([]string, 0)
	if !requirements.Length.Met {
		suggestions = append(suggestions, requirements.Length.Message)
	}
	if !requirements.Uppercase.Met {
		suggestions = append(suggestions, requirements.Uppercase.Message)
	}
	if !requirements.Lowercase.Met {
		suggestions = append(suggestions, requirements.Lowercase.Message)
	}
	if !requirements.Number.Met {
		suggestions = append(suggestions, requirements.Number.Message)
	}
	if !requirements.Special.Met {
		suggestions = append(suggestions, requirements.Special.Message)
	}

	// Add pattern-based suggestions
	for _, penalty := range penalties {
		if penalty == "Contains common dictionary words" {
			suggestions = append(suggestions, "WARNING: Contains dictionary word - try something unique")
		} else if penalty == "Contains keyboard patterns" {
			suggestions = append(suggestions, "WARNING: Contains keyboard pattern - mix it up")
		} else if penalty == "Contains repeated characters" {
			suggestions = append(suggestions, "WARNING: Contains repeated sequence - add variety")
		} else if penalty == "Contains sequential patterns" {
			suggestions = append(suggestions, "WARNING: Contains sequential pattern - add variety")
		}
	}

	// If all requirements met, provide positive message
	if len(suggestions) == 0 && entropyBits >= minEntropy {
		suggestions = append(suggestions, "Strong password! All requirements met")
	}

	return &PasswordValidationResult{
		Entropy:          entropyBits,
		StrengthScore:    result.Score, // zxcvbn already provides 0-4 scale
		Feedback:         feedback,
		MeetsRequirement: entropyBits >= minEntropy,
		PatternPenalties: penalties,
		Requirements:     requirements,
		Suggestions:      suggestions,
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
