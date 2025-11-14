package crypto

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"sync"

	"github.com/trustelem/zxcvbn"
)

//go:embed password-requirements.json
var embeddedPasswordRequirements []byte

// PasswordRequirements holds password validation configuration
type PasswordRequirements struct {
	MinAccountPasswordLength int     `json:"minAccountPasswordLength"`
	MinCustomPasswordLength  int     `json:"minCustomPasswordLength"`
	MinSharePasswordLength   int     `json:"minSharePasswordLength"`
	MinEntropyBits           float64 `json:"minEntropyBits"`
	RequireUppercase         bool    `json:"requireUppercase"`
	RequireLowercase         bool    `json:"requireLowercase"`
	RequireNumber            bool    `json:"requireNumber"`
	RequireSpecial           bool    `json:"requireSpecial"`
}

var (
	passwordRequirements     *PasswordRequirements
	passwordRequirementsOnce sync.Once
	passwordRequirementsErr  error
)

// LoadPasswordRequirements loads password requirements from embedded config
func LoadPasswordRequirements() (*PasswordRequirements, error) {
	passwordRequirementsOnce.Do(func() {
		// Default values (fallback)
		passwordRequirements = &PasswordRequirements{
			MinAccountPasswordLength: 14,
			MinCustomPasswordLength:  14,
			MinSharePasswordLength:   18,
			MinEntropyBits:           60.0,
			RequireUppercase:         true,
			RequireLowercase:         true,
			RequireNumber:            true,
			RequireSpecial:           true,
		}

		// Parse embedded JSON
		if err := json.Unmarshal(embeddedPasswordRequirements, passwordRequirements); err != nil {
			passwordRequirementsErr = fmt.Errorf("failed to parse embedded password requirements: %w", err)
			return
		}
	})

	return passwordRequirements, passwordRequirementsErr
}

// GetPasswordRequirements returns the loaded password requirements (panics if not loaded)
func GetPasswordRequirements() *PasswordRequirements {
	reqs, err := LoadPasswordRequirements()
	if err != nil {
		panic(fmt.Sprintf("Failed to load password requirements: %v", err))
	}
	return reqs
}

// GetEmbeddedPasswordRequirementsJSON returns the raw embedded JSON for API serving
func GetEmbeddedPasswordRequirementsJSON() []byte {
	return embeddedPasswordRequirements
}

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
		checks.Length.Message = fmt.Sprintf("Length requirement met (%d+ characters)", minLength)
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
func ValidatePasswordEntropy(password string, minLength int, minEntropy float64) *PasswordValidationResult {
	if password == "" {
		return &PasswordValidationResult{
			Entropy:          0,
			StrengthScore:    0,
			Feedback:         []string{"Password cannot be empty"},
			MeetsRequirement: false,
			Requirements:     checkPasswordRequirements(password, minLength),
			Suggestions:      []string{fmt.Sprintf("Enter a password (minimum %d characters)", minLength)},
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
	if len(password) < minLength {
		feedback = append(feedback, fmt.Sprintf("Consider using %d+ characters for better security", minLength))
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
	requirements := checkPasswordRequirements(password, minLength)

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

// ValidateAccountPassword validates account passwords using config requirements
func ValidateAccountPassword(password string) *PasswordValidationResult {
	reqs := GetPasswordRequirements()
	return ValidatePasswordEntropy(password, reqs.MinAccountPasswordLength, reqs.MinEntropyBits)
}

// ValidateSharePassword validates share passwords using config requirements
func ValidateSharePassword(password string) *PasswordValidationResult {
	reqs := GetPasswordRequirements()
	return ValidatePasswordEntropy(password, reqs.MinSharePasswordLength, reqs.MinEntropyBits)
}

// ValidateCustomPassword validates custom passwords using config requirements
func ValidateCustomPassword(password string) *PasswordValidationResult {
	reqs := GetPasswordRequirements()
	return ValidatePasswordEntropy(password, reqs.MinCustomPasswordLength, reqs.MinEntropyBits)
}
