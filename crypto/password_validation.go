package crypto

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

//go:embed password-requirements.json
var embeddedPasswordRequirements []byte

// PasswordRequirements holds password validation configuration
type PasswordRequirements struct {
	MinAccountPasswordLength    int    `json:"minAccountPasswordLength"`
	MinCustomPasswordLength     int    `json:"minCustomPasswordLength"`
	MinSharePasswordLength      int    `json:"minSharePasswordLength"`
	MaxPasswordLength           int    `json:"maxPasswordLength"`
	MinCharacterClassesRequired int    `json:"minCharacterClassesRequired"`
	SpecialCharacters           string `json:"specialCharacters"`
}

var (
	passwordRequirements     *PasswordRequirements
	passwordRequirementsOnce sync.Once
	passwordRequirementsErr  error
)

// LoadPasswordRequirements loads password requirements from embedded config
// The JSON is embedded at build time from crypto/password-requirements.json.
func LoadPasswordRequirements() (*PasswordRequirements, error) {
	passwordRequirementsOnce.Do(func() {
		passwordRequirements = &PasswordRequirements{}
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
	MeetsRequirement bool              `json:"meets_requirements"`
	Requirements     RequirementChecks `json:"requirements"`
	Reasons          []string          `json:"reasons,omitempty"`
}

// RequirementChecks tracks individual password requirements
type RequirementChecks struct {
	Length          RequirementStatus `json:"length"`
	Uppercase       RequirementStatus `json:"uppercase"`
	Lowercase       RequirementStatus `json:"lowercase"`
	Number          RequirementStatus `json:"number"`
	Special         RequirementStatus `json:"special"`
	ClassCount      int               `json:"class_count"`
	ClassesRequired int               `json:"classes_required"`
}

// RequirementStatus represents the status of a single requirement
type RequirementStatus struct {
	Met     bool   `json:"met"`
	Current int    `json:"current,omitempty"`
	Needed  int    `json:"needed,omitempty"`
	Message string `json:"message"`
}

// ValidatePassword performs deterministic password validation.
// Pass = (length >= minLength) AND (length <= maxLength) AND (character classes met >= minCharacterClassesRequired)
// maxLength of 0 means no maximum is enforced.
func ValidatePassword(password string, minLength int, maxLength int, minClasses int, specialChars string) *PasswordValidationResult {
	length := len(password)

	// Check max length first (fail fast on absurdly long inputs)
	if maxLength > 0 && length > maxLength {
		return &PasswordValidationResult{
			MeetsRequirement: false,
			Requirements: RequirementChecks{
				Length: RequirementStatus{
					Met:     false,
					Current: length,
					Needed:  minLength,
					Message: fmt.Sprintf("Password too long (maximum %d characters)", maxLength),
				},
				Uppercase:       RequirementStatus{Met: false, Message: ""},
				Lowercase:       RequirementStatus{Met: false, Message: ""},
				Number:          RequirementStatus{Met: false, Message: ""},
				Special:         RequirementStatus{Met: false, Message: ""},
				ClassCount:      0,
				ClassesRequired: minClasses,
			},
			Reasons: []string{fmt.Sprintf("Password too long: %d characters (maximum %d)", length, maxLength)},
		}
	}

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
		default:
			if strings.ContainsRune(specialChars, char) {
				hasSpecial = true
			}
		}
	}

	classCount := 0
	if hasUpper {
		classCount++
	}
	if hasLower {
		classCount++
	}
	if hasNumber {
		classCount++
	}
	if hasSpecial {
		classCount++
	}

	lengthOK := length >= minLength
	classesOK := classCount >= minClasses
	meetsRequirement := lengthOK && classesOK

	// Build requirement checks
	checks := RequirementChecks{
		Length: RequirementStatus{
			Met:     lengthOK,
			Current: length,
			Needed:  minLength,
		},
		Uppercase:       RequirementStatus{Met: hasUpper},
		Lowercase:       RequirementStatus{Met: hasLower},
		Number:          RequirementStatus{Met: hasNumber},
		Special:         RequirementStatus{Met: hasSpecial},
		ClassCount:      classCount,
		ClassesRequired: minClasses,
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

	// Build reasons for failure
	var reasons []string
	if !lengthOK {
		reasons = append(reasons, checks.Length.Message)
	}
	if !classesOK {
		// List which classes are missing
		var missing []string
		if !hasUpper {
			missing = append(missing, "uppercase (A-Z)")
		}
		if !hasLower {
			missing = append(missing, "lowercase (a-z)")
		}
		if !hasNumber {
			missing = append(missing, "number (0-9)")
		}
		if !hasSpecial {
			missing = append(missing, "special character")
		}
		reasons = append(reasons, fmt.Sprintf("Need %d character classes, have %d", minClasses, classCount))
		if len(missing) > 0 {
			reasons = append(reasons, fmt.Sprintf("Missing: %s", strings.Join(missing, ", ")))
		}
	}

	return &PasswordValidationResult{
		MeetsRequirement: meetsRequirement,
		Requirements:     checks,
		Reasons:          reasons,
	}
}

// ValidateAccountPassword validates account passwords using config requirements
func ValidateAccountPassword(password string) *PasswordValidationResult {
	reqs := GetPasswordRequirements()
	return ValidatePassword(password, reqs.MinAccountPasswordLength, reqs.MaxPasswordLength, reqs.MinCharacterClassesRequired, reqs.SpecialCharacters)
}

// ValidateSharePassword validates share passwords using config requirements
func ValidateSharePassword(password string) *PasswordValidationResult {
	reqs := GetPasswordRequirements()
	return ValidatePassword(password, reqs.MinSharePasswordLength, reqs.MaxPasswordLength, reqs.MinCharacterClassesRequired, reqs.SpecialCharacters)
}

// ValidateCustomPassword validates custom passwords using config requirements
func ValidateCustomPassword(password string) *PasswordValidationResult {
	reqs := GetPasswordRequirements()
	return ValidatePassword(password, reqs.MinCustomPasswordLength, reqs.MaxPasswordLength, reqs.MinCharacterClassesRequired, reqs.SpecialCharacters)
}
