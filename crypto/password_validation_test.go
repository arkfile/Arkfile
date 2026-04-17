package crypto

import (
	"encoding/json"
	"strings"
	"testing"
)

// Helper: build a password of exactly the given length using mixed character classes.
// Uses a repeating pattern of lowercase, uppercase, digit, special to ensure
// multiple character classes are present.
func buildPassword(length int, specialChars string) string {
	if length <= 0 {
		return ""
	}
	// Pick one special char from the config
	special := byte('!')
	if len(specialChars) > 0 {
		special = specialChars[0]
	}
	pattern := []byte{'a', 'A', '1', special}
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = pattern[i%len(pattern)]
	}
	return string(buf)
}

// Helper: build a password of given length with only lowercase letters (1 character class)
func buildSingleClassPassword(length int) string {
	return strings.Repeat("a", length)
}

// -- Config loading tests --

// TestGetPasswordRequirements_ReturnsValidConfig verifies embedded config loads and has sensible values
func TestGetPasswordRequirements_ReturnsValidConfig(t *testing.T) {
	reqs := GetPasswordRequirements()
	if reqs == nil {
		t.Fatal("GetPasswordRequirements returned nil")
	}

	if reqs.MinAccountPasswordLength <= 0 {
		t.Errorf("MinAccountPasswordLength should be positive, got %d", reqs.MinAccountPasswordLength)
	}
	if reqs.MinCustomPasswordLength <= 0 {
		t.Errorf("MinCustomPasswordLength should be positive, got %d", reqs.MinCustomPasswordLength)
	}
	if reqs.MinSharePasswordLength <= 0 {
		t.Errorf("MinSharePasswordLength should be positive, got %d", reqs.MinSharePasswordLength)
	}
	if reqs.MaxPasswordLength <= 0 {
		t.Errorf("MaxPasswordLength should be positive, got %d", reqs.MaxPasswordLength)
	}
	if reqs.MinCharacterClassesRequired <= 0 {
		t.Errorf("MinCharacterClassesRequired should be positive, got %d", reqs.MinCharacterClassesRequired)
	}
	if reqs.SpecialCharacters == "" {
		t.Error("SpecialCharacters should not be empty")
	}

	// Share passwords should require at least as many characters as account passwords
	if reqs.MinSharePasswordLength < reqs.MinAccountPasswordLength {
		t.Errorf("MinSharePasswordLength (%d) should be >= MinAccountPasswordLength (%d)",
			reqs.MinSharePasswordLength, reqs.MinAccountPasswordLength)
	}
}

// TestGetEmbeddedPasswordRequirementsJSON verifies raw JSON is valid and parseable
func TestGetEmbeddedPasswordRequirementsJSON(t *testing.T) {
	raw := GetEmbeddedPasswordRequirementsJSON()
	if len(raw) == 0 {
		t.Fatal("embedded password requirements JSON should not be empty")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("embedded password requirements is not valid JSON: %v", err)
	}

	requiredFields := []string{
		"minAccountPasswordLength",
		"minCustomPasswordLength",
		"minSharePasswordLength",
		"maxPasswordLength",
		"minCharacterClassesRequired",
		"specialCharacters",
	}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("missing required field in password requirements JSON: %s", field)
		}
	}
}

// -- ValidateAccountPassword tests --

// TestValidateAccountPassword_StrongPassword verifies a password that meets all requirements passes
func TestValidateAccountPassword_StrongPassword(t *testing.T) {
	reqs := GetPasswordRequirements()
	// Build a password that exceeds the minimum length and has multiple character classes
	password := buildPassword(reqs.MinAccountPasswordLength+5, reqs.SpecialCharacters)

	result := ValidateAccountPassword(password)
	if !result.MeetsRequirement {
		t.Errorf("password of length %d with mixed classes should meet account requirements, reasons: %v",
			len(password), result.Reasons)
	}
}

// TestValidateAccountPassword_TooShort verifies short passwords are rejected
func TestValidateAccountPassword_TooShort(t *testing.T) {
	reqs := GetPasswordRequirements()
	// Password one character shorter than minimum, but with good character classes
	password := buildPassword(reqs.MinAccountPasswordLength-1, reqs.SpecialCharacters)

	result := ValidateAccountPassword(password)
	if result.MeetsRequirement {
		t.Errorf("password of length %d should not meet account min length %d",
			len(password), reqs.MinAccountPasswordLength)
	}
	if result.Requirements.Length.Met {
		t.Error("length requirement should not be met")
	}
}

// TestValidateAccountPassword_ExactMinLength verifies boundary: exactly minimum length passes
func TestValidateAccountPassword_ExactMinLength(t *testing.T) {
	reqs := GetPasswordRequirements()
	password := buildPassword(reqs.MinAccountPasswordLength, reqs.SpecialCharacters)

	result := ValidateAccountPassword(password)
	if !result.MeetsRequirement {
		t.Errorf("password of exactly min length %d should pass, reasons: %v",
			reqs.MinAccountPasswordLength, result.Reasons)
	}
}

// TestValidateAccountPassword_TooFewClasses verifies insufficient character classes are rejected
func TestValidateAccountPassword_TooFewClasses(t *testing.T) {
	reqs := GetPasswordRequirements()
	if reqs.MinCharacterClassesRequired < 2 {
		t.Skip("test requires MinCharacterClassesRequired >= 2")
	}

	// Build a long password with only one character class (lowercase)
	password := buildSingleClassPassword(reqs.MinAccountPasswordLength + 10)

	result := ValidateAccountPassword(password)
	if result.MeetsRequirement {
		t.Errorf("password with only 1 character class should not meet requirement of %d classes",
			reqs.MinCharacterClassesRequired)
	}
	if result.Requirements.ClassCount >= reqs.MinCharacterClassesRequired {
		t.Errorf("class count %d should be less than required %d",
			result.Requirements.ClassCount, reqs.MinCharacterClassesRequired)
	}
}

// TestValidateAccountPassword_Empty verifies empty password is rejected
func TestValidateAccountPassword_Empty(t *testing.T) {
	result := ValidateAccountPassword("")
	if result.MeetsRequirement {
		t.Error("empty password should not meet requirements")
	}
}

// -- ValidateSharePassword tests --

// TestValidateSharePassword_StrongPassword verifies a strong share password passes
func TestValidateSharePassword_StrongPassword(t *testing.T) {
	reqs := GetPasswordRequirements()
	password := buildPassword(reqs.MinSharePasswordLength+5, reqs.SpecialCharacters)

	result := ValidateSharePassword(password)
	if !result.MeetsRequirement {
		t.Errorf("password of length %d should meet share requirements (min %d), reasons: %v",
			len(password), reqs.MinSharePasswordLength, result.Reasons)
	}
}

// TestValidateSharePassword_TooShort verifies share passwords below minimum are rejected
func TestValidateSharePassword_TooShort(t *testing.T) {
	reqs := GetPasswordRequirements()
	// Meets account length but not share length (share min > account min)
	if reqs.MinSharePasswordLength <= reqs.MinAccountPasswordLength {
		t.Skip("test requires MinSharePasswordLength > MinAccountPasswordLength")
	}
	password := buildPassword(reqs.MinSharePasswordLength-1, reqs.SpecialCharacters)

	result := ValidateSharePassword(password)
	if result.MeetsRequirement {
		t.Errorf("password of length %d should not meet share min length %d",
			len(password), reqs.MinSharePasswordLength)
	}
}

// TestValidateSharePassword_WeakPassword verifies clearly weak password fails
func TestValidateSharePassword_WeakPassword(t *testing.T) {
	result := ValidateSharePassword("weak")
	if result.MeetsRequirement {
		t.Error("'weak' should not meet share password requirements")
	}
}

// -- ValidateCustomPassword tests --

// TestValidateCustomPassword_StrongPassword verifies a strong custom password passes
func TestValidateCustomPassword_StrongPassword(t *testing.T) {
	reqs := GetPasswordRequirements()
	password := buildPassword(reqs.MinCustomPasswordLength+5, reqs.SpecialCharacters)

	result := ValidateCustomPassword(password)
	if !result.MeetsRequirement {
		t.Errorf("password of length %d should meet custom requirements (min %d), reasons: %v",
			len(password), reqs.MinCustomPasswordLength, result.Reasons)
	}
}

// TestValidateCustomPassword_TooShort verifies short custom passwords are rejected
func TestValidateCustomPassword_TooShort(t *testing.T) {
	reqs := GetPasswordRequirements()
	password := buildPassword(reqs.MinCustomPasswordLength-1, reqs.SpecialCharacters)

	result := ValidateCustomPassword(password)
	if result.MeetsRequirement {
		t.Errorf("password of length %d should not meet custom min length %d",
			len(password), reqs.MinCustomPasswordLength)
	}
}

// -- Core ValidatePassword function tests --

// TestValidatePassword_MaxLengthEnforcement verifies max length is enforced
func TestValidatePassword_MaxLengthEnforcement(t *testing.T) {
	reqs := GetPasswordRequirements()
	if reqs.MaxPasswordLength <= 0 {
		t.Skip("no max length configured")
	}

	// Build a password exceeding max length
	tooLong := buildPassword(reqs.MaxPasswordLength+1, reqs.SpecialCharacters)

	result := ValidatePassword(tooLong, 1, reqs.MaxPasswordLength, 1, reqs.SpecialCharacters)
	if result.MeetsRequirement {
		t.Errorf("password of length %d should fail max length check (%d)",
			len(tooLong), reqs.MaxPasswordLength)
	}
}

// TestValidatePassword_ExactMaxLength verifies boundary: exactly max length passes (if classes met)
func TestValidatePassword_ExactMaxLength(t *testing.T) {
	reqs := GetPasswordRequirements()
	if reqs.MaxPasswordLength <= 0 {
		t.Skip("no max length configured")
	}

	exactMax := buildPassword(reqs.MaxPasswordLength, reqs.SpecialCharacters)

	result := ValidatePassword(exactMax, 1, reqs.MaxPasswordLength, reqs.MinCharacterClassesRequired, reqs.SpecialCharacters)
	if !result.MeetsRequirement {
		t.Errorf("password of exactly max length %d should pass, reasons: %v",
			reqs.MaxPasswordLength, result.Reasons)
	}
}

// TestValidatePassword_CharacterClassCounting verifies each class is detected
func TestValidatePassword_CharacterClassCounting(t *testing.T) {
	reqs := GetPasswordRequirements()
	special := string(reqs.SpecialCharacters[0])

	tests := []struct {
		name          string
		password      string
		expectClasses int
		expectUpper   bool
		expectLower   bool
		expectNumber  bool
		expectSpecial bool
	}{
		{"lowercase only", "aaaaaaaaaaaaaaaa", 1, false, true, false, false},
		{"uppercase only", "AAAAAAAAAAAAAAAA", 1, true, false, false, false},
		{"numbers only", "1234567890123456", 1, false, false, true, false},
		{"lower + upper", "aaaaaaaaAAAAAAAA", 2, true, true, false, false},
		{"lower + number", "aaaaaaaa12345678", 2, false, true, true, false},
		{"lower + upper + number", "aaaaAAAA12345678", 3, true, true, true, false},
		{"all four classes", "aAA1" + special + "aaaaaaaaaaa", 4, true, true, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use minLength=1 so length doesn't interfere
			result := ValidatePassword(tt.password, 1, 0, 1, reqs.SpecialCharacters)

			if result.Requirements.ClassCount != tt.expectClasses {
				t.Errorf("expected %d classes, got %d", tt.expectClasses, result.Requirements.ClassCount)
			}
			if result.Requirements.Uppercase.Met != tt.expectUpper {
				t.Errorf("uppercase: expected %v, got %v", tt.expectUpper, result.Requirements.Uppercase.Met)
			}
			if result.Requirements.Lowercase.Met != tt.expectLower {
				t.Errorf("lowercase: expected %v, got %v", tt.expectLower, result.Requirements.Lowercase.Met)
			}
			if result.Requirements.Number.Met != tt.expectNumber {
				t.Errorf("number: expected %v, got %v", tt.expectNumber, result.Requirements.Number.Met)
			}
			if result.Requirements.Special.Met != tt.expectSpecial {
				t.Errorf("special: expected %v, got %v", tt.expectSpecial, result.Requirements.Special.Met)
			}
		})
	}
}

// TestValidatePassword_ReasonsPopulated verifies failure reasons are provided
func TestValidatePassword_ReasonsPopulated(t *testing.T) {
	reqs := GetPasswordRequirements()

	// Short + only 1 class = both length and class failure
	result := ValidatePassword("aa", reqs.MinAccountPasswordLength, reqs.MaxPasswordLength, reqs.MinCharacterClassesRequired, reqs.SpecialCharacters)
	if result.MeetsRequirement {
		t.Error("should not meet requirements")
	}
	if len(result.Reasons) == 0 {
		t.Error("failure reasons should not be empty when requirements are not met")
	}
}

// TestValidatePassword_ZeroMaxLengthMeansNoMax verifies maxLength=0 disables max check
func TestValidatePassword_ZeroMaxLengthMeansNoMax(t *testing.T) {
	reqs := GetPasswordRequirements()
	// Very long password with good classes, maxLength=0
	veryLong := buildPassword(1000, reqs.SpecialCharacters)

	result := ValidatePassword(veryLong, 1, 0, reqs.MinCharacterClassesRequired, reqs.SpecialCharacters)
	if !result.MeetsRequirement {
		t.Errorf("maxLength=0 should mean no max, but password of length %d was rejected: %v",
			len(veryLong), result.Reasons)
	}
}

// TestValidatePassword_RequirementStatusMessages verifies status messages are populated
func TestValidatePassword_RequirementStatusMessages(t *testing.T) {
	reqs := GetPasswordRequirements()

	// Passing case
	good := buildPassword(reqs.MinAccountPasswordLength+5, reqs.SpecialCharacters)
	result := ValidateAccountPassword(good)

	if result.Requirements.Length.Message == "" {
		t.Error("length status message should not be empty")
	}
	if result.Requirements.Uppercase.Message == "" {
		t.Error("uppercase status message should not be empty")
	}
	if result.Requirements.Lowercase.Message == "" {
		t.Error("lowercase status message should not be empty")
	}
	if result.Requirements.Number.Message == "" {
		t.Error("number status message should not be empty")
	}
	if result.Requirements.Special.Message == "" {
		t.Error("special status message should not be empty")
	}
}
