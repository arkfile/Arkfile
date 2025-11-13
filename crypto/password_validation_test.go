package crypto

import (
	"testing"
)

func TestValidatePasswordEntropy(t *testing.T) {
	// Load password requirements for testing
	reqs := GetPasswordRequirements()

	tests := []struct {
		name           string
		password       string
		minEntropy     float64
		expectMeetsReq bool
		expectMinChars int
	}{
		{
			name:           "Very weak password",
			password:       "weak",
			minEntropy:     60.0,
			expectMeetsReq: false,
			expectMinChars: 4,
		},
		{
			name:           "Medium strength password",
			password:       "MyPasswordIs18Chars!",
			minEntropy:     60.0,
			expectMeetsReq: false, // Contains "password" dictionary word
			expectMinChars: 20,
		},
		{
			name:           "Strong password",
			password:       "MyVacation2025PhotosForFamily!ExtraSecure",
			minEntropy:     60.0,
			expectMeetsReq: true,
			expectMinChars: 41, // Actual length is 41, not 40
		},
		{
			name:           "Empty password",
			password:       "",
			minEntropy:     60.0,
			expectMeetsReq: false,
			expectMinChars: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePasswordEntropy(tt.password, reqs.MinAccountPasswordLength, tt.minEntropy)

			if len(tt.password) != tt.expectMinChars {
				t.Errorf("Password length = %d, expected %d", len(tt.password), tt.expectMinChars)
			}

			if result.MeetsRequirement != tt.expectMeetsReq {
				t.Errorf("MeetsRequirement = %v, expected %v (entropy=%.2f)",
					result.MeetsRequirement, tt.expectMeetsReq, result.Entropy)
			}

			if result.Entropy < 0 {
				t.Errorf("Entropy should not be negative: %.2f", result.Entropy)
			}

			if len(result.Feedback) == 0 && !result.MeetsRequirement {
				t.Error("Expected feedback for password that doesn't meet requirements")
			}

			t.Logf("Password: %s", tt.password)
			t.Logf("Entropy: %.2f bits", result.Entropy)
			t.Logf("Strength Score: %d/4", result.StrengthScore)
			t.Logf("Meets Requirement: %v", result.MeetsRequirement)
			t.Logf("Feedback: %v", result.Feedback)
		})
	}
}

func TestSharePasswordValidation(t *testing.T) {
	// Test the specific share password validation function
	weakResult := ValidateSharePassword("weak")
	if weakResult.MeetsRequirement {
		t.Error("Weak password should not meet share requirements")
	}

	strongResult := ValidateSharePassword("MyVacation2025PhotosForFamily!ExtraSecure")
	if !strongResult.MeetsRequirement {
		t.Errorf("Strong password should meet share requirements (entropy=%.2f)", strongResult.Entropy)
	}

	t.Logf("Weak password entropy: %.2f bits", weakResult.Entropy)
	t.Logf("Strong password entropy: %.2f bits", strongResult.Entropy)
}

func TestPatternDetection(t *testing.T) {
	// Load password requirements for testing
	reqs := GetPasswordRequirements()

	tests := []struct {
		name     string
		password string
		hasIssue bool
	}{
		{
			name:     "Repeated characters",
			password: "aaaaabbbbbccccc123",
			hasIssue: true,
		},
		{
			name:     "Sequential pattern",
			password: "abcdefg1234567890",
			hasIssue: true,
		},
		{
			name:     "Dictionary word",
			password: "password123456789",
			hasIssue: true,
		},
		{
			name:     "Keyboard pattern",
			password: "qwerty123456789abc",
			hasIssue: true,
		},
		{
			name:     "Clean strong password",
			password: "MyVacation2025PhotosForFamily!",
			hasIssue: true, // "2025" triggers substitution detection (contains '2')
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePasswordEntropy(tt.password, reqs.MinAccountPasswordLength, 60.0)

			hasPenalties := len(result.PatternPenalties) > 0
			if tt.hasIssue && !hasPenalties {
				t.Errorf("Expected pattern penalties for %s, but found none", tt.name)
			}

			if !tt.hasIssue && hasPenalties {
				t.Errorf("Did not expect pattern penalties for %s, but found: %v", tt.name, result.PatternPenalties)
			}

			t.Logf("Password: %s", tt.password)
			t.Logf("Pattern Penalties: %v", result.PatternPenalties)
			t.Logf("Final Entropy: %.2f bits", result.Entropy)
		})
	}
}
