package utils

import (
	"testing"
)

func TestValidateUsername(t *testing.T) {
	validUsernames := []string{
		"john.doe.2024",
		"user_name_123",
		"alice,bob,charlie",
		"my-project.v1,stable",
		"developer_2024.backup,main",
		"team.alpha-beta.test",
		"first.last,nickname",
		"org.dept.person",
		"a123456789", // exactly 10 characters
		"12345678901234567890123456789012345678901234567890", // exactly 50 characters
	}

	for _, username := range validUsernames {
		t.Run("valid_"+username, func(t *testing.T) {
			err := ValidateUsername(username)
			if err != nil {
				t.Errorf("Expected username '%s' to be valid, but got error: %v", username, err)
			}

			if !IsValidUsername(username) {
				t.Errorf("IsValidUsername should return true for '%s'", username)
			}
		})
	}
}

func TestValidateUsernameInvalid(t *testing.T) {
	invalidUsernames := []struct {
		username string
		reason   string
	}{
		{"", "empty username"},
		{"short123", "too short (< 10 chars)"},
		{"user@domain", "contains @ (not allowed)"},
		{"user name", "contains space"},
		{"user#tag", "contains # (not allowed)"},
		{"verylongusernamethatexceedsfiftycharacterslimitandisnotallowed", "too long (> 50 chars)"},
		{".username", "starts with period"},
		{"username.", "ends with period"},
		{",username", "starts with comma"},
		{"username,", "ends with comma"},
		{"-username", "starts with hyphen"},
		{"username-", "ends with hyphen"},
		{"_username", "starts with underscore"},
		{"username_", "ends with underscore"},
		{"user..name", "consecutive periods"},
		{"user,,name", "consecutive commas"},
		{"user__name", "consecutive underscores"},
		{"user--name", "consecutive hyphens"},
		{"user$.name", "contains $ (not allowed)"},
		{"user%name", "contains % (not allowed)"},
		{"user!name", "contains ! (not allowed)"},
		{"user*name", "contains * (not allowed)"},
		{"user+name", "contains + (not allowed)"},
		{"user=name", "contains = (not allowed)"},
		{"user?name", "contains ? (not allowed)"},
		{"user[name", "contains [ (not allowed)"},
		{"user]name", "contains ] (not allowed)"},
		{"user{name", "contains { (not allowed)"},
		{"user}name", "contains } (not allowed)"},
		{"user|name", "contains | (not allowed)"},
		{"user\\name", "contains \\ (not allowed)"},
		{"user/name", "contains / (not allowed)"},
		{"user:name", "contains : (not allowed)"},
		{"user;name", "contains ; (not allowed)"},
		{"user\"name", "contains \" (not allowed)"},
		{"user'name", "contains ' (not allowed)"},
		{"user<name", "contains < (not allowed)"},
		{"user>name", "contains > (not allowed)"},
		{"user name", "contains space (not allowed)"},
		{"user\tname", "contains tab (not allowed)"},
		{"user\nname", "contains newline (not allowed)"},
	}

	for _, test := range invalidUsernames {
		t.Run("invalid_"+test.username+"_"+test.reason, func(t *testing.T) {
			err := ValidateUsername(test.username)
			if err == nil {
				t.Errorf("Expected username '%s' to be invalid (%s), but validation passed", test.username, test.reason)
			}

			if IsValidUsername(test.username) {
				t.Errorf("IsValidUsername should return false for '%s' (%s)", test.username, test.reason)
			}
		})
	}
}

func TestSanitizeUsername(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"  username  ", "username"},
		{"\tusername\t", "username"},
		{"\nusername\n", "username"},
		{"username", "username"},
		{"", ""},
		{"  ", ""},
	}

	for _, test := range testCases {
		t.Run("sanitize_"+test.input, func(t *testing.T) {
			result := SanitizeUsername(test.input)
			if result != test.expected {
				t.Errorf("Expected SanitizeUsername('%s') to return '%s', got '%s'", test.input, test.expected, result)
			}
		})
	}
}

func TestGetUsernameValidationRules(t *testing.T) {
	rules := GetUsernameValidationRules()
	if rules == "" {
		t.Error("GetUsernameValidationRules should return non-empty string")
	}

	// Check that the rules contain key information
	requiredStrings := []string{
		"10-50 characters",
		"letters",
		"numbers",
		"underscore",
		"hyphen",
		"period",
		"comma",
		"john.doe.2024",
		"short123",
	}

	for _, required := range requiredStrings {
		if !containsString(rules, required) {
			t.Errorf("Expected validation rules to contain '%s', but it was not found", required)
		}
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsString(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle ||
			len(needle) > 0 &&
				(haystack[:len(needle)] == needle ||
					haystack[len(haystack)-len(needle):] == needle ||
					findSubstring(haystack, needle)))
}

func findSubstring(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestUsernameConstants(t *testing.T) {
	if MinUsernameLength != 10 {
		t.Errorf("Expected MinUsernameLength to be 10, got %d", MinUsernameLength)
	}

	if MaxUsernameLength != 50 {
		t.Errorf("Expected MaxUsernameLength to be 50, got %d", MaxUsernameLength)
	}

	expectedPattern := `^[a-zA-Z0-9_\-.,]{10,50}$`
	if UsernamePattern != expectedPattern {
		t.Errorf("Expected UsernamePattern to be '%s', got '%s'", expectedPattern, UsernamePattern)
	}
}

// Benchmark tests
func BenchmarkValidateUsername(b *testing.B) {
	username := "test.user.name.2024"
	for i := 0; i < b.N; i++ {
		ValidateUsername(username)
	}
}

func BenchmarkIsValidUsername(b *testing.B) {
	username := "test.user.name.2024"
	for i := 0; i < b.N; i++ {
		IsValidUsername(username)
	}
}
