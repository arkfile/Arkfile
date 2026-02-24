package utils

import (
	"fmt"
	"regexp"
	"strings"
)

// Username validation constants
const (
	MinUsernameLength = 10
	MaxUsernameLength = 50
	UsernamePattern   = `^[a-zA-Z0-9_\-.,]{10,50}$`
)

var (
	usernameRegex = regexp.MustCompile(UsernamePattern)
)

// ValidateUsername validates that a username meets all requirements
func ValidateUsername(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}

	if len(username) < MinUsernameLength {
		return fmt.Errorf("username must be at least %d characters", MinUsernameLength)
	}

	if len(username) > MaxUsernameLength {
		return fmt.Errorf("username must be at most %d characters", MaxUsernameLength)
	}

	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, hyphens, periods, and commas")
	}

	// Additional checks for reasonable usernames
	if strings.HasPrefix(username, ".") || strings.HasSuffix(username, ".") {
		return fmt.Errorf("username cannot start or end with a period")
	}

	if strings.HasPrefix(username, ",") || strings.HasSuffix(username, ",") {
		return fmt.Errorf("username cannot start or end with a comma")
	}

	if strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
		return fmt.Errorf("username cannot start or end with a hyphen")
	}

	if strings.HasPrefix(username, "_") || strings.HasSuffix(username, "_") {
		return fmt.Errorf("username cannot start or end with an underscore")
	}

	// Check for consecutive special characters
	if strings.Contains(username, "..") || strings.Contains(username, ",,") ||
		strings.Contains(username, "__") || strings.Contains(username, "--") {
		return fmt.Errorf("username cannot contain consecutive special characters")
	}

	return nil
}

// IsValidUsername returns true if the username is valid, false otherwise
func IsValidUsername(username string) bool {
	return ValidateUsername(username) == nil
}

// SanitizeUsername performs basic sanitization on a username
// Note: This is for display purposes only, not for bypassing validation
func SanitizeUsername(username string) string {
	// Trim whitespace
	username = strings.TrimSpace(username)

	// Convert to lowercase for case-insensitive operations if needed
	// Note: We keep original case for the actual username storage
	return username
}

// GetUsernameValidationRules returns a human-readable description of username rules
func GetUsernameValidationRules() string {
	return fmt.Sprintf(`Username Requirements:
- Length: %d-%d characters
- Allowed characters: letters (a-z, A-Z), numbers (0-9), underscore (_), hyphen (-), period (.), comma (,)
- Cannot start or end with special characters (_, -, ., ,)
- Cannot contain consecutive special characters
- Case-sensitive (usernames are stored exactly as entered)
- Must be unique across the system

Valid examples:
- john.doe.2024
- user_name_123
- alice,bob,charlie
- my-project.v1

Invalid examples:
- short123 (too short)
- .username (starts with period)
- user..name (consecutive periods)
- user@domain (contains @)`, MinUsernameLength, MaxUsernameLength)
}
