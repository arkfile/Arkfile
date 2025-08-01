package crypto

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// PasswordValidationResult represents the result of password validation
type PasswordValidationResult struct {
	Entropy          float64  `json:"entropy"`
	StrengthScore    int      `json:"strength_score"`
	Feedback         []string `json:"feedback"`
	MeetsRequirement bool     `json:"meets_requirements"`
	PatternPenalties []string `json:"pattern_penalties,omitempty"`
}

// PatternPenalty represents a detected weak pattern and its entropy penalty
type PatternPenalty struct {
	Pattern     string  `json:"pattern"`
	Penalty     float64 `json:"penalty"`
	Description string  `json:"description"`
}

// ValidatePasswordEntropy performs comprehensive password entropy validation with pattern detection
func ValidatePasswordEntropy(password string, minEntropy float64) *PasswordValidationResult {
	if password == "" {
		return &PasswordValidationResult{
			Entropy:          0,
			StrengthScore:    0,
			Feedback:         []string{"Password cannot be empty"},
			MeetsRequirement: false,
		}
	}

	// Calculate base entropy from character set analysis
	baseEntropy := calculateBaseEntropy(password)

	// Detect weak patterns and calculate penalties
	penalties := detectWeakPatterns(password)
	totalPenalty := calculateTotalPenalty(penalties)

	// Apply penalties to base entropy
	finalEntropy := math.Max(0, baseEntropy-totalPenalty)

	// Generate feedback based on analysis
	feedback := generatePasswordFeedback(password, penalties, finalEntropy, minEntropy)

	// Calculate strength score (0-4 scale)
	strengthScore := calculateStrengthScore(finalEntropy, minEntropy)

	// Extract penalty descriptions for result
	penaltyDescriptions := make([]string, len(penalties))
	for i, p := range penalties {
		penaltyDescriptions[i] = p.Description
	}

	return &PasswordValidationResult{
		Entropy:          finalEntropy,
		StrengthScore:    strengthScore,
		Feedback:         feedback,
		MeetsRequirement: finalEntropy >= minEntropy,
		PatternPenalties: penaltyDescriptions,
	}
}

// calculateBaseEntropy calculates password entropy based on character set diversity
func calculateBaseEntropy(password string) float64 {
	if len(password) == 0 {
		return 0
	}

	// Analyze character sets used
	var charsetSize int
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

	for _, r := range password {
		if unicode.IsLower(r) {
			hasLower = true
		} else if unicode.IsUpper(r) {
			hasUpper = true
		} else if unicode.IsDigit(r) {
			hasDigit = true
		} else {
			hasSpecial = true
		}
	}

	// Calculate charset size
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
		charsetSize += 32 // Approximate number of common special characters
	}

	if charsetSize == 0 {
		return 0
	}

	// Calculate entropy: log2(charset^length)
	return float64(len(password)) * math.Log2(float64(charsetSize))
}

// detectWeakPatterns identifies common weak password patterns
func detectWeakPatterns(password string) []PatternPenalty {
	var penalties []PatternPenalty
	lower := strings.ToLower(password)

	// Pattern 1: Repeating characters (90% penalty)
	if penalty := detectRepeatingChars(password); penalty.Penalty > 0 {
		penalties = append(penalties, penalty)
	}

	// Pattern 2: Sequential patterns (70% penalty)
	if penalty := detectSequentialPatterns(lower); penalty.Penalty > 0 {
		penalties = append(penalties, penalty)
	}

	// Pattern 3: Dictionary words (70% penalty)
	if penalty := detectDictionaryWords(lower); penalty.Penalty > 0 {
		penalties = append(penalties, penalty)
	}

	// Pattern 4: Keyboard patterns (50% penalty)
	if penalty := detectKeyboardPatterns(lower); penalty.Penalty > 0 {
		penalties = append(penalties, penalty)
	}

	// Pattern 5: Common substitutions (30% penalty)
	if penalty := detectCommonSubstitutions(lower); penalty.Penalty > 0 {
		penalties = append(penalties, penalty)
	}

	return penalties
}

// detectRepeatingChars detects repeated character patterns
func detectRepeatingChars(password string) PatternPenalty {
	maxRepeat := 1
	currentRepeat := 1

	runes := []rune(password)
	for i := 1; i < len(runes); i++ {
		if runes[i] == runes[i-1] {
			currentRepeat++
			if currentRepeat > maxRepeat {
				maxRepeat = currentRepeat
			}
		} else {
			currentRepeat = 1
		}
	}

	if maxRepeat >= 3 {
		penalty := 0.9 // 90% penalty for significant repetition
		return PatternPenalty{
			Pattern:     "repeating_chars",
			Penalty:     penalty * calculateBaseEntropy(password),
			Description: "Contains repeated characters",
		}
	}

	return PatternPenalty{}
}

// detectSequentialPatterns detects sequential character patterns
func detectSequentialPatterns(password string) PatternPenalty {
	sequences := []string{
		"abc", "bcd", "cde", "def", "efg", "fgh", "ghi", "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu", "tuv", "uvw", "vwx", "wxy", "xyz",
		"123", "234", "345", "456", "567", "678", "789", "890",
		"qwe", "wer", "ert", "rty", "tyu", "yui", "uio", "iop", "asd", "sdf", "dfg", "fgh", "ghj", "hjk", "jkl", "zxc", "xcv", "cvb", "vbn", "bnm",
	}

	for _, seq := range sequences {
		if strings.Contains(password, seq) || strings.Contains(password, reverse(seq)) {
			penalty := 0.7 // 70% penalty for sequential patterns
			return PatternPenalty{
				Pattern:     "sequential",
				Penalty:     penalty * calculateBaseEntropy(password),
				Description: "Contains sequential patterns",
			}
		}
	}

	return PatternPenalty{}
}

// detectDictionaryWords detects common dictionary words
func detectDictionaryWords(password string) PatternPenalty {
	commonWords := []string{
		"password", "admin", "user", "login", "welcome", "hello", "world", "test", "demo", "sample",
		"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december",
		"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
		"love", "hate", "good", "bad", "nice", "cool", "awesome", "great", "best", "worst",
	}

	for _, word := range commonWords {
		if strings.Contains(password, word) {
			penalty := 0.7 // 70% penalty for dictionary words
			return PatternPenalty{
				Pattern:     "dictionary",
				Penalty:     penalty * calculateBaseEntropy(password),
				Description: "Contains common dictionary words",
			}
		}
	}

	return PatternPenalty{}
}

// detectKeyboardPatterns detects common keyboard patterns
func detectKeyboardPatterns(password string) PatternPenalty {
	patterns := []string{
		"qwerty", "asdf", "zxcv", "1234", "abcd",
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
	}

	for _, pattern := range patterns {
		if strings.Contains(password, pattern) || strings.Contains(password, reverse(pattern)) {
			penalty := 0.5 // 50% penalty for keyboard patterns
			return PatternPenalty{
				Pattern:     "keyboard",
				Penalty:     penalty * calculateBaseEntropy(password),
				Description: "Contains keyboard patterns",
			}
		}
	}

	return PatternPenalty{}
}

// detectCommonSubstitutions detects l33t speak substitutions
func detectCommonSubstitutions(password string) PatternPenalty {
	// Check for common substitutions that don't add real entropy
	substitutions := map[string]string{
		"@": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "4": "a",
	}

	hasSubstitutions := false
	for sub := range substitutions {
		if strings.Contains(password, sub) {
			hasSubstitutions = true
			break
		}
	}

	if hasSubstitutions {
		// Check if it's likely l33t speak (has both letters and number/symbol substitutions)
		hasLetters := regexp.MustCompile(`[a-zA-Z]`).MatchString(password)
		if hasLetters {
			penalty := 0.3 // 30% penalty for predictable substitutions
			return PatternPenalty{
				Pattern:     "substitution",
				Penalty:     penalty * calculateBaseEntropy(password),
				Description: "Contains predictable character substitutions",
			}
		}
	}

	return PatternPenalty{}
}

// calculateTotalPenalty sums up all pattern penalties
func calculateTotalPenalty(penalties []PatternPenalty) float64 {
	total := 0.0
	for _, p := range penalties {
		total += p.Penalty
	}
	return total
}

// generatePasswordFeedback creates user-friendly feedback
func generatePasswordFeedback(password string, penalties []PatternPenalty, entropy, minEntropy float64) []string {
	var feedback []string

	// Length feedback
	if len(password) < 14 {
		feedback = append(feedback, "Consider using 14+ characters for better security")
	}

	// Entropy feedback
	if entropy < minEntropy {
		feedback = append(feedback, "Password entropy is too low - add more varied characters")
	}

	// Character variety feedback
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password)

	if !hasLower || !hasUpper {
		feedback = append(feedback, "Mix uppercase and lowercase letters")
	}
	if !hasDigit {
		feedback = append(feedback, "Include numbers")
	}
	if !hasSpecial {
		feedback = append(feedback, "Include special characters")
	}

	// Pattern-specific feedback
	for _, penalty := range penalties {
		switch penalty.Pattern {
		case "repeating_chars":
			feedback = append(feedback, "Avoid repeated characters")
		case "sequential":
			feedback = append(feedback, "Avoid sequential patterns like 'abc' or '123'")
		case "dictionary":
			feedback = append(feedback, "Avoid common words")
		case "keyboard":
			feedback = append(feedback, "Avoid keyboard patterns like 'qwerty'")
		case "substitution":
			feedback = append(feedback, "Simple character substitutions don't add much security")
		}
	}

	// Positive feedback for strong passwords
	if entropy >= minEntropy && len(feedback) == 0 {
		feedback = append(feedback, "Strong password!")
	}

	return feedback
}

// calculateStrengthScore converts entropy to a 0-4 strength score
func calculateStrengthScore(entropy, minEntropy float64) int {
	if entropy < minEntropy*0.5 {
		return 0 // Very weak
	} else if entropy < minEntropy*0.75 {
		return 1 // Weak
	} else if entropy < minEntropy {
		return 2 // Fair
	} else if entropy < minEntropy*1.5 {
		return 3 // Good
	} else {
		return 4 // Excellent
	}
}

// reverse reverses a string
func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
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
