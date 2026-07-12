package money

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// MicrocentsPerUSD is Arkfile's canonical integer money scale.
const MicrocentsPerUSD int64 = 100_000_000

// ParseUSDToMicrocents converts a decimal USD string to the canonical integer
// money unit. maxFractionalDigits controls accepted input precision; conversion
// never rounds or uses floating-point arithmetic.
func ParseUSDToMicrocents(value string, maxFractionalDigits int, allowNegative bool) (int64, error) {
	if maxFractionalDigits < 0 || maxFractionalDigits > 8 {
		return 0, errors.New("invalid USD precision")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("amount is empty")
	}

	negative := false
	switch value[0] {
	case '-':
		negative = true
		value = value[1:]
	case '+':
		value = value[1:]
	}
	if negative && !allowNegative {
		return 0, errors.New("amount must not be negative")
	}
	if len(value) > 0 && value[0] == '$' {
		value = value[1:]
	}
	if value == "" {
		return 0, errors.New("amount has no digits")
	}
	if strings.Count(value, ".") > 1 {
		return 0, fmt.Errorf("invalid USD decimal amount: %q", value)
	}

	dollarsPart := value
	fractionalPart := ""
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		dollarsPart = value[:dot]
		fractionalPart = value[dot+1:]
		if fractionalPart == "" {
			return 0, errors.New("amount has no fractional digits")
		}
	}
	if dollarsPart == "" {
		return 0, errors.New("amount has no dollar digits")
	}
	for _, digit := range dollarsPart {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("invalid digit in dollars part: %q", value)
		}
	}
	for _, digit := range fractionalPart {
		if digit < '0' || digit > '9' {
			return 0, fmt.Errorf("invalid digit in fractional part: %q", value)
		}
	}
	if len(fractionalPart) > maxFractionalDigits {
		return 0, fmt.Errorf("too many decimal places (max %d): %q", maxFractionalDigits, value)
	}

	dollars, err := strconv.ParseInt(dollarsPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid or overflowing dollars part: %w", err)
	}
	for len(fractionalPart) < 8 {
		fractionalPart += "0"
	}
	var fractional int64
	if fractionalPart != "" {
		fractional, err = strconv.ParseInt(fractionalPart, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid fractional part: %w", err)
		}
	}
	if dollars > (math.MaxInt64-fractional)/MicrocentsPerUSD {
		return 0, errors.New("USD amount overflows microcent storage")
	}
	microcents := dollars*MicrocentsPerUSD + fractional
	if negative {
		microcents = -microcents
	}
	return microcents, nil
}
