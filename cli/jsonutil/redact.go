package jsonutil

import (
	"encoding/json"
	"fmt"
	"strings"
)

const redactedValue = "[REDACTED]"

// sensitiveResponseKeys are JSON object keys whose values grant account access
// or reveal second-factor secrets. Matching is case-insensitive at any depth.
var sensitiveResponseKeys = map[string]struct{}{
	"token":          {},
	"access_token":   {},
	"refresh_token":  {},
	"temp_token":     {},
	"ticket":         {},
	"download_token": {},
	"secret":         {},
	"manual_entry":   {},
	"qr_code_url":    {},
	"qr_code_image":  {},
	"backup_codes":   {},
	"backup_code":    {},
	"password":       {},
}

// RedactSensitiveJSON returns body as JSON text with session tokens, MFA
// secrets, and backup codes replaced, for verbose logging. Bodies that are not
// JSON are summarized by length only.
func RedactSensitiveJSON(body []byte) string {
	var parsed interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Sprintf("<%d bytes, not JSON>", len(body))
	}
	out, err := json.Marshal(redactValue(parsed))
	if err != nil {
		return fmt.Sprintf("<%d bytes>", len(body))
	}
	return string(out)
}

func redactValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for key, val := range t {
			if _, sensitive := sensitiveResponseKeys[strings.ToLower(key)]; sensitive && val != nil {
				t[key] = redactedValue
				continue
			}
			t[key] = redactValue(val)
		}
		return t
	case []interface{}:
		for i, val := range t {
			t[i] = redactValue(val)
		}
		return t
	default:
		return v
	}
}
