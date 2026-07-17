package jsonutil

import (
	"encoding/json"
	"fmt"
	"os"
)

// SafeBool reads a bool from a generic JSON object map.
func SafeBool(m map[string]interface{}, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

// SafeInt64 reads an int64 from a generic JSON object map.
func SafeInt64(m map[string]interface{}, key string) int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	if i, ok := v.(int64); ok {
		return i
	}
	return 0
}

// SafeFloat64 reads a float64 from a generic JSON object map.
func SafeFloat64(m map[string]interface{}, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}

// SafeString reads a string from a generic JSON object map.
func SafeString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// DefaultString returns defaultVal when value is empty.
func DefaultString(value, defaultVal string) string {
	if value == "" {
		return defaultVal
	}
	return value
}

// PrintJSON pretty-prints v to stdout.
func PrintJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
