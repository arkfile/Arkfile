package main

import (
	"fmt"
	"strings"

	"github.com/arkfile/Arkfile/cli/format"
	"github.com/arkfile/Arkfile/cli/jsonutil"
	"github.com/arkfile/Arkfile/cli/secureinput"
)

func formatFileSize(bytes int64) string {
	return format.FileSize(bytes)
}

func boolYesNo(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func parseStringSlice(v interface{}) []string {
	switch items := v.(type) {
	case []string:
		out := make([]string, 0, len(items))
		for _, item := range items {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func formatMFAStatus(enabled bool, methods []string) string {
	if !enabled && len(methods) == 0 {
		return "No"
	}
	labels := make([]string, 0, len(methods))
	for _, method := range methods {
		switch strings.ToLower(strings.TrimSpace(method)) {
		case "totp":
			labels = append(labels, "TOTP")
		case "webauthn":
			labels = append(labels, "HW")
		}
	}
	if len(labels) == 0 {
		if enabled {
			return "Yes"
		}
		return "No"
	}
	return "Yes (" + strings.Join(labels, "+") + ")"
}

func parseStorageLimit(limit string) (int64, error) {
	limit = strings.ToUpper(strings.TrimSpace(limit))

	var value float64
	var unit string

	if strings.HasSuffix(limit, "GB") {
		unit = "GB"
		if _, err := fmt.Sscanf(limit, "%fGB", &value); err != nil {
			return 0, fmt.Errorf("invalid GB format: %s", limit)
		}
	} else if strings.HasSuffix(limit, "MB") {
		unit = "MB"
		if _, err := fmt.Sscanf(limit, "%fMB", &value); err != nil {
			return 0, fmt.Errorf("invalid MB format: %s", limit)
		}
	} else if strings.HasSuffix(limit, "KB") {
		unit = "KB"
		if _, err := fmt.Sscanf(limit, "%fKB", &value); err != nil {
			return 0, fmt.Errorf("invalid KB format: %s", limit)
		}
	} else if strings.HasSuffix(limit, "B") {
		unit = "B"
		if _, err := fmt.Sscanf(limit, "%fB", &value); err != nil {
			return 0, fmt.Errorf("invalid B format: %s", limit)
		}
	} else {
		return 0, fmt.Errorf("invalid storage limit format: %s (use GB, MB, KB, or B)", limit)
	}

	if value < 0 {
		return 0, fmt.Errorf("storage limit cannot be negative")
	}

	var bytes int64
	switch unit {
	case "GB":
		bytes = int64(value * 1024 * 1024 * 1024)
	case "MB":
		bytes = int64(value * 1024 * 1024)
	case "KB":
		bytes = int64(value * 1024)
	case "B":
		bytes = int64(value)
	}

	return bytes, nil
}

func safeBool(m map[string]interface{}, key string) bool {
	return jsonutil.SafeBool(m, key)
}

func safeInt64(m map[string]interface{}, key string) int64 {
	return jsonutil.SafeInt64(m, key)
}

func safeFloat64(m map[string]interface{}, key string) float64 {
	return jsonutil.SafeFloat64(m, key)
}

func safeString(m map[string]interface{}, key string) string {
	return jsonutil.SafeString(m, key)
}

func statusStr(m map[string]interface{}) string {
	if safeBool(m, "is_approved") {
		return "approved"
	}
	return "pending"
}

func emptyOrValue(v, defaultVal string) string {
	return jsonutil.DefaultString(v, defaultVal)
}

func printJSON(v interface{}) error {
	return jsonutil.PrintJSON(v)
}

// passwordFromStdin is set by commands that accept --password-stdin.
var passwordFromStdin bool

func withPasswordStdin(enabled bool) func() {
	prev := passwordFromStdin
	passwordFromStdin = enabled
	return func() { passwordFromStdin = prev }
}

func readPasswordPrompt(prompt string) ([]byte, error) {
	if passwordFromStdin {
		return secureinput.ReadPasswordFromStdin(secureinput.DefaultPipeTimeout)
	}
	return secureinput.ReadPassword(prompt, secureinput.DefaultInteractiveTimeout)
}

func readPassword() (string, error) {
	pw, err := readPasswordPrompt("")
	if err != nil {
		return "", err
	}
	defer secureinput.Zero(pw)
	return string(pw), nil
}
