package utils

import (
	"os"
	"strings"
)

// IsDebugMode reports whether DEBUG_MODE is enabled (true or 1).
func IsDebugMode() bool {
	debug := strings.ToLower(os.Getenv("DEBUG_MODE"))
	return debug == "true" || debug == "1"
}
