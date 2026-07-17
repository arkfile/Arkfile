package format

import "fmt"

// FileSize formats bytes using binary IEC units (B, KB, MB, GB, TB).
func FileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	units := []string{"KB", "MB", "GB", "TB"}
	if exp >= len(units) {
		return fmt.Sprintf("%d B", bytes)
	}

	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

// ClientBillingBytes formats storage bytes for client billing output.
func ClientBillingBytes(n int64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%d B", n)
}
