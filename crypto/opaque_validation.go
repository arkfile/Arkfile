package crypto

import (
	"fmt"
)

// ValidateOPAQUEExportKey validates an OPAQUE export key format and content
func ValidateOPAQUEExportKey(exportKey []byte) error {
	if len(exportKey) == 0 {
		return fmt.Errorf("OPAQUE export key cannot be empty")
	}

	if len(exportKey) < 32 {
		return fmt.Errorf("OPAQUE export key too short, expected at least 32 bytes, got %d", len(exportKey))
	}

	// Basic validation - ensure it's not all zeros
	allZeros := true
	for _, b := range exportKey {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		return fmt.Errorf("OPAQUE export key cannot be all zeros")
	}

	return nil
}

// DerivePasswordHintKey derives a hint key from an OPAQUE export key for password hints
func DerivePasswordHintKey(exportKey []byte, context string) ([]byte, error) {
	if len(exportKey) == 0 {
		return nil, fmt.Errorf("export key cannot be empty")
	}

	if context == "" {
		return nil, fmt.Errorf("context cannot be empty")
	}

	// Use HKDF to derive hint key from export key
	info := fmt.Sprintf("arkfile-password-hint:%s", context)
	return hkdfExpand(exportKey[:32], []byte(info), 32)
}
