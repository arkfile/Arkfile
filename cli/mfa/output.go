package mfa

import "fmt"

// PrintSetupComplete emits human-readable enrollment success output.
func PrintSetupComplete(method Method, backupCodes []string) {
	switch method {
	case MethodWebAuthn:
		fmt.Println("Security key enrollment complete!")
	default:
		fmt.Println("TOTP Setup Complete!")
	}
	if len(backupCodes) == 0 {
		return
	}
	fmt.Println("\n=== BACKUP CODES ===")
	fmt.Println("SAVE THESE CODES IN A SAFE PLACE!")
	fmt.Println("--------------------")
	for _, code := range backupCodes {
		fmt.Println(code)
	}
	fmt.Println("--------------------")
}
