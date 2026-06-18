package mfa

import "fmt"

// PrintBackupCodes shows plaintext backup codes for interactive CLI enrollment.
func PrintBackupCodes(codes []string) {
	if len(codes) == 0 {
		return
	}
	fmt.Println("\n=== BACKUP CODES ===")
	fmt.Println("SAVE THESE CODES IN A SAFE PLACE!")
	fmt.Println("--------------------")
	for _, code := range codes {
		fmt.Println(code)
	}
	fmt.Println("--------------------")
}

// PrintAutomationBackupCodes emits machine-readable lines for scripts and e2e.
func PrintAutomationBackupCodes(codes []string) {
	for i, c := range codes {
		switch i {
		case 0:
			fmt.Printf("BACKUP_CODE_0:%s\n", c)
		case 1:
			fmt.Printf("BACKUP_CODE_1:%s\n", c)
		}
	}
}

// PrintSetupComplete emits enrollment success output after MFA setup finishes.
func PrintSetupComplete() {
	fmt.Println("MFA setup complete!")
}
