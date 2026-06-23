package mfa

import (
	"fmt"
	"strings"
)

// RecoverConfig drives path-B backup-code recovery and factor replacement.
type RecoverConfig struct {
	Requester      Requester
	BackupCode     string
	Token          string
	MethodType     Method
	NonInteractive bool
	ShowSecret     bool
}

// RecoverResult is returned after a successful MFA reset during recovery.
type RecoverResult struct {
	Method      Method
	TempToken   string
	TOTPSecret  string
	BackupCodes []string
	Message     string
}

// PickResetMethod chooses which factor type to replace during path-B recovery.
func PickResetMethod(nonInteractive bool, methodFlag Method) (Method, error) {
	if methodFlag == MethodTOTP || methodFlag == MethodWebAuthn {
		return methodFlag, nil
	}
	if nonInteractive {
		return "", fmt.Errorf("non-interactive mode: --method-type totp|webauthn required when choosing a factor to replace")
	}
	fmt.Println("Which second factor are you replacing?")
	fmt.Println("  1) Authenticator app (TOTP)")
	fmt.Println("  2) Security key (WebAuthn)")
	fmt.Print("Enter 1 or 2: ")
	method, err := PickMethod(false, "")
	if err != nil {
		return "", err
	}
	return method, nil
}

// RunRecover performs path-B recovery: backup code → reset token → factor reset.
func RunRecover(cfg RecoverConfig) (*RecoverResult, error) {
	code := strings.TrimSpace(cfg.BackupCode)
	if len(code) != 10 {
		return nil, fmt.Errorf("backup code must be exactly 10 characters")
	}

	method, err := PickResetMethod(cfg.NonInteractive, cfg.MethodType)
	if err != nil {
		return nil, err
	}

	recoverResp, err := cfg.Requester("POST", "/api/mfa/recover-with-backup-code", map[string]string{
		"backup_code": code,
	}, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("backup code recovery failed: %w", err)
	}

	resetToken := recoverResp.TempToken
	if resetToken == "" {
		if t, ok := recoverResp.Data["reset_token"].(string); ok {
			resetToken = t
		}
	}
	if resetToken == "" {
		return nil, fmt.Errorf("server didn't return a reset token")
	}

	resetResp, err := cfg.Requester("POST", "/api/mfa/reset", map[string]string{
		"method_type": string(method),
	}, resetToken)
	if err != nil {
		return nil, fmt.Errorf("MFA reset failed: %w", err)
	}

	result := &RecoverResult{
		Method:    method,
		TempToken: resetResp.TempToken,
		Message:   resetResp.Message,
	}
	if result.TempToken == "" {
		if t, ok := resetResp.Data["temp_token"].(string); ok {
			result.TempToken = t
		}
	}
	if result.Message == "" {
		if m, ok := resetResp.Data["message"].(string); ok {
			result.Message = m
		}
	}
	result.BackupCodes = stringSlice(resetResp.Data["backup_codes"])
	if method == MethodTOTP {
		if secret, ok := resetResp.Data["secret"].(string); ok {
			result.TOTPSecret = secret
		}
	}
	return result, nil
}

// PrintRecoverResult emits human-readable recovery output.
func PrintRecoverResult(result *RecoverResult, showSecret bool) {
	if result == nil {
		return
	}
	fmt.Println("\n=== MFA Reset Complete ===")
	if result.Message != "" {
		fmt.Println(result.Message)
	}

	if result.Method == MethodTOTP {
		if result.TOTPSecret == "" {
			fmt.Println("TOTP reset staged but no secret was returned.")
			return
		}
		if showSecret {
			fmt.Printf("TOTP_SECRET:%s\n", result.TOTPSecret)
		}
		fmt.Println("1. Open your authenticator app")
		fmt.Println("2. Add a new manual account with this secret:")
		fmt.Printf("   Secret: %s\n", result.TOTPSecret)
		fmt.Println("\nVerify with: setup-mfa --verify CODE")
	} else {
		fmt.Println("Security key reset staged.")
		fmt.Println("Enroll your replacement key with: setup-mfa --mfa-method webauthn")
	}

	if len(result.BackupCodes) > 0 {
		emitBackupCodes(result.BackupCodes, SetupConfig{ShowSecret: showSecret})
	}
}
