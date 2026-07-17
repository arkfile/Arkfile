package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/arkfile/Arkfile/cli/mfa"
)

func handleMFACommand(client *HTTPClient, config *ClientConfig, args []string) error {
	session, err := requireSession(config)
	if err != nil {
		return err
	}
	return mfa.RunManageCommand(args, clientMFARequester(client), session.AccessToken)
}

func handleRecoverMFACommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("recover-mfa", flag.ExitOnError)
	codeFlag := fs.String("code", "", "Alphanumeric 10-char backup code")
	methodTypeFlag := fs.String("method-type", "", "Factor to replace: totp or webauthn")
	showSecret := fs.Bool("show-secret", false, "Emit machine-readable TOTP_SECRET and BACKUP_CODE_* lines (TOTP enrollment output is always shown)")
	nonInteractive := fs.Bool("non-interactive", false, "Don't prompt for input")
	if err := fs.Parse(args); err != nil {
		return err
	}

	session, err := loadAuthSession(config.TokenFile)
	if err != nil {
		return fmt.Errorf("not logged in. Please run OPAQUE auth (register/login) first: %w", err)
	}
	token := session.TempToken
	if token == "" {
		token = session.AccessToken
	}
	if token == "" {
		return fmt.Errorf("no valid session found. Please register or login first")
	}

	backupCode := strings.TrimSpace(*codeFlag)
	if backupCode == "" {
		fmt.Print("Enter your 10-character backup code: ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read backup code: %w", err)
		}
		backupCode = strings.TrimSpace(input)
	}

	fmt.Println("Verifying backup code and starting MFA reset...")
	result, err := mfa.RunRecover(mfa.RecoverConfig{
		Requester:      clientMFARequester(client),
		BackupCode:     backupCode,
		Token:          token,
		MethodType:     mfa.Method(strings.ToLower(strings.TrimSpace(*methodTypeFlag))),
		NonInteractive: *nonInteractive,
		ShowSecret:     *showSecret,
	})
	if err != nil {
		return err
	}

	session.TempToken = result.TempToken
	if err := saveAuthSession(session, config.TokenFile); err != nil {
		logError("Warning: Failed to save session after MFA reset: %v", err)
	}

	mfa.PrintRecoverResult(result, *showSecret)
	return nil
}
