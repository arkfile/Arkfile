package mfa

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

// RunManageCommand handles `mfa` subcommands for credential self-service.
func RunManageCommand(args []string, req Requester, token string) error {
	if len(args) == 0 {
		printManageUsage("")
		return nil
	}

	switch args[0] {
	case "list":
		return runManageList(req, token)
	case "remove":
		return runManageRemove(args[1:], req, token)
	case "regenerate-backup-codes":
		return runManageRegenerateBackupCodes(args[1:], req, token)
	case "set-label":
		return runManageSetLabel(args[1:], req, token)
	case "help", "-h", "--help":
		printManageUsage(args[0])
		return nil
	default:
		return fmt.Errorf("unknown mfa subcommand: %s", args[0])
	}
}

func printManageUsage(sub string) {
	fmt.Println(`Usage: mfa <subcommand> [flags]

Manage enrolled second factors while logged in.

Subcommands:
  list                         List your enrolled MFA methods
  remove                       Remove one enrolled method (--credential-id, --confirm)
  regenerate-backup-codes      Issue a new set of backup codes (--confirm)
  set-label                    Update your private security key label

Examples:
  mfa list
  mfa remove --credential-id CRED_ID --confirm
  mfa regenerate-backup-codes --confirm
  mfa set-label --credential-id CRED_ID --label "Desk Nitrokey"`)
	if sub != "" {
		fmt.Printf("\nRun 'mfa help' for all subcommands.\n")
	}
}

func runManageList(req Requester, token string) error {
	creds, err := ListCredentials(req, token)
	if err != nil {
		return err
	}
	PrintCredentials(creds)
	return nil
}

func runManageRemove(args []string, req Requester, token string) error {
	fs := flag.NewFlagSet("mfa remove", flag.ExitOnError)
	credentialID := fs.String("credential-id", "", "Credential id to remove (required)")
	confirm := fs.Bool("confirm", false, "Confirm removal without interactive prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*credentialID) == "" {
		return fmt.Errorf("--credential-id is required")
	}
	if !*confirm {
		fmt.Printf("Remove MFA credential %s? All sessions will be signed out. [y/N]: ", *credentialID)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	requiresSetup, forceLogout, err := RemoveCredential(req, token, *credentialID)
	if err != nil {
		return err
	}
	fmt.Println("MFA credential removed.")
	if forceLogout {
		fmt.Println("All sessions for this account have been revoked.")
	}
	if requiresSetup {
		fmt.Println("This was your last second factor. Sign in again and complete MFA setup.")
	}
	return nil
}

func runManageRegenerateBackupCodes(args []string, req Requester, token string) error {
	fs := flag.NewFlagSet("mfa regenerate-backup-codes", flag.ExitOnError)
	confirm := fs.Bool("confirm", false, "Confirm without interactive prompt")
	showSecret := fs.Bool("show-secret", false, "Emit machine-readable BACKUP_CODE_* lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*confirm {
		fmt.Print("Generate new backup codes? Old unused codes stop working immediately. [y/N]: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "y" && answer != "yes" {
			fmt.Println("Cancelled.")
			return nil
		}
	}

	codes, err := RegenerateBackupCodes(req, token)
	if err != nil {
		return err
	}
	fmt.Printf("Generated %d new backup codes.\n", len(codes))
	emitBackupCodes(codes, SetupConfig{ShowSecret: *showSecret})
	return nil
}

func runManageSetLabel(args []string, req Requester, token string) error {
	fs := flag.NewFlagSet("mfa set-label", flag.ExitOnError)
	credentialID := fs.String("credential-id", "", "Security key credential id (required)")
	label := fs.String("label", "", "New private label (max 64 printable ASCII; empty clears label)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*credentialID) == "" {
		return fmt.Errorf("--credential-id is required")
	}
	if err := UpdateCredentialLabel(req, token, *credentialID, strings.TrimSpace(*label)); err != nil {
		return err
	}
	fmt.Println("Security key label updated.")
	return nil
}
