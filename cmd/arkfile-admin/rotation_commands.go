package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
)

func handleRotateUserSecretMasterCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: prepare or apply (use --help)")
	}

	switch args[0] {
	case "prepare":
		return handleRotateUserSecretMasterPrepare(client, config, args[1:])
	case "apply":
		return handleRotateUserSecretMasterApply(config, args[1:])
	case "help", "--help", "-h":
		printRotateUserSecretMasterUsage()
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q (expected prepare or apply)", args[0])
	}
}

func printRotateUserSecretMasterUsage() {
	fmt.Print(`Usage: arkfile-admin rotate-user-secret-master <subcommand> [FLAGS]

Safely rotate the user-secret master key with database re-encryption.

SUBCOMMANDS:
    prepare    Issue a signed rotation mandate (server must be running)
    apply      Apply rotation offline using a mandate (server must be stopped)

EXAMPLES:
    arkfile-admin login --username admin
    arkfile-admin rotate-user-secret-master prepare --mandate-file /root/user-secret-rotation-mandate.txt --confirm
    sudo systemctl stop arkfile
    arkfile-admin rotate-user-secret-master apply --mandate-file /root/user-secret-rotation-mandate.txt --confirm
    sudo systemctl start arkfile
`)
}

func handleRotateUserSecretMasterPrepare(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-user-secret-master prepare", flag.ExitOnError)
	mandateFile := fs.String("mandate-file", "", "Write mandate to this file (default: stdout)")
	confirm := fs.Bool("confirm", false, "Skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*confirm {
		fmt.Print("Issue a user-secret rotation mandate? This authorizes offline master key rotation. (yes/no): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" && response != "y" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	resp, err := client.makeRequest("POST", "/api/admin/system/prepare-user-secret-master-rotation", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("prepare rotation mandate failed: %w", err)
	}

	mandate, _ := resp.Data["mandate"].(string)
	expiresAt, _ := resp.Data["expires_at"].(string)
	if mandate == "" {
		return fmt.Errorf("server returned empty rotation mandate")
	}

	output := mandate
	if *mandateFile != "" {
		if err := os.WriteFile(*mandateFile, []byte(mandate+"\n"), 0600); err != nil {
			return fmt.Errorf("failed to write mandate file: %w", err)
		}
		fmt.Printf("Rotation mandate written to %s (expires %s)\n", *mandateFile, expiresAt)
	} else {
		fmt.Println(output)
		if expiresAt != "" {
			fmt.Fprintf(os.Stderr, "Mandate expires: %s\n", expiresAt)
		}
	}
	return nil
}

func handleRotateUserSecretMasterApply(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-user-secret-master apply", flag.ExitOnError)
	mandateFile := fs.String("mandate-file", "", "Path to mandate file (required)")
	baseDir := fs.String("base-dir", "/opt/arkfile", "Arkfile installation directory")
	confirm := fs.Bool("confirm", false, "Skip confirmation prompt")
	skipServiceCheck := fs.Bool("skip-service-check", false, "Skip systemd service check (tests only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *mandateFile == "" {
		return fmt.Errorf("--mandate-file is required")
	}

	if !*confirm {
		fmt.Print("Apply user-secret master rotation using the mandate? The arkfile service must be stopped. (yes/no): ")
		var response string
		if _, err := fmt.Scanln(&response); err != nil {
			return fmt.Errorf("failed to read confirmation: %w", err)
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "yes" && response != "y" {
			fmt.Println("Cancelled")
			return nil
		}
	}

	mandateBytes, err := os.ReadFile(*mandateFile)
	if err != nil {
		return fmt.Errorf("failed to read mandate file: %w", err)
	}
	mandate := strings.TrimSpace(string(mandateBytes))

	secretsPath := filepath.Join(*baseDir, "etc", "secrets.env")
	if err := database.LoadSecretsEnvFile(secretsPath); err != nil {
		return fmt.Errorf("failed to load secrets env: %w", err)
	}

	db, err := database.OpenMaintenanceDB()
	if err != nil {
		return err
	}
	defer db.Close()

	if err := crypto.InitKeyManager(db); err != nil {
		return fmt.Errorf("failed to initialize key manager: %w", err)
	}

	stats, err := auth.ApplyUserSecretMasterRotation(auth.ApplyUserSecretMasterRotationOptions{
		BaseDir:          *baseDir,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: *skipServiceCheck,
	})
	if err != nil {
		return err
	}

	fmt.Printf("User-secret master rotation complete: %d MFA credential(s), %d contact info row(s) re-encrypted\n",
		stats.MFACredentials, stats.ContactInfo)
	return nil
}
