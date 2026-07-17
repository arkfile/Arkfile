package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
)

func handleRotateEnvelopeMasterCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: prepare or apply (use --help)")
	}

	switch args[0] {
	case "prepare":
		return handleRotateEnvelopeMasterPrepare(client, config, args[1:])
	case "apply":
		return handleRotateEnvelopeMasterApply(config, args[1:])
	case "help", "--help", "-h":
		printRotateEnvelopeMasterUsage()
		return nil
	default:
		return fmt.Errorf("unknown subcommand %q (expected prepare or apply)", args[0])
	}
}

func printRotateEnvelopeMasterUsage() {
	fmt.Print(`Usage: arkfile-admin rotate-envelope-master <subcommand> [FLAGS]

Safely rotate the envelope master key (ARKFILE_MASTER_KEY) that wraps every
secret in the system_keys table. The rotation re-wraps all rows under a freshly
generated master and regenerates the EntityID master (resetting rate-limiting
correlation windows). It is fully server-side with no user impact.

SUBCOMMANDS:
    prepare    Issue a signed rotation mandate (server must be running)
    apply      Apply rotation offline using a mandate (server must be stopped)

EXAMPLES:
    arkfile-admin login --username admin
    arkfile-admin rotate-envelope-master prepare --mandate-file /root/envelope-rotation-mandate.txt --confirm
    sudo systemctl stop arkfile
    arkfile-admin rotate-envelope-master apply --mandate-file /root/envelope-rotation-mandate.txt --confirm
    sudo systemctl start arkfile
`)
}

func handleRotateEnvelopeMasterPrepare(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-envelope-master prepare", flag.ExitOnError)
	mandateFile := fs.String("mandate-file", "", "Write mandate to this file (default: stdout)")
	confirm := fs.Bool("confirm", false, "Skip confirmation prompt")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*confirm {
		fmt.Print("Issue an envelope master rotation mandate? This authorizes offline master key rotation. (yes/no): ")
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

	resp, err := client.makeRequest("POST", "/api/admin/system/prepare-envelope-master-rotation", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("prepare rotation mandate failed: %w", err)
	}

	mandate, _ := resp.Data["mandate"].(string)
	expiresAt, _ := resp.Data["expires_at"].(string)
	if mandate == "" {
		return fmt.Errorf("server returned empty rotation mandate")
	}

	if *mandateFile != "" {
		if err := os.WriteFile(*mandateFile, []byte(mandate+"\n"), 0600); err != nil {
			return fmt.Errorf("failed to write mandate file: %w", err)
		}
		fmt.Printf("Rotation mandate written to %s (expires %s)\n", *mandateFile, expiresAt)
	} else {
		fmt.Println(mandate)
		if expiresAt != "" {
			fmt.Fprintf(os.Stderr, "Mandate expires: %s\n", expiresAt)
		}
	}
	return nil
}

func handleRotateEnvelopeMasterApply(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("rotate-envelope-master apply", flag.ExitOnError)
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
		fmt.Print("Apply envelope master rotation using the mandate? The arkfile service must be stopped. (yes/no): ")
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

	stats, err := auth.ApplyEnvelopeMasterRotation(auth.ApplyEnvelopeMasterRotationOptions{
		BaseDir:          *baseDir,
		SecretsEnvPath:   secretsPath,
		Mandate:          mandate,
		DB:               db,
		SkipServiceCheck: *skipServiceCheck,
	})
	if err != nil {
		return err
	}

	entityNote := "EntityID master not present (will be generated on next start)"
	if stats.EntityIDRegenerated {
		entityNote = "EntityID master regenerated"
	}
	fmt.Printf("Envelope master rotation complete: %d system_keys row(s) re-wrapped; %s\n",
		stats.RowsRewrapped, entityNote)
	fmt.Println("Restart the arkfile service to load the new master.")
	return nil
}
