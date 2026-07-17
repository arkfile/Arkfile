// arkfile-admin - Hybrid network/local admin tool for arkfile server management.

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/arkfile/Arkfile/config"
)

const (
	Usage = `arkfile-admin - Hybrid network/local admin tool for arkfile server management

USAGE:
    arkfile-admin [global options] command [command options] [arguments...]

Place boolean flags such as --json before positional arguments.

NETWORK COMMANDS (Admin API - localhost only):
    bootstrap         Bootstrap the first admin user (requires token)
    login             Admin login via OPAQUE + MFA (TOTP or security key)
    setup-mfa         Setup Two-Factor Authentication (TOTP or security key)
    mfa               Manage your enrolled second factors (list, remove, backup codes)
    recover-mfa       Self-service MFA recovery with a backup code (path B)
    logout            Clear admin session
    list-users        List all users
    approve-user      Approve user account
    unapprove-user    Revoke approval and force-logout a user (terminates all active sessions)
    set-approval-policy   Set instance-wide auto-approval policy (live, no restart)
    get-approval-policy   Show the current auto-approval policy and its source
    user-status       Get status of a specific user
    user-contact-info View a user's contact information
    set-storage       Set user storage limit
    revoke-user       Revoke user access and disable account (also terminates all active sessions)
    update-user       Update user properties (admin, approved, storage)
    delete-user       Delete a user and all associated data
    force-logout      Force-logout a user (revoke all tokens)
    reset-user-mfa    Clear MFA enrollment for a user (full or credential-scoped reset)
    list-user-mfa     List a user's MFA credentials (admin metadata only; no labels)
    flag-user-reregistration  Flag account(s) for one-time OPAQUE re-registration
    list-files        List files owned by a user
    list-shares       List shares owned by a user
    delete-file       Delete a specific file by ID
    revoke-share      Revoke a specific share by ID
    security-events   View recent security events
    export-file       Export a user's encrypted file as .arkbackup bundle

STORAGE MANAGEMENT COMMANDS (Admin API):
    storage-status        Show configured providers, file counts, sync status, and costs
    storage-sync-status   Detailed breakdown of file locations and replication gaps
    copy-all              Copy all files from one provider to another
    copy-user-files       Copy all files for a specific user between providers
    copy-file             Copy a single file between providers
    task-status           Check status of a background storage task
    list-tasks            List running or recent background storage tasks
    cancel-task           Cancel a running background storage task
    cancel-all-tasks      Cancel all running tasks in a category
    set-primary           Promote a provider to primary (new uploads go here)
    set-secondary         Promote/demote a provider to secondary (auto-replication target)
    set-tertiary          Demote a provider to tertiary (manual-only)
    swap-providers        Swap primary and secondary provider roles
    set-cost              Set monthly cost per TB for a provider
    verify-all            Verify all file locations via HEAD requests (detect missing/corrupt blobs)

BILLING COMMANDS (storage credits / usage metering):
    billing show                          Show current price + last 30 days of sweep activity
    billing show --user NAME              Show one user's balance, usage, and runway
    billing set-price USD-per-TB-month    Update the customer price (atomic, no restart)
    billing gift                          Add positive credit to a user's balance
    billing list-overdrawn                List users with negative balance
    billing tick-now [--sweep]            Force an immediate tick (dev/test only)

    See 'arkfile-admin billing --help' for full subcommand documentation.

PAYMENTS COMMANDS:
    payments list                         List invoice payments
    payments show ID                      Show one invoice payment
    payments sync-invoice ID              Sync invoice status from BTCPay
    payments reconcile                    Reconcile payments ledger

    See 'arkfile-admin payments --help' for full subcommand documentation.

SUBSCRIPTIONS COMMANDS:
    subscriptions list-plans              List subscription plans
    subscriptions show USER               Show a user's subscription
    subscriptions set-plan                Assign or change a user's plan
    subscriptions sync                    Sync subscription state
    subscriptions reconcile               Reconcile subscription ledger
    subscriptions grant-gift-subscription Grant a gift subscription
    subscriptions cancel-gift-subscription Cancel a gift subscription

    See 'arkfile-admin subscriptions --help' for full subcommand documentation.

SYSTEM COMMANDS:
    system-status     System status overview
    health-check      System health check
    reset-registration-throttle  Clear registration_attempts (dev/test only)
    verify-storage    Verify S3 storage connectivity (upload/download/delete round-trip)
    rotate-user-secret-master  User-secret master rotation (prepare|apply)
    rotate-envelope-master     Envelope master key rotation (prepare|apply)
    rotate-jwt-keys   JWT signing key rotation (rotate|retire)
    rotate-opaque-keys OPAQUE server key rotation (rotate|replace-keys)
    version           Show version information

GLOBAL OPTIONS:
    --server-url URL    Server URL for network commands (default: https://localhost:8443)
    --tls-insecure      Skip TLS certificate verification (dev/localhost only)
    --config FILE       Configuration file path
    --username USER     Admin username for authentication
    --verbose, -v       Verbose output
    --help, -h          Show help

EXAMPLES:
    arkfile-admin login --username admin
    arkfile-admin list-users
    arkfile-admin approve-user --username alice12345
    arkfile-admin set-storage --username alice12345 --limit 10GB
    arkfile-admin system-status
    arkfile-admin health-check --detailed
    arkfile-admin billing set-price --json 19.99
`
)

var verbose bool

func main() {
	var (
		serverURL   = flag.String("server-url", "https://localhost:8443", "Server URL")
		configFile  = flag.String("config", "", "Configuration file path")
		tlsInsecure = flag.Bool("tls-insecure", false, "Skip TLS certificate verification (localhost only)")
		username    = flag.String("username", "", "Admin username for authentication")
		verboseFlag = flag.Bool("verbose", false, "Verbose output")
		vFlag       = flag.Bool("v", false, "Verbose output (short)")
		helpFlag    = flag.Bool("help", false, "Show help information")
		hFlag       = flag.Bool("h", false, "Show help information (short)")
		versionFlag = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	verbose = *verboseFlag || *vFlag

	if *versionFlag {
		printVersion()
		return
	}

	if *helpFlag || *hFlag || flag.NArg() == 0 {
		printUsage()
		return
	}

	adminConfig := &AdminConfig{
		ServerURL:   *serverURL,
		Username:    strings.ToLower(strings.TrimSpace(*username)),
		TLSInsecure: *tlsInsecure,
		ConfigFile:  *configFile,
		TokenFile:   getAdminSessionFilePath(),
	}
	// Force TLS 1.3 only for maximum security
	adminConfig.TLSMinVersion = tls.VersionTLS13

	if *configFile != "" {
		if err := loadConfigFile(adminConfig, *configFile); err != nil {
			logError("Failed to load config file: %v", err)
			os.Exit(1)
		}
	}

	client := newHTTPClient(adminConfig.ServerURL, adminConfig.TLSInsecure, adminConfig.TLSMinVersion, verbose)

	// Parse command
	command := flag.Arg(0)
	args := flag.Args()[1:]

	// Execute command - route to network or local implementation
	switch command {
	case "bootstrap":
		if err := handleBootstrapCommand(client, adminConfig, args); err != nil {
			logError("Bootstrap failed: %v", err)
			os.Exit(1)
		}
	case "login":
		if err := handleLoginCommand(client, adminConfig, args); err != nil {
			logError("Login failed: %v", err)
			os.Exit(1)
		}
	case "setup-mfa":
		if err := handleSetupMFACommand(client, adminConfig, args); err != nil {
			logError("MFA setup failed: %v", err)
			os.Exit(1)
		}
	case "mfa":
		if err := handleMFACommand(client, adminConfig, args); err != nil {
			logError("MFA command failed: %v", err)
			os.Exit(1)
		}
	case "recover-mfa":
		if err := handleRecoverMFACommand(client, adminConfig, args); err != nil {
			logError("MFA recovery failed: %v", err)
			os.Exit(1)
		}
	case "logout":
		if err := handleLogoutCommand(adminConfig, args); err != nil {
			logError("Logout failed: %v", err)
			os.Exit(1)
		}
	case "list-users":
		if err := handleListUsersCommand(client, adminConfig, args); err != nil {
			logError("List users failed: %v", err)
			os.Exit(1)
		}
	case "approve-user":
		if err := handleApproveUserCommand(client, adminConfig, args); err != nil {
			logError("Approve user failed: %v", err)
			os.Exit(1)
		}
	case "unapprove-user":
		if err := handleUnapproveUserCommand(client, adminConfig, args); err != nil {
			logError("Unapprove user failed: %v", err)
			os.Exit(1)
		}
	case "set-storage":
		if err := handleSetStorageCommand(client, adminConfig, args); err != nil {
			logError("Set storage failed: %v", err)
			os.Exit(1)
		}
	case "revoke-user":
		if err := handleRevokeUserCommand(client, adminConfig, args); err != nil {
			logError("Revoke user failed: %v", err)
			os.Exit(1)
		}
	case "user-status":
		if err := handleUserStatusCommand(client, adminConfig, args); err != nil {
			logError("User status failed: %v", err)
			os.Exit(1)
		}
	case "user-contact-info":
		if err := handleUserContactInfoCommand(client, adminConfig, args); err != nil {
			logError("User contact info failed: %v", err)
			os.Exit(1)
		}
	case "export-file":
		if err := handleExportFileCommand(client, adminConfig, args); err != nil {
			logError("Export file failed: %v", err)
			os.Exit(1)
		}
	case "update-user":
		if err := handleUpdateUserCommand(client, adminConfig, args); err != nil {
			logError("Update user failed: %v", err)
			os.Exit(1)
		}
	case "delete-user":
		if err := handleDeleteUserCommand(client, adminConfig, args); err != nil {
			logError("Delete user failed: %v", err)
			os.Exit(1)
		}
	case "force-logout":
		if err := handleForceLogoutCommand(client, adminConfig, args); err != nil {
			logError("Force logout failed: %v", err)
			os.Exit(1)
		}
	case "reset-user-mfa":
		if err := handleResetUserMFACommand(client, adminConfig, args); err != nil {
			logError("Reset user MFA failed: %v", err)
			os.Exit(1)
		}
	case "list-user-mfa":
		if err := handleListUserMFACommand(client, adminConfig, args); err != nil {
			logError("List user MFA failed: %v", err)
			os.Exit(1)
		}
	case "flag-user-reregistration":
		if err := handleFlagUserReregistrationCommand(client, adminConfig, args); err != nil {
			logError("Flag user re-registration failed: %v", err)
			os.Exit(1)
		}
	case "list-files":
		if err := handleListFilesCommand(client, adminConfig, args); err != nil {
			logError("List files failed: %v", err)
			os.Exit(1)
		}
	case "list-shares":
		if err := handleListSharesCommand(client, adminConfig, args); err != nil {
			logError("List shares failed: %v", err)
			os.Exit(1)
		}
	case "delete-file":
		if err := handleDeleteFileCommand(client, adminConfig, args); err != nil {
			logError("Delete file failed: %v", err)
			os.Exit(1)
		}
	case "revoke-share":
		if err := handleRevokeShareCommand(client, adminConfig, args); err != nil {
			logError("Revoke share failed: %v", err)
			os.Exit(1)
		}
	case "security-events":
		if err := handleSecurityEventsCommand(client, adminConfig, args); err != nil {
			logError("Security events failed: %v", err)
			os.Exit(1)
		}
	case "system-status":
		if err := handleSystemStatusCommand(client, adminConfig, args); err != nil {
			logError("System status failed: %v", err)
			os.Exit(1)
		}
	case "health-check":
		if err := handleHealthCheckCommand(client, adminConfig, args); err != nil {
			logError("Health check failed: %v", err)
			os.Exit(1)
		}
	case "verify-storage":
		if err := handleVerifyStorageCommand(client, adminConfig, args); err != nil {
			logError("Storage verification failed: %v", err)
			os.Exit(1)
		}
	case "storage-status":
		if err := handleStorageStatusCommand(client, adminConfig, args); err != nil {
			logError("Storage status failed: %v", err)
			os.Exit(1)
		}
	case "storage-sync-status":
		if err := handleStorageSyncStatusCommand(client, adminConfig, args); err != nil {
			logError("Storage sync status failed: %v", err)
			os.Exit(1)
		}
	case "copy-all":
		if err := handleCopyAllCommand(client, adminConfig, args); err != nil {
			logError("Copy all failed: %v", err)
			os.Exit(1)
		}
	case "copy-user-files":
		if err := handleCopyUserFilesCommand(client, adminConfig, args); err != nil {
			logError("Copy user files failed: %v", err)
			os.Exit(1)
		}
	case "copy-file":
		if err := handleCopyFileCommand(client, adminConfig, args); err != nil {
			logError("Copy file failed: %v", err)
			os.Exit(1)
		}
	case "task-status":
		if err := handleTaskStatusCommand(client, adminConfig, args); err != nil {
			logError("Task status failed: %v", err)
			os.Exit(1)
		}
	case "list-tasks":
		if err := handleListTasksCommand(client, adminConfig, args); err != nil {
			logError("List tasks failed: %v", err)
			os.Exit(1)
		}
	case "cancel-task":
		if err := handleCancelTaskCommand(client, adminConfig, args); err != nil {
			logError("Cancel task failed: %v", err)
			os.Exit(1)
		}
	case "cancel-all-tasks":
		if err := handleCancelAllTasksCommand(client, adminConfig, args); err != nil {
			logError("Cancel all tasks failed: %v", err)
			os.Exit(1)
		}
	case "set-primary":
		if err := handleSetPrimaryCommand(client, adminConfig, args); err != nil {
			logError("Set primary failed: %v", err)
			os.Exit(1)
		}
	case "set-secondary":
		if err := handleSetSecondaryCommand(client, adminConfig, args); err != nil {
			logError("Set secondary failed: %v", err)
			os.Exit(1)
		}
	case "set-tertiary":
		if err := handleSetTertiaryCommand(client, adminConfig, args); err != nil {
			logError("Set tertiary failed: %v", err)
			os.Exit(1)
		}
	case "swap-providers":
		if err := handleSwapProvidersCommand(client, adminConfig, args); err != nil {
			logError("Swap providers failed: %v", err)
			os.Exit(1)
		}
	case "set-cost":
		if err := handleSetCostCommand(client, adminConfig, args); err != nil {
			logError("Set cost failed: %v", err)
			os.Exit(1)
		}
	case "verify-all":
		if err := handleVerifyAllCommand(client, adminConfig, args); err != nil {
			logError("Verify all failed: %v", err)
			os.Exit(1)
		}
	case "billing":
		if err := handleBillingCommand(client, adminConfig, args); err != nil {
			logError("Billing command failed: %v", err)
			os.Exit(1)
		}
	case "payments":
		if err := handlePaymentsCommand(client, adminConfig, args); err != nil {
			logError("Payments command failed: %v", err)
			os.Exit(1)
		}
	case "subscriptions":
		if err := handleSubscriptionsCommand(client, adminConfig, args); err != nil {
			logError("Subscriptions command failed: %v", err)
			os.Exit(1)
		}
	case "version":
		printVersion()
	case "set-approval-policy":
		if err := handleSetApprovalPolicyCommand(client, adminConfig, args); err != nil {
			logError("Set approval policy failed: %v", err)
			os.Exit(1)
		}
	case "get-approval-policy":
		if err := handleGetApprovalPolicyCommand(client, adminConfig, args); err != nil {
			logError("Get approval policy failed: %v", err)
			os.Exit(1)
		}
	case "reset-registration-throttle":
		if err := handleResetRegistrationThrottleCommand(client, adminConfig, args); err != nil {
			logError("Reset registration throttle failed: %v", err)
			os.Exit(1)
		}
	case "rotate-user-secret-master":
		if err := handleRotateUserSecretMasterCommand(client, adminConfig, args); err != nil {
			logError("User-secret rotation failed: %v", err)
			os.Exit(1)
		}
	case "rotate-envelope-master":
		if err := handleRotateEnvelopeMasterCommand(client, adminConfig, args); err != nil {
			logError("Envelope master rotation failed: %v", err)
			os.Exit(1)
		}
	case "rotate-jwt-keys":
		if err := handleRotateJWTKeysCommand(client, adminConfig, args); err != nil {
			logError("JWT key rotation failed: %v", err)
			os.Exit(1)
		}
	case "rotate-opaque-keys":
		if err := handleRotateOpaqueKeysCommand(client, adminConfig, args); err != nil {
			logError("OPAQUE key rotation failed: %v", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("arkfile-admin %s\n", config.Version)
}

func printUsage() {
	fmt.Print(Usage)
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Printf("[VERBOSE] "+format+"\n", args...)
	}
}

func logError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}
