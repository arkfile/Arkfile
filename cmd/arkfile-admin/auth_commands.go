package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/cli/mfa"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/utils"
)

// handleBootstrapCommand processes the bootstrap command
func handleBootstrapCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	var (
		tokenFlag    = fs.String("token", "", "Bootstrap token (argv exposure possible)")
		tokenStdin   = fs.Bool("token-stdin", false, "Read bootstrap token from standard input (secure)")
		usernameFlag = fs.String("username", "admin", "Username for admin account")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin bootstrap [FLAGS]

Bootstrap the first admin user using the token provided by the server logs.

FLAGS:
    --token TOKEN      Bootstrap token from server logs (argv exposure possible)
    --token-stdin      Read bootstrap token from standard input (secure)
    --username USER    Username for admin account (default: admin)
    --help            Show this help message

EXAMPLES:
    arkfile-admin bootstrap --token-stdin < /opt/arkfile/etc/keys/bootstrap-token.bin
    sudo cat /opt/arkfile/etc/keys/bootstrap-token.bin | arkfile-admin bootstrap --token-stdin
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	var finalToken string
	if *tokenStdin {
		// Read token from standard input (stdin) to prevent argv exposure.
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read token from stdin: %w", err)
		}
		finalToken = strings.TrimSpace(input)
	} else {
		finalToken = *tokenFlag
	}

	if finalToken == "" {
		return fmt.Errorf("bootstrap token is required (provide via --token or --token-stdin)")
	}

	adminUsername := strings.ToLower(strings.TrimSpace(*usernameFlag))
	if err := utils.ValidateUsername(adminUsername); err != nil {
		return fmt.Errorf("invalid username: %w\n\nUsername requirements: 10-50 characters, allowed: a-z 0-9 _ - . ,", err)
	}

	// Get password securely
	fmt.Printf("Enter password for admin user %s: ", *usernameFlag)
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Confirm password
	fmt.Print("Confirm password: ")
	passwordConfirm, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password confirmation: %w", err)
	}

	// Verify passwords match
	if password != passwordConfirm {
		return fmt.Errorf("passwords do not match")
	}

	// Validate password meets requirements (min/max length, character classes)
	validation := crypto.ValidateAccountPassword(password)
	if !validation.MeetsRequirement {
		reasons := ""
		for i, r := range validation.Reasons {
			if i > 0 {
				reasons += "; "
			}
			reasons += r
		}
		return fmt.Errorf("password does not meet requirements: %s", reasons)
	}

	// Perform OPAQUE multi-step registration
	logVerbose("Starting OPAQUE bootstrap for user: %s", adminUsername)

	// Step 1: Create registration request (client-side)
	clientSecret, registrationRequest, err := auth.ClientCreateRegistrationRequest([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	// Encode registration request for transmission
	registrationRequestB64 := base64.StdEncoding.EncodeToString(registrationRequest)

	// Step 2: Send registration request to server
	regReq := map[string]string{
		"bootstrap_token":      finalToken,
		"username":             adminUsername,
		"registration_request": registrationRequestB64,
	}

	regResp, err := client.makeRequest("POST", "/api/bootstrap/register/response", regReq, "")
	if err != nil {
		return fmt.Errorf("bootstrap registration failed: %w", err)
	}

	// Step 3: Decode server's registration response
	registrationResponseB64, ok := regResp.Data["registration_response"].(string)
	if !ok {
		return fmt.Errorf("invalid server response: missing registration_response")
	}

	sessionID, ok := regResp.Data["session_id"].(string)
	if !ok || sessionID == "" {
		return fmt.Errorf("invalid server response: missing session_id")
	}

	registrationResponse, err := base64.StdEncoding.DecodeString(registrationResponseB64)
	if err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	// Step 4: Finalize registration (client-side). idS is fetched from the
	// server so all OPAQUE participants bind the same server identity.
	serverID, err := client.fetchOpaqueServerID()
	if err != nil {
		return fmt.Errorf("failed to fetch OPAQUE server identity: %w", err)
	}
	registrationRecord, _, err := auth.ClientFinalizeRegistration(clientSecret, registrationResponse, adminUsername, serverID)
	if err != nil {
		return fmt.Errorf("failed to finalize registration: %w", err)
	}

	// Encode registration record for transmission
	registrationRecordB64 := base64.StdEncoding.EncodeToString(registrationRecord)

	// Step 5: Send registration record to server to complete registration
	finalizeReq := map[string]string{
		"bootstrap_token":     finalToken,
		"session_id":          sessionID,
		"username":            adminUsername,
		"registration_record": registrationRecordB64,
	}

	regFinalizeResp, err := client.makeRequest("POST", "/api/bootstrap/register/finalize", finalizeReq, "")
	if err != nil {
		return fmt.Errorf("bootstrap finalization failed: %w", err)
	}

	fmt.Printf("Bootstrap successful! Admin user '%s' created.\n", adminUsername)

	// Handle TOTP requirement
	requiresTOTP, _ := regFinalizeResp.Data["requires_mfa"].(bool)
	tempToken, _ := regFinalizeResp.Data["temp_token"].(string)

	if requiresTOTP && tempToken != "" {
		session := &AdminSession{
			Username:       adminUsername,
			TempToken:      tempToken,
			ServerURL:      config.ServerURL,
			SessionCreated: time.Now(),
			ExpiresAt:      time.Now().Add(15 * time.Minute), // Temp token usually short-lived
			IsAdmin:        true,
		}

		if err := saveAdminSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save session for TOTP setup: %v", err)
		} else {
			fmt.Printf("\nMFA setup required. Session saved.\n")
			fmt.Printf("Please run 'arkfile-admin setup-mfa' to complete account setup.\n")
		}
	}

	return nil
}

// handleSetupMFACommand processes MFA setup (TOTP or security key).
func handleSetupMFACommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("setup-mfa", flag.ExitOnError)
	var (
		showSecret = fs.Bool("show-secret", false, "Only show the secret key and exit (for automation)")
		verifyCode = fs.String("verify", "", "Verify TOTP setup with a code (for automation)")
		mfaMethod  = fs.String("mfa-method", "", "Enrollment method: totp or webauthn")
		addSecond  = fs.Bool("add-second", false, "Add a complementary second factor while logged in")
		label      = fs.String("label", "", "Optional private label for a security key (max 64 printable ASCII)")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin setup-mfa [FLAGS]

Setup Two-Factor Authentication for the account (TOTP or security key).
This is usually required immediately after registration.

FLAGS:
    --mfa-method METHOD  totp or webauthn (interactive picker if omitted)
    --add-second         Add the complementary second factor (no new backup codes)
    --label TEXT         Optional private security key label
    --show-secret        Only show the TOTP secret and exit (for automation)
    --verify CODE        Verify TOTP setup with a code (for automation)
    --help               Show this help message

EXAMPLES:
    arkfile-admin setup-mfa
    arkfile-admin setup-mfa --mfa-method webauthn --label "Bootstrap key"
    arkfile-admin setup-mfa --add-second --mfa-method totp
    arkfile-admin setup-mfa --show-secret
    arkfile-admin setup-mfa --verify 123456
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	session, token, err := requireAdminMFASession(config)
	if err != nil {
		return err
	}

	if *verifyCode != "" {
		return verifyTOTP(client, config, session, token, *verifyCode)
	}

	method := mfa.Method(strings.ToLower(strings.TrimSpace(*mfaMethod)))
	result, err := mfa.RunSetup(adminMFARequester(client), mfa.SetupConfig{
		ServerURL:  config.ServerURL,
		Token:      token,
		Method:     method,
		Label:      strings.TrimSpace(*label),
		AddSecond:  *addSecond,
		ShowSecret: *showSecret,
		OnComplete: func(resp *mfa.APIResponse) error {
			if resp.Token != "" {
				session.AccessToken = resp.Token
			}
			if resp.RefreshToken != "" {
				session.RefreshToken = resp.RefreshToken
			}
			if !resp.ExpiresAt.IsZero() {
				session.ExpiresAt = resp.ExpiresAt
			}
			session.TempToken = ""
			return saveAdminSession(session, config.TokenFile)
		},
	})
	if err != nil {
		return err
	}
	if result == nil || result.Response == nil {
		return nil
	}

	mfa.PrintSetupComplete()
	return nil
}

func verifyTOTP(client *HTTPClient, config *AdminConfig, session *AdminSession, token, code string) error {
	verifyReq := map[string]string{
		"code": code,
	}

	verifyResp, err := client.makeRequest("POST", "/api/mfa/verify", verifyReq, token)
	if err != nil {
		return fmt.Errorf("failed to verify TOTP code: %w", err)
	}

	// Update session with final tokens
	if token, ok := verifyResp.Data["token"].(string); ok {
		session.AccessToken = token
	}
	if refreshToken, ok := verifyResp.Data["refresh_token"].(string); ok {
		session.RefreshToken = refreshToken
	}
	if expiresStr, ok := verifyResp.Data["expires_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, expiresStr); err == nil {
			session.ExpiresAt = t
		}
	}

	session.TempToken = "" // Clear temp token

	if err := saveAdminSession(session, config.TokenFile); err != nil {
		logError("Warning: Failed to save updated session: %v", err)
	}

	mfa.PrintSetupComplete()

	return nil
}

// handleLoginCommand processes admin login command
func handleLoginCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var (
		usernameFlag   = fs.String("username", config.Username, "Admin username for login")
		saveSession    = fs.Bool("save-session", true, "Save session for future use")
		totpCode       = fs.String("totp-code", "", "TOTP code for non-interactive login")
		totpSecret     = fs.String("totp-secret", "", "TOTP secret — CLI generates the code internally (for scripted/test use)")
		backupCode     = fs.String("backup-code", "", "10-character backup code for one-shot emergency login")
		mfaMethod      = fs.String("mfa-method", "", "Second factor method for login: totp or webauthn")
		credentialID   = fs.String("credential-id", "", "WebAuthn credential id when multiple security keys are enrolled")
		nonInteractive = fs.Bool("non-interactive", false, "Don't prompt for input")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin login [FLAGS]

Authenticate as administrator using OPAQUE protocol.

FLAGS:
    --username USER     Admin username for authentication (required)
    --save-session      Save session for future use (default: true)
    --totp-code CODE    TOTP code for non-interactive login
    --totp-secret SEC   TOTP secret — CLI generates code internally (for scripted/test use)
    --backup-code CODE  10-character backup code for emergency login
    --mfa-method METHOD Second factor for login: totp or webauthn
    --credential-id ID  WebAuthn credential id when choosing a specific key
    --non-interactive   Don't prompt for input
    --help              Show this help message

EXAMPLES:
    arkfile-admin login --username admin
    arkfile-admin login --username root --save-session=false
    arkfile-admin login --username admin --totp-secret YOURSECRETHERE
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *usernameFlag == "" {
		return fmt.Errorf("admin username is required")
	}

	// Get password securely
	fmt.Printf("Enter admin password for %s: ", *usernameFlag)
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Perform multi-step OPAQUE login with admin verification
	logVerbose("Starting multi-step OPAQUE authentication for admin user: %s", *usernameFlag)

	// Step 1: Create credential request
	clientState, credentialRequest, err := auth.ClientCreateCredentialRequest([]byte(password))
	if err != nil {
		return fmt.Errorf("failed to create credential request: %w", err)
	}

	// Step 2: Send credential request to server
	authStartReq := map[string]string{
		"username":           *usernameFlag,
		"credential_request": base64.StdEncoding.EncodeToString(credentialRequest),
	}

	authStartResp, err := client.makeRequest("POST", "/api/admin/login/response", authStartReq, "")
	if err != nil {
		return fmt.Errorf("admin authentication start failed: %w", err)
	}

	sessionID, ok := authStartResp.Data["session_id"].(string)
	if !ok {
		return fmt.Errorf("invalid session ID in response")
	}

	credentialResponseStr, ok := authStartResp.Data["credential_response"].(string)
	if !ok {
		return fmt.Errorf("invalid credential response")
	}

	// Decode base64 credential response
	credentialResponse, err := base64.StdEncoding.DecodeString(credentialResponseStr)
	if err != nil {
		return fmt.Errorf("failed to decode credential response: %w", err)
	}

	// Step 3: Recover credentials and create auth token. idS is fetched from
	// the server so all OPAQUE participants bind the same server identity.
	serverID, err := client.fetchOpaqueServerID()
	if err != nil {
		return fmt.Errorf("failed to fetch OPAQUE server identity: %w", err)
	}
	_, authU, exportKey, err := auth.ClientRecoverCredentials(clientState, credentialResponse, *usernameFlag, serverID)
	if err != nil {
		return fmt.Errorf("incorrect password or account not found")
	}

	// Step 4: Finalize authentication
	authFinishReq := map[string]string{
		"session_id": sessionID,
		"username":   *usernameFlag,
		"auth_u":     base64.StdEncoding.EncodeToString(authU),
	}

	loginResp, err := client.makeRequest("POST", "/api/admin/login/finalize", authFinishReq, "")
	if err != nil {
		return fmt.Errorf("admin authentication finalization failed: %w", err)
	}

	// Extract data from login response
	var accessToken, refreshToken, opaqueExport string
	var expiresAt time.Time

	// Check if TOTP is required
	requiresTOTP, _ := loginResp.Data["requires_mfa"].(bool)
	requiresTOTPSetup, _ := loginResp.Data["requires_mfa_setup"].(bool)

	if requiresTOTPSetup {
		tempToken, _ := loginResp.Data["temp_token"].(string)
		if tempToken == "" {
			return fmt.Errorf("missing temporary TOTP token in response")
		}
		// Save session for setup-mfa
		session := &AdminSession{
			Username:       *usernameFlag,
			TempToken:      tempToken,
			ServerURL:      config.ServerURL,
			SessionCreated: time.Now(),
			ExpiresAt:      time.Now().Add(15 * time.Minute),
			IsAdmin:        true,
		}
		if err := saveAdminSession(session, config.TokenFile); err != nil {
			return fmt.Errorf("failed to save admin session for TOTP setup: %w", err)
		}
		fmt.Printf("\nMFA setup required. Session saved.\n")
		fmt.Printf("Please run 'arkfile-admin setup-mfa' to complete account setup.\n")
		return nil
	}

	if requiresTOTP {
		tempToken, _ := loginResp.Data["temp_token"].(string)
		if tempToken == "" {
			return fmt.Errorf("missing temporary MFA token in response")
		}

		methods := mfa.ParseMFAMethods(loginResp.Data)
		chosenMethod, chosenCredentialID, pickErr := mfa.PickLoginMethod(
			*nonInteractive,
			methods,
			mfa.Method(strings.ToLower(strings.TrimSpace(*mfaMethod))),
			strings.TrimSpace(*credentialID),
		)
		if pickErr != nil {
			return pickErr
		}

		mfaResp, err := mfa.CompleteLogin(adminMFARequester(client), mfa.LoginMFAConfig{
			ServerURL:      config.ServerURL,
			MFAMethod:      chosenMethod,
			CredentialID:   chosenCredentialID,
			TempToken:      tempToken,
			TOTPCode:       *totpCode,
			TOTPSecret:     *totpSecret,
			BackupCode:     *backupCode,
			NonInteractive: *nonInteractive,
		})
		if err != nil {
			return err
		}

		accessToken = mfaResp.Token
		refreshToken = mfaResp.RefreshToken
		if !mfaResp.ExpiresAt.IsZero() {
			expiresAt = mfaResp.ExpiresAt
		} else if expiresStr, ok := mfaResp.Data["expires_at"].(string); ok {
			expiresAt, _ = time.Parse(time.RFC3339, expiresStr)
		}
		opaqueExport, _ = mfaResp.Data["opaque_export"].(string)
	} else {
		// Get tokens directly from login response
		accessToken, _ = loginResp.Data["token"].(string)
		refreshToken, _ = loginResp.Data["refresh_token"].(string)
		// Use the export key we derived locally if not provided by server
		if export, ok := loginResp.Data["opaque_export"].(string); ok {
			opaqueExport = export
		} else {
			opaqueExport = base64.StdEncoding.EncodeToString(exportKey)
		}

		if expiresStr, ok := loginResp.Data["expires_at"].(string); ok {
			expiresAt, _ = time.Parse(time.RFC3339, expiresStr)
		}
	}

	// Create admin session
	session := &AdminSession{
		Username:       *usernameFlag,
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		ExpiresAt:      expiresAt,
		OPAQUEExport:   opaqueExport,
		ServerURL:      config.ServerURL,
		SessionCreated: time.Now(),
		IsAdmin:        true,
	}

	// Save session if requested
	if *saveSession {
		if err := saveAdminSession(session, config.TokenFile); err != nil {
			logError("Warning: Failed to save admin session: %v", err)
		} else {
			logVerbose("Admin session saved to: %s", config.TokenFile)
		}
	}

	fmt.Printf("Admin login successful for user: %s\n", *usernameFlag)
	fmt.Printf("Session expires: %s\n", session.ExpiresAt.Format("2006-01-02 15:04:05"))

	// Check for storage alerts and display after login
	displayLoginAlerts(client, session.AccessToken)
	fmt.Printf("Administrative privileges active\n")

	return nil
}

func handleLogoutCommand(config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin logout

Clear the saved admin session and logout.

EXAMPLES:
    arkfile-admin logout
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.Remove(config.TokenFile); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove admin session file: %w", err)
		}
	}

	fmt.Printf("Admin logout successful\n")
	return nil
}

