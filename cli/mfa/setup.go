package mfa

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/84adam/Arkfile/clictap"
	"github.com/pquerna/otp/totp"
)

// Method identifies the enrolled second factor type.
type Method string

const (
	MethodTOTP     Method = "totp"
	MethodWebAuthn Method = "webauthn"
)

// APIResponse is the subset of CLI HTTP responses MFA flows need.
type APIResponse struct {
	Success      bool
	Message      string
	Data         map[string]interface{}
	Token        string
	RefreshToken string
	ExpiresAt    time.Time
	TempToken    string
}

// Requester performs authenticated JSON API calls.
type Requester func(method, endpoint string, payload interface{}, token string) (*APIResponse, error)

// Session holds tokens needed during MFA setup/login.
type Session struct {
	AccessToken  string
	RefreshToken string
	TempToken    string
	ExpiresAt    time.Time
}

// SetupConfig drives interactive or scripted MFA enrollment.
type SetupConfig struct {
	ServerURL      string
	Token          string
	Method         Method
	Label          string
	AddSecond      bool
	ShowSecret     bool
	VerifyCode     string
	NonInteractive bool
	OnBackupCodes  func([]string)
	OnComplete     func(*APIResponse) error
}

// LoginMFAConfig drives the second factor step after OPAQUE login.
type LoginMFAConfig struct {
	ServerURL      string
	MFAMethod      Method
	CredentialID   string
	TempToken      string
	TOTPCode       string
	TOTPSecret     string
	BackupCode     string
	NonInteractive bool
}

// PickMethod interactively chooses totp or webauthn.
func PickMethod(nonInteractive bool, methodFlag Method) (Method, error) {
	if methodFlag == MethodTOTP || methodFlag == MethodWebAuthn {
		return methodFlag, nil
	}
	if nonInteractive {
		return "", fmt.Errorf("non-interactive mode: --mfa-method totp|webauthn required")
	}
	fmt.Println("Choose second factor method:")
	fmt.Println("  1) Authenticator app (TOTP)")
	fmt.Println("  2) Security key (WebAuthn)")
	fmt.Print("Enter 1 or 2: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(line) {
	case "1":
		return MethodTOTP, nil
	case "2":
		return MethodWebAuthn, nil
	default:
		return "", fmt.Errorf("invalid method selection")
	}
}

// SetupResult is returned after interactive or scripted MFA enrollment.
type SetupResult struct {
	Response *APIResponse
	Method   Method
}

// RunSetup enrolls TOTP or a security key.
func RunSetup(req Requester, cfg SetupConfig) (*SetupResult, error) {
	method := cfg.Method
	if method == "" {
		var err error
		method, err = PickMethod(cfg.NonInteractive, "")
		if err != nil {
			return nil, err
		}
	}

	switch method {
	case MethodWebAuthn:
		resp, err := runWebAuthnSetup(req, cfg)
		if err != nil {
			return nil, err
		}
		return &SetupResult{Response: resp, Method: MethodWebAuthn}, nil
	default:
		resp, err := runTOTPSetup(req, cfg)
		if err != nil {
			return nil, err
		}
		return &SetupResult{Response: resp, Method: MethodTOTP}, nil
	}
}

func runWebAuthnSetup(req Requester, cfg SetupConfig) (*APIResponse, error) {
	beginPath := "/api/mfa/webauthn/register/begin"
	finishPath := "/api/mfa/webauthn/register/finish"
	if cfg.AddSecond {
		beginPath = "/api/mfa/credentials/webauthn/register/begin"
		finishPath = "/api/mfa/credentials/webauthn/register/finish"
	}

	begin, err := req("POST", beginPath, map[string]interface{}{}, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to start security key enrollment: %w", err)
	}
	optsRaw, err := extractOptionsJSON(begin.Data)
	if err != nil {
		return nil, err
	}

	if codes := stringSlice(begin.Data["backup_codes"]); len(codes) > 0 {
		emitBackupCodes(codes, cfg)
	} else if isResumeEnrollment(begin.Data) {
		if cfg.ShowSecret {
			fmt.Println("BACKUP_CODES: (resume: use codes from earlier in this session)")
		} else {
			fmt.Println("\nBackup codes were issued in an earlier step this session. Use your saved copy.")
		}
	}

	fmt.Println("Touch your security key when prompted...")
	origin := clictap.OriginFromServerURL(cfg.ServerURL)
	credential, err := clictap.RegisterFromOptions(optsRaw, origin)
	if err != nil {
		return nil, err
	}

	finish, err := req("POST", finishPath, map[string]interface{}{
		"credential": json.RawMessage(credential),
		"label":      cfg.Label,
	}, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("security key enrollment verification failed: %w", err)
	}
	if cfg.OnComplete != nil {
		if err := cfg.OnComplete(finish); err != nil {
			return nil, err
		}
	}
	return finish, nil
}

func runTOTPSetup(req Requester, cfg SetupConfig) (*APIResponse, error) {
	if cfg.VerifyCode != "" {
		return req("POST", "/api/mfa/verify", map[string]string{"code": cfg.VerifyCode}, cfg.Token)
	}

	setupPath := "/api/mfa/setup"
	if cfg.AddSecond {
		setupPath = "/api/mfa/credentials/totp/add"
	}

	setup, err := req("POST", setupPath, nil, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to initiate TOTP setup: %w", err)
	}

	secret, _ := setup.Data["secret"].(string)
	if secret == "" {
		return nil, fmt.Errorf("invalid server response: missing secret")
	}

	if codes := stringSlice(setup.Data["backup_codes"]); len(codes) > 0 {
		emitBackupCodes(codes, cfg)
	}

	if cfg.ShowSecret {
		fmt.Printf("TOTP_SECRET:%s\n", secret)
		return nil, nil
	}

	fmt.Println("=== Two-Factor Authentication Setup ===")
	fmt.Println("1. Open your authenticator app")
	fmt.Println("2. Add a new account manually")
	fmt.Printf("3. Enter this secret key: %s\n", secret)
	fmt.Println("=======================================")

	code := cfg.VerifyCode
	if code == "" {
		fmt.Print("Enter the 6-digit code from your app: ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		code = strings.TrimSpace(line)
	}

	verify, err := req("POST", "/api/mfa/verify", map[string]string{"code": code}, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to verify TOTP code: %w", err)
	}
	if cfg.OnComplete != nil {
		if err := cfg.OnComplete(verify); err != nil {
			return nil, err
		}
	}
	return verify, nil
}

// CompleteLogin performs the MFA step after OPAQUE authentication.
func CompleteLogin(req Requester, cfg LoginMFAConfig) (*APIResponse, error) {
	if cfg.BackupCode != "" {
		if len(cfg.BackupCode) != 10 {
			return nil, fmt.Errorf("backup code must be exactly 10 characters")
		}
		return req("POST", "/api/mfa/auth", map[string]interface{}{
			"code":      cfg.BackupCode,
			"is_backup": true,
		}, cfg.TempToken)
	}

	switch cfg.MFAMethod {
	case MethodWebAuthn:
		return completeWebAuthnLogin(req, cfg)
	default:
		return completeTOTPLogin(req, cfg)
	}
}

func completeWebAuthnLogin(req Requester, cfg LoginMFAConfig) (*APIResponse, error) {
	beginBody := map[string]interface{}{}
	if cfg.CredentialID != "" {
		beginBody["credential_id"] = cfg.CredentialID
	}
	begin, err := req("POST", "/api/mfa/webauthn/auth/begin", beginBody, cfg.TempToken)
	if err != nil {
		return nil, fmt.Errorf("failed to start security key authentication: %w", err)
	}
	optsRaw, err := extractOptionsJSON(begin.Data)
	if err != nil {
		return nil, err
	}

	fmt.Println("Touch your security key when prompted...")
	origin := clictap.OriginFromServerURL(cfg.ServerURL)
	credential, err := clictap.AuthenticateFromOptions(optsRaw, origin)
	if err != nil {
		return nil, err
	}

	finish, err := req("POST", "/api/mfa/webauthn/auth/finish", map[string]interface{}{
		"credential":    json.RawMessage(credential),
		"credential_id": cfg.CredentialID,
	}, cfg.TempToken)
	if err != nil {
		return nil, fmt.Errorf("security key authentication failed: %w", err)
	}
	return finish, nil
}

func completeTOTPLogin(req Requester, cfg LoginMFAConfig) (*APIResponse, error) {
	code := cfg.TOTPCode
	if code == "" && cfg.TOTPSecret != "" {
		generated, err := totp.GenerateCode(cfg.TOTPSecret, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("failed to generate TOTP code from secret: %w", err)
		}
		code = generated
	}
	if code == "" {
		if cfg.NonInteractive {
			return nil, fmt.Errorf("non-interactive mode: --totp-code, --totp-secret, or --backup-code required")
		}
		fmt.Print("Enter TOTP code: ")
		reader := bufio.NewReader(os.Stdin)
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		code = strings.TrimSpace(line)
	}

	resp, err := req("POST", "/api/mfa/auth", map[string]interface{}{
		"code":      code,
		"is_backup": false,
	}, cfg.TempToken)
	if err != nil {
		return nil, fmt.Errorf("TOTP authentication failed: %w", err)
	}
	return resp, nil
}

func extractOptionsJSON(data map[string]interface{}) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("missing response data")
	}
	opts, ok := data["options"]
	if !ok {
		return nil, fmt.Errorf("missing options in server response")
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal options: %w", err)
	}
	return raw, nil
}

func stringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func isResumeEnrollment(data map[string]interface{}) bool {
	if data == nil {
		return false
	}
	resume, _ := data["resume"].(bool)
	return resume
}

func emitBackupCodes(codes []string, cfg SetupConfig) {
	if cfg.OnBackupCodes != nil {
		cfg.OnBackupCodes(codes)
	}
	if cfg.ShowSecret {
		PrintAutomationBackupCodes(codes)
		return
	}
	PrintBackupCodes(codes)
}

// PickLoginMethod resolves which enrolled factor to use at login.
func PickLoginMethod(nonInteractive bool, methods []map[string]string, methodFlag Method, credentialIDFlag string) (Method, string, error) {
	if credentialIDFlag != "" {
		for _, m := range methods {
			if m["credential_id"] == credentialIDFlag {
				return Method(strings.TrimSpace(m["type"])), credentialIDFlag, nil
			}
		}
		return "", "", fmt.Errorf("credential id %q not found in enrolled methods", credentialIDFlag)
	}

	if methodFlag == MethodTOTP || methodFlag == MethodWebAuthn {
		return methodFlag, "", nil
	}

	if len(methods) == 0 {
		return MethodTOTP, "", nil
	}
	if len(methods) == 1 {
		return Method(strings.TrimSpace(methods[0]["type"])), methods[0]["credential_id"], nil
	}

	if nonInteractive {
		return "", "", fmt.Errorf("non-interactive mode: multiple MFA methods enrolled; pass --mfa-method and --credential-id when needed")
	}

	fmt.Println("Choose second factor:")
	for i, m := range methods {
		label := strings.TrimSpace(m["type"])
		if label == "webauthn" {
			if l := strings.TrimSpace(m["label"]); l != "" {
				label = "security key: " + l
			} else {
				label = "security key"
			}
		} else {
			label = "authenticator app (TOTP)"
		}
		fmt.Printf("  %d) %s\n", i+1, label)
	}
	fmt.Print("Enter number: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	choice := strings.TrimSpace(line)
	idx := 0
	if _, scanErr := fmt.Sscanf(choice, "%d", &idx); scanErr != nil || idx < 1 || idx > len(methods) {
		return "", "", fmt.Errorf("invalid method selection")
	}
	selected := methods[idx-1]
	return Method(strings.TrimSpace(selected["type"])), selected["credential_id"], nil
}

// ParseMFAMethods reads mfa_methods from OPAQUE finalize responses.
func ParseMFAMethods(data map[string]interface{}) []map[string]string {
	raw, ok := data["mfa_methods"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		method := map[string]string{"type": strings.TrimSpace(fmt.Sprint(entry["type"]))}
		if id, _ := entry["credential_id"].(string); id != "" {
			method["credential_id"] = id
		}
		if label, _ := entry["label"].(string); label != "" {
			method["label"] = label
		}
		out = append(out, method)
	}
	return out
}

// ParseMFAMethod normalizes mfa_method from OPAQUE finalize responses.
func ParseMFAMethod(data map[string]interface{}) Method {
	if data == nil {
		return MethodTOTP
	}
	raw, _ := data["mfa_method"].(string)
	switch strings.TrimSpace(raw) {
	case "webauthn":
		return MethodWebAuthn
	case "totp":
		return MethodTOTP
	default:
		return MethodTOTP
	}
}
