package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const (
	adminNotLoggedInMsg    = "not logged in as admin (use 'arkfile-admin login' first)"
	adminSessionExpiredMsg = "admin session expired, please login again"
	adminSessionEndedMsg   = "admin session ended 60 minutes after login, please login again"
	adminSessionIdleMsg    = "admin session ended after 15 minutes without activity, please login again"
	adminLoggedOutMsg      = "admin session was logged out, please login again"
)

// adminSessionEndedError maps a server session code to the admin notice.
// ok is false when code is not a session-ended code.
func adminSessionEndedError(code string) (err error, ok bool) {
	switch code {
	case "session_idle":
		return errors.New(adminSessionIdleMsg), true
	case "session_absolute":
		return errors.New(adminSessionEndedMsg), true
	case "session_logged_out":
		return errors.New(adminLoggedOutMsg), true
	default:
		return nil, false
	}
}

// readSessionEndedCode returns the JSON error code from a refused response body.
func readSessionEndedCode(body []byte) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	return parsed.Error
}

// AdminConfig holds configuration for the admin client.
type AdminConfig struct {
	ServerURL     string `json:"server_url"`
	Username      string `json:"username"`
	TLSInsecure   bool   `json:"tls_insecure"`
	TLSMinVersion uint16 `json:"tls_min_version"`
	TokenFile     string `json:"token_file"`
	ConfigFile    string `json:"config_file"`
}

// AdminSession holds admin authentication session data.
type AdminSession struct {
	Username       string    `json:"username"`
	AccessToken    string    `json:"access_token"`
	RefreshToken   string    `json:"refresh_token"`
	TempToken      string    `json:"temp_token,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
	OPAQUEExport   string    `json:"opaque_export"`
	ServerURL      string    `json:"server_url"`
	SessionCreated time.Time `json:"session_created"`
	IsAdmin        bool      `json:"is_admin"`
}

func getAdminSessionFilePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".arkfile-admin-session.json"
	}
	return filepath.Join(homeDir, ".arkfile-admin-session.json")
}

func saveAdminSession(session *AdminSession, filePath string) error {
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, ".arkfile-admin-session.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, filePath)
}

func lockAdminSession(filePath string) (*os.File, error) {
	lock, err := os.OpenFile(filePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return lock, nil
}

func unlockAdminSession(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func loadAdminSession(filePath string) (*AdminSession, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var session AdminSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func loadConfigFile(config *AdminConfig, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, config)
}

// requireAdminSession loads the admin session and rejects expired sessions.
func requireAdminSession(config *AdminConfig) (*AdminSession, error) {
	lock, err := lockAdminSession(config.TokenFile)
	if err != nil {
		return nil, err
	}
	defer unlockAdminSession(lock)

	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", adminNotLoggedInMsg, err)
	}
	if session.AccessToken == "" && session.TempToken == "" {
		return nil, fmt.Errorf("%s: session has no access token", adminNotLoggedInMsg)
	}
	if session.AccessToken == "" {
		return session, nil
	}
	if session.ExpiresAt.IsZero() || time.Until(session.ExpiresAt) < 5*time.Minute {
		client := newHTTPClient(config.ServerURL, config.TLSInsecure, config.TLSMinVersion, false)
		if err := refreshAdminSession(client, session, config.TokenFile); err != nil {
			return nil, err
		}
	}
	return session, nil
}

func refreshAdminSession(client *HTTPClient, session *AdminSession, filePath string) error {
	if session.RefreshToken == "" {
		_ = os.Remove(filePath)
		return fmt.Errorf(adminSessionEndedMsg)
	}
	resp, err := client.makeRequest("POST", "/api/refresh", map[string]string{
		"refresh_token": session.RefreshToken,
	}, "")
	if err != nil {
		_ = os.Remove(filePath)
		if resp != nil {
			if endedErr, ok := adminSessionEndedError(resp.Error); ok {
				return endedErr
			}
		}
		return fmt.Errorf("%s: %v", adminSessionEndedMsg, err)
	}
	token, _ := resp.Data["token"].(string)
	refresh, _ := resp.Data["refresh_token"].(string)
	if token == "" {
		token = resp.Token
	}
	if refresh == "" {
		refresh = resp.RefreshToken
	}
	if token == "" {
		_ = os.Remove(filePath)
		return fmt.Errorf(adminSessionEndedMsg)
	}
	session.AccessToken = token
	if refresh != "" {
		session.RefreshToken = refresh
	}
	if expires, ok := resp.Data["expires_at"].(string); ok {
		if parsed, perr := time.Parse(time.RFC3339, expires); perr == nil {
			session.ExpiresAt = parsed
		}
	}
	return saveAdminSession(session, filePath)
}

// requireAdminMFASession loads a session for MFA setup/recovery using temp or access token.
// Temp tokens may have zero ExpiresAt during enrollment; access tokens still honor expiry.
func requireAdminMFASession(config *AdminConfig) (*AdminSession, string, error) {
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return nil, "", fmt.Errorf("not logged in (use 'arkfile-admin login' or 'bootstrap'): %w", err)
	}

	token := session.TempToken
	if token == "" {
		token = session.AccessToken
	}
	if token == "" {
		return nil, "", fmt.Errorf("no valid session found. Please register or login first")
	}

	if session.TempToken == "" && !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, "", fmt.Errorf(adminSessionExpiredMsg)
	}

	return session, token, nil
}

// requireBillingSession is retained as an alias during migration.
func requireBillingSession(config *AdminConfig) (*AdminSession, error) {
	return requireAdminSession(config)
}
