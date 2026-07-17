package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	adminNotLoggedInMsg    = "not logged in as admin (use 'arkfile-admin login' first)"
	adminSessionExpiredMsg = "admin session expired, please login again"
)

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
	return os.WriteFile(filePath, data, 0600)
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
	session, err := loadAdminSession(config.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", adminNotLoggedInMsg, err)
	}
	if session.AccessToken == "" {
		return nil, fmt.Errorf("%s: session has no access token", adminNotLoggedInMsg)
	}
	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf(adminSessionExpiredMsg)
	}
	return session, nil
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
