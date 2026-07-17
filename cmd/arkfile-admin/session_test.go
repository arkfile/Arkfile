package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRequireAdminSessionExpired(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "session.json")
	session := &AdminSession{
		Username:    "alice12345",
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(-time.Hour),
	}
	if err := saveAdminSession(session, tokenFile); err != nil {
		t.Fatalf("save session: %v", err)
	}

	cfg := &AdminConfig{TokenFile: tokenFile}
	_, err := requireAdminSession(cfg)
	if err == nil {
		t.Fatal("expected expired session error")
	}
	if err.Error() != adminSessionExpiredMsg {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequireAdminSessionValid(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "session.json")
	session := &AdminSession{
		Username:    "alice12345",
		AccessToken: "token",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := saveAdminSession(session, tokenFile); err != nil {
		t.Fatalf("save session: %v", err)
	}

	cfg := &AdminConfig{TokenFile: tokenFile}
	got, err := requireAdminSession(cfg)
	if err != nil {
		t.Fatalf("requireAdminSession: %v", err)
	}
	if got.AccessToken != "token" {
		t.Fatalf("unexpected token: %q", got.AccessToken)
	}
}

func TestRequireAdminSessionMissingFile(t *testing.T) {
	cfg := &AdminConfig{TokenFile: filepath.Join(t.TempDir(), "missing.json")}
	_, err := requireAdminSession(cfg)
	if err == nil {
		t.Fatal("expected error for missing session file")
	}
}

func TestRequireAdminMFASessionUsesTempToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "session.json")
	session := &AdminSession{
		Username:    "alice12345",
		TempToken:   "temp-token",
		AccessToken: "access-token",
	}
	if err := saveAdminSession(session, tokenFile); err != nil {
		t.Fatalf("save session: %v", err)
	}

	cfg := &AdminConfig{TokenFile: tokenFile}
	_, token, err := requireAdminMFASession(cfg)
	if err != nil {
		t.Fatalf("requireAdminMFASession: %v", err)
	}
	if token != "temp-token" {
		t.Fatalf("expected temp token, got %q", token)
	}
}
