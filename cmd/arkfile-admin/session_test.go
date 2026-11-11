package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func saveTestAdminSession(t *testing.T, session *AdminSession) string {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "session.json")
	if err := saveAdminSession(session, tokenFile); err != nil {
		t.Fatalf("save session: %v", err)
	}
	return tokenFile
}

func sessionEndedServer(t *testing.T, code string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success":false,"error":%q,"message":"ended"}`, code)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestRefreshAdminSessionMapsEachEndedCode(t *testing.T) {
	cases := map[string]string{
		"session_idle":       adminSessionIdleMsg,
		"session_absolute":   adminSessionEndedMsg,
		"session_logged_out": adminLoggedOutMsg,
	}
	for code, want := range cases {
		t.Run(code, func(t *testing.T) {
			server := sessionEndedServer(t, code)
			tokenFile := saveTestAdminSession(t, &AdminSession{
				Username:     "alice12345",
				AccessToken:  "token",
				RefreshToken: "refresh",
				ExpiresAt:    time.Now().Add(time.Minute),
			})
			cfg := &AdminConfig{ServerURL: server.URL, TokenFile: tokenFile}
			_, err := requireAdminSession(cfg)
			if err == nil || err.Error() != want {
				t.Fatalf("got %v, want %q", err, want)
			}
			if _, statErr := os.Stat(tokenFile); !os.IsNotExist(statErr) {
				t.Fatalf("session file should be removed, stat err: %v", statErr)
			}
		})
	}
}

func TestAdminRequestRemovesSessionWhenServerEndsIt(t *testing.T) {
	server := sessionEndedServer(t, "session_idle")
	tokenFile := saveTestAdminSession(t, &AdminSession{Username: "alice12345", AccessToken: "token"})

	client := newHTTPClient(server.URL, false, 0, false)
	client.sessionFile = tokenFile
	_, err := client.makeRequest("GET", "/api/admin/users", nil, "token")
	if err == nil || err.Error() != adminSessionIdleMsg {
		t.Fatalf("got %v, want %q", err, adminSessionIdleMsg)
	}
	if _, statErr := os.Stat(tokenFile); !os.IsNotExist(statErr) {
		t.Fatalf("session file should be removed, stat err: %v", statErr)
	}
}

func TestAdminRequestKeepsSessionOnOtherUnauthorized(t *testing.T) {
	server := sessionEndedServer(t, "")
	tokenFile := saveTestAdminSession(t, &AdminSession{Username: "alice12345", AccessToken: "token"})

	client := newHTTPClient(server.URL, false, 0, false)
	client.sessionFile = tokenFile
	if _, err := client.makeRequest("GET", "/api/admin/users", nil, "token"); err == nil {
		t.Fatal("expected an error for HTTP 401")
	}
	if _, statErr := os.Stat(tokenFile); statErr != nil {
		t.Fatalf("session file should remain: %v", statErr)
	}
}

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
	if err.Error() != adminSessionEndedMsg {
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
