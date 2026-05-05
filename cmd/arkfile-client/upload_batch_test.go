// upload_batch_test.go - Unit tests for multi-file upload batch helpers.
// Tests isFatalUploadError, collectUploadInputs, ensureFreshSessionToken,
// makeRequestWithSession, and atomicSaveAuthSession.
//
// All tests run without a live server: network-touching tests use
// httptest.NewServer so they remain deterministic and offline-safe.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================
// isFatalUploadError
// ============================================================

func TestIsFatalUploadError_Sentinels(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		fatal bool
	}{
		{"nil", nil, false},
		{"errAuthExpired", errAuthExpired, true},
		{"errTooManyInProgressUploads", errTooManyInProgressUploads, true},
		{"errQuotaExceeded", errQuotaExceeded, true},
		{"errAccountDisabled", errAccountDisabled, true},
		{"generic non-fatal", errors.New("network timeout"), false},
		{"wrapped authExpired", fmt.Errorf("batch: %w", errAuthExpired), true},
		{"wrapped quota", fmt.Errorf("file failed: %w", errQuotaExceeded), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isFatalUploadError(tc.err)
			if got != tc.fatal {
				t.Errorf("isFatalUploadError(%v) = %v, want %v", tc.err, got, tc.fatal)
			}
		})
	}
}

func TestIsFatalUploadError_TextualClassification(t *testing.T) {
	// Best-effort textual classification for messages not using sentinels.
	cases := []struct {
		msg   string
		fatal bool
	}{
		{"HTTP 429: too_many_in_progress_uploads", true},
		{"storage limit would be exceeded", true},
		{"quota exceeded for user", true},
		{"pending approval required", true},
		{"account disabled by admin", true},
		{"connection reset by peer", false},
		{"file not found", false},
	}
	for _, tc := range cases {
		t.Run(tc.msg, func(t *testing.T) {
			err := errors.New(tc.msg)
			got := isFatalUploadError(err)
			if got != tc.fatal {
				t.Errorf("isFatalUploadError(%q) = %v, want %v", tc.msg, got, tc.fatal)
			}
		})
	}
}

// ============================================================
// collectUploadInputs
// ============================================================

func TestCollectUploadInputs_SingleFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(f, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := collectUploadInputs([]string{f}, nil, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 file, got %d", len(result))
	}
}

func TestCollectUploadInputs_DeduplicatesAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(f, []byte("dup"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := collectUploadInputs([]string{f, f}, []string{f}, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 unique file, got %d", len(result))
	}
}

func TestCollectUploadInputs_SortedOutput(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"c.txt", "a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	flags := []string{
		filepath.Join(dir, "c.txt"),
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	}
	result, err := collectUploadInputs(flags, nil, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("expected 3 files, got %d", len(result))
	}
	for i := 1; i < len(result); i++ {
		if result[i] < result[i-1] {
			t.Errorf("output not sorted: %v", result)
			break
		}
	}
}

func TestCollectUploadInputs_DirNonRecursive(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("top"), 0644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "deep.txt"), []byte("deep"), 0644); err != nil {
		t.Fatal(err)
	}
	// Non-recursive: should find top.txt but not sub/deep.txt
	result, err := collectUploadInputs(nil, nil, root, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range result {
		if strings.Contains(p, "deep.txt") {
			t.Errorf("non-recursive walk should not include sub/deep.txt")
		}
	}
	found := false
	for _, p := range result {
		if strings.HasSuffix(p, "top.txt") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected top.txt in results, got %v", result)
	}
}

func TestCollectUploadInputs_DirRecursive(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("t"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "deep.txt"), []byte("d"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := collectUploadInputs(nil, nil, root, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 files with --recursive, got %d: %v", len(result), result)
	}
}

func TestCollectUploadInputs_SkipsDotfiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".hidden"), []byte("h"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("v"), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := collectUploadInputs(nil, nil, root, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, p := range result {
		if strings.Contains(filepath.Base(p), ".hidden") {
			t.Errorf("dotfile should be skipped, got %s", p)
		}
	}
	found := false
	for _, p := range result {
		if strings.HasSuffix(p, "visible.txt") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected visible.txt in results, got %v", result)
	}
}

func TestCollectUploadInputs_EmptyInputReturnsEmpty(t *testing.T) {
	result, err := collectUploadInputs(nil, nil, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestCollectUploadInputs_NonExistentFileReturnsError(t *testing.T) {
	_, err := collectUploadInputs([]string{"/this/does/not/exist.txt"}, nil, "", false)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

// ============================================================
// atomicSaveAuthSession
// ============================================================

func TestAtomicSaveAuthSession_WritesCorrectly(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "session.json")

	session := &AuthSession{
		Username:     "testuser",
		AccessToken:  "tok-abc",
		RefreshToken: "ref-xyz",
		ExpiresAt:    time.Now().Add(30 * time.Minute).Truncate(time.Second),
	}

	if err := atomicSaveAuthSession(session, target); err != nil {
		t.Fatalf("atomicSaveAuthSession returned error: %v", err)
	}

	// File must exist and be mode 0600.
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected mode 0600, got %v", fi.Mode().Perm())
	}

	// No temp file left over.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file still present after atomic save: %s", e.Name())
		}
	}

	// Content round-trips cleanly.
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var got AuthSession
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal saved session: %v", err)
	}
	if got.Username != session.Username {
		t.Errorf("username mismatch: got %q want %q", got.Username, session.Username)
	}
	if got.AccessToken != session.AccessToken {
		t.Errorf("access_token mismatch: got %q want %q", got.AccessToken, session.AccessToken)
	}
}

func TestAtomicSaveAuthSession_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "session.json")

	old := &AuthSession{Username: "old", AccessToken: "old-tok"}
	if err := atomicSaveAuthSession(old, target); err != nil {
		t.Fatal(err)
	}

	fresh := &AuthSession{Username: "new", AccessToken: "new-tok"}
	if err := atomicSaveAuthSession(fresh, target); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(target)
	var got AuthSession
	json.Unmarshal(data, &got)
	if got.Username != "new" {
		t.Errorf("expected overwritten session username 'new', got %q", got.Username)
	}
}

// ============================================================
// ensureFreshSessionToken
// ============================================================

// refreshCallCount is a helper that runs a mock /api/refresh server and
// returns how many times it was called after ensureFreshSessionToken runs.
func runEnsureFreshTest(t *testing.T, expiresAt time.Time, threshold time.Duration, serverStatus int) (int, error) {
	t.Helper()
	calls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/refresh" {
			calls++
			if serverStatus != http.StatusOK {
				w.WriteHeader(serverStatus)
				fmt.Fprintf(w, `{"success":false,"error":"bad_token"}`)
				return
			}
			newExpiry := time.Now().Add(30 * time.Minute)
			resp := map[string]interface{}{
				"success":       true,
				"token":         "new-tok",
				"refresh_token": "new-ref",
				"expires_at":    newExpiry.Format(time.RFC3339),
			}
			json.NewEncoder(w).Encode(resp)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	dir := t.TempDir()
	sessionFile := filepath.Join(dir, "test-session.json")

	session := &AuthSession{
		Username:     "testuser",
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    expiresAt,
	}
	if err := atomicSaveAuthSession(session, sessionFile); err != nil {
		t.Fatal(err)
	}

	// Override the global session file path for this test. We do this by
	// calling ensureFreshSessionToken directly; refreshSessionToken uses
	// getSessionFilePath() internally. We pass a temporary file path by
	// testing atomicSaveAuthSession separately (tested above). Here we
	// accept that the production code writes to ~/.arkfile-session.json
	// but since no token rotation happens when status is 200 (the
	// mutation is in-memory), we can verify the mutation on `session`.
	err := ensureFreshSessionToken(client, session, threshold)

	return calls, err
}

func TestEnsureFreshSessionToken_NoRefreshNeeded(t *testing.T) {
	// Token has 30 minutes remaining, well above the 5-minute threshold.
	calls, err := runEnsureFreshTest(t, time.Now().Add(30*time.Minute), 5*time.Minute, http.StatusOK)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if calls != 0 {
		t.Errorf("expected 0 refresh calls, got %d", calls)
	}
}

func TestEnsureFreshSessionToken_RefreshFiredWhenNearExpiry(t *testing.T) {
	// Token expires in 2 minutes, below the 5-minute threshold.
	calls, err := runEnsureFreshTest(t, time.Now().Add(2*time.Minute), 5*time.Minute, http.StatusOK)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 refresh call, got %d", calls)
	}
}

func TestEnsureFreshSessionToken_RefreshFiredWhenAlreadyExpired(t *testing.T) {
	// Token already expired.
	calls, err := runEnsureFreshTest(t, time.Now().Add(-1*time.Minute), 5*time.Minute, http.StatusOK)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 refresh call, got %d", calls)
	}
}

func TestEnsureFreshSessionToken_RefreshFailureReturnsAuthExpiredError(t *testing.T) {
	// Server returns 401 on refresh.
	_, err := runEnsureFreshTest(t, time.Now().Add(1*time.Minute), 5*time.Minute, http.StatusUnauthorized)
	if err == nil {
		t.Fatal("expected error when refresh fails, got nil")
	}
	if !errors.Is(err, errAuthExpired) {
		t.Errorf("expected errAuthExpired, got %v (type %T)", err, err)
	}
}

func TestEnsureFreshSessionToken_NilSessionReturnsError(t *testing.T) {
	client := newHTTPClient("http://localhost:1", false, 5, false)
	err := ensureFreshSessionToken(client, nil, 5*time.Minute)
	if err == nil {
		t.Fatal("expected error for nil session, got nil")
	}
	if !errors.Is(err, errAuthExpired) {
		t.Errorf("expected errAuthExpired, got %v", err)
	}
}

// ============================================================
// makeRequestWithSession
// ============================================================

// newTestSession creates a session with a future expiry and a non-empty refresh token.
func newTestSession(accessToken, refreshToken string, expiresIn time.Duration) *AuthSession {
	return &AuthSession{
		Username:     "testuser",
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(expiresIn),
	}
}

func TestMakeRequestWithSession_200Passthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"success":true,"message":"ok"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	session := newTestSession("tok", "ref", 30*time.Minute)

	resp, err := client.makeRequestWithSession("GET", "/api/test", nil, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Success {
		t.Errorf("expected success=true, got false")
	}
}

func TestMakeRequestWithSession_401ThenRefreshThen200(t *testing.T) {
	attempt := 0
	refreshCalled := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/refresh" {
			refreshCalled = true
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":       true,
				"token":         "new-tok",
				"refresh_token": "new-ref",
				"expires_at":    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
			})
			return
		}
		attempt++
		if attempt == 1 {
			// First call: return 401
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"success":false,"error":"unauthorized","message":"unauthorized"}`)
			return
		}
		// Second call (after refresh): return 200
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"success":true,"message":"ok after refresh"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	session := newTestSession("old-tok", "ref", 30*time.Minute)

	resp, err := client.makeRequestWithSession("GET", "/api/protected", nil, session)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !refreshCalled {
		t.Error("expected refresh to be called after 401")
	}
	if !resp.Success {
		t.Errorf("expected success=true on retry, got false")
	}
	if session.AccessToken != "new-tok" {
		t.Errorf("expected session.AccessToken='new-tok' after refresh, got %q", session.AccessToken)
	}
}

func TestMakeRequestWithSession_401ThenRefreshAlso401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Everything returns 401 (both the original request and refresh).
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"success":false,"error":"unauthorized","message":"unauthorized"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	session := newTestSession("bad-tok", "bad-ref", 30*time.Minute)

	_, err := client.makeRequestWithSession("GET", "/api/protected", nil, session)
	if err == nil {
		t.Fatal("expected error when both original and refresh return 401, got nil")
	}
	if !errors.Is(err, errAuthExpired) {
		t.Errorf("expected errAuthExpired, got %v", err)
	}
}

func TestMakeRequestWithSession_429TooManyInProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		// Stable error code matching the server response shape.
		fmt.Fprintf(w, `{"success":false,"error":"too_many_in_progress_uploads","message":"You have 4 upload(s) already in progress (max 4)."}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	session := newTestSession("tok", "ref", 30*time.Minute)

	_, err := client.makeRequestWithSession("POST", "/api/uploads/init", nil, session)
	if err == nil {
		t.Fatal("expected error for 429 too_many_in_progress_uploads, got nil")
	}
	if !errors.Is(err, errTooManyInProgressUploads) {
		t.Errorf("expected errTooManyInProgressUploads, got %v (type %T)", err, err)
	}
	if !isFatalUploadError(err) {
		t.Errorf("errTooManyInProgressUploads should be classified as fatal")
	}
}

func TestMakeRequestWithSession_403QuotaExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"success":false,"error":"quota_exceeded","message":"Storage limit would be exceeded"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	session := newTestSession("tok", "ref", 30*time.Minute)

	_, err := client.makeRequestWithSession("POST", "/api/uploads/init", nil, session)
	if err == nil {
		t.Fatal("expected error for 403 quota exceeded, got nil")
	}
	if !errors.Is(err, errQuotaExceeded) {
		t.Errorf("expected errQuotaExceeded, got %v (type %T)", err, err)
	}
	if !isFatalUploadError(err) {
		t.Errorf("errQuotaExceeded should be classified as fatal")
	}
}

func TestMakeRequestWithSession_NilSessionReturnsError(t *testing.T) {
	client := newHTTPClient("http://localhost:1", false, 5, false)
	_, err := client.makeRequestWithSession("GET", "/api/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for nil session, got nil")
	}
	if !errors.Is(err, errAuthExpired) {
		t.Errorf("expected errAuthExpired for nil session, got %v", err)
	}
}
