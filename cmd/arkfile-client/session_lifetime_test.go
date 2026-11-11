package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBatchSessionEndedSummary(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		verb      string
		prior     bool
		after     int
		want      string
		wantEmpty bool
	}{
		{
			name: "next file refused after one finished",
			err:  notStarted(errSessionAbsolute), verb: "downloaded", prior: true, after: 2,
			want: "session ended 24 hours after login. The file in progress finished. 3 other files in the queue were not downloaded. Please run: arkfile-client login --username <user>",
		},
		{
			name: "last file refused after one finished",
			err:  notStarted(errSessionAbsolute), verb: "uploaded", prior: true, after: 0,
			want: "session ended 24 hours after login. The file in progress finished. 1 other file in the queue was not uploaded. Please run: arkfile-client login --username <user>",
		},
		{
			name: "first file refused",
			err:  notStarted(errSessionIdle), verb: "exported", prior: false, after: 1,
			want: "session ended after 6 hours without activity. 2 files in the queue were not exported. Please run: arkfile-client login --username <user>",
		},
		{
			name: "file stopped mid-transfer",
			err:  fmt.Errorf("failed to upload chunk 3: %w", errSessionAbsolute), verb: "uploaded", prior: true, after: 3,
			want: "session ended 24 hours after login. The file in progress did not finish. 3 other files in the queue were not started. Please run: arkfile-client login --username <user>",
		},
		{
			name: "file stopped mid-transfer with nothing queued",
			err:  errSessionAbsolute, verb: "downloaded", prior: false, after: 0,
			want: "session ended 24 hours after login. The file in progress did not finish. Please run: arkfile-client login --username <user>",
		},
		{name: "generic expiry", err: errAuthExpired, verb: "uploaded", wantEmpty: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := batchSessionEndedSummary(tc.err, tc.verb, tc.prior, tc.after)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("expected no summary, got %q", got)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func writeHomeSession(t *testing.T, session *AuthSession) string {
	t.Helper()
	path := getSessionFilePath()
	if err := atomicSaveAuthSession(session, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func TestUploadChunkReportsSessionAbsolute(t *testing.T) {
	isolateSessionHome(t)
	sessionPath := writeHomeSession(t, newTestSession("chunk-access", "chunk-refresh", 30*time.Minute))
	session := newTestSession("chunk-access", "chunk-refresh", 30*time.Minute)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"error":"session_absolute","message":"ended"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	err := uploadChunk(client, session, "upload-session", 0, []byte("ciphertext"))
	if !errors.Is(err, errSessionAbsolute) {
		t.Fatalf("expected errSessionAbsolute, got %v", err)
	}
	if !isFatalUploadError(err) {
		t.Fatal("a session-ended chunk error must stop the batch")
	}
	if _, statErr := os.Stat(sessionPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected local session removal, stat error: %v", statErr)
	}
}

func TestDownloadChunkRefreshesThenReportsSessionIdle(t *testing.T) {
	isolateSessionHome(t)
	writeHomeSession(t, newTestSession("dl-access", "dl-refresh", 30*time.Minute))
	session := newTestSession("dl-access", "dl-refresh", 30*time.Minute)

	var refreshCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		if r.URL.Path == "/api/refresh" {
			atomic.AddInt32(&refreshCalls, 1)
			fmt.Fprint(w, `{"success":false,"error":"session_idle","message":"idle"}`)
			return
		}
		fmt.Fprint(w, `{"success":false,"error":"","message":"expired"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	meta := ServerFileInfo{ChunkCount: 1}
	err := doChunkedDownload(context.Background(), client, session, "file-1", make([]byte, 32), meta, nil)
	if !errors.Is(err, errSessionIdle) {
		t.Fatalf("expected errSessionIdle from refresh, got %v", err)
	}
	if atomic.LoadInt32(&refreshCalls) != 1 {
		t.Fatalf("expected one refresh after a plain 401, got %d", refreshCalls)
	}
}

func TestRefreshAdoptsTokensRotatedByAnotherProcess(t *testing.T) {
	isolateSessionHome(t)
	rotated := newTestSession("rotated-access", "rotated-refresh", 30*time.Minute)
	writeHomeSession(t, rotated)
	stale := newTestSession("stale-access", "stale-refresh", time.Minute)

	var refreshCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&refreshCalls, 1)
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"success":false,"error":"","message":"reused"}`)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 10, false)
	if err := refreshSessionToken(client, stale); err != nil {
		t.Fatalf("refresh should adopt the stored tokens: %v", err)
	}
	if refreshCalls != 0 {
		t.Fatalf("a superseded refresh token must not be presented, got %d calls", refreshCalls)
	}
	if stale.AccessToken != "rotated-access" || stale.RefreshToken != "rotated-refresh" {
		t.Fatalf("tokens not adopted: %+v", stale)
	}
}

func refreshServer(t *testing.T, calls *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/refresh" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":       true,
			"token":         "refreshed-access",
			"refresh_token": "refreshed-refresh",
			"expires_at":    time.Now().Add(30 * time.Minute).Format(time.RFC3339),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRequireSessionRefreshesExpiredAccessToken(t *testing.T) {
	isolateSessionHome(t)
	sessionPath := writeHomeSession(t, newTestSession("expired-access", "valid-refresh", -time.Minute))
	var calls int32
	srv := refreshServer(t, &calls)

	session, err := requireSession(&ClientConfig{ServerURL: srv.URL, TokenFile: sessionPath, TimeoutSecs: 10})
	if err != nil {
		t.Fatalf("requireSession should refresh an expired access token: %v", err)
	}
	if calls != 1 || session.AccessToken != "refreshed-access" {
		t.Fatalf("expected one refresh and the new token, calls=%d token=%q", calls, session.AccessToken)
	}
	stored, err := loadAuthSession(sessionPath)
	if err != nil || stored.RefreshToken != "refreshed-refresh" {
		t.Fatalf("rotated refresh token not persisted: %+v, %v", stored, err)
	}
}

func TestRequireSessionWithoutServerRefusesExpiredToken(t *testing.T) {
	isolateSessionHome(t)
	sessionPath := writeHomeSession(t, newTestSession("expired-access", "valid-refresh", -time.Minute))
	_, err := requireSession(&ClientConfig{TokenFile: sessionPath})
	if err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("expected local expiry refusal, got %v", err)
	}
}

func TestRefreshRebindsAgentToNewAccessToken(t *testing.T) {
	isolateSessionHome(t)
	socketPath, err := getAgentSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	agent := &Agent{socketPath: socketPath, digestCache: make(map[string]string), stopChan: make(chan struct{})}
	agent.accessCountReset.Store(time.Now().Unix())
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	agentClient, err := NewAgentClient()
	if err != nil {
		t.Fatal(err)
	}
	salt := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	key := bytes.Repeat([]byte{7}, 32)
	if err := agentClient.StoreAccountKey(key, "testuser", salt, 1, "before-refresh", 1); err != nil {
		t.Fatalf("store key: %v", err)
	}

	writeHomeSession(t, newTestSession("before-refresh", "refresh-1", time.Minute))
	session := newTestSession("before-refresh", "refresh-1", time.Minute)
	var calls int32
	srv := refreshServer(t, &calls)
	client := newHTTPClient(srv.URL, false, 10, false)
	if err := refreshSessionToken(client, session); err != nil {
		t.Fatalf("refresh failed: %v", err)
	}

	got, err := agentClient.GetAccountKey(session.AccessToken, salt, 1)
	if err != nil {
		t.Fatalf("agent key should follow the refreshed token: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("agent returned a different key after rebind")
	}
}

func TestOwnerBatchStopsWhenSessionEnds(t *testing.T) {
	f := &fakeBatch{retryAnswer: true}
	f.downloadFn = func(p batchPendingFile, _ int, _ []byte) error {
		if p.FileID == "a2" {
			return notStarted(fmt.Errorf("failed to fetch file metadata: %w", errSessionAbsolute))
		}
		return nil
	}
	pending := []batchPendingFile{accountFile("a1"), accountFile("a2"), accountFile("a3"), customFile("c1")}
	totals := runOwnerDownloadBatch(context.Background(), pending, f.ops(false))

	if fmt.Sprint(f.downloads) != fmt.Sprint([]string{"a1", "a2"}) {
		t.Fatalf("no file may start after the session ends: %v", f.downloads)
	}
	if f.retryAsked != 0 {
		t.Fatal("a session-ended batch must not offer a retry")
	}
	if totals.Cancelled {
		t.Fatal("a session-ended batch is not a cancellation")
	}
	want := "session ended 24 hours after login. The file in progress finished. 3 other files in the queue were not downloaded. Please run: arkfile-client login --username <user>"
	if totals.SessionEnded != want {
		t.Fatalf("got  %q\nwant %q", totals.SessionEnded, want)
	}
}
