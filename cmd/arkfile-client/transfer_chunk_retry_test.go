package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func useFastTransferRetries(t *testing.T) {
	t.Helper()
	prev := transferRetryDelayFn
	transferRetryDelayFn = func(int) time.Duration { return time.Millisecond }
	t.Cleanup(func() { transferRetryDelayFn = prev })
}

func TestUploadChunk_Retries503ThenSucceeds(t *testing.T) {
	useFastTransferRetries(t)

	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/chunks/") {
			attempts++
			body, _ := io.ReadAll(r.Body)
			if len(body) == 0 {
				t.Errorf("expected non-empty chunk body on attempt %d", attempts)
			}
			if r.Header.Get("X-Chunk-Hash") == "" {
				t.Errorf("expected X-Chunk-Hash on attempt %d", attempts)
			}
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`unavailable`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"chunk_number":0}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 30, false)
	session := &AuthSession{
		Username:    "retry-user",
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	data := []byte("encrypted-chunk-payload-for-retry-test")

	if err := uploadChunk(client, session, "sess-retry", 0, data); err != nil {
		t.Fatalf("uploadChunk failed after retries: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 chunk POST attempts, got %d", attempts)
	}
}

func TestFetchShareChunk_403Then503ThenSucceeds(t *testing.T) {
	useFastTransferRetries(t)

	chunkGets := 0
	ticketPosts := 0
	wantBody := []byte("share-ciphertext-bytes")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/ticket"):
			ticketPosts++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ticket":     "refreshed-ticket",
				"expires_in": 300,
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/chunks/"):
			chunkGets++
			switch chunkGets {
			case 1:
				w.WriteHeader(http.StatusForbidden)
			case 2:
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`unavailable`))
			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(wantBody)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client := newHTTPClient(srv.URL, false, 30, false)
	ctx := context.Background()
	holder := newShareTicketHolder(ctx, client, "share-retry", "dl-token-b64")
	holder.ticket = "stale-ticket"
	holder.expiresAt = time.Now().Add(time.Hour)

	got, err := fetchShareChunkWithTicketRefresh(client, holder, "share-retry", 0, 1)
	if err != nil {
		t.Fatalf("fetchShareChunkWithTicketRefresh failed: %v", err)
	}
	if string(got) != string(wantBody) {
		t.Fatalf("unexpected chunk body: %q", got)
	}
	if chunkGets != 3 {
		t.Fatalf("expected 3 chunk GETs (403, 503, 200), got %d", chunkGets)
	}
	if ticketPosts < 1 {
		t.Fatalf("expected at least one ticket refresh after 403, got %d", ticketPosts)
	}
}
