package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// invoiceStatusServer replies to GET /api/billing/invoice/{id} with a scripted
// sequence. An entry of the form "HTTP 503" replies with that status code.
type invoiceStatusServer struct {
	mu       sync.Mutex
	sequence []string
	calls    int
}

func (s *invoiceStatusServer) handler(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !strings.HasPrefix(r.URL.Path, "/api/billing/invoice/") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	next := s.sequence[len(s.sequence)-1]
	if s.calls < len(s.sequence) {
		next = s.sequence[s.calls]
	}
	s.calls++
	w.Header().Set("Content-Type", "application/json")
	switch next {
	case "HTTP 401":
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"success":false,"message":"unauthorized"}`))
		return
	case "HTTP 404":
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"success":false,"message":"Invoice not found"}`))
		return
	case "HTTP 503":
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"success":false,"message":"unavailable"}`))
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    map[string]interface{}{"invoice_id": "inv_cli", "status": next},
	})
}

func newInvoiceWaitEnv(t *testing.T, sequence ...string) (*HTTPClient, *AuthSession, *invoiceStatusServer) {
	t.Helper()
	server := &invoiceStatusServer{sequence: sequence}
	srv := httptest.NewServer(http.HandlerFunc(server.handler))
	t.Cleanup(srv.Close)
	client := &HTTPClient{client: srv.Client(), baseURL: srv.URL}
	session := &AuthSession{AccessToken: "test-token", ExpiresAt: time.Now().Add(time.Hour)}
	return client, session, server
}

func noSleep(time.Duration) {}

func TestWaitForInvoiceSettlement_PrintsStagesAndSucceedsOnPaid(t *testing.T) {
	client, session, server := newInvoiceWaitEnv(t, "pending", "pending", "confirming", "confirming", "paid")
	var out bytes.Buffer
	status, err := waitForInvoiceSettlement(client, session, "inv_cli", invoiceWaitOptions{Out: &out, Sleep: noSleep})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if status != "paid" {
		t.Fatalf("status = %q", status)
	}
	if server.calls != 5 {
		t.Fatalf("calls = %d", server.calls)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected one line per status change, got %q", out.String())
	}
	if !strings.Contains(lines[1], "confirming") || !strings.Contains(lines[1], "not yet credited") {
		t.Fatalf("confirming line = %q", lines[1])
	}
}

func TestWaitForInvoiceSettlement_ExpiredAndFailedExitNonZero(t *testing.T) {
	for _, final := range []string{"expired", "failed"} {
		client, session, _ := newInvoiceWaitEnv(t, "pending", final)
		status, err := waitForInvoiceSettlement(client, session, "inv_cli", invoiceWaitOptions{Sleep: noSleep})
		if err == nil || !strings.Contains(err.Error(), "no balance was credited") {
			t.Fatalf("%s: expected no-credit error, got %v", final, err)
		}
		if status != final {
			t.Fatalf("status = %q, want %q", status, final)
		}
	}
}

func TestWaitForInvoiceSettlement_RetriesServerErrors(t *testing.T) {
	client, session, _ := newInvoiceWaitEnv(t, "HTTP 503", "HTTP 503", "confirming", "paid")
	if _, err := waitForInvoiceSettlement(client, session, "inv_cli", invoiceWaitOptions{Sleep: noSleep}); err != nil {
		t.Fatalf("expected success after transient errors, got %v", err)
	}
}

func TestWaitForInvoiceSettlement_StopsWhenSessionEnds(t *testing.T) {
	client, session, server := newInvoiceWaitEnv(t, "pending", "HTTP 401")
	_, err := waitForInvoiceSettlement(client, session, "inv_cli", invoiceWaitOptions{Sleep: noSleep})
	if !errors.Is(err, errAuthExpired) {
		t.Fatalf("expected errAuthExpired, got %v", err)
	}
	if server.calls != 2 {
		t.Fatalf("must stop polling after the session ends; calls = %d", server.calls)
	}
}

func TestWaitForInvoiceSettlement_StopsOnUnknownInvoice(t *testing.T) {
	client, session, _ := newInvoiceWaitEnv(t, "HTTP 404")
	_, err := waitForInvoiceSettlement(client, session, "inv_cli", invoiceWaitOptions{Sleep: noSleep})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestWaitForInvoiceSettlement_TimesOut(t *testing.T) {
	client, session, _ := newInvoiceWaitEnv(t, "confirming")
	now := time.Unix(1_800_000_000, 0)
	_, err := waitForInvoiceSettlement(client, session, "inv_cli", invoiceWaitOptions{
		Timeout:  time.Minute,
		Interval: 15 * time.Second,
		Sleep:    func(d time.Duration) { now = now.Add(d) },
		Now:      func() time.Time { return now },
	})
	if err == nil || !strings.Contains(err.Error(), "timed out") || !strings.Contains(err.Error(), "confirming") {
		t.Fatalf("expected timeout mentioning last status, got %v", err)
	}
}

func TestCheckBrowserCheckoutURL(t *testing.T) {
	ok := []string{"https://pay.example.com/i/abc", "http://127.0.0.1:8082/i/abc", "http://localhost/i/x"}
	for _, u := range ok {
		if err := checkBrowserCheckoutURL(u); err != nil {
			t.Errorf("%s: unexpected error %v", u, err)
		}
	}
	bad := []string{"http://pay.example.com/i/abc", "javascript:alert(1)", "file:///etc/passwd", "", "https://"}
	for _, u := range bad {
		if err := checkBrowserCheckoutURL(u); err == nil {
			t.Errorf("%s: expected rejection", u)
		}
	}
}
