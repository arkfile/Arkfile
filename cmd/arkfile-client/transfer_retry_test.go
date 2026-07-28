package main

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestIsRetryableTransferError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"http 500", &httpStatusError{Status: 500}, true},
		{"http 503", &httpStatusError{Status: 503}, true},
		{"http 429", &httpStatusError{Status: 429}, true},
		{"http 408", &httpStatusError{Status: 408}, true},
		{"http 400", &httpStatusError{Status: 400}, false},
		{"http 401", &httpStatusError{Status: 401}, false},
		{"http 403", &httpStatusError{Status: 403}, false},
		{"http 409", &httpStatusError{Status: 409}, false},
		{"plain error", errors.New("boom"), false},
		{"op error", &net.OpError{Op: "dial", Err: errors.New("refused")}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableTransferError(tc.err); got != tc.want {
				t.Fatalf("isRetryableTransferError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestWithTransferRetrySucceedsAfterTransientFailures(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := withTransferRetry(context.Background(), func() error {
		attempts++
		if attempts < 3 {
			return &httpStatusError{Status: 503, Body: "unavailable"}
		}
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestWithTransferRetryAbortsOnNonRetryable(t *testing.T) {
	t.Parallel()

	attempts := 0
	err := withTransferRetry(context.Background(), func() error {
		attempts++
		return &httpStatusError{Status: 400, Body: "bad request"}
	}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var statusErr *httpStatusError
	if !errors.As(err, &statusErr) || statusErr.Status != 400 {
		t.Fatalf("expected httpStatusError 400, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", attempts)
	}
}

func TestWithTransferRetryRespectsContextCancelDuringBackoff(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := withTransferRetry(ctx, func() error {
		attempts++
		cancel()
		return &httpStatusError{Status: 503}
	}, func(attempt int, err error, delay time.Duration) {
		// Intentionally empty: cancel already triggered.
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt before cancel, got %d", attempts)
	}
}
