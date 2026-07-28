package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"time"
)

// Transfer retry policy mirrors the TypeScript retry-handler defaults:
// up to 3 retries after the first attempt, exponential backoff with jitter,
// retrying network errors and HTTP 408 / 429 / 5xx.
const (
	defaultTransferMaxRetries     = 3
	defaultTransferInitialDelayMs = 1000
	defaultTransferMaxDelayMs     = 30000
	defaultTransferBackoffMult    = 2.0
)

// httpStatusError carries an HTTP status for retry classification.
type httpStatusError struct {
	Status int
	Body   string
}

func (e *httpStatusError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

// isRetryableTransferError reports whether err should be retried under the
// shared chunk transfer policy.
func isRetryableTransferError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		return statusErr.Status >= 500 || statusErr.Status == 429 || statusErr.Status == 408
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	// Go's http client often wraps dial/connection failures without net.Error.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	return false
}

func transferRetryDelay(attempt int) time.Duration {
	delayMs := float64(defaultTransferInitialDelayMs) * math.Pow(defaultTransferBackoffMult, float64(attempt))
	if delayMs > float64(defaultTransferMaxDelayMs) {
		delayMs = float64(defaultTransferMaxDelayMs)
	}
	jitterRange := delayMs * 0.25
	delayMs = delayMs + (rand.Float64()*jitterRange*2 - jitterRange)
	if delayMs < 0 {
		delayMs = 0
	}
	return time.Duration(delayMs) * time.Millisecond
}

// transferRetryDelayFn is the delay source for withTransferRetry. Tests may
// replace it with a near-zero delay to keep unit tests fast.
var transferRetryDelayFn = transferRetryDelay

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// withTransferRetry runs fn with exponential backoff on retryable errors.
// onRetry is optional and receives the 1-based retry attempt number.
func withTransferRetry(ctx context.Context, fn func() error, onRetry func(attempt int, err error, delay time.Duration)) error {
	var lastErr error
	for attempt := 0; attempt <= defaultTransferMaxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := fn()
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt >= defaultTransferMaxRetries || !isRetryableTransferError(err) {
			break
		}
		delay := transferRetryDelayFn(attempt)
		if onRetry != nil {
			onRetry(attempt+1, err, delay)
		}
		if sleepErr := sleepContext(ctx, delay); sleepErr != nil {
			return sleepErr
		}
	}
	return lastErr
}
