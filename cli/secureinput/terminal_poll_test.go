//go:build linux || freebsd || openbsd || netbsd || darwin

package secureinput

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func inputPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	return r, w
}

func TestReadSecretFromFDEditingKeys(t *testing.T) {
	r, w := inputPipe(t)
	// "ab", Backspace, "c", Ctrl-U, "xyz", Enter
	if _, err := w.WriteString("ab\x7fc\x15xyz\r"); err != nil {
		t.Fatalf("write: %v", err)
	}
	pw, err := readSecretFromFD(context.Background(), int(r.Fd()), time.Second)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(pw) != "xyz" {
		t.Fatalf("got %q, want xyz", pw)
	}
}

func TestReadSecretFromFDTimeoutLeavesNoReader(t *testing.T) {
	r, w := inputPipe(t)
	_, err := readSecretFromFD(context.Background(), int(r.Fd()), 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if errors.Is(err, ErrInputCancelled) {
		t.Fatalf("a timeout must not be reported as cancellation: %v", err)
	}
	// Input typed after the timeout must reach the next prompt, which proves
	// the timed-out read is not still consuming the terminal.
	if _, err := w.WriteString("next-attempt\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	pw, err := readSecretFromFD(context.Background(), int(r.Fd()), time.Second)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if string(pw) != "next-attempt" {
		t.Fatalf("got %q, want next-attempt", pw)
	}
}

func TestReadSecretFromFDContextCancel(t *testing.T) {
	r, _ := inputPipe(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	_, err := readSecretFromFD(ctx, int(r.Fd()), time.Minute)
	if !errors.Is(err, ErrInputCancelled) || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %s", elapsed)
	}
}

func TestReadSecretFromFDInterruptKey(t *testing.T) {
	r, w := inputPipe(t)
	if _, err := w.WriteString("partial\x03"); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := readSecretFromFD(context.Background(), int(r.Fd()), time.Second)
	if !errors.Is(err, errInterruptKey) || !errors.Is(err, ErrInputCancelled) {
		t.Fatalf("expected Ctrl-C cancellation, got %v", err)
	}
}

func TestReadSecretFromFDEndOfInput(t *testing.T) {
	r, w := inputPipe(t)
	_ = w.Close()
	_, err := readSecretFromFD(context.Background(), int(r.Fd()), time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestReadSecretFromFDRejectsOverlongInput(t *testing.T) {
	r, w := inputPipe(t)
	go func() {
		_, _ = w.WriteString(strings.Repeat("a", maxSecretInputBytes+1) + "\n")
	}()
	_, err := readSecretFromFD(context.Background(), int(r.Fd()), 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected overlong input error, got %v", err)
	}
}

func TestReadLineFromTerminalTimeoutLeavesNoReader(t *testing.T) {
	r, w := inputPipe(t)
	_, err := readLineFromTerminal(r, "", 150*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout, got %v", err)
	}
	if _, err := w.WriteString("123456\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := readLineFromTerminal(r, "", time.Second)
	if err != nil {
		t.Fatalf("second read: %v", err)
	}
	if line != "123456" {
		t.Fatalf("got %q, want 123456", line)
	}
}
