package secureinput

import (
	"io"
	"os"
	"testing"
	"time"
)

func TestReadPasswordPrefersControllingTTYOverStdinPipe(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

	// Leftover stdin data must not be treated as the password.
	if _, err := io.WriteString(stdinW, "from-stdin-pipe\n"); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	ttyR, ttyW, err := os.Pipe()
	if err != nil {
		t.Fatalf("tty pipe: %v", err)
	}
	defer ttyR.Close()
	defer ttyW.Close()

	oldOpen := openControllingTTY
	oldRead := readPasswordInteractive
	defer func() {
		openControllingTTY = oldOpen
		readPasswordInteractive = oldRead
	}()

	openControllingTTY = func() (*os.File, error) {
		return ttyR, nil
	}
	readPasswordInteractive = func(fd int) ([]byte, error) {
		if fd != int(ttyR.Fd()) {
			t.Fatalf("expected tty fd %d, got %d", ttyR.Fd(), fd)
		}
		return []byte("from-tty"), nil
	}

	pw, err := ReadPassword("", time.Second, time.Second)
	if err != nil {
		t.Fatalf("ReadPassword: %v", err)
	}
	if string(pw) != "from-tty" {
		t.Fatalf("got %q, want password from controlling tty", string(pw))
	}
}

func TestReadPasswordFallsBackToStdinPipeWhenNoTTY(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

	oldOpen := openControllingTTY
	defer func() { openControllingTTY = oldOpen }()
	openControllingTTY = func() (*os.File, error) {
		return nil, os.ErrNotExist
	}

	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(stdinW, "piped-secret\n")
		done <- err
		_ = stdinW.Close()
	}()

	pw, err := ReadPassword("", time.Second, time.Second)
	if writeErr := <-done; writeErr != nil {
		t.Fatalf("write stdin: %v", writeErr)
	}
	if err != nil {
		t.Fatalf("ReadPassword: %v", err)
	}
	if string(pw) != "piped-secret" {
		t.Fatalf("got %q, want piped-secret", string(pw))
	}
}
