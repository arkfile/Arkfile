package secureinput

import (
	"io"
	"os"
	"testing"
	"time"
)

func TestReadPasswordUsesControllingTTYNotStdinPipe(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

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

	pw, err := ReadPassword("", time.Second)
	if err != nil {
		t.Fatalf("ReadPassword: %v", err)
	}
	if string(pw) != "from-tty" {
		t.Fatalf("got %q, want password from controlling tty", string(pw))
	}
}

func TestReadPasswordFromStdin(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

	done := make(chan error, 1)
	go func() {
		_, err := io.WriteString(stdinW, "piped-secret\n")
		done <- err
		_ = stdinW.Close()
	}()

	pw, err := ReadPasswordFromStdin(time.Second)
	if writeErr := <-done; writeErr != nil {
		t.Fatalf("write stdin: %v", writeErr)
	}
	if err != nil {
		t.Fatalf("ReadPasswordFromStdin: %v", err)
	}
	if string(pw) != "piped-secret" {
		t.Fatalf("got %q, want piped-secret", string(pw))
	}
}

func TestReadLineUsesControllingTTYNotStdinPipe(t *testing.T) {
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	defer stdinR.Close()
	defer stdinW.Close()

	oldStdin := os.Stdin
	os.Stdin = stdinR
	defer func() { os.Stdin = oldStdin }()

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
	oldRead := readLineInteractive
	defer func() {
		openControllingTTY = oldOpen
		readLineInteractive = oldRead
	}()

	openControllingTTY = func() (*os.File, error) {
		return ttyR, nil
	}
	readLineInteractive = func(f *os.File, prompt string, timeout time.Duration) (string, error) {
		if f != ttyR {
			t.Fatalf("expected tty file, got %#v", f)
		}
		if prompt != "Enter TOTP code: " {
			t.Fatalf("unexpected prompt %q", prompt)
		}
		return "123456", nil
	}

	line, err := ReadLine("Enter TOTP code: ", time.Second)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if line != "123456" {
		t.Fatalf("got %q, want line from controlling tty", line)
	}
}

func TestReadLineErrorsWithoutTTYWhenStdinIsPipe(t *testing.T) {
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

	_, err = ReadLine("prompt: ", time.Second)
	if err == nil {
		t.Fatal("expected error when no tty and stdin is a pipe")
	}
}

func TestReadPasswordErrorsWithoutTTYWhenStdinIsPipe(t *testing.T) {
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

	_, err = ReadPassword("prompt: ", time.Second)
	if err == nil {
		t.Fatal("expected error when no tty and stdin is a pipe")
	}
}
