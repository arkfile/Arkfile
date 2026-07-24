package secureinput

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

const (
	DefaultInteractiveTimeout = 60 * time.Second
	DefaultPipeTimeout        = 10 * time.Second
)

// openControllingTTY opens the process controlling terminal.
// Overridable in tests.
var openControllingTTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// readPasswordInteractive reads a password with echo disabled from fd.
// Overridable in tests.
var readPasswordInteractive = func(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// ReadPassword reads a password from the controlling terminal with echo off.
// Use for interactive prompts. Does not read from stdin pipes — that keeps
// stdin free for other data (for example bootstrap --token-stdin).
// Returns a byte slice the caller must zero after use.
func ReadPassword(prompt string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultInteractiveTimeout
	}

	if tty, err := openControllingTTY(); err == nil {
		defer tty.Close()
		return readPasswordFromTerminal(tty, prompt, timeout)
	}

	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat stdin: %w", err)
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return nil, fmt.Errorf("no controlling terminal for password prompt; use --password-stdin to read from a pipe")
	}
	if prompt != "" {
		fmt.Print(prompt)
	}
	return readPasswordFromTerminal(os.Stdin, "", timeout)
}

// ReadPasswordFromStdin reads one password line from stdin.
// Use only when the caller set --password-stdin (or equivalent) for scripts/tests.
// Returns a byte slice the caller must zero after use.
func ReadPasswordFromStdin(timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultPipeTimeout
	}
	return readPasswordFromPipe(os.Stdin, timeout)
}

func readPasswordFromTerminal(f *os.File, prompt string, timeout time.Duration) ([]byte, error) {
	if prompt != "" {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return nil, fmt.Errorf("failed to write password prompt: %w", err)
		}
	}

	result := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		bytePassword, err := readPasswordInteractive(int(f.Fd()))
		if err != nil {
			errCh <- err
			return
		}
		_, _ = fmt.Fprintln(f)
		result <- append([]byte(nil), bytePassword...)
	}()

	select {
	case pw := <-result:
		return pw, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(timeout):
		return nil, fmt.Errorf("password input timed out after %s", timeout)
	}
}

func readPasswordFromPipe(r io.Reader, timeout time.Duration) ([]byte, error) {
	type readResult struct {
		pw  []byte
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		var passwordBytes []byte
		buf := make([]byte, 1)
		for {
			n, err := r.Read(buf)
			if err != nil {
				if err == io.EOF {
					break
				}
				ch <- readResult{err: fmt.Errorf("failed to read password from stdin: %w", err)}
				return
			}
			if n > 0 {
				if buf[0] == '\n' {
					break
				}
				passwordBytes = append(passwordBytes, buf[0])
			}
		}
		for len(passwordBytes) > 0 && passwordBytes[len(passwordBytes)-1] == '\r' {
			passwordBytes = passwordBytes[:len(passwordBytes)-1]
		}
		ch <- readResult{pw: passwordBytes}
	}()

	select {
	case res := <-ch:
		return res.pw, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("password input timed out after %s", timeout)
	}
}

// Zero clears sensitive memory in place.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
