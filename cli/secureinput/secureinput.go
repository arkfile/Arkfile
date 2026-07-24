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

// ReadPassword reads a password with optional prompt text.
// When a controlling terminal is available, the password is read from /dev/tty
// (echo off) so stdin can carry other data such as --token-stdin. If /dev/tty
// cannot be opened, falls back to stdin (interactive TTY or pipe).
// Returns a byte slice the caller must zero after use.
func ReadPassword(prompt string, interactiveTimeout, pipeTimeout time.Duration) ([]byte, error) {
	if interactiveTimeout <= 0 {
		interactiveTimeout = DefaultInteractiveTimeout
	}
	if pipeTimeout <= 0 {
		pipeTimeout = DefaultPipeTimeout
	}

	if tty, err := openControllingTTY(); err == nil {
		defer tty.Close()
		return readPasswordFromTerminal(tty, prompt, interactiveTimeout)
	}

	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat stdin: %w", err)
	}

	if prompt != "" {
		fmt.Print(prompt)
	}

	if (fi.Mode() & os.ModeCharDevice) != 0 {
		return readPasswordFromTerminal(os.Stdin, "", interactiveTimeout)
	}

	return readPasswordFromPipe(os.Stdin, pipeTimeout)
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
