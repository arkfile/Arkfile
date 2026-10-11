package secureinput

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	DefaultInteractiveTimeout = 60 * time.Second
	DefaultPipeTimeout        = 10 * time.Second
)

// ErrInputCancelled reports a prompt ended by Ctrl-C or by cancellation of the
// caller's context, as opposed to a timeout.
var ErrInputCancelled = errors.New("password input cancelled")

// openControllingTTY opens the process controlling terminal.
// Overridable in tests.
var openControllingTTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// readPasswordInteractive reads one password with echo disabled from a
// terminal file. It returns only after its read has finished, so no reader is
// left behind on the terminal after a timeout or cancellation.
// Overridable in tests.
var readPasswordInteractive = readPasswordFromTerminalFile

// readLineInteractive reads one echoed line from a terminal file.
// Overridable in tests.
var readLineInteractive = readLineFromTerminal

// ReadPassword reads a password from the controlling terminal with echo off.
// Use for interactive prompts. Does not read from stdin pipes -- that keeps
// stdin free for other data (for example bootstrap --token-stdin).
// Returns a byte slice the caller must zero after use.
func ReadPassword(prompt string, timeout time.Duration) ([]byte, error) {
	return ReadPasswordContext(context.Background(), prompt, timeout)
}

// ReadPasswordContext is ReadPassword that also stops waiting when ctx is
// cancelled, for example when the caller's interrupt handler fires.
func ReadPasswordContext(ctx context.Context, prompt string, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = DefaultInteractiveTimeout
	}

	if tty, err := openControllingTTY(); err == nil {
		defer tty.Close()
		return readPasswordFromTerminal(ctx, tty, prompt, timeout)
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
	return readPasswordFromTerminal(ctx, os.Stdin, "", timeout)
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

// ReadLine reads one interactive line with echo enabled from the controlling
// terminal. Unlike ReadPassword, typed or pasted characters remain visible.
// It does not read from stdin pipes, so password/--token pipes cannot steal
// TOTP codes or menu selections. Use explicit flags for non-interactive input.
func ReadLine(prompt string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultInteractiveTimeout
	}

	if tty, err := openControllingTTY(); err == nil {
		defer tty.Close()
		return readLineInteractive(tty, prompt, timeout)
	}

	fi, err := os.Stdin.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to stat stdin: %w", err)
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return "", fmt.Errorf("no controlling terminal for interactive prompt; use an explicit non-interactive flag such as --totp-code")
	}
	return readLineInteractive(os.Stdin, prompt, timeout)
}

func readPasswordFromTerminal(ctx context.Context, f *os.File, prompt string, timeout time.Duration) ([]byte, error) {
	if prompt != "" {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return nil, fmt.Errorf("failed to write password prompt: %w", err)
		}
	}
	return readPasswordInteractive(ctx, f, timeout)
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
