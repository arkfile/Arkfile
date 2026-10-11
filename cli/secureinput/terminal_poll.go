//go:build linux || freebsd || openbsd || netbsd || darwin

package secureinput

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	maxSecretInputBytes = 4096
	maxLineInputBytes   = 4096
	inputPollSlice      = 100 * time.Millisecond
)

// errInterruptKey reports Ctrl-C typed at a raw-mode password prompt.
var errInterruptKey = fmt.Errorf("%w by Ctrl-C", ErrInputCancelled)

// raiseInterrupt re-delivers Ctrl-C as SIGINT once the terminal is restored,
// because raw mode stops the terminal from generating the signal itself.
// Overridable in tests.
var raiseInterrupt = func() {
	_ = syscall.Kill(os.Getpid(), syscall.SIGINT)
}

// readPasswordFromTerminalFile disables echo, reads one line, and restores the
// terminal on every path before returning.
func readPasswordFromTerminalFile(ctx context.Context, f *os.File, timeout time.Duration) ([]byte, error) {
	fd := int(f.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return nil, fmt.Errorf("failed to disable terminal echo: %w", err)
	}
	pw, readErr := readSecretFromFD(ctx, fd, timeout)
	_ = term.Restore(fd, state)
	_, _ = fmt.Fprintln(f)
	if errors.Is(readErr, errInterruptKey) {
		raiseInterrupt()
	}
	return pw, readErr
}

// waitReadable polls fd in short slices until it is readable, the deadline
// passes, or ctx is cancelled. It never leaves a blocked read behind.
func waitReadable(ctx context.Context, fd int, deadline time.Time, timeout time.Duration, what string) error {
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %w", ErrInputCancelled, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("%s timed out after %s", what, timeout)
		}
		wait := inputPollSlice
		if remaining < wait {
			wait = remaining
		}
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		ready, err := unix.Poll(fds, int(wait/time.Millisecond))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("failed to wait for %s: %w", what, err)
		}
		if ready > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
			return nil
		}
	}
}

// readSecretFromFD reads raw-mode keystrokes into a fixed buffer that is
// zeroed on return. Enter finishes, Backspace and Ctrl-U edit, Ctrl-C cancels,
// and Ctrl-D on an empty line ends input.
func readSecretFromFD(ctx context.Context, fd int, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, maxSecretInputBytes)
	chunk := make([]byte, 256)
	defer Zero(buf)
	defer Zero(chunk)

	n := 0
	deadline := time.Now().Add(timeout)
	for {
		if err := waitReadable(ctx, fd, deadline, timeout, "password input"); err != nil {
			return nil, err
		}
		r, err := unix.Read(fd, chunk)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		if r == 0 {
			return nil, fmt.Errorf("failed to read password: %w", io.EOF)
		}
		for _, b := range chunk[:r] {
			switch {
			case b == '\r' || b == '\n':
				out := make([]byte, n)
				copy(out, buf[:n])
				return out, nil
			case b == 0x03:
				return nil, errInterruptKey
			case b == 0x04:
				if n == 0 {
					return nil, fmt.Errorf("failed to read password: %w", io.EOF)
				}
			case b == 0x7f || b == 0x08:
				if n > 0 {
					n--
					buf[n] = 0
				}
			case b == 0x15:
				Zero(buf[:n])
				n = 0
			case b < 0x20:
				// Ignore other control bytes.
			default:
				if n == len(buf) {
					return nil, fmt.Errorf("password input exceeds %d bytes", maxSecretInputBytes)
				}
				buf[n] = b
				n++
			}
		}
	}
}

// readLineFromTerminal reads one echoed line in the terminal's normal mode,
// waiting with the same bounded poll so a timeout leaves no reader behind.
func readLineFromTerminal(f *os.File, prompt string, timeout time.Duration) (string, error) {
	if prompt != "" {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return "", fmt.Errorf("failed to write prompt: %w", err)
		}
	}
	fd := int(f.Fd())
	line := make([]byte, 0, 64)
	chunk := make([]byte, 256)
	deadline := time.Now().Add(timeout)
	for {
		if err := waitReadable(context.Background(), fd, deadline, timeout, "interactive input"); err != nil {
			return "", err
		}
		r, err := unix.Read(fd, chunk)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			return "", fmt.Errorf("failed to read input: %w", err)
		}
		if r == 0 {
			if strings.TrimSpace(string(line)) != "" {
				return strings.TrimRight(string(line), "\r\n"), nil
			}
			return "", io.EOF
		}
		for _, b := range chunk[:r] {
			if b == '\n' {
				return strings.TrimRight(string(line), "\r"), nil
			}
			if len(line) >= maxLineInputBytes {
				return "", fmt.Errorf("interactive input exceeds %d bytes", maxLineInputBytes)
			}
			line = append(line, b)
		}
	}
}
