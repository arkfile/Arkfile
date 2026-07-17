package secureinput

import (
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/term"
)

const (
	DefaultInteractiveTimeout = 60 * time.Second
	DefaultPipeTimeout        = 10 * time.Second
)

// ReadPassword reads a password from stdin with optional prompt text.
// Returns a byte slice the caller must zero after use.
func ReadPassword(prompt string, interactiveTimeout, pipeTimeout time.Duration) ([]byte, error) {
	if interactiveTimeout <= 0 {
		interactiveTimeout = DefaultInteractiveTimeout
	}
	if pipeTimeout <= 0 {
		pipeTimeout = DefaultPipeTimeout
	}

	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat stdin: %w", err)
	}

	if prompt != "" {
		fmt.Print(prompt)
	}

	if (fi.Mode() & os.ModeCharDevice) != 0 {
		result := make(chan []byte, 1)
		errCh := make(chan error, 1)
		go func() {
			bytePassword, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				errCh <- err
				return
			}
			fmt.Println()
			result <- append([]byte(nil), bytePassword...)
		}()

		select {
		case pw := <-result:
			return pw, nil
		case err := <-errCh:
			return nil, err
		case <-time.After(interactiveTimeout):
			return nil, fmt.Errorf("password input timed out after %s", interactiveTimeout)
		}
	}

	type readResult struct {
		pw  []byte
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		var passwordBytes []byte
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
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
	case <-time.After(pipeTimeout):
		return nil, fmt.Errorf("password input timed out after %s", pipeTimeout)
	}
}

// Zero clears sensitive memory in place.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
