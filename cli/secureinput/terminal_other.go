//go:build !(linux || freebsd || openbsd || netbsd || darwin)

package secureinput

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// readPasswordFromTerminalFile uses the platform terminal reader. Platforms
// without poll(2) cannot cancel a blocked console read, so a timed-out read
// may finish later; its result is zeroed when it arrives.
func readPasswordFromTerminalFile(ctx context.Context, f *os.File, timeout time.Duration) ([]byte, error) {
	type readResult struct {
		pw  []byte
		err error
	}
	ch := make(chan readResult, 1)
	go func() {
		pw, err := term.ReadPassword(int(f.Fd()))
		ch <- readResult{pw: pw, err: err}
	}()

	discardLate := func() {
		go func() {
			res := <-ch
			Zero(res.pw)
		}()
	}

	select {
	case res := <-ch:
		_, _ = fmt.Fprintln(f)
		return res.pw, res.err
	case <-ctx.Done():
		discardLate()
		return nil, fmt.Errorf("%w: %w", ErrInputCancelled, ctx.Err())
	case <-time.After(timeout):
		discardLate()
		return nil, fmt.Errorf("password input timed out after %s", timeout)
	}
}

func readLineFromTerminal(f *os.File, prompt string, timeout time.Duration) (string, error) {
	if prompt != "" {
		if _, err := fmt.Fprint(f, prompt); err != nil {
			return "", fmt.Errorf("failed to write prompt: %w", err)
		}
	}

	type readResult struct {
		line string
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		line, err := bufio.NewReader(f).ReadString('\n')
		if err != nil {
			if err == io.EOF && strings.TrimSpace(line) != "" {
				ch <- readResult{line: line}
				return
			}
			ch <- readResult{err: err}
			return
		}
		ch <- readResult{line: line}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			return "", res.err
		}
		return strings.TrimRight(res.line, "\r\n"), nil
	case <-time.After(timeout):
		return "", fmt.Errorf("interactive input timed out after %s", timeout)
	}
}
