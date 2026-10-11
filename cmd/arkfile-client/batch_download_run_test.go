package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/arkfile/Arkfile/cli/secureinput"
)

// fakeBatch records every download and password request made by
// runOwnerDownloadBatch and lets each test script its outcomes.
type fakeBatch struct {
	downloads     []string
	passwordsSeen [][]byte
	prompts       int
	retryAsked    int
	downloadFn    func(p batchPendingFile, attempt int, customPass []byte) error
	readFn        func(prompt string, call int) ([]byte, error)
	retryAnswer   bool
	attemptByID   map[string]int
}

func (f *fakeBatch) ops(stdin bool) batchDownloadOps {
	f.attemptByID = map[string]int{}
	return batchDownloadOps{
		download: func(_ context.Context, p batchPendingFile, customPass []byte) error {
			f.downloads = append(f.downloads, p.FileID)
			f.attemptByID[p.FileID]++
			if customPass != nil {
				f.passwordsSeen = append(f.passwordsSeen, customPass)
			}
			if f.downloadFn == nil {
				return nil
			}
			return f.downloadFn(p, f.attemptByID[p.FileID], customPass)
		},
		readCustom: func(_ context.Context, prompt string) ([]byte, error) {
			f.prompts++
			if f.readFn == nil {
				return []byte("custom-secret"), nil
			}
			return f.readFn(prompt, f.prompts)
		},
		confirmRetry: func(int, int) bool {
			f.retryAsked++
			return f.retryAnswer
		},
		targetPath:     func(fileID string) string { return fileID + ".out" },
		stdinPasswords: stdin,
	}
}

func accountFile(id string) batchPendingFile {
	return batchPendingFile{FileID: id, Filename: id + ".bin", PasswordType: "account"}
}

func customFile(id string) batchPendingFile {
	return batchPendingFile{FileID: id, Filename: id + ".bin", PasswordType: "custom"}
}

func assertAllZero(t *testing.T, bufs [][]byte) {
	t.Helper()
	for i, b := range bufs {
		for _, c := range b {
			if c != 0 {
				t.Fatalf("custom password buffer %d was not cleared: %q", i, b)
			}
		}
	}
}

func TestOwnerBatchDownloadsAccountFilesBeforeCustomFiles(t *testing.T) {
	f := &fakeBatch{}
	pending := []batchPendingFile{customFile("c1"), accountFile("a1"), customFile("c2"), accountFile("a2")}
	totals := runOwnerDownloadBatch(context.Background(), pending, f.ops(false))

	want := []string{"a1", "a2", "c1", "c2"}
	if fmt.Sprint(f.downloads) != fmt.Sprint(want) {
		t.Fatalf("download order %v, want %v", f.downloads, want)
	}
	if totals.AccountOK != 2 || totals.CustomOK != 2 || totals.Unresolved != 0 || totals.Skipped != 0 || totals.Cancelled {
		t.Fatalf("unexpected totals: %+v", totals)
	}
	assertAllZero(t, f.passwordsSeen)
}

func TestOwnerBatchRetriesOnlyFailedFiles(t *testing.T) {
	f := &fakeBatch{retryAnswer: true}
	f.downloadFn = func(p batchPendingFile, attempt int, _ []byte) error {
		if p.FileID == "a1" && attempt == 1 {
			return errors.New("network error")
		}
		return nil
	}
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{accountFile("a1"), accountFile("a2")}, f.ops(false))

	if f.attemptByID["a1"] != 2 || f.attemptByID["a2"] != 1 {
		t.Fatalf("succeeded files must never be retried: %v", f.attemptByID)
	}
	if f.retryAsked != 1 {
		t.Fatalf("retry asked %d times, want 1", f.retryAsked)
	}
	if totals.AccountOK != 2 || totals.Unresolved != 0 {
		t.Fatalf("unexpected totals: %+v", totals)
	}
}

func TestOwnerBatchStopsAfterMaxRounds(t *testing.T) {
	f := &fakeBatch{retryAnswer: true}
	f.downloadFn = func(batchPendingFile, int, []byte) error { return errors.New("network error") }
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{accountFile("a1")}, f.ops(false))

	if f.attemptByID["a1"] != MaxBatchDownloadRounds {
		t.Fatalf("attempts %d, want %d rounds", f.attemptByID["a1"], MaxBatchDownloadRounds)
	}
	if f.retryAsked != MaxBatchDownloadRounds-1 {
		t.Fatalf("retry asked %d times, want %d", f.retryAsked, MaxBatchDownloadRounds-1)
	}
	if totals.Unresolved != 1 || totals.AccountOK != 0 {
		t.Fatalf("unexpected totals: %+v", totals)
	}
}

func TestOwnerBatchDeclinedRetryEndsRun(t *testing.T) {
	f := &fakeBatch{retryAnswer: false}
	f.downloadFn = func(batchPendingFile, int, []byte) error { return errors.New("network error") }
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{accountFile("a1")}, f.ops(false))
	if f.attemptByID["a1"] != 1 || totals.Unresolved != 1 {
		t.Fatalf("declined retry must end the run: attempts=%d totals=%+v", f.attemptByID["a1"], totals)
	}
}

func TestOwnerBatchCustomPasswordAttemptsAndCleanup(t *testing.T) {
	f := &fakeBatch{}
	f.downloadFn = func(_ batchPendingFile, attempt int, _ []byte) error {
		if attempt < MaxBatchCustomPasswordAttempts {
			return errors.New("wrong password: failed to unwrap FEK")
		}
		return nil
	}
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{customFile("c1")}, f.ops(false))

	if f.prompts != MaxBatchCustomPasswordAttempts {
		t.Fatalf("prompts %d, want %d", f.prompts, MaxBatchCustomPasswordAttempts)
	}
	if totals.CustomOK != 1 || totals.Unresolved != 0 {
		t.Fatalf("unexpected totals: %+v", totals)
	}
	if len(f.passwordsSeen) != MaxBatchCustomPasswordAttempts {
		t.Fatalf("saw %d password buffers, want %d", len(f.passwordsSeen), MaxBatchCustomPasswordAttempts)
	}
	assertAllZero(t, f.passwordsSeen)
}

func TestOwnerBatchWrongPasswordExhaustsAttempts(t *testing.T) {
	f := &fakeBatch{}
	f.downloadFn = func(batchPendingFile, int, []byte) error {
		return errors.New("wrong password: failed to unwrap FEK")
	}
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{customFile("c1")}, f.ops(false))
	if len(totals.LastFailures) != 1 || totals.LastFailures[0].Reason != "wrong_custom_password" {
		t.Fatalf("unexpected failures: %+v", totals.LastFailures)
	}
	assertAllZero(t, f.passwordsSeen)
}

func TestOwnerBatchPromptTimeoutCountsAsAttempt(t *testing.T) {
	f := &fakeBatch{}
	f.readFn = func(string, int) ([]byte, error) {
		return nil, errors.New("password input timed out after 2m0s")
	}
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{customFile("c1")}, f.ops(false))

	if f.prompts != MaxBatchCustomPasswordAttempts {
		t.Fatalf("prompts %d, want %d", f.prompts, MaxBatchCustomPasswordAttempts)
	}
	if len(f.downloads) != 0 {
		t.Fatalf("no download may start without a password: %v", f.downloads)
	}
	if len(totals.LastFailures) != 1 || totals.LastFailures[0].Reason != "prompt_timeout" {
		t.Fatalf("unexpected failures: %+v", totals.LastFailures)
	}
}

func TestOwnerBatchCancelledPromptSkipsRemainder(t *testing.T) {
	f := &fakeBatch{retryAnswer: true}
	f.readFn = func(string, int) ([]byte, error) {
		return nil, fmt.Errorf("%w by Ctrl-C", secureinput.ErrInputCancelled)
	}
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{customFile("c1"), customFile("c2")}, f.ops(false))

	if f.prompts != 1 {
		t.Fatalf("a cancelled prompt must not be retried: prompts=%d", f.prompts)
	}
	if !totals.Cancelled || totals.Skipped != 1 {
		t.Fatalf("expected cancellation with one skipped file: %+v", totals)
	}
	if f.retryAsked != 0 {
		t.Fatal("retry must not be offered after cancellation")
	}
}

func TestOwnerBatchInterruptDuringAccountPhase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeBatch{retryAnswer: true}
	f.downloadFn = func(batchPendingFile, int, []byte) error {
		cancel()
		return context.Canceled
	}
	totals := runOwnerDownloadBatch(ctx, []batchPendingFile{accountFile("a1"), accountFile("a2"), customFile("c1")}, f.ops(false))

	if len(f.downloads) != 1 || f.prompts != 0 {
		t.Fatalf("interrupt must stop the run: downloads=%v prompts=%d", f.downloads, f.prompts)
	}
	if !totals.Cancelled || totals.Skipped != 2 {
		t.Fatalf("expected the two unstarted files skipped: %+v", totals)
	}
	if f.retryAsked != 0 {
		t.Fatal("retry must not be offered after an interrupt")
	}
}

func TestOwnerBatchNoTerminalFailsCustomFilesWithoutRetryPrompt(t *testing.T) {
	f := &fakeBatch{retryAnswer: true}
	f.readFn = func(string, int) ([]byte, error) {
		return nil, errors.New("no controlling terminal for password prompt; use --password-stdin to read from a pipe")
	}
	totals := runOwnerDownloadBatch(context.Background(), []batchPendingFile{accountFile("a1"), customFile("c1")}, f.ops(true))

	if f.prompts != 1 || f.retryAsked != 0 {
		t.Fatalf("prompts=%d retryAsked=%d", f.prompts, f.retryAsked)
	}
	if totals.AccountOK != 1 || totals.Unresolved != 1 || totals.Cancelled {
		t.Fatalf("unexpected totals: %+v", totals)
	}
	if totals.LastFailures[0].Reason != "prompt_cancelled" {
		t.Fatalf("unexpected reason: %+v", totals.LastFailures)
	}
}
