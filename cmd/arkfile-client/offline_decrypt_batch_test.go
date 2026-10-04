package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/crypto"
)

const (
	batchFileA = "aaaaaaaa-0000-0000-0000-000000000001"
	batchFileB = "aaaaaaaa-0000-0000-0000-000000000002"
	batchFileC = "aaaaaaaa-0000-0000-0000-000000000003"
	batchFileD = "aaaaaaaa-0000-0000-0000-000000000004"
)

func overrideTerminalPassword(t *testing.T, fn func(prompt string, timeout time.Duration) ([]byte, error)) {
	t.Helper()
	orig := readTerminalPassword
	readTerminalPassword = fn
	t.Cleanup(func() { readTerminalPassword = orig })
}

func noTerminal(string, time.Duration) ([]byte, error) {
	return nil, errors.New("no controlling terminal for password prompt; use --password-stdin to read from a pipe")
}

func runChainedDecrypt(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = handleDecryptBlobCommand(args) })
	return out, err
}

func TestChainedDecryptDiscoveryAndDuplicateFallback(t *testing.T) {
	key := randomBytes(t, 32)
	bundles := t.TempDir()
	out := t.TempDir()

	// The first copy of file A sorts first and has a damaged payload.
	damaged := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "a-1-damaged.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "alpha.txt", Plaintext: []byte("alpha payload")})
	data, _ := os.ReadFile(damaged)
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(damaged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "a-2-good.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "alpha.txt", Plaintext: []byte("alpha payload")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "a-3-extra.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "alpha.txt", Plaintext: []byte("alpha payload")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "renamed-without-suffix", FileID: batchFileB, AccountKey: key, Filename: "beta.txt", Plaintext: []byte("beta payload")})
	_, truncated := buildTestBundleBytes(t, testBundleSpec{FileID: batchFileC, AccountKey: key, Filename: "gamma.txt", Plaintext: []byte("gamma")})
	if err := os.WriteFile(filepath.Join(bundles, "gamma.txt.arkbackup"), truncated[:len(truncated)-4], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundles, "notes.txt"), []byte("recovery note"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundles, "wrong-magic.arkbackup"), []byte("XXXX garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", out, "--account-key-file", writeAccountKeyFile(t, key))
	if err == nil {
		t.Fatalf("expected non-zero exit for damaged and truncated bundles:\n%s", stdout)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "alpha.txt")); string(got) != "alpha payload" {
		t.Fatalf("damaged first copy suppressed the valid copy: %v\n%s", listDirNames(t, out), stdout)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "beta.txt")); string(got) != "beta payload" {
		t.Fatalf("bundle discovered by content was not restored:\n%s", stdout)
	}
	for _, want := range []string{
		"Decrypted: 2 (account: 2, custom: 0)",
		"Non-bundle files: 2",
		"[-] duplicate_file_id: alpha.txt",
		"integrity_mismatch: alpha.txt",
		"bundle_length_mismatch",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("summary missing %q:\n%s", want, stdout)
		}
	}
	if strings.Count(stdout, "duplicate_file_id") != 1 {
		t.Fatalf("expected exactly one duplicate_file_id:\n%s", stdout)
	}
	if hasTempLeftovers(listDirNames(t, out)) {
		t.Fatalf("temporary output left behind: %v", listDirNames(t, out))
	}
}

func TestChainedDecryptExitZeroWhenOnlyDuplicatesAndNonBundles(t *testing.T) {
	key := randomBytes(t, 32)
	bundles := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "a.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "a.txt", Plaintext: []byte("a")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "a-copy.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "a.txt", Plaintext: []byte("a")})
	os.WriteFile(filepath.Join(bundles, "readme.txt"), []byte("x"), 0o600)
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", t.TempDir(), "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("duplicates and non-bundles must not fail the run: %v\n%s", err, stdout)
	}
}

func TestChainedDecryptDamagedFirstCandidateDoesNotPoisonGroup(t *testing.T) {
	key := randomBytes(t, 32)
	bundles := t.TempDir()
	first := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "one.txt", Plaintext: []byte("one")})
	rewriteBundleMeta(t, first, func(m *bundleMeta) {
		raw, _ := crypto.DecodeBase64(m.EncryptedFEK)
		raw[len(raw)-1] ^= 0x01
		m.EncryptedFEK = crypto.EncodeBase64(raw)
	})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "2.arkbackup", FileID: batchFileB, AccountKey: key, Filename: "two.txt", Plaintext: []byte("two")})
	out := t.TempDir()
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", out, "--account-key-file", writeAccountKeyFile(t, key))
	if err == nil {
		t.Fatal("expected non-zero exit for the damaged bundle")
	}
	if strings.Contains(stdout, reasonAccountKeyUnavailable) || strings.Contains(stdout, reasonWrongAccountPassword) {
		t.Fatalf("a damaged first candidate made the correct key look wrong:\n%s", stdout)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "two.txt")); string(got) != "two" {
		t.Fatalf("valid bundle in the same group was not restored:\n%s", stdout)
	}
}

func TestChainedDecryptGroupsBySaltAndLimitsKeySources(t *testing.T) {
	keyA := randomBytes(t, 32)
	keyB := randomBytes(t, 32)
	saltB := bytes.Repeat([]byte{0x11}, crypto.OwnerEnvelopeSaltSize())
	bundles := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1.arkbackup", FileID: batchFileA, AccountKey: keyA, Filename: "a.txt", Plaintext: []byte("a")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "2.arkbackup", FileID: batchFileB, Owner: testOwner2, AccountKey: keyB, AccountSalt: saltB, Filename: "b.txt", Plaintext: []byte("b")})

	b1, _ := validateBundleFile(filepath.Join(bundles, "1.arkbackup"))
	b2, _ := validateBundleFile(filepath.Join(bundles, "2.arkbackup"))
	groups := groupBundles([]*validatedBundle{b1, b2})
	if len(groups) != 2 || groups[0].Owner != testOwner || groups[1].Owner != testOwner2 {
		t.Fatalf("expected two groups in first-appearance order, got %d", len(groups))
	}

	out := t.TempDir()
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", out, "--account-key-file", writeAccountKeyFile(t, keyA))
	if err == nil {
		t.Fatal("a group the key file cannot unlock must make the run incomplete")
	}
	if !strings.Contains(stdout, "span 2 Account Key salts") {
		t.Fatalf("multiple salt groups not announced:\n%s", stdout)
	}
	if !strings.Contains(stdout, "account_key_unavailable: - ") {
		t.Fatalf("second group should be account_key_unavailable:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(out, "a.txt")); err != nil {
		t.Fatal("first group was not restored")
	}
	if _, err := os.Stat(filepath.Join(out, "b.txt")); err == nil {
		t.Fatal("key from one salt was reused against another salt")
	}
}

func TestChainedDecryptStdinCarriesOnlyFirstGroupPassword(t *testing.T) {
	password := []byte("Stdin-Account-Password-2026!")
	saltA := testOwnerSalt()
	saltB := bytes.Repeat([]byte{0x22}, crypto.OwnerEnvelopeSaltSize())
	keyA, err := crypto.DeriveAccountPasswordKey(password, saltA)
	if err != nil {
		t.Fatal(err)
	}
	keyB, err := crypto.DeriveAccountPasswordKey(password, saltB)
	if err != nil {
		t.Fatal(err)
	}
	bundles := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1.arkbackup", FileID: batchFileA, AccountKey: keyA, Filename: "a.txt", Plaintext: []byte("a")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "2.arkbackup", FileID: batchFileB, Owner: testOwner2, AccountKey: keyB, AccountSalt: saltB, Filename: "b.txt", Plaintext: []byte("b")})

	reads := 0
	orig := readAccountPasswordInput
	defer func() { readAccountPasswordInput = orig }()
	readAccountPasswordInput = func(string) ([]byte, error) {
		reads++
		return append([]byte(nil), password...), nil
	}
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", t.TempDir(), "--password-stdin")
	if err == nil {
		t.Fatal("second group must be skipped when stdin carries one password")
	}
	if reads != 1 {
		t.Fatalf("multi-bundle stdin consumed %d lines, want 1", reads)
	}
	if !strings.Contains(stdout, "Decrypted: 1") || !strings.Contains(stdout, reasonAccountKeyUnavailable) {
		t.Fatalf("unexpected summary:\n%s", stdout)
	}
}

func TestChainedDecryptCustomWithoutTerminalSkippedAfterHint(t *testing.T) {
	key := randomBytes(t, 32)
	customKey, customSalt := testCustomKey(t)
	bundles := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1-custom.arkbackup", FileID: batchFileA, AccountKey: key, PasswordType: "custom", CustomKey: customKey, CustomSalt: customSalt, Filename: "custom.txt", Hint: "sentinel-hint", Tags: "a,b", Plaintext: []byte("c")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "2-account.arkbackup", FileID: batchFileB, AccountKey: key, Filename: "account.txt", Plaintext: []byte("a")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "3-custom-nohint.arkbackup", FileID: batchFileC, AccountKey: key, PasswordType: "custom", CustomKey: customKey, CustomSalt: customSalt, Filename: "plain.txt", Plaintext: []byte("p")})
	overrideTerminalPassword(t, noTerminal)

	out := t.TempDir()
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", out, "--account-key-file", writeAccountKeyFile(t, key))
	if err == nil {
		t.Fatal("terminal_required skips must make the exit non-zero")
	}
	accountAt := strings.Index(stdout, "[OK] account.txt")
	hintAt := strings.Index(stdout, "Password hint: sentinel-hint")
	if accountAt < 0 || hintAt < 0 || accountAt > hintAt {
		t.Fatalf("account bundles must run before custom bundles and the hint must print:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Tags: a, b") || !strings.Contains(stdout, "Password hint: (none saved)") {
		t.Fatalf("custom metadata not shown:\n%s", stdout)
	}
	if strings.Count(stdout, "terminal_required") != 2 {
		t.Fatalf("expected two terminal_required skips:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(out, "custom.txt")); err == nil {
		t.Fatal("output created for a skipped custom bundle")
	}
	if hasTempLeftovers(listDirNames(t, out)) {
		t.Fatal("temporary output left behind")
	}
}

func TestChainedDecryptCustomTerminalPromptWithRetries(t *testing.T) {
	key := randomBytes(t, 32)
	customKey, customSalt := testCustomKey(t)
	bundles := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "c.arkbackup", FileID: batchFileA, AccountKey: key, PasswordType: "custom", CustomKey: customKey, CustomSalt: customSalt, Filename: "custom.txt", Hint: "think", Plaintext: []byte("custom bytes")})
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "c2.arkbackup", FileID: batchFileB, AccountKey: key, PasswordType: "custom", CustomKey: customKey, CustomSalt: customSalt, Filename: "never.txt", Plaintext: []byte("never")})

	prompts := map[string]int{}
	overrideTerminalPassword(t, func(prompt string, timeout time.Duration) ([]byte, error) {
		if timeout != PasswordTimeoutBatchCustom {
			t.Errorf("custom prompt timeout = %s", timeout)
		}
		if strings.Contains(prompt, "never.txt") {
			prompts["never"]++
			return []byte("wrong"), nil
		}
		prompts["custom"]++
		if prompts["custom"] == 1 {
			return []byte("wrong-first"), nil
		}
		return append([]byte(nil), testCustomPassword...), nil
	})
	out := t.TempDir()
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", out, "--account-key-file", writeAccountKeyFile(t, key))
	if err == nil {
		t.Fatal("wrong_custom_password must fail the run")
	}
	if prompts["custom"] != 2 || prompts["never"] != MaxBatchCustomPasswordAttempts {
		t.Fatalf("unexpected prompt counts: %v", prompts)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "custom.txt")); string(got) != "custom bytes" {
		t.Fatalf("custom file not restored:\n%s", stdout)
	}
	if !strings.Contains(stdout, "wrong_custom_password: never.txt") {
		t.Fatalf("missing wrong_custom_password line:\n%s", stdout)
	}
}

func TestChainedDecryptInspectReadsNoPayloadAndNoCustomPrompt(t *testing.T) {
	key := randomBytes(t, 32)
	customKey, customSalt := testCustomKey(t)
	bundles := t.TempDir()
	custom := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "c.arkbackup", FileID: batchFileA, AccountKey: key, PasswordType: "custom", CustomKey: customKey, CustomSalt: customSalt, Filename: "evil\x1b]0;x\x07.txt", Hint: "inspect-hint", Tags: "t1", Plaintext: []byte("c")})
	// Corrupt the payload: inspection must still succeed because it never reads it.
	data, _ := os.ReadFile(custom)
	data[len(data)-1] ^= 0xff
	os.WriteFile(custom, data, 0o600)
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "a.arkbackup", FileID: batchFileB, AccountKey: key, Filename: "acct.txt", Plaintext: []byte("a")})
	overrideTerminalPassword(t, func(string, time.Duration) ([]byte, error) {
		t.Fatal("inspection requested a custom password")
		return nil, nil
	})
	before := listDirNames(t, bundles)
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--inspect", "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, stdout)
	}
	for _, want := range []string{"File: evil?]0;x?.txt", "Password hint: inspect-hint", "Tags: t1", "File ID: " + batchFileA, "Password type: custom", "Inspected: 2"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("inspection output missing %q:\n%q", want, stdout)
		}
	}
	if fmt.Sprint(listDirNames(t, bundles)) != fmt.Sprint(before) {
		t.Fatal("inspection created files")
	}
}

func TestChainedDecryptReservationCarriesAcrossGroups(t *testing.T) {
	keyA := randomBytes(t, 32)
	keyB := randomBytes(t, 32)
	saltB := bytes.Repeat([]byte{0x33}, crypto.OwnerEnvelopeSaltSize())
	bundles := t.TempDir()
	a := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1.arkbackup", FileID: batchFileA, AccountKey: keyA, Filename: "photo.png", Plaintext: []byte("first")})
	b := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "2.arkbackup", FileID: batchFileD, Owner: testOwner2, AccountKey: keyB, AccountSalt: saltB, Filename: "PHOTO.png", Plaintext: []byte("second")})
	out := t.TempDir()
	os.WriteFile(filepath.Join(out, "Photo.png"), []byte("existing"), 0o600)

	keys := map[string][]byte{testOwner: keyA, testOwner2: keyB}
	run := newOfflineDecryptRun(t.Context(), decryptRunOptions{OutputDir: out})
	ba, _ := validateBundleFile(a)
	bb, _ := validateBundleFile(b)
	reserver, _ := newOutputNameReserver(out, "")
	run.reserver = reserver
	for _, g := range groupBundles([]*validatedBundle{ba, bb}) {
		key := keys[g.Owner]
		if !run.validateGroupKey(g, key) {
			t.Fatal("group key rejected")
		}
		for _, lf := range g.Files {
			lf.Display = decryptOwnerDisplayMetadata(lf.Usable[0], key)
			lf.Target = run.outputTargetFor(lf)
			run.restoreAccountFile(lf, key)
		}
	}
	names := strings.Join(listDirNames(t, out), ",")
	if names != "PHOTO-2.png,Photo.png,photo-1.png" {
		t.Fatalf("reservation did not carry across groups: %s", names)
	}
}

func TestChainedDecryptOwnerMismatch(t *testing.T) {
	key := randomBytes(t, 32)
	bundles := t.TempDir()
	writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "a.txt", Plaintext: []byte("a")})
	stdout, err := runChainedDecrypt(t, "--bundle-dir", bundles, "--output-dir", t.TempDir(), "--username", "someone-else", "--account-key-file", writeAccountKeyFile(t, key))
	if err == nil || !strings.Contains(stdout, reasonOwnerMismatch) {
		t.Fatalf("expected owner_mismatch: %v\n%s", err, stdout)
	}
}

func TestChainedDecryptInterruptMarksRemainderSkipped(t *testing.T) {
	key := randomBytes(t, 32)
	bundles := t.TempDir()
	a := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "1.arkbackup", FileID: batchFileA, AccountKey: key, Filename: "a.txt", Plaintext: []byte("a")})
	b := writeTestBundle(t, testBundleSpec{Dir: bundles, Name: "2.arkbackup", FileID: batchFileB, AccountKey: key, Filename: "b.txt", Plaintext: []byte("b")})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := t.TempDir()
	run := newOfflineDecryptRun(ctx, decryptRunOptions{OutputDir: out, AccountKeyFile: writeAccountKeyFile(t, key)})
	ba, _ := validateBundleFile(a)
	bb, _ := validateBundleFile(b)
	captureStdout(t, func() { run.execute([]*validatedBundle{ba, bb}) })
	skipped := 0
	for _, o := range run.outcomes {
		if o.Reason == reasonSkipped || o.Reason == reasonCancelled {
			skipped++
		}
	}
	if skipped != 2 || len(listDirNames(t, out)) != 0 {
		t.Fatalf("interrupt should skip every remaining bundle: %+v %v", run.outcomes, listDirNames(t, out))
	}
}
