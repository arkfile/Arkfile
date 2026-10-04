// offline_decrypt_test.go - Tests for the .arkbackup validator and the
// single-bundle offline decrypt path.
//
// Bundles are self-describing. Every bundle must carry
// file_id, owner_username, encrypted_fek, encrypted_filename + nonce,
// encrypted_sha256sum + nonce, password_type, size_bytes, chunk_count,
// chunk_size_bytes.

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/arkfile/Arkfile/crypto"
)

func accountSpec(t *testing.T, key []byte, filename string, plaintext []byte) testBundleSpec {
	t.Helper()
	return testBundleSpec{
		FileID:     testFileID,
		AccountKey: key,
		Filename:   filename,
		Plaintext:  plaintext,
	}
}

func customSpec(t *testing.T, key []byte, filename, hint string, plaintext []byte) testBundleSpec {
	t.Helper()
	customKey, customSalt := testCustomKey(t)
	return testBundleSpec{
		FileID:       testFileID2,
		AccountKey:   key,
		PasswordType: "custom",
		CustomKey:    customKey,
		CustomSalt:   customSalt,
		Filename:     filename,
		Hint:         hint,
		Plaintext:    plaintext,
	}
}

func expectBundleReason(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", reason)
	}
	if got := bundleErrorReason(err, ""); got != reason {
		t.Fatalf("reason = %q (%v), want %q", got, err, reason)
	}
}

func TestValidateBundleFileAcceptsRealBundle(t *testing.T) {
	key := randomBytes(t, 32)
	path := writeTestBundle(t, accountSpec(t, key, "report.pdf", []byte("hello bundle")))
	b, err := validateBundleFile(path)
	if err != nil {
		t.Fatalf("validateBundleFile: %v", err)
	}
	if b.Meta.FileID != testFileID || b.OuterVersion != 2 || b.FileSize <= b.BlobOffset {
		t.Fatalf("unexpected validated bundle: %+v", b)
	}
	if !accountKeyUnlocks(b, key) {
		t.Fatal("correct Account Key did not unlock the bundle")
	}
	if accountKeyUnlocks(b, randomBytes(t, 32)) {
		t.Fatal("wrong Account Key unlocked the bundle")
	}
}

func TestValidateBundleFileAcceptsPaddingAndMultipleChunks(t *testing.T) {
	key := randomBytes(t, 32)
	spec := accountSpec(t, key, "chunks.bin", bytes.Repeat([]byte("abcdefgh"), 9))
	spec.ChunkSize = 16
	spec.PaddingBytes = 37
	path := writeTestBundle(t, spec)
	b, err := validateBundleFile(path)
	if err != nil {
		t.Fatalf("validateBundleFile: %v", err)
	}
	if b.Meta.ChunkCount != 5 {
		t.Fatalf("chunk_count = %d, want 5", b.Meta.ChunkCount)
	}
}

func TestValidateBundleFileAcceptsOldBundleWithoutPaddedSize(t *testing.T) {
	key := randomBytes(t, 32)
	path := writeTestBundle(t, accountSpec(t, key, "old.bin", []byte("old bundle")))
	rewriteBundleMeta(t, path, func(m *bundleMeta) { m.PaddedSize = 0 })
	if _, err := validateBundleFile(path); err != nil {
		t.Fatalf("old bundle without padded_size rejected: %v", err)
	}
}

func TestValidateBundleFileRejectsMalformedBundles(t *testing.T) {
	key := randomBytes(t, 32)
	cases := []struct {
		name   string
		mutate func(*bundleMeta)
		reason string
	}{
		{"inner version mismatch", func(m *bundleMeta) { m.Version = 3 }, reasonUnsupportedVersion},
		{"missing file id", func(m *bundleMeta) { m.FileID = "" }, reasonInvalidBundleMetadata},
		{"path in file id", func(m *bundleMeta) { m.FileID = "../x" }, reasonInvalidBundleMetadata},
		{"missing owner", func(m *bundleMeta) { m.OwnerUsername = "" }, reasonInvalidBundleMetadata},
		{"unsupported kdf profile", func(m *bundleMeta) { m.AccountKDFProfile = 99 }, reasonUnsupportedKDFProfile},
		{"short account salt", func(m *bundleMeta) { m.AccountKDFSalt = crypto.EncodeBase64([]byte("short")) }, reasonInvalidBundleMetadata},
		{"unknown password type", func(m *bundleMeta) { m.PasswordType = "share" }, reasonInvalidBundleMetadata},
		{"password type mismatch", func(m *bundleMeta) { m.PasswordType = "custom" }, reasonInvalidBundleMetadata},
		{"truncated envelope", func(m *bundleMeta) { m.EncryptedFEK = m.EncryptedFEK[:20] }, reasonInvalidBundleMetadata},
		{"envelope version mismatch", func(m *bundleMeta) { m.EnvelopeVersion = 7 }, reasonInvalidBundleMetadata},
		{"bad filename nonce", func(m *bundleMeta) { m.FilenameNonce = crypto.EncodeBase64([]byte("abc")) }, reasonInvalidBundleMetadata},
		{"missing digest", func(m *bundleMeta) { m.EncryptedSHA256Sum = ""; m.SHA256SumNonce = "" }, reasonInvalidBundleMetadata},
		{"half tags pair", func(m *bundleMeta) { m.EncryptedTags = "AAAAAAAAAAAAAAAAAAAAAA==" }, reasonInvalidBundleMetadata},
		{"half hint pair", func(m *bundleMeta) { m.PasswordHintNonce = "AAAAAAAAAAAAAAAA" }, reasonInvalidBundleMetadata},
		{"negative size", func(m *bundleMeta) { m.SizeBytes = -1 }, reasonInvalidBundleMetadata},
		{"negative chunk count", func(m *bundleMeta) { m.ChunkCount = -1 }, reasonInvalidBundleMetadata},
		{"inconsistent chunk count", func(m *bundleMeta) { m.ChunkCount = 4 }, reasonInvalidBundleMetadata},
		{"negative chunk size", func(m *bundleMeta) { m.ChunkSizeBytes = -5 }, reasonInvalidBundleMetadata},
		{"padded smaller than size", func(m *bundleMeta) { m.PaddedSize = m.SizeBytes - 1 }, reasonInvalidBundleMetadata},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTestBundle(t, accountSpec(t, key, "x.bin", []byte("payload for validation")))
			rewriteBundleMeta(t, path, tc.mutate)
			_, err := validateBundleFile(path)
			expectBundleReason(t, err, tc.reason)
		})
	}
}

func TestValidateBundleFileRejectsLengthMismatch(t *testing.T) {
	key := randomBytes(t, 32)
	path, data := buildTestBundleBytes(t, accountSpec(t, key, "len.bin", []byte("length checks")))

	if err := os.WriteFile(path, data[:len(data)-3], 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := validateBundleFile(path)
	expectBundleReason(t, err, reasonBundleLengthMismatch)

	if err := os.WriteFile(path, append(append([]byte(nil), data...), 0, 0), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = validateBundleFile(path)
	expectBundleReason(t, err, reasonBundleLengthMismatch)
}

func TestValidateBundleFileRejectsSymlinkAndNonBundles(t *testing.T) {
	key := randomBytes(t, 32)
	path := writeTestBundle(t, accountSpec(t, key, "real.bin", []byte("x")))
	link := filepath.Join(t.TempDir(), "link.arkbackup")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, err := validateBundleFile(link)
	expectBundleReason(t, err, reasonUnsafeBundleFile)

	decoy := filepath.Join(t.TempDir(), "notes.arkbackup")
	if err := os.WriteFile(decoy, []byte("NOTB not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = validateBundleFile(decoy)
	expectBundleReason(t, err, reasonNotABundle)

	wrongVersion := filepath.Join(t.TempDir(), "v9.arkbackup")
	header := []byte("ARKB\x00\x09\x00\x00\x00\x02{}")
	if err := os.WriteFile(wrongVersion, header, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = validateBundleFile(wrongVersion)
	expectBundleReason(t, err, reasonUnsupportedVersion)

	huge := filepath.Join(t.TempDir(), "huge.arkbackup")
	hugeHeader := make([]byte, 10)
	copy(hugeHeader, "ARKB")
	binary.BigEndian.PutUint16(hugeHeader[4:6], 2)
	binary.BigEndian.PutUint32(hugeHeader[6:10], 2*1024*1024)
	if err := os.WriteFile(huge, hugeHeader, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = validateBundleFile(huge)
	expectBundleReason(t, err, reasonInvalidBundleMetadata)
}

func TestReadBundleHeaderHandlesShortReads(t *testing.T) {
	key := randomBytes(t, 32)
	_, data := buildTestBundleBytes(t, accountSpec(t, key, "short.bin", []byte("short reads")))
	meta, version, headerLen, err := readBundleHeader(iotest.OneByteReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatalf("readBundleHeader with one-byte reads: %v", err)
	}
	if meta.FileID != testFileID || version != 2 || headerLen == 0 {
		t.Fatalf("unexpected header: %+v %d %d", meta, version, headerLen)
	}
}

func TestDecryptBundleStreamHandlesShortReads(t *testing.T) {
	key := randomBytes(t, 32)
	plaintext := bytes.Repeat([]byte("0123456789"), 7)
	spec := accountSpec(t, key, "stream.bin", plaintext)
	spec.ChunkSize = 16
	path, data := buildTestBundleBytes(t, spec)
	b, err := validateBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fek, _, err := unwrapFEK(b.Meta.EncryptedFEK, key, b.Meta.FileID)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reader := iotest.HalfReader(bytes.NewReader(data[b.BlobOffset:]))
	if err := decryptBundleStream(context.Background(), reader, b.Meta, fek, &out); err != nil {
		t.Fatalf("decryptBundleStream with short reads: %v", err)
	}
	if !bytes.Equal(out.Bytes(), plaintext) {
		t.Fatal("plaintext mismatch after short reads")
	}
}

func TestDecryptBundleBlobStopsBeforeWritingWhenCanceled(t *testing.T) {
	key := randomBytes(t, 32)
	path := writeTestBundle(t, accountSpec(t, key, "cancel.bin", []byte("cancelled payload")))
	b, err := validateBundleFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Seek(b.BlobOffset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	err = decryptBundleStream(ctx, f, b.Meta, make([]byte, 32), &out)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("decryptBundleStream error = %v, want context.Canceled", err)
	}
	if out.Len() != 0 {
		t.Fatalf("canceled decryption wrote %d plaintext bytes", out.Len())
	}
}

// TestOfflineArkbackupDecrypt_WrongFileID_Fails proves that a bundle
// whose JSON metadata claims a different file_id than the one the FEK /
// chunks were encrypted under cannot be decrypted.
func TestOfflineArkbackupDecrypt_WrongFileID_Fails(t *testing.T) {
	key := randomBytes(t, 32)
	path := writeTestBundle(t, accountSpec(t, key, "tamper.bin", []byte("payload")))
	rewriteBundleMeta(t, path, func(m *bundleMeta) { m.FileID = testFileID2 })
	b, err := validateBundleFile(path)
	if err != nil {
		t.Fatalf("structurally valid tampered bundle rejected early: %v", err)
	}
	if accountKeyUnlocks(b, key) {
		t.Fatal("FEK envelope authenticated under a substituted file_id")
	}
}

func runSingleDecrypt(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = handleDecryptBlobCommand(args) })
	return out, err
}

func TestSingleBundleAccountRestoreToExactPath(t *testing.T) {
	key := randomBytes(t, 32)
	plaintext := []byte("account bundle restore")
	spec := accountSpec(t, key, "report.pdf", plaintext)
	spec.Tags = "backup-restore"
	bundle := writeTestBundle(t, spec)
	output := filepath.Join(t.TempDir(), "out.bin")
	if err := os.WriteFile(output, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := runSingleDecrypt(t, "--bundle", bundle, "--output", output, "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(output)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("exact --output was not replaced with the restored plaintext")
	}
	for _, want := range []string{"Decrypted: report.pdf", "Tags: backup-restore", "Verified: [OK]"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestSingleBundleOutputDirReservesName(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, accountSpec(t, key, "Photo.png", []byte("new photo")))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "photo.png"), []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runSingleDecrypt(t, "--bundle", bundle, "--output-dir", dir, "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	existing, _ := os.ReadFile(filepath.Join(dir, "photo.png"))
	if string(existing) != "existing" {
		t.Fatal("existing entry was replaced")
	}
	restored, err := os.ReadFile(filepath.Join(dir, "Photo-1.png"))
	if err != nil || string(restored) != "new photo" {
		t.Fatalf("expected case-insensitive reservation Photo-1.png: %v %v", listDirNames(t, dir), err)
	}
}

func TestSingleBundleCustomShowsHintBeforePrompt(t *testing.T) {
	key := randomBytes(t, 32)
	plaintext := []byte("custom payload")
	bundle := writeTestBundle(t, customSpec(t, key, "secret.txt", "blue \x1b[31mdoor\u202e", plaintext))
	output := filepath.Join(t.TempDir(), "secret.out")

	origCustom := readSingleBundleCustomPassword
	defer func() { readSingleBundleCustomPassword = origCustom }()
	readSingleBundleCustomPassword = func(prompt string) ([]byte, error) {
		os.Stdout.WriteString("<<PROMPT>>\n")
		return append([]byte(nil), testCustomPassword...), nil
	}

	out, err := runSingleDecrypt(t, "--bundle", bundle, "--output", output, "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	hintAt := strings.Index(out, "Password hint: blue ?[31mdoor?")
	promptAt := strings.Index(out, "<<PROMPT>>")
	decryptedAt := strings.Index(out, "Decrypted: secret.txt")
	if hintAt < 0 || promptAt < 0 || decryptedAt < 0 || hintAt > promptAt || promptAt > decryptedAt {
		t.Fatalf("hint must print sanitized before the prompt and Decrypted line:\n%q", out)
	}
	got, _ := os.ReadFile(output)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("custom restore produced wrong plaintext")
	}
}

func TestSingleBundleCustomWithoutHintPrintsNoHintLine(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, customSpec(t, key, "nohint.txt", "", []byte("x")))
	origCustom := readSingleBundleCustomPassword
	defer func() { readSingleBundleCustomPassword = origCustom }()
	readSingleBundleCustomPassword = func(string) ([]byte, error) {
		return append([]byte(nil), testCustomPassword...), nil
	}
	out, err := runSingleDecrypt(t, "--bundle", bundle, "--output", filepath.Join(t.TempDir(), "o"), "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !strings.Contains(out, "Password hint: (none saved)") {
		t.Fatalf("missing no-hint line:\n%s", out)
	}
}

func TestSingleBundleUndecryptableHintWarnsAndContinues(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, customSpec(t, key, "badhint.txt", "real hint", []byte("x")))
	otherKey := randomBytes(t, 32)
	rewriteBundleMeta(t, bundle, func(m *bundleMeta) {
		m.EncryptedPasswordHint, m.PasswordHintNonce = encryptTestField(t, "other", otherKey, m.FileID, crypto.AADFieldPasswordHint, m.OwnerUsername)
	})
	origCustom := readSingleBundleCustomPassword
	defer func() { readSingleBundleCustomPassword = origCustom }()
	readSingleBundleCustomPassword = func(string) ([]byte, error) {
		return append([]byte(nil), testCustomPassword...), nil
	}
	out, err := runSingleDecrypt(t, "--bundle", bundle, "--output", filepath.Join(t.TempDir(), "o"), "--account-key-file", writeAccountKeyFile(t, key))
	if err != nil {
		t.Fatalf("an undecryptable hint must not fail the bundle: %v", err)
	}
	if !strings.Contains(out, "Password hint could not be decrypted") || strings.Contains(out, "(none saved)") {
		t.Fatalf("expected could-not-decrypt warning:\n%s", out)
	}
}

func TestHintTamperingFailsAEADAcrossFilesAndOwners(t *testing.T) {
	key := randomBytes(t, 32)
	ciphertext, nonce := encryptTestField(t, "hint", key, testFileID, crypto.AADFieldPasswordHint, testOwner)
	if _, state := decryptPasswordHint(ciphertext, nonce, key, testFileID, testOwner); state != hintPresent {
		t.Fatal("hint did not round trip")
	}
	if _, state := decryptPasswordHint(ciphertext, nonce, key, testFileID2, testOwner); state != hintUndecryptable {
		t.Fatal("hint decrypted under another file_id")
	}
	if _, state := decryptPasswordHint(ciphertext, nonce, key, testFileID, testOwner2); state != hintUndecryptable {
		t.Fatal("hint decrypted under another owner")
	}
}

func TestSingleBundleWrongAccountKeyFailsBeforeCustomPrompt(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, customSpec(t, key, "c.txt", "hint", []byte("x")))
	prompted := false
	origCustom := readSingleBundleCustomPassword
	defer func() { readSingleBundleCustomPassword = origCustom }()
	readSingleBundleCustomPassword = func(string) ([]byte, error) {
		prompted = true
		return append([]byte(nil), testCustomPassword...), nil
	}
	output := filepath.Join(t.TempDir(), "o")
	_, err := runSingleDecrypt(t, "--bundle", bundle, "--output", output, "--account-key-file", writeAccountKeyFile(t, randomBytes(t, 32)))
	if err == nil || !strings.Contains(err.Error(), "wrong account password") {
		t.Fatalf("expected wrong account password error, got %v", err)
	}
	if prompted {
		t.Fatal("custom password was requested after a wrong Account Key")
	}
	if _, statErr := os.Stat(output); !os.IsNotExist(statErr) {
		t.Fatal("output was created after a wrong Account Key")
	}
}

func TestSingleBundleInteractiveAccountReentry(t *testing.T) {
	password := []byte("Interactive-Account-Password-2026")
	salt := testOwnerSalt()
	key, err := crypto.DeriveAccountPasswordKey(password, salt)
	if err != nil {
		t.Fatal(err)
	}
	bundle := writeTestBundle(t, accountSpec(t, key, "re.bin", []byte("reentry")))
	entries := 0
	orig := readAccountPasswordInput
	defer func() { readAccountPasswordInput = orig }()
	readAccountPasswordInput = func(string) ([]byte, error) {
		entries++
		if entries == 1 {
			return []byte("wrong-password-first"), nil
		}
		return append([]byte(nil), password...), nil
	}
	if _, err := runSingleDecrypt(t, "--bundle", bundle, "--output", filepath.Join(t.TempDir(), "o")); err != nil {
		t.Fatalf("re-entry should succeed: %v", err)
	}
	if entries != 2 {
		t.Fatalf("entries = %d, want 2", entries)
	}
}

func TestSingleBundleStdinWrongAccountPasswordFailsOnce(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, accountSpec(t, key, "s.bin", []byte("x")))
	entries := 0
	orig := readAccountPasswordInput
	defer func() { readAccountPasswordInput = orig }()
	readAccountPasswordInput = func(string) ([]byte, error) {
		entries++
		return []byte("not-the-password"), nil
	}
	_, err := runSingleDecrypt(t, "--bundle", bundle, "--output", filepath.Join(t.TempDir(), "o"), "--password-stdin")
	if err == nil || !strings.Contains(err.Error(), "wrong account password") {
		t.Fatalf("expected wrong account password, got %v", err)
	}
	if entries != 1 {
		t.Fatalf("stdin read %d times, want 1", entries)
	}
}

func TestDecryptBlobCommandRejectsBundleMissingOwnerUsername(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, accountSpec(t, key, "o.bin", []byte("x")))
	rewriteBundleMeta(t, bundle, func(m *bundleMeta) { m.OwnerUsername = "" })
	_, err := runSingleDecrypt(t, "--bundle", bundle, "--output", filepath.Join(t.TempDir(), "o"), "--account-key-file", writeAccountKeyFile(t, key))
	if err == nil {
		t.Fatal("decrypt-blob must reject a bundle missing owner_username")
	}
}

func TestDecryptBlobOutputFlagRules(t *testing.T) {
	key := randomBytes(t, 32)
	bundle := writeTestBundle(t, accountSpec(t, key, "f.bin", []byte("x")))
	dir := t.TempDir()
	cases := [][]string{
		{"--bundle", bundle, "--output", "a", "--output-dir", dir},
		{"--bundle", bundle, "--bundle", bundle + "2", "--output", "a"},
		{"--bundle-dir", dir, "--output", "a"},
		{"--bundle-dir", dir},
		{"--bundle", bundle},
		{"--bundle-dir", dir, "--inspect", "--dry-run"},
		{"--bundle-dir", dir, "--inspect", "--output-dir", dir},
	}
	for _, args := range cases {
		if _, err := runSingleDecrypt(t, args...); err == nil {
			t.Errorf("expected rejection for %v", args)
		}
	}
}

func TestReadAccountKeyFromFileRejectsBroadPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, 64), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAccountKeyFromFile(path); err == nil {
		t.Fatal("accepted account key file readable by group or others")
	}
}

func TestPasswordHintTimeoutConstantsReused(t *testing.T) {
	if MaxBatchCustomPasswordAttempts != 3 || PasswordTimeoutBatchCustom != 2*time.Minute {
		t.Fatal("chained decrypt relies on the batch custom-password limits")
	}
}

func FuzzParseBundle(f *testing.F) {
	validMeta, _ := json.Marshal(bundleMeta{
		Version:           2,
		FileID:            testFileID,
		OwnerUsername:     testOwner,
		AccountKDFSalt:    crypto.EncodeBase64(testOwnerSalt()),
		AccountKDFProfile: int(crypto.OwnerEnvelopeKDFProfile()),
		EnvelopeVersion:   int(crypto.OwnerEnvelopeVersion()),
		PasswordType:      "account",
		ChunkCount:        1,
		ChunkSizeBytes:    int64(crypto.PlaintextChunkSize()),
	})
	seed := func(meta []byte) []byte {
		out := make([]byte, 10+len(meta))
		copy(out, []byte("ARKB"))
		binary.BigEndian.PutUint16(out[4:6], 2)
		binary.BigEndian.PutUint32(out[6:10], uint32(len(meta)))
		copy(out[10:], meta)
		return out
	}
	f.Add(seed(validMeta))
	hintMeta, _ := json.Marshal(bundleMeta{
		Version:               2,
		FileID:                testFileID,
		OwnerUsername:         testOwner,
		PasswordType:          "custom",
		EncryptedPasswordHint: "AAAAAAAAAAAAAAAAAAAAAAAA",
		PasswordHintNonce:     "AAAAAAAAAAAAAAAA",
	})
	f.Add(seed(hintMeta))
	oversizedHint, _ := json.Marshal(bundleMeta{
		Version:               2,
		FileID:                testFileID,
		OwnerUsername:         testOwner,
		EncryptedPasswordHint: strings.Repeat("A", 4096),
		PasswordHintNonce:     "AAAAAAAAAAAAAAAA",
	})
	f.Add(seed(oversizedHint))
	f.Add([]byte("ARKB"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		meta, version, headerLen, err := readBundleHeader(bytes.NewReader(input))
		if err != nil {
			return
		}
		_, _ = validateBundleMeta(meta, version, headerLen, int64(len(input)))
	})
}
