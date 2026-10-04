package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/arkfile/Arkfile/crypto"
)

// testBundleSpec describes a real, fully encrypted .arkbackup fixture.
type testBundleSpec struct {
	Dir          string
	Name         string
	FileID       string
	Owner        string
	AccountKey   []byte
	AccountSalt  []byte
	PasswordType string
	CustomKey    []byte
	CustomSalt   []byte
	Plaintext    []byte
	Filename     string
	Tags         string
	Hint         string
	ChunkSize    int64
	PaddingBytes int
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func encryptTestField(t *testing.T, plaintext string, key []byte, fileID, field, owner string) (string, string) {
	t.Helper()
	aad := crypto.BuildMetadataFieldAAD(fileID, field, owner)
	sealed, err := crypto.EncryptGCMWithAAD([]byte(plaintext), key, aad)
	if err != nil {
		t.Fatal(err)
	}
	nonceSize := crypto.AesGcmNonceSize()
	return crypto.EncodeBase64(sealed[nonceSize:]), crypto.EncodeBase64(sealed[:nonceSize])
}

// writeTestBundle writes spec as a bundle and returns its path.
func writeTestBundle(t *testing.T, spec testBundleSpec) string {
	t.Helper()
	path, _ := buildTestBundleBytes(t, spec)
	return path
}

func buildTestBundleBytes(t *testing.T, spec testBundleSpec) (string, []byte) {
	t.Helper()
	if spec.Owner == "" {
		spec.Owner = testOwner
	}
	if spec.PasswordType == "" {
		spec.PasswordType = "account"
	}
	if spec.AccountSalt == nil {
		spec.AccountSalt = testOwnerSalt()
	}
	if spec.Filename == "" {
		spec.Filename = "file.bin"
	}
	chunkSize := spec.ChunkSize
	if chunkSize == 0 {
		chunkSize = crypto.PlaintextChunkSize()
	}

	fek, err := generateFEK()
	if err != nil {
		t.Fatal(err)
	}
	kek, envelopeSalt := spec.AccountKey, spec.AccountSalt
	if spec.PasswordType == "custom" {
		kek, envelopeSalt = spec.CustomKey, spec.CustomSalt
	}
	wrapped, err := wrapFEK(fek, kek, envelopeSalt, spec.PasswordType, spec.FileID)
	if err != nil {
		t.Fatal(err)
	}

	var payload bytes.Buffer
	chunkCount := int64(0)
	plain := spec.Plaintext
	for {
		end := int64(len(plain))
		if end > chunkSize {
			end = chunkSize
		}
		chunkCount++
		plain = plain[end:]
		if len(plain) == 0 {
			break
		}
	}
	plain = spec.Plaintext
	for i := int64(0); i < chunkCount; i++ {
		end := int64(len(plain))
		if end > chunkSize {
			end = chunkSize
		}
		enc, err := encryptChunk(plain[:end], fek, spec.FileID, i, chunkCount)
		if err != nil {
			t.Fatal(err)
		}
		payload.Write(enc)
		plain = plain[end:]
	}
	sizeBytes := int64(payload.Len())
	payload.Write(make([]byte, spec.PaddingBytes))

	digest := sha256.Sum256(spec.Plaintext)
	meta := bundleMeta{
		Version:           2,
		FileID:            spec.FileID,
		OwnerUsername:     spec.Owner,
		AccountKDFSalt:    crypto.EncodeBase64(spec.AccountSalt),
		AccountKDFProfile: int(crypto.OwnerEnvelopeKDFProfile()),
		EncryptedFEK:      wrapped,
		PasswordType:      spec.PasswordType,
		SizeBytes:         sizeBytes,
		PaddedSize:        int64(payload.Len()),
		ChunkSizeBytes:    chunkSize,
		ChunkCount:        chunkCount,
		EnvelopeVersion:   int(crypto.OwnerEnvelopeVersion()),
		CreatedAt:         "2026-01-01T00:00:00Z",
	}
	meta.EncryptedFilename, meta.FilenameNonce = encryptTestField(t, spec.Filename, spec.AccountKey, spec.FileID, crypto.AADFieldFilename, spec.Owner)
	meta.EncryptedSHA256Sum, meta.SHA256SumNonce = encryptTestField(t, hex.EncodeToString(digest[:]), spec.AccountKey, spec.FileID, crypto.AADFieldSha256, spec.Owner)
	if spec.Tags != "" {
		meta.EncryptedTags, meta.TagsNonce = encryptTestField(t, spec.Tags, spec.AccountKey, spec.FileID, crypto.AADFieldTags, spec.Owner)
	}
	if spec.Hint != "" {
		meta.EncryptedPasswordHint, meta.PasswordHintNonce = encryptTestField(t, spec.Hint, spec.AccountKey, spec.FileID, crypto.AADFieldPasswordHint, spec.Owner)
	}

	data := encodeTestBundle(t, meta, payload.Bytes())
	dir := spec.Dir
	if dir == "" {
		dir = t.TempDir()
	}
	name := spec.Name
	if name == "" {
		name = spec.Filename + arkbackupSuffix
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func encodeTestBundle(t *testing.T, meta bundleMeta, payload []byte) []byte {
	t.Helper()
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.WriteString("ARKB")
	_ = binary.Write(&out, binary.BigEndian, uint16(2))
	_ = binary.Write(&out, binary.BigEndian, uint32(len(metaJSON)))
	out.Write(metaJSON)
	out.Write(payload)
	return out.Bytes()
}

// rewriteBundleMeta re-encodes the bundle at path after mutate edits its
// metadata, keeping the payload bytes.
func rewriteBundleMeta(t *testing.T, path string, mutate func(*bundleMeta)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	meta, _, headerLen, err := readBundleHeader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	payload := data[10+int(headerLen):]
	mutate(meta)
	if err := os.WriteFile(path, encodeTestBundle(t, *meta, payload), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeAccountKeyFile(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "account.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var (
	testCustomPassword    = []byte("Fixture-Custom-Password-2026!")
	testCustomSaltOnce    sync.Once
	testCustomSaltValue   []byte
	testCustomKeyValue    []byte
	testCustomKeyDeriveEr error
)

// testCustomKey derives the fixture custom-password key once per test binary.
func testCustomKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	testCustomSaltOnce.Do(func() {
		testCustomSaltValue = bytes.Repeat([]byte{0x3c}, crypto.OwnerEnvelopeSaltSize())
		testCustomKeyValue, testCustomKeyDeriveEr = crypto.DeriveCustomPasswordKey(testCustomPassword, testCustomSaltValue)
	})
	if testCustomKeyDeriveEr != nil {
		t.Fatal(testCustomKeyDeriveEr)
	}
	return append([]byte(nil), testCustomKeyValue...), append([]byte(nil), testCustomSaltValue...)
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() { os.Stdout = orig }()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func fileSHA256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func listDirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func hasTempLeftovers(names []string) bool {
	for _, n := range names {
		if strings.HasPrefix(n, ".arkfile-output-") {
			return true
		}
	}
	return false
}
