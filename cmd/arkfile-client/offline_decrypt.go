// offline_decrypt.go - Offline decryption of .arkbackup bundles
// Decrypts .arkbackup bundles using only local computation. No network required.
// This file holds the bundle format, the strict shared validator used by
// decrypt-blob and backup-manifest, and the per-bundle crypto helpers.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arkfile/Arkfile/crypto"
)

// bundleMeta matches the JSON metadata schema in the .arkbackup bundle.
//
// bundles are self-describing. OwnerUsername is required
// to reconstruct the metadata AAD when decrypting `encrypted_filename`,
// `encrypted_sha256sum`, `encrypted_tags`, and `encrypted_password_hint`.
// The exporter writes the file owner here so the offline decrypter can
// decrypt without any external state. The schema matches `bundleMetadata`
// in handlers/export.go field for field.
type bundleMeta struct {
	Version               int    `json:"version"`
	FileID                string `json:"file_id"`
	OwnerUsername         string `json:"owner_username"`
	AccountKDFSalt        string `json:"account_kdf_salt"`
	AccountKDFProfile     int    `json:"account_kdf_profile"`
	EncryptedFEK          string `json:"encrypted_fek"`
	PasswordType          string `json:"password_type"`
	SizeBytes             int64  `json:"size_bytes"`
	PaddedSize            int64  `json:"padded_size"`
	EncryptedFilename     string `json:"encrypted_filename"`
	FilenameNonce         string `json:"filename_nonce"`
	EncryptedSHA256Sum    string `json:"encrypted_sha256sum"`
	SHA256SumNonce        string `json:"sha256sum_nonce"`
	EncryptedTags         string `json:"encrypted_tags,omitempty"`
	TagsNonce             string `json:"tags_nonce,omitempty"`
	EncryptedPasswordHint string `json:"encrypted_password_hint,omitempty"`
	PasswordHintNonce     string `json:"password_hint_nonce,omitempty"`
	ChunkSizeBytes        int64  `json:"chunk_size_bytes"`
	ChunkCount            int64  `json:"chunk_count"`
	EnvelopeVersion       int    `json:"envelope_version"`
	CreatedAt             string `json:"created_at"`
}

const (
	bundleFixedHeaderSize = 10
	bundleFormatVersion   = 2
	maxBundleHeaderBytes  = 1024 * 1024
	// Bounds keep chunk arithmetic far from int64 overflow and keep the
	// per-chunk read buffer small enough for constrained devices.
	maxBundleChunkSizeBytes = 256 * 1024 * 1024
	maxBundlePayloadBytes   = int64(1) << 50
)

// Stable failure and skip reasons reported by decrypt-blob and
// backup-manifest. Reason strings never contain password material.
const (
	reasonNotABundle            = "not_a_bundle"
	reasonUnsafeBundleFile      = "unsafe_bundle_file"
	reasonUnsupportedVersion    = "unsupported_version"
	reasonUnsupportedKDFProfile = "unsupported_kdf_profile"
	reasonInvalidBundleMetadata = "invalid_bundle_metadata"
	reasonBundleLengthMismatch  = "bundle_length_mismatch"
	reasonDuplicateFileID       = "duplicate_file_id"
	reasonOwnerMismatch         = "owner_mismatch"
	reasonAccountKeyUnavailable = "account_key_unavailable"
	reasonWrongAccountPassword  = "wrong_account_password"
	reasonWrongCustomPassword   = "wrong_custom_password"
	reasonTerminalRequired      = "terminal_required"
	reasonPromptTimeout         = "prompt_timeout"
	reasonPromptCancelled       = "prompt_cancelled"
	reasonIntegrityMismatch     = "integrity_mismatch"
	reasonWriteFailed           = "write_failed"
	reasonCancelled             = "cancelled"
	reasonSkipped               = "skipped"
)

// bundleError carries a stable reason alongside a human-readable cause.
type bundleError struct {
	Reason string
	Err    error
}

func (e *bundleError) Error() string {
	if e.Err == nil {
		return e.Reason
	}
	return fmt.Sprintf("%s: %v", e.Reason, e.Err)
}

func (e *bundleError) Unwrap() error { return e.Err }

func newBundleError(reason, format string, args ...interface{}) error {
	return &bundleError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// bundleErrorReason returns the stable reason for err, or fallback.
func bundleErrorReason(err error, fallback string) string {
	var be *bundleError
	if errors.As(err, &be) {
		return be.Reason
	}
	return fallback
}

// validatedBundle is a bundle that passed every structural check. Nothing in
// it has been authenticated yet; AEAD checks happen at decrypt time.
type validatedBundle struct {
	Path         string
	Meta         *bundleMeta
	OuterVersion uint16
	BlobOffset   int64
	FileSize     int64
	AccountSalt  []byte
	Envelope     *crypto.FEKEnvelopeHeader
}

// validateBundleFile applies the strict shared validator to path. It reads
// only the bounded header and file metadata, never the payload.
func validateBundleFile(path string) (*validatedBundle, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, newBundleError(reasonUnsafeBundleFile, "cannot inspect bundle: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, newBundleError(reasonUnsafeBundleFile, "not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, newBundleError(reasonUnsafeBundleFile, "cannot open bundle: %v", err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, newBundleError(reasonUnsafeBundleFile, "bundle changed while it was being opened")
	}

	meta, outerVersion, headerLen, err := readBundleHeader(f)
	if err != nil {
		return nil, err
	}
	b, err := validateBundleMeta(meta, outerVersion, headerLen, openedInfo.Size())
	if err != nil {
		return nil, err
	}
	b.Path = path
	return b, nil
}

// readBundleHeader reads magic, version, header length, and the JSON header
// with full reads, so short reads from FUSE or network mounts are handled.
func readBundleHeader(r io.Reader) (*bundleMeta, uint16, uint32, error) {
	fixed := make([]byte, bundleFixedHeaderSize)
	n, err := io.ReadFull(r, fixed[:4])
	if err != nil || n != 4 || string(fixed[:4]) != "ARKB" {
		return nil, 0, 0, newBundleError(reasonNotABundle, "missing ARKB magic")
	}
	if _, err := io.ReadFull(r, fixed[4:]); err != nil {
		return nil, 0, 0, newBundleError(reasonBundleLengthMismatch, "truncated bundle header")
	}
	outerVersion := binary.BigEndian.Uint16(fixed[4:6])
	if outerVersion != bundleFormatVersion {
		return nil, 0, 0, newBundleError(reasonUnsupportedVersion, "unsupported bundle version %d (expected %d)", outerVersion, bundleFormatVersion)
	}
	headerLen := binary.BigEndian.Uint32(fixed[6:10])
	if headerLen == 0 || headerLen > maxBundleHeaderBytes {
		return nil, 0, 0, newBundleError(reasonInvalidBundleMetadata, "metadata header length %d outside 1..%d bytes", headerLen, maxBundleHeaderBytes)
	}
	metaJSON := make([]byte, headerLen)
	if _, err := io.ReadFull(r, metaJSON); err != nil {
		return nil, 0, 0, newBundleError(reasonBundleLengthMismatch, "truncated metadata header")
	}
	var meta bundleMeta
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil, 0, 0, newBundleError(reasonInvalidBundleMetadata, "metadata is not valid JSON")
	}
	return &meta, outerVersion, headerLen, nil
}

// validateBundleMeta checks identifiers, crypto-field encodings, size and
// chunk arithmetic, and the exact file length against the header.
func validateBundleMeta(meta *bundleMeta, outerVersion uint16, headerLen uint32, fileSize int64) (*validatedBundle, error) {
	invalid := func(format string, args ...interface{}) error {
		return newBundleError(reasonInvalidBundleMetadata, format, args...)
	}
	if meta.Version != int(outerVersion) {
		return nil, newBundleError(reasonUnsupportedVersion, "metadata version %d does not match bundle version %d", meta.Version, outerVersion)
	}
	if strings.TrimSpace(meta.FileID) == "" || strings.ContainsAny(meta.FileID, "/\\\x00") {
		return nil, invalid("missing or malformed file_id")
	}
	if strings.TrimSpace(meta.OwnerUsername) == "" {
		return nil, invalid("missing owner_username")
	}
	if meta.AccountKDFProfile != int(crypto.OwnerEnvelopeKDFProfile()) {
		return nil, newBundleError(reasonUnsupportedKDFProfile, "unsupported Account Key KDF profile %d", meta.AccountKDFProfile)
	}
	accountSalt, err := decodeStrictBase64(meta.AccountKDFSalt)
	if err != nil || crypto.ValidatePasswordSalt(accountSalt) != nil {
		return nil, invalid("malformed account_kdf_salt")
	}

	if meta.PasswordType != "account" && meta.PasswordType != "custom" {
		return nil, invalid("unsupported password_type %q", meta.PasswordType)
	}
	envelopeBytes, err := decodeStrictBase64(meta.EncryptedFEK)
	if err != nil {
		return nil, invalid("malformed encrypted_fek")
	}
	expectedEnvelope := crypto.OwnerEnvelopeHeaderSize() + crypto.AesGcmNonceSize() + 32 + crypto.AesGcmTagSize()
	if len(envelopeBytes) != expectedEnvelope {
		return nil, invalid("encrypted_fek must be %d bytes, got %d", expectedEnvelope, len(envelopeBytes))
	}
	envelope, err := crypto.ParseFEKEnvelopeHeader(envelopeBytes)
	if err != nil {
		if strings.Contains(err.Error(), "KDF profile") {
			return nil, newBundleError(reasonUnsupportedKDFProfile, "%v", err)
		}
		return nil, invalid("%v", err)
	}
	if meta.EnvelopeVersion != 0 && meta.EnvelopeVersion != int(envelope.Version) {
		return nil, invalid("envelope_version %d does not match the FEK envelope", meta.EnvelopeVersion)
	}
	if envelope.PasswordType() != meta.PasswordType {
		return nil, invalid("FEK envelope key type does not match password_type")
	}
	if meta.PasswordType == "account" && !bytes.Equal(envelope.Salt, accountSalt) {
		return nil, invalid("account FEK envelope salt does not match account_kdf_salt")
	}

	if err := validateMetadataCiphertext(meta.EncryptedFilename, meta.FilenameNonce, true); err != nil {
		return nil, invalid("filename: %v", err)
	}
	if err := validateMetadataCiphertext(meta.EncryptedSHA256Sum, meta.SHA256SumNonce, true); err != nil {
		return nil, invalid("sha256sum: %v", err)
	}
	if err := validateMetadataCiphertext(meta.EncryptedTags, meta.TagsNonce, false); err != nil {
		return nil, invalid("tags: %v", err)
	}
	if err := validateMetadataCiphertext(meta.EncryptedPasswordHint, meta.PasswordHintNonce, false); err != nil {
		return nil, invalid("password hint: %v", err)
	}

	if err := validateChunkLayout(meta); err != nil {
		return nil, err
	}

	blobOffset := int64(bundleFixedHeaderSize) + int64(headerLen)
	if meta.PaddedSize != 0 {
		if meta.PaddedSize < meta.SizeBytes || meta.PaddedSize > maxBundlePayloadBytes {
			return nil, invalid("padded_size %d is inconsistent with size_bytes %d", meta.PaddedSize, meta.SizeBytes)
		}
		if fileSize != blobOffset+meta.PaddedSize {
			return nil, newBundleError(reasonBundleLengthMismatch, "file is %d bytes, header declares %d", fileSize, blobOffset+meta.PaddedSize)
		}
	} else if fileSize < blobOffset+meta.SizeBytes {
		return nil, newBundleError(reasonBundleLengthMismatch, "file is %d bytes, payload needs at least %d", fileSize, blobOffset+meta.SizeBytes)
	}

	return &validatedBundle{
		Meta:         meta,
		OuterVersion: outerVersion,
		BlobOffset:   blobOffset,
		FileSize:     fileSize,
		AccountSalt:  accountSalt,
		Envelope:     envelope,
	}, nil
}

// validateChunkLayout checks that size_bytes is exactly what chunk_count
// chunks of chunk_size_bytes plaintext (each with GCM overhead) can produce.
func validateChunkLayout(meta *bundleMeta) error {
	invalid := func(format string, args ...interface{}) error {
		return newBundleError(reasonInvalidBundleMetadata, format, args...)
	}
	if meta.SizeBytes <= 0 || meta.SizeBytes > maxBundlePayloadBytes {
		return invalid("size_bytes %d out of range", meta.SizeBytes)
	}
	if meta.ChunkSizeBytes < 0 || meta.ChunkSizeBytes > maxBundleChunkSizeBytes {
		return invalid("chunk_size_bytes %d out of range", meta.ChunkSizeBytes)
	}
	if meta.ChunkCount <= 0 {
		return invalid("chunk_count %d out of range", meta.ChunkCount)
	}
	chunkSize := effectiveChunkSize(meta)
	overhead := int64(crypto.AesGcmOverhead())
	fullChunk := chunkSize + overhead
	if meta.ChunkCount > maxBundlePayloadBytes/fullChunk+1 {
		return invalid("chunk_count %d out of range", meta.ChunkCount)
	}
	minSize := (meta.ChunkCount-1)*fullChunk + overhead
	maxSize := meta.ChunkCount * fullChunk
	if meta.SizeBytes < minSize || meta.SizeBytes > maxSize {
		return invalid("size_bytes %d is inconsistent with %d chunk(s) of %d bytes", meta.SizeBytes, meta.ChunkCount, chunkSize)
	}
	return nil
}

func effectiveChunkSize(meta *bundleMeta) int64 {
	if meta.ChunkSizeBytes > 0 {
		return meta.ChunkSizeBytes
	}
	return crypto.PlaintextChunkSize()
}

func validateMetadataCiphertext(ciphertextB64, nonceB64 string, required bool) error {
	if ciphertextB64 == "" && nonceB64 == "" {
		if required {
			return fmt.Errorf("missing")
		}
		return nil
	}
	if ciphertextB64 == "" || nonceB64 == "" {
		return fmt.Errorf("ciphertext and nonce must both be present")
	}
	nonce, err := decodeStrictBase64(nonceB64)
	if err != nil || len(nonce) != crypto.AesGcmNonceSize() {
		return fmt.Errorf("malformed nonce")
	}
	ciphertext, err := decodeStrictBase64(ciphertextB64)
	if err != nil || len(ciphertext) < crypto.AesGcmTagSize() || len(ciphertext) > maxBundleHeaderBytes {
		return fmt.Errorf("malformed ciphertext")
	}
	return nil
}

func decodeStrictBase64(s string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(s)
}

// accountKeyUnlocks reports whether accountKey authenticates material in b:
// the FEK envelope for an account-password bundle, otherwise the encrypted
// filename. A false result means a wrong key or a damaged bundle.
func accountKeyUnlocks(b *validatedBundle, accountKey []byte) bool {
	if b.Meta.PasswordType == "account" {
		fek, _, err := unwrapFEK(b.Meta.EncryptedFEK, accountKey, b.Meta.FileID)
		clearBytes(fek)
		return err == nil
	}
	_, err := decryptMetadataField(b.Meta.EncryptedFilename, b.Meta.FilenameNonce, accountKey,
		b.Meta.FileID, crypto.AADFieldFilename, b.Meta.OwnerUsername)
	return err == nil
}

// ownerDisplayMetadata is the decrypted owner metadata shown to the user.
// Every string is user-authored and must pass through sanitizeDisplayText.
type ownerDisplayMetadata struct {
	Filename    string
	TagsLine    string
	TagsFailed  bool
	Hint        string
	HintState   hintState
	FilenameSet bool
}

func decryptOwnerDisplayMetadata(b *validatedBundle, accountKey []byte) ownerDisplayMetadata {
	m := b.Meta
	var md ownerDisplayMetadata
	if name, err := decryptMetadataField(m.EncryptedFilename, m.FilenameNonce, accountKey,
		m.FileID, crypto.AADFieldFilename, m.OwnerUsername); err == nil && name != "" {
		md.Filename = name
		md.FilenameSet = true
	}
	if m.EncryptedTags != "" && m.TagsNonce != "" {
		if tags, err := decryptMetadataField(m.EncryptedTags, m.TagsNonce, accountKey,
			m.FileID, crypto.AADFieldTags, m.OwnerUsername); err == nil {
			if tags == "" {
				md.TagsLine = "(none)"
			} else {
				md.TagsLine = strings.ReplaceAll(tags, ",", ", ")
			}
		} else {
			md.TagsFailed = true
		}
	}
	md.Hint, md.HintState = decryptPasswordHint(m.EncryptedPasswordHint, m.PasswordHintNonce, accountKey, m.FileID, m.OwnerUsername)
	return md
}

// printOwnerMetadata prints filename, tags, and (for custom-password
// bundles) the hint line. Hints go to stdout only.
func printOwnerMetadata(b *validatedBundle, md ownerDisplayMetadata, indent string) {
	name := "[unknown]"
	if md.FilenameSet {
		name = md.Filename
	}
	fmt.Printf("%sFile: %s\n", indent, sanitizeDisplayText(name))
	if md.TagsLine != "" {
		fmt.Printf("%sTags: %s\n", indent, sanitizeDisplayText(md.TagsLine))
	} else if md.TagsFailed {
		fmt.Printf("%s[!] WARNING: Could not decrypt tags\n", indent)
	}
	if b.Meta.PasswordType == "custom" {
		fmt.Printf("%s%s\n", indent, hintDisplayLine(md.Hint, md.HintState))
	}
}

// restoreBundlePayload decrypts b's payload with fek into target, verifies
// the plaintext SHA-256 against the encrypted digest, and publishes the
// output only when it matches. It returns the published path and digest.
func restoreBundlePayload(ctx context.Context, b *validatedBundle, fek, accountKey []byte, target *outputTarget) (string, string, error) {
	expectedSHA256, err := decryptMetadataField(b.Meta.EncryptedSHA256Sum, b.Meta.SHA256SumNonce, accountKey,
		b.Meta.FileID, crypto.AADFieldSha256, b.Meta.OwnerUsername)
	if err != nil {
		return "", "", newBundleError(reasonIntegrityMismatch, "encrypted SHA-256 does not authenticate")
	}
	var actualSHA256 string
	path, err := target.write(func(outFile *os.File) error {
		if err := decryptBundleBlob(ctx, b.Path, b.BlobOffset, b.Meta, fek, outFile); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		digest, err := computeStreamingSHA256(outFile.Name())
		if err != nil {
			return newBundleError(reasonWriteFailed, "failed to hash output: %v", err)
		}
		if digest != expectedSHA256 {
			return newBundleError(reasonIntegrityMismatch, "SHA-256 verification failed")
		}
		actualSHA256 = digest
		return nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return "", "", &bundleError{Reason: reasonCancelled, Err: err}
		}
		var be *bundleError
		if errors.As(err, &be) {
			return "", "", err
		}
		return "", "", &bundleError{Reason: reasonWriteFailed, Err: err}
	}
	return path, actualSHA256, nil
}

func handleDecryptBlobCommand(args []string) error {
	fs := flag.NewFlagSet("decrypt-blob", flag.ExitOnError)
	var bundlePaths multiStringFlag
	fs.Var(&bundlePaths, "bundle", "Path to a .arkbackup bundle (repeatable)")
	bundleDir := fs.String("bundle-dir", "", "Directory of bundles to process (non-recursive, validated by content)")
	username := fs.String("username", "", "Optional username assertion; every bundle's owner_username must match")
	outputPath := fs.String("output", "", "Exact output path for one listed --bundle")
	outputDir := fs.String("output-dir", "", "Destination directory; outputs get reserved names and never replace existing entries")
	passwordStdin := fs.Bool("password-stdin", false, "Read the account password from stdin (single bundle: account then custom password, one per line)")
	accountKeyFile := fs.String("account-key-file", "", "Path to hex-encoded 32-byte account key file")
	useAgent := fs.Bool("use-agent", false, "Read account key from running agent")
	inspect := fs.Bool("inspect", false, "Show decrypted owner metadata without reading payloads or asking for custom passwords")
	dryRun := fs.Bool("dry-run", false, "List bundles from plaintext headers only; never prompts")

	fs.Usage = func() {
		fmt.Printf("Usage:\n" +
			"  arkfile-client decrypt-blob --bundle FILE --output PATH\n" +
			"  arkfile-client decrypt-blob --bundle FILE --output-dir DIR\n" +
			"  arkfile-client decrypt-blob --bundle F1 --bundle F2 [...] --output-dir DIR\n" +
			"  arkfile-client decrypt-blob --bundle-dir DIR --output-dir DIR [--dry-run]\n" +
			"  arkfile-client decrypt-blob --bundle-dir DIR --inspect\n\n" +
			"Decrypt .arkbackup bundles offline using only local computation.\n" +
			"Bundles are grouped by Account Key; one account password entry is needed per group.\n" +
			"Account-password files are restored first; custom-password files prompt on the terminal\n" +
			"after their filename, tags, and hint are shown.\n\n" +
			"Options:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	explicit := dedupeStrings(bundlePaths)
	single := len(explicit) == 1 && *bundleDir == ""
	switch {
	case len(explicit) == 0 && *bundleDir == "":
		return fmt.Errorf("--bundle or --bundle-dir is required")
	case *inspect && *dryRun:
		return fmt.Errorf("--inspect and --dry-run are mutually exclusive")
	case *outputPath != "" && *outputDir != "":
		return fmt.Errorf("--output and --output-dir are mutually exclusive")
	case *inspect && (*outputPath != "" || *outputDir != ""):
		return fmt.Errorf("--inspect creates no output; remove --output and --output-dir")
	case *outputPath != "" && !single:
		return fmt.Errorf("--output accepts exactly one --bundle; use --output-dir for multiple bundles or --bundle-dir")
	case !*inspect && !single && *outputDir == "":
		return fmt.Errorf("--output-dir is required for multiple bundles and --bundle-dir")
	case !*inspect && single && *outputPath == "" && *outputDir == "":
		return fmt.Errorf("--output or --output-dir is required")
	case *accountKeyFile != "" && *useAgent:
		return fmt.Errorf("--account-key-file and --use-agent are mutually exclusive")
	}
	defer withPasswordStdin(*passwordStdin)()

	if *outputDir != "" && !*dryRun {
		if err := os.MkdirAll(*outputDir, 0o700); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	ctx, stop := interruptContext()
	defer stop()

	run := newOfflineDecryptRun(ctx, decryptRunOptions{
		Username:       strings.ToLower(strings.TrimSpace(*username)),
		OutputPath:     *outputPath,
		OutputDir:      *outputDir,
		PasswordStdin:  *passwordStdin,
		AccountKeyFile: *accountKeyFile,
		UseAgent:       *useAgent,
		Inspect:        *inspect,
		DryRun:         *dryRun,
		SingleBundle:   single && !*dryRun,
	})
	bundles, err := run.discover(explicit, *bundleDir)
	if err != nil {
		return err
	}
	run.execute(bundles)
	if run.opts.SingleBundle {
		if *inspect {
			return run.summarize()
		}
		return run.singleBundleResult()
	}
	return run.summarize()
}

// readAccountKeyFromFile reads a hex-encoded 32-byte key from a file
func readAccountKeyFromFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect key file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("account key file must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("account key file permissions must not grant group or other access")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	defer clearBytes(data)

	hexStr := strings.TrimSpace(string(data))
	key, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %w", err)
	}

	if len(key) != 32 {
		clearBytes(key)
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	return key, nil
}

// decryptBundleBlob opens the bundle at bundlePath, seeks to the payload,
// and decrypts it into outFile.
func decryptBundleBlob(ctx context.Context, bundlePath string, blobOffset int64, meta *bundleMeta, fek []byte, outFile *os.File) error {
	f, err := os.Open(bundlePath)
	if err != nil {
		return newBundleError(reasonWriteFailed, "failed to open bundle: %v", err)
	}
	defer f.Close()

	if _, err := f.Seek(blobOffset, io.SeekStart); err != nil {
		return newBundleError(reasonWriteFailed, "failed to seek to payload: %v", err)
	}
	return decryptBundleStream(ctx, f, meta, fek, outFile)
}

// decryptBundleStream reads the encrypted payload from r with full reads,
// splits it into uniform chunks, decrypts each chunk, and writes plaintext
// to out.
//
// every chunk uses the uniform layout
// [nonce (12)][ciphertext][tag (16)] with NO per-chunk envelope header.
// Each chunk decrypts with AAD = (file_id, chunk_index, total_chunks)
// so swap / reorder / truncation across the bundle is detected at the
// AEAD layer.
func decryptBundleStream(ctx context.Context, r io.Reader, meta *bundleMeta, fek []byte, out io.Writer) error {
	totalChunks := meta.ChunkCount
	if totalChunks <= 0 {
		return newBundleError(reasonInvalidBundleMetadata, "bundle metadata missing chunk_count")
	}
	fullChunkEnc := effectiveChunkSize(meta) + int64(crypto.AesGcmOverhead())

	remaining := meta.SizeBytes
	for chunkIndex := int64(0); chunkIndex < totalChunks; chunkIndex++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		actualChunk := fullChunkEnc
		if remaining < actualChunk {
			actualChunk = remaining
		}
		if actualChunk <= 0 {
			return newBundleError(reasonIntegrityMismatch, "payload ended before chunk %d", chunkIndex)
		}

		chunkData := make([]byte, actualChunk)
		if _, err := io.ReadFull(r, chunkData); err != nil {
			return newBundleError(reasonBundleLengthMismatch, "failed to read chunk %d: %v", chunkIndex, err)
		}

		plaintext, err := decryptChunk(chunkData, fek, meta.FileID, chunkIndex, totalChunks)
		if err != nil {
			return newBundleError(reasonIntegrityMismatch, "chunk %d does not authenticate", chunkIndex)
		}
		if _, err := out.Write(plaintext); err != nil {
			clearBytes(plaintext)
			return newBundleError(reasonWriteFailed, "failed to write chunk %d: %v", chunkIndex, err)
		}
		clearBytes(plaintext)

		remaining -= actualChunk
		if verbose {
			logVerbose("  Chunk %d decrypted (%d bytes remaining)", chunkIndex+1, remaining)
		}
	}
	if remaining != 0 {
		return newBundleError(reasonIntegrityMismatch, "payload length does not match chunk_count")
	}

	logVerbose("Decrypted %d chunks", totalChunks)
	return nil
}
