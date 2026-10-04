// backup_manifest.go - Minimal integrity manifest for a folder of .arkbackup
// bundles. The manifest is a passwordless, rebuildable inventory of stored
// bundle names, file IDs, bundle versions, byte lengths, and whole-bundle
// SHA-256 digests. It detects accidental corruption, incomplete copies, and
// directory drift; it is not signed or keyed and does not authenticate the
// collection against someone who can replace both bundles and manifest.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	integrityManifestFormat      = "arkbackup-integrity-manifest"
	integrityManifestVersion     = 1
	defaultIntegrityManifestName = "arkbackup-manifest.json"
	maxIntegrityManifestBytes    = 64 * 1024 * 1024
	manifestHashBufferBytes      = 1024 * 1024
)

// Verification problem reasons.
const (
	manifestReasonMissing   = "missing_bundle"
	manifestReasonChanged   = "changed_bundle"
	manifestReasonMalformed = "malformed_bundle"
	manifestReasonUnlisted  = "unlisted_bundle"
	manifestReasonUnsafe    = "unsafe_bundle_file"
)

type integrityManifestEntry struct {
	BundleName      string `json:"bundle_name"`
	FileID          string `json:"file_id"`
	BundleVersion   int    `json:"bundle_version"`
	BundleSizeBytes int64  `json:"bundle_size_bytes"`
	SHA256          string `json:"sha256"`
}

type integrityManifest struct {
	Format  string                   `json:"format"`
	Version int                      `json:"version"`
	Entries []integrityManifestEntry `json:"entries"`
}

type manifestProblem struct {
	Name   string
	Reason string
	Detail string
}

func handleBackupManifestCommand(args []string) error {
	usage := "Usage:\n" +
		"  arkfile-client backup-manifest create --bundle-dir DIR [--output FILE]\n" +
		"  arkfile-client backup-manifest verify --bundle-dir DIR [--manifest FILE]\n\n" +
		"Create or verify an optional integrity manifest for a folder of .arkbackup bundles.\n" +
		"No password is needed. The manifest lists only each bundle's stored name, file ID,\n" +
		"bundle version, byte length, and whole-bundle SHA-256, and can always be rebuilt.\n"
	if len(args) == 0 {
		fmt.Print(usage)
		return fmt.Errorf("backup-manifest requires a subcommand: create or verify")
	}
	switch args[0] {
	case "create":
		return handleBackupManifestCreate(args[1:])
	case "verify":
		return handleBackupManifestVerify(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Print(usage)
		return fmt.Errorf("unknown backup-manifest subcommand: %s", args[0])
	}
}

func handleBackupManifestCreate(args []string) error {
	fs := flag.NewFlagSet("backup-manifest create", flag.ExitOnError)
	bundleDir := fs.String("bundle-dir", "", "Directory of .arkbackup bundles (non-recursive)")
	outputPath := fs.String("output", "", "Manifest path (default: DIR/"+defaultIntegrityManifestName+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRealDirectory(*bundleDir); err != nil {
		return err
	}
	manifestPath := *outputPath
	if manifestPath == "" {
		manifestPath = filepath.Join(*bundleDir, defaultIntegrityManifestName)
	}
	if err := checkManifestOutputPath(*bundleDir, manifestPath); err != nil {
		return err
	}

	ctx, stop := interruptContext()
	defer stop()

	manifest, ignored, problems, err := buildIntegrityManifest(ctx, *bundleDir)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		printManifestProblems(problems)
		return fmt.Errorf("manifest not written: %d bundle candidate(s) failed validation", len(problems))
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("manifest creation interrupted: %w", err)
	}
	if err := writeAtomicOutput(manifestPath, func(file *os.File) error {
		_, werr := file.Write(encoded)
		return werr
	}); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}
	fmt.Printf("Manifest written: %s (%d bundle(s), %d other file(s) ignored)\n",
		sanitizeDisplayText(manifestPath), len(manifest.Entries), ignored)
	return nil
}

func handleBackupManifestVerify(args []string) error {
	fs := flag.NewFlagSet("backup-manifest verify", flag.ExitOnError)
	bundleDir := fs.String("bundle-dir", "", "Directory of .arkbackup bundles (non-recursive)")
	manifestPath := fs.String("manifest", "", "Manifest path (default: DIR/"+defaultIntegrityManifestName+")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireRealDirectory(*bundleDir); err != nil {
		return err
	}
	path := *manifestPath
	if path == "" {
		path = filepath.Join(*bundleDir, defaultIntegrityManifestName)
	}

	ctx, stop := interruptContext()
	defer stop()

	manifest, err := readIntegrityManifest(path)
	if err != nil {
		return err
	}
	verified, problems, err := verifyIntegrityManifest(ctx, *bundleDir, manifest)
	if err != nil {
		return err
	}
	printManifestProblems(problems)
	fmt.Printf("Manifest verification: %d listed, %d verified, %d problem(s).\n", len(manifest.Entries), verified, len(problems))
	if len(problems) > 0 {
		return fmt.Errorf("manifest verification failed")
	}
	return nil
}

func requireRealDirectory(dir string) error {
	if dir == "" {
		return fmt.Errorf("--bundle-dir is required")
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("cannot read --bundle-dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--bundle-dir must be a real directory, not a file or symlink")
	}
	return nil
}

// checkManifestOutputPath refuses a manifest path that would be mistaken for
// or replace a bundle candidate.
func checkManifestOutputPath(bundleDir, manifestPath string) error {
	if strings.HasSuffix(strings.ToLower(manifestPath), arkbackupSuffix) {
		return fmt.Errorf("manifest path must not end in %s", arkbackupSuffix)
	}
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("manifest path exists and is not a regular file")
	}
	if hasBundleMagic(manifestPath) {
		return fmt.Errorf("manifest path is an existing .arkbackup bundle")
	}
	return nil
}

// isManifestCandidate reports whether a regular file must validate as a
// bundle: it has ARKB magic, or its name ends in .arkbackup. The suffix rule
// keeps a bundle with damaged magic from being reclassified as an ordinary
// file during regeneration.
func isManifestCandidate(path string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(path)), arkbackupSuffix) || hasBundleMagic(path)
}

func hasBundleMagic(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := io.ReadFull(f, magic); err != nil {
		return false
	}
	return bytes.Equal(magic, []byte("ARKB"))
}

// buildIntegrityManifest scans dir, validates every candidate, and hashes it.
// It returns the manifest, the count of ignored ordinary files, and any
// candidate failures; callers publish nothing when failures exist.
func buildIntegrityManifest(ctx context.Context, dir string) (*integrityManifest, int, []manifestProblem, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("failed to read --bundle-dir: %w", err)
	}
	manifest := &integrityManifest{Format: integrityManifestFormat, Version: integrityManifestVersion, Entries: []integrityManifestEntry{}}
	var problems []manifestProblem
	ignored := 0
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, 0, nil, fmt.Errorf("manifest creation interrupted: %w", err)
		}
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			continue
		}
		if !entry.Type().IsRegular() {
			ignored++
			continue
		}
		if !isManifestCandidate(path) {
			ignored++
			continue
		}
		b, err := validateBundleFile(path)
		if err != nil {
			problems = append(problems, manifestProblem{Name: entry.Name(), Reason: manifestReasonMalformed, Detail: bundleErrorReason(err, reasonInvalidBundleMetadata)})
			continue
		}
		size, digest, err := hashBundleFile(ctx, path)
		if err != nil {
			if ctx.Err() != nil {
				return nil, 0, nil, fmt.Errorf("manifest creation interrupted: %w", ctx.Err())
			}
			problems = append(problems, manifestProblem{Name: entry.Name(), Reason: manifestReasonUnsafe, Detail: err.Error()})
			continue
		}
		manifest.Entries = append(manifest.Entries, integrityManifestEntry{
			BundleName:      entry.Name(),
			FileID:          b.Meta.FileID,
			BundleVersion:   int(b.OuterVersion),
			BundleSizeBytes: size,
			SHA256:          digest,
		})
	}
	sort.Slice(manifest.Entries, func(i, j int) bool {
		return manifest.Entries[i].BundleName < manifest.Entries[j].BundleName
	})
	return manifest, ignored, problems, nil
}

// hashBundleFile streams SHA-256 over every byte of a regular, non-symlink
// file with bounded memory.
func hashBundleFile(ctx context.Context, path string) (int64, string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return 0, "", fmt.Errorf("file changed while it was being opened")
	}
	hasher := sha256.New()
	buf := make([]byte, manifestHashBufferBytes)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			hasher.Write(buf[:n])
			total += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return 0, "", rerr
		}
	}
	return total, hex.EncodeToString(hasher.Sum(nil)), nil
}

// readIntegrityManifest parses the manifest as an untrusted claim and
// rejects unknown formats, unsafe names, and duplicate entries.
func readIntegrityManifest(path string) (*integrityManifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read manifest: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("manifest must be a regular file")
	}
	if info.Size() > maxIntegrityManifestBytes {
		return nil, fmt.Errorf("manifest is larger than %d bytes", maxIntegrityManifestBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read manifest: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest integrityManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("manifest is not a valid integrity manifest: %w", err)
	}
	if manifest.Format != integrityManifestFormat {
		return nil, fmt.Errorf("unsupported manifest format %q", manifest.Format)
	}
	if manifest.Version != integrityManifestVersion {
		return nil, fmt.Errorf("unsupported manifest version %d", manifest.Version)
	}
	seen := make(map[string]struct{}, len(manifest.Entries))
	for _, e := range manifest.Entries {
		name := e.BundleName
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") || filepath.Base(name) != name {
			return nil, fmt.Errorf("manifest entry has an unsafe bundle name %q", sanitizeDisplayText(name))
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("manifest lists bundle %q more than once", sanitizeDisplayText(name))
		}
		seen[name] = struct{}{}
		if e.FileID == "" || e.BundleVersion != bundleFormatVersion || e.BundleSizeBytes < 0 || !isLowerHexSHA256(e.SHA256) {
			return nil, fmt.Errorf("manifest entry %q is malformed", sanitizeDisplayText(name))
		}
	}
	return &manifest, nil
}

// verifyIntegrityManifest checks every listed bundle's length, whole-file
// digest, and strict parse, then reports valid bundles the manifest omits.
func verifyIntegrityManifest(ctx context.Context, dir string, manifest *integrityManifest) (int, []manifestProblem, error) {
	var problems []manifestProblem
	verified := 0
	listed := make(map[string]struct{}, len(manifest.Entries))
	for _, e := range manifest.Entries {
		if err := ctx.Err(); err != nil {
			return 0, nil, fmt.Errorf("verification interrupted: %w", err)
		}
		listed[e.BundleName] = struct{}{}
		path := filepath.Join(dir, e.BundleName)
		info, err := os.Lstat(path)
		if err != nil {
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonMissing})
			continue
		}
		if !info.Mode().IsRegular() {
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonUnsafe, Detail: "not a regular file"})
			continue
		}
		if info.Size() != e.BundleSizeBytes {
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonChanged, Detail: fmt.Sprintf("length %d, manifest records %d", info.Size(), e.BundleSizeBytes)})
			continue
		}
		b, err := validateBundleFile(path)
		if err != nil {
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonMalformed, Detail: bundleErrorReason(err, reasonInvalidBundleMetadata)})
			continue
		}
		if b.Meta.FileID != e.FileID || int(b.OuterVersion) != e.BundleVersion {
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonChanged, Detail: "file ID or bundle version differs from the manifest"})
			continue
		}
		size, digest, err := hashBundleFile(ctx, path)
		if err != nil {
			if ctx.Err() != nil {
				return 0, nil, fmt.Errorf("verification interrupted: %w", ctx.Err())
			}
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonUnsafe, Detail: err.Error()})
			continue
		}
		if size != e.BundleSizeBytes || digest != e.SHA256 {
			problems = append(problems, manifestProblem{Name: e.BundleName, Reason: manifestReasonChanged, Detail: "SHA-256 differs from the manifest"})
			continue
		}
		verified++
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read --bundle-dir: %w", err)
	}
	for _, entry := range entries {
		if _, ok := listed[entry.Name()]; ok || entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if !isManifestCandidate(path) {
			continue
		}
		if _, err := validateBundleFile(path); err != nil {
			problems = append(problems, manifestProblem{Name: entry.Name(), Reason: manifestReasonMalformed, Detail: bundleErrorReason(err, reasonInvalidBundleMetadata)})
			continue
		}
		problems = append(problems, manifestProblem{Name: entry.Name(), Reason: manifestReasonUnlisted})
	}
	return verified, problems, nil
}

func printManifestProblems(problems []manifestProblem) {
	for _, p := range problems {
		if p.Detail != "" {
			fmt.Printf("  [X] %s: %s (%s)\n", p.Reason, sanitizeDisplayText(p.Name), sanitizeDisplayText(p.Detail))
		} else {
			fmt.Printf("  [X] %s: %s\n", p.Reason, sanitizeDisplayText(p.Name))
		}
	}
}
