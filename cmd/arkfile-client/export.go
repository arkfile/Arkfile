// export.go - Export command for arkfile-client
// Downloads .arkbackup bundles from the server for offline decryption.
// Export never asks for a password: bundles are stored ciphertext plus the
// owner metadata needed to decrypt them later.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/arkfile/Arkfile/crypto"
)

const arkbackupSuffix = ".arkbackup"

type exportTarget struct {
	FileID   string
	Filename string
	Output   *outputTarget
}

type exportOutcome struct {
	Target exportTarget
	Reason string
}

func handleExportCommand(client *HTTPClient, config *ClientConfig, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	var fileIDs multiStringFlag
	fs.Var(&fileIDs, "file-id", "File ID to export (repeatable)")
	outputPath := fs.String("output", "", "Exact output path for one listed --file-id (default: <file-id>.arkbackup)")
	outputDir := fs.String("output-dir", "", "Destination directory; bundles get readable reserved names and never replace existing entries")
	tagsFilter := fs.String("tags", "", "Select all owner files matching these tags (client-side AND)")
	allFiles := fs.Bool("all", false, "Select every file in the vault (requires --output-dir)")
	dryRun := fs.Bool("dry-run", false, "List export targets without exporting")
	pageLimit := fs.Int("limit", 100, "Server page size while scanning for --tags or --all")

	fs.Usage = func() {
		fmt.Printf("Usage:\n" +
			"  arkfile-client export --file-id ID [--output PATH]\n" +
			"  arkfile-client export --file-id ID [--file-id ID ...] --output-dir DIR\n" +
			"  arkfile-client export --tags TAGS --output-dir DIR [--dry-run]\n" +
			"  arkfile-client export --all --output-dir DIR [--dry-run]\n\n" +
			"Export encrypted files as .arkbackup bundles for offline decryption.\n" +
			"With --output-dir, bundles are named after the original filename (photo.png.arkbackup)\n" +
			"when the agent holds the Account Key, and otherwise <file-id>.arkbackup.\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	selection := ownerSelectionFlags{
		FileIDs:   fileIDs,
		Tags:      *tagsFilter,
		All:       *allFiles,
		Output:    *outputPath,
		OutputDir: *outputDir,
	}
	if err := validateOwnerSelectionFlags(selection); err != nil {
		return err
	}

	session, err := requireSession(config)
	if err != nil {
		return err
	}

	var accountKey []byte
	if *outputDir != "" || strings.TrimSpace(*tagsFilter) != "" {
		accountKey = getOptionalAccountKey(client, session)
		defer clearBytes(accountKey)
	}

	targetIDs, err := resolveOwnerSelectionForSession(client, session, selection, *pageLimit, accountKey)
	if errors.Is(err, errEmptyVault) {
		fmt.Println("No files in the vault; nothing to export.")
		return nil
	}
	if err != nil {
		return err
	}

	if *dryRun {
		for _, id := range targetIDs {
			fmt.Println(id)
		}
		fmt.Printf("Dry run: %d file(s)\n", len(targetIDs))
		return nil
	}

	ctx, stop := interruptContext()
	defer stop()

	if *outputDir == "" {
		path := *outputPath
		if path == "" {
			path = targetIDs[0] + arkbackupSuffix
		}
		written, err := exportOneBundle(ctx, client, session, targetIDs[0], exactOutputTarget(path))
		if err != nil {
			return err
		}
		fmt.Printf("Exported %s to %s (%d bytes)\n", targetIDs[0], path, written)
		return nil
	}

	if err := os.MkdirAll(*outputDir, 0o700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	reserver, err := newOutputNameReserver(*outputDir, arkbackupSuffix)
	if err != nil {
		return err
	}
	if accountKey == nil {
		fmt.Println("[!] Account Key unavailable from the agent; bundles will be named <file-id>.arkbackup.")
	}

	targets := make([]exportTarget, 0, len(targetIDs))
	for _, id := range targetIDs {
		filename := exportFilenameForNaming(ctx, client, session, accountKey, id)
		desired := id
		if filename != "" {
			desired = safeOwnerBasename(filename, id)
		}
		targets = append(targets, exportTarget{
			FileID:   id,
			Filename: filename,
			Output:   reservedOutputTarget(reserver, desired),
		})
	}

	return runExportBatch(ctx, client, session, targets)
}

// exportFilenameForNaming decrypts the owner filename for a readable bundle
// name. It returns "" when no Account Key is available or decryption fails.
func exportFilenameForNaming(ctx context.Context, client *HTTPClient, session *AuthSession, accountKey []byte, fileID string) string {
	if accountKey == nil {
		return ""
	}
	meta, err := fetchOwnerFileMeta(ctx, client, session, fileID)
	if err != nil || meta.EncryptedFilename == "" || meta.FilenameNonce == "" {
		return ""
	}
	owner := meta.OwnerUsername
	if owner == "" {
		owner = session.Username
	}
	name, err := decryptMetadataField(meta.EncryptedFilename, meta.FilenameNonce, accountKey, fileID, crypto.AADFieldFilename, owner)
	if err != nil {
		logVerbose("Warning: could not decrypt filename for %s", fileID)
		return ""
	}
	return name
}

// runExportBatch exports targets sequentially, continues past per-file
// failures, aborts the remainder on session loss or interrupt, retries each
// failed file once at the end under its reserved name, and prints a summary.
func runExportBatch(ctx context.Context, client *HTTPClient, session *AuthSession, targets []exportTarget) error {
	var succeeded int
	var failed, skipped []exportOutcome

	runPass := func(work []exportTarget) []exportOutcome {
		var passFailures []exportOutcome
		for i, t := range work {
			if ctx.Err() != nil {
				for _, rest := range work[i:] {
					skipped = append(skipped, exportOutcome{Target: rest, Reason: "cancelled"})
				}
				return passFailures
			}
			label := t.FileID
			if t.Filename != "" {
				label = sanitizeDisplayText(t.Filename)
			}
			fmt.Printf("Exporting %d of %d: %s\n", i+1, len(work), label)
			if _, err := exportOneBundle(ctx, client, session, t.FileID, t.Output); err != nil {
				if errors.Is(err, errAuthExpired) || errors.Is(err, context.Canceled) || ctx.Err() != nil {
					reason := "session_expired"
					if !errors.Is(err, errAuthExpired) {
						reason = "cancelled"
					}
					fmt.Fprintf(os.Stderr, "[X] %s (%s): %s\n", label, t.FileID, reason)
					for _, rest := range work[i:] {
						skipped = append(skipped, exportOutcome{Target: rest, Reason: reason})
					}
					return passFailures
				}
				fmt.Fprintf(os.Stderr, "[X] %s (%s): %v\n", label, t.FileID, err)
				passFailures = append(passFailures, exportOutcome{Target: t, Reason: err.Error()})
				continue
			}
			succeeded++
			fmt.Printf("[OK] %s -> %s\n", t.FileID, sanitizeDisplayText(t.Output.path()))
		}
		return passFailures
	}

	firstFailures := runPass(targets)
	if len(firstFailures) > 0 && len(skipped) == 0 {
		retry := make([]exportTarget, 0, len(firstFailures))
		for _, f := range firstFailures {
			retry = append(retry, f.Target)
		}
		fmt.Printf("Retrying %d failed export(s) once...\n", len(retry))
		failed = runPass(retry)
	} else {
		failed = firstFailures
	}

	fmt.Printf("Export finished. Succeeded: %d. Failed: %d. Skipped: %d.\n", succeeded, len(failed), len(skipped))
	for _, f := range append(append([]exportOutcome(nil), failed...), skipped...) {
		label := f.Target.FileID
		if f.Target.Filename != "" {
			label = sanitizeDisplayText(f.Target.Filename)
		}
		fmt.Fprintf(os.Stderr, "  [X] %s (%s): %s\n", label, f.Target.FileID, f.Reason)
	}
	if len(failed) > 0 || len(skipped) > 0 {
		return fmt.Errorf("export incomplete")
	}
	return nil
}

// exportOneBundle streams GET /api/files/:fileId/export into target. The
// response is checked against Content-Length and the strict bundle validator
// before it is published, so a truncated or malformed download never
// replaces or claims a destination.
func exportOneBundle(ctx context.Context, client *HTTPClient, session *AuthSession, fileID string, target *outputTarget) (int64, error) {
	if err := ensureFreshSessionToken(client, session, jwtRefreshThreshold); err != nil {
		return 0, errAuthExpired
	}
	resp, err := requestExportBundle(ctx, client, session, fileID)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		if refreshErr := refreshSessionToken(client, session); refreshErr != nil {
			return 0, errAuthExpired
		}
		resp, err = requestExportBundle(ctx, client, session, fileID)
		if err != nil {
			return 0, err
		}
		if resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			return 0, errAuthExpired
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return 0, fmt.Errorf("export failed (HTTP %d): %s", resp.StatusCode, sanitizeDisplayText(strings.TrimSpace(string(body))))
	}

	var written int64
	_, err = target.write(func(outFile *os.File) error {
		n, copyErr := io.Copy(outFile, resp.Body)
		written = n
		if copyErr != nil {
			return fmt.Errorf("failed to write export bundle: %w", copyErr)
		}
		if resp.ContentLength >= 0 && n != resp.ContentLength {
			return fmt.Errorf("export bundle truncated: received %d of %d bytes", n, resp.ContentLength)
		}
		if err := outFile.Sync(); err != nil {
			return fmt.Errorf("failed to sync export bundle: %w", err)
		}
		if _, validateErr := validateBundleFile(outFile.Name()); validateErr != nil {
			return fmt.Errorf("server returned an invalid bundle: %w", validateErr)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return written, nil
}

func requestExportBundle(ctx context.Context, client *HTTPClient, session *AuthSession, fileID string) (*http.Response, error) {
	url := fmt.Sprintf("%s/api/files/%s/export", client.baseURL, fileID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create export request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	// The bundle body can take far longer than the per-request API timeout,
	// so stream it on the shared transport without an overall deadline;
	// interrupt cancels it through ctx.
	streamingClient := &http.Client{Transport: client.client.Transport}
	resp, err := streamingClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("export request failed: %w", err)
	}
	return resp, nil
}
