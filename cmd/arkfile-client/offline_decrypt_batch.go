// offline_decrypt_batch.go - Chained offline restore and inspection of
// .arkbackup bundles. One explicitly listed bundle runs through the same
// per-group, per-file path as a whole folder, so there is one code path for
// one file and for many.

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/cli/secureinput"
	"github.com/arkfile/Arkfile/crypto"
)

// readTerminalPassword reads a custom password from the controlling terminal
// only, even when --password-stdin supplied the account password.
// Overridable in tests.
var readTerminalPassword = func(prompt string, timeout time.Duration) ([]byte, error) {
	return secureinput.ReadPassword(prompt, timeout)
}

// readAccountPasswordInput reads the account password from the terminal, or
// one stdin line when --password-stdin is active. Overridable in tests.
var readAccountPasswordInput = func(prompt string) ([]byte, error) {
	return readPassword(prompt)
}

// readSingleBundleCustomPassword reads the custom password in single-bundle
// mode, where --password-stdin carries it as the second stdin line.
// Overridable in tests.
var readSingleBundleCustomPassword = func(prompt string) ([]byte, error) {
	return readPassword(prompt)
}

const maxAccountPasswordEntries = 3

type decryptRunOptions struct {
	Username       string
	OutputPath     string
	OutputDir      string
	PasswordStdin  bool
	AccountKeyFile string
	UseAgent       bool
	Inspect        bool
	DryRun         bool
	SingleBundle   bool
}

type bundleOutcome struct {
	Path         string
	FileID       string
	Filename     string
	PasswordType string
	Reason       string
	Detail       string
	OutputPath   string
	SHA256       string
}

// logicalBundleFile is one file_id with its physical copies in processing
// order. Copies are fallback candidates until one restores successfully.
type logicalBundleFile struct {
	FileID       string
	PasswordType string
	Copies       []*validatedBundle
	Usable       []*validatedBundle
	Display      ownerDisplayMetadata
	Target       *outputTarget
}

type accountKeyGroup struct {
	Owner   string
	SaltB64 string
	Profile int
	Files   []*logicalBundleFile
}

type offlineDecryptRun struct {
	opts       decryptRunOptions
	ctx        context.Context
	reserver   *outputNameReserver
	outcomes   []bundleOutcome
	recorded   map[*validatedBundle]bool
	nonBundles []string
	stdinUsed  bool
	cancelled  bool
	// dryRunListed counts valid bundles printed by --dry-run.
	dryRunListed int
}

func newOfflineDecryptRun(ctx context.Context, opts decryptRunOptions) *offlineDecryptRun {
	return &offlineDecryptRun{opts: opts, ctx: ctx, recorded: make(map[*validatedBundle]bool)}
}

func (run *offlineDecryptRun) record(b *validatedBundle, display ownerDisplayMetadata, reason, detail, outputPath, digest string) {
	if b != nil {
		if run.recorded[b] {
			return
		}
		run.recorded[b] = true
	}
	o := bundleOutcome{Reason: reason, Detail: detail, OutputPath: outputPath, SHA256: digest}
	if b != nil {
		o.Path = b.Path
		o.FileID = b.Meta.FileID
		o.PasswordType = b.Meta.PasswordType
	}
	if display.FilenameSet {
		o.Filename = display.Filename
	}
	run.outcomes = append(run.outcomes, o)
}

// discover validates explicit bundles in argument order, then directory
// entries in sorted name order, deduplicating identical absolute paths.
func (run *offlineDecryptRun) discover(explicit []string, dir string) ([]*validatedBundle, error) {
	var valid []*validatedBundle
	seen := make(map[string]struct{})
	add := func(path string, fromDir bool) {
		if abs, err := filepath.Abs(path); err == nil {
			if _, dup := seen[abs]; dup {
				return
			}
			seen[abs] = struct{}{}
		}
		b, err := validateBundleFile(path)
		if err != nil {
			reason := bundleErrorReason(err, reasonInvalidBundleMetadata)
			if fromDir && reason == reasonNotABundle {
				run.nonBundles = append(run.nonBundles, path)
				return
			}
			run.outcomes = append(run.outcomes, bundleOutcome{Path: path, Reason: reason, Detail: err.Error()})
			return
		}
		if run.opts.Username != "" && b.Meta.OwnerUsername != run.opts.Username {
			run.record(b, ownerDisplayMetadata{}, reasonOwnerMismatch, "bundle owner does not match --username", "", "")
			return
		}
		valid = append(valid, b)
	}

	for _, path := range explicit {
		add(path, false)
	}
	if dir != "" {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("--bundle-dir must be an existing directory")
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("failed to read --bundle-dir: %w", err)
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if entry.IsDir() {
				continue
			}
			if !entry.Type().IsRegular() {
				run.nonBundles = append(run.nonBundles, path)
				continue
			}
			add(path, true)
		}
	}
	return valid, nil
}

// groupBundles groups copies by file_id, then logical files by
// (owner_username, account_kdf_salt, account_kdf_profile), both in
// first-appearance order.
func groupBundles(bundles []*validatedBundle) []*accountKeyGroup {
	var groups []*accountKeyGroup
	groupIndex := make(map[string]*accountKeyGroup)
	fileIndex := make(map[string]*logicalBundleFile)
	for _, b := range bundles {
		m := b.Meta
		groupKey := fmt.Sprintf("%s\x00%s\x00%d", m.OwnerUsername, m.AccountKDFSalt, m.AccountKDFProfile)
		g, ok := groupIndex[groupKey]
		if !ok {
			g = &accountKeyGroup{Owner: m.OwnerUsername, SaltB64: m.AccountKDFSalt, Profile: m.AccountKDFProfile}
			groupIndex[groupKey] = g
			groups = append(groups, g)
		}
		fileKey := groupKey + "\x00" + m.FileID
		lf, ok := fileIndex[fileKey]
		if !ok {
			lf = &logicalBundleFile{FileID: m.FileID, PasswordType: m.PasswordType}
			fileIndex[fileKey] = lf
			g.Files = append(g.Files, lf)
		}
		lf.Copies = append(lf.Copies, b)
	}
	return groups
}

// execute runs discovery output, per-group processing, and returns the
// groups so callers can inspect outcomes.
func (run *offlineDecryptRun) execute(bundles []*validatedBundle) {
	groups := groupBundles(bundles)

	if run.opts.DryRun {
		run.printDryRun(groups)
		return
	}

	if !run.opts.Inspect && run.opts.OutputDir != "" {
		reserver, err := newOutputNameReserver(run.opts.OutputDir, "")
		if err != nil {
			for _, g := range groups {
				for _, lf := range g.Files {
					for _, c := range lf.Copies {
						run.record(c, ownerDisplayMetadata{}, reasonWriteFailed, err.Error(), "", "")
					}
				}
			}
			return
		}
		run.reserver = reserver
	}

	if len(groups) > 1 {
		fmt.Printf("These bundles span %d Account Key salts (different owners or account generations).\n", len(groups))
		fmt.Printf("One account password entry is needed per group.\n")
	}
	for i, g := range groups {
		if run.cancelled || run.ctx.Err() != nil {
			run.cancelled = true
			break
		}
		if len(groups) > 1 {
			fmt.Printf("Account Key group %d of %d: owner %s, %d file(s)\n", i+1, len(groups), sanitizeDisplayText(g.Owner), len(g.Files))
		}
		run.processGroup(g)
	}

	for _, g := range groups {
		for _, lf := range g.Files {
			for _, c := range lf.Copies {
				run.record(c, lf.Display, reasonSkipped, "", "", "")
			}
		}
	}
}

func (run *offlineDecryptRun) processGroup(g *accountKeyGroup) {
	accountKey, reason := run.obtainGroupKey(g)
	if accountKey == nil {
		for _, lf := range g.Files {
			for _, c := range lf.Copies {
				run.record(c, ownerDisplayMetadata{}, reason, "", "", "")
			}
		}
		return
	}
	defer clearBytes(accountKey)

	for _, lf := range g.Files {
		if len(lf.Usable) == 0 {
			continue
		}
		lf.Display = decryptOwnerDisplayMetadata(lf.Usable[0], accountKey)
		if !run.opts.Inspect {
			lf.Target = run.outputTargetFor(lf)
		}
	}

	if run.opts.Inspect {
		for _, lf := range g.Files {
			if len(lf.Usable) == 0 {
				continue
			}
			run.printInspection(lf)
			for _, c := range lf.Usable {
				run.record(c, lf.Display, "", "", "", "")
			}
		}
		return
	}

	for _, accountPass := range []bool{true, false} {
		for _, lf := range g.Files {
			if len(lf.Usable) == 0 || (lf.PasswordType == "account") != accountPass {
				continue
			}
			if run.ctx.Err() != nil {
				run.cancelled = true
				return
			}
			if accountPass {
				run.restoreAccountFile(lf, accountKey)
			} else {
				run.restoreCustomFile(lf, accountKey)
			}
			if run.cancelled {
				return
			}
		}
	}
}

// obtainGroupKey gets one Account Key for g from the run's source and
// validates it against the group's candidates. It returns nil and a reason
// when the group cannot be unlocked.
func (run *offlineDecryptRun) obtainGroupKey(g *accountKeyGroup) ([]byte, string) {
	salt, err := crypto.DecodeBase64(g.SaltB64)
	if err != nil {
		return nil, reasonInvalidBundleMetadata
	}
	mismatchReason := reasonAccountKeyUnavailable
	if run.opts.SingleBundle {
		mismatchReason = reasonWrongAccountPassword
	}

	switch {
	case run.opts.AccountKeyFile != "":
		key, err := readAccountKeyFromFile(run.opts.AccountKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[X] Account key file unusable: %v\n", err)
			return nil, reasonAccountKeyUnavailable
		}
		if !run.validateGroupKey(g, key) {
			clearBytes(key)
			return nil, mismatchReason
		}
		return key, ""

	case run.opts.UseAgent:
		agentClient, err := NewAgentClient()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[X] Agent unavailable: %v\n", err)
			return nil, reasonAccountKeyUnavailable
		}
		key, err := agentClient.GetOfflineAccountKey(g.SaltB64, g.Profile)
		if err != nil {
			return nil, reasonAccountKeyUnavailable
		}
		if !run.validateGroupKey(g, key) {
			clearBytes(key)
			return nil, mismatchReason
		}
		return key, ""

	case run.opts.PasswordStdin:
		if run.stdinUsed {
			return nil, reasonAccountKeyUnavailable
		}
		run.stdinUsed = true
		password, err := readAccountPasswordInput("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[X] Could not read account password from stdin\n")
			return nil, reasonAccountKeyUnavailable
		}
		key, err := crypto.DeriveAccountPasswordKey(password, salt)
		clearBytes(password)
		if err != nil {
			return nil, reasonAccountKeyUnavailable
		}
		if !run.validateGroupKey(g, key) {
			clearBytes(key)
			return nil, reasonWrongAccountPassword
		}
		return key, ""
	}

	for attempt := 1; attempt <= maxAccountPasswordEntries; attempt++ {
		prompt := "Enter your account password: "
		if !run.opts.SingleBundle {
			prompt = fmt.Sprintf("Enter the account password for %s: ", sanitizeDisplayText(g.Owner))
		}
		password, err := readAccountPasswordInput(prompt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[X] Could not read account password: %v\n", err)
			return nil, reasonAccountKeyUnavailable
		}
		key, err := crypto.DeriveAccountPasswordKey(password, salt)
		clearBytes(password)
		if err != nil {
			return nil, reasonAccountKeyUnavailable
		}
		if run.validateGroupKey(g, key) {
			return key, ""
		}
		clearBytes(key)
		fmt.Fprintf(os.Stderr, "[!] That account password does not unlock these bundles (entry %d/%d)\n", attempt, maxAccountPasswordEntries)
	}
	return nil, reasonWrongAccountPassword
}

// validateGroupKey checks key against authenticated material from every
// candidate. The key is accepted when any candidate validates; candidates
// that fail under an accepted key are recorded as damaged, so a corrupt
// first copy cannot make the correct key look wrong.
func (run *offlineDecryptRun) validateGroupKey(g *accountKeyGroup, key []byte) bool {
	usable := make(map[*logicalBundleFile][]*validatedBundle, len(g.Files))
	anyValid := false
	for _, lf := range g.Files {
		for _, c := range lf.Copies {
			if accountKeyUnlocks(c, key) {
				usable[lf] = append(usable[lf], c)
				anyValid = true
			}
		}
	}
	if !anyValid {
		return false
	}
	for _, lf := range g.Files {
		lf.Usable = usable[lf]
		accepted := make(map[*validatedBundle]bool, len(lf.Usable))
		for _, c := range lf.Usable {
			accepted[c] = true
		}
		for _, c := range lf.Copies {
			if !accepted[c] {
				run.record(c, ownerDisplayMetadata{}, reasonIntegrityMismatch, "owner metadata does not authenticate under the group's Account Key", "", "")
			}
		}
	}
	return true
}

// outputTargetFor reserves the output name: the decrypted filename, else
// the bundle name minus .arkbackup, else the file ID.
func (run *offlineDecryptRun) outputTargetFor(lf *logicalBundleFile) *outputTarget {
	if run.opts.OutputPath != "" {
		return exactOutputTarget(run.opts.OutputPath)
	}
	fallback := filepath.Base(lf.Usable[0].Path)
	if strings.HasSuffix(strings.ToLower(fallback), arkbackupSuffix) {
		fallback = fallback[:len(fallback)-len(arkbackupSuffix)]
	}
	if sanitizeUntrustedBasename(fallback, true) == "" {
		fallback = lf.FileID
	}
	desired := safeOwnerBasename(lf.Display.Filename, fallback)
	return reservedOutputTarget(run.reserver, desired)
}

func (run *offlineDecryptRun) restoreAccountFile(lf *logicalBundleFile, accountKey []byte) {
	for i, c := range lf.Usable {
		fek, _, err := unwrapFEK(c.Meta.EncryptedFEK, accountKey, c.Meta.FileID)
		if err != nil {
			run.record(c, lf.Display, reasonIntegrityMismatch, "FEK envelope does not authenticate", "", "")
			continue
		}
		path, digest, err := restoreBundlePayload(run.ctx, c, fek, accountKey, lf.Target)
		clearBytes(fek)
		if err != nil {
			reason := bundleErrorReason(err, reasonWriteFailed)
			run.record(c, lf.Display, reason, err.Error(), "", "")
			if reason == reasonCancelled {
				run.cancelled = true
				return
			}
			continue
		}
		run.record(c, lf.Display, "", "", path, digest)
		run.reportRestored(lf, path, digest)
		run.markDuplicates(lf, lf.Usable[i+1:])
		return
	}
}

func (run *offlineDecryptRun) restoreCustomFile(lf *logicalBundleFile, accountKey []byte) {
	first := lf.Usable[0]
	if run.opts.SingleBundle {
		printOwnerMetadata(first, lf.Display, "")
	} else {
		fmt.Printf("Custom-password file:\n")
		printOwnerMetadata(first, lf.Display, "  ")
	}

	displayName := "this file"
	if lf.Display.FilenameSet {
		displayName = sanitizeDisplayText(lf.Display.Filename)
	}
	attempts := MaxBatchCustomPasswordAttempts
	if run.opts.SingleBundle && run.opts.PasswordStdin {
		attempts = 1
	}

	var fek []byte
	lastReason := reasonWrongCustomPassword
	for attempt := 1; attempt <= attempts && fek == nil; attempt++ {
		if run.ctx.Err() != nil {
			lastReason = reasonCancelled
			break
		}
		password, err := run.readCustomPassword(displayName, attempt, attempts)
		if err != nil {
			msg := err.Error()
			switch {
			case strings.Contains(msg, "no controlling terminal"):
				lastReason = reasonTerminalRequired
			case strings.Contains(msg, "timed out"):
				lastReason = reasonPromptTimeout
				fmt.Fprintf(os.Stderr, "[!] %s: password prompt timed out\n", displayName)
				continue
			default:
				lastReason = reasonPromptCancelled
			}
			break
		}
		customKey, err := crypto.DeriveCustomPasswordKey(password, first.Envelope.Salt)
		clearBytes(password)
		if err != nil {
			lastReason = reasonPromptCancelled
			break
		}
		for _, c := range lf.Usable {
			if unwrapped, _, uerr := unwrapFEK(c.Meta.EncryptedFEK, customKey, c.Meta.FileID); uerr == nil {
				fek = unwrapped
				break
			}
		}
		clearBytes(customKey)
		if fek == nil {
			lastReason = reasonWrongCustomPassword
			fmt.Fprintf(os.Stderr, "[!] %s: wrong custom password (attempt %d/%d)\n", displayName, attempt, attempts)
		}
	}

	if fek == nil {
		if lastReason == reasonCancelled {
			run.cancelled = true
		}
		for _, c := range lf.Usable {
			run.record(c, lf.Display, lastReason, "", "", "")
		}
		return
	}
	defer clearBytes(fek)

	for i, c := range lf.Usable {
		path, digest, err := restoreBundlePayload(run.ctx, c, fek, accountKey, lf.Target)
		if err != nil {
			reason := bundleErrorReason(err, reasonWriteFailed)
			run.record(c, lf.Display, reason, err.Error(), "", "")
			if reason == reasonCancelled {
				run.cancelled = true
				return
			}
			continue
		}
		run.record(c, lf.Display, "", "", path, digest)
		run.reportRestored(lf, path, digest)
		run.markDuplicates(lf, lf.Usable[i+1:])
		return
	}
}

func (run *offlineDecryptRun) readCustomPassword(displayName string, attempt, attempts int) ([]byte, error) {
	if run.opts.SingleBundle {
		prompt := "Enter the custom file password: "
		if !run.opts.PasswordStdin && attempts > 1 {
			prompt = fmt.Sprintf("Enter the custom file password (attempt %d/%d): ", attempt, attempts)
		}
		return readSingleBundleCustomPassword(prompt)
	}
	return readTerminalPassword(
		fmt.Sprintf("Enter the custom password for '%s' (attempt %d/%d, wait up to 2 minutes): ", displayName, attempt, attempts),
		PasswordTimeoutBatchCustom,
	)
}

func (run *offlineDecryptRun) markDuplicates(lf *logicalBundleFile, rest []*validatedBundle) {
	for _, c := range rest {
		run.record(c, lf.Display, reasonDuplicateFileID, "another copy of this file was restored", "", "")
	}
}

func (run *offlineDecryptRun) reportRestored(lf *logicalBundleFile, path, digest string) {
	name := "[unknown]"
	if lf.Display.FilenameSet {
		name = lf.Display.Filename
	}
	if run.opts.SingleBundle {
		fmt.Printf("Decrypted: %s\n", sanitizeDisplayText(name))
		if lf.Display.TagsLine != "" {
			fmt.Printf("Tags: %s\n", sanitizeDisplayText(lf.Display.TagsLine))
		}
		fmt.Printf("Saved to: %s\n", sanitizeDisplayText(path))
		fmt.Printf("SHA-256: %s\n", digest)
		fmt.Printf("Verified: [OK] (matches encrypted metadata)\n")
		return
	}
	fmt.Printf("[OK] %s -> %s\n", sanitizeDisplayText(name), sanitizeDisplayText(path))
}

func (run *offlineDecryptRun) printInspection(lf *logicalBundleFile) {
	printOwnerMetadata(lf.Usable[0], lf.Display, "")
	fmt.Printf("  File ID: %s\n", sanitizeDisplayText(lf.FileID))
	fmt.Printf("  Password type: %s\n", lf.PasswordType)
	for i, c := range lf.Usable {
		label := "Bundle"
		if i > 0 {
			label = "Bundle (duplicate copy)"
		}
		fmt.Printf("  %s: %s (%d bytes)\n", label, sanitizeDisplayText(c.Path), c.FileSize)
	}
}

func (run *offlineDecryptRun) printDryRun(groups []*accountKeyGroup) {
	for _, g := range groups {
		for _, lf := range g.Files {
			for i, c := range lf.Copies {
				dup := ""
				if len(lf.Copies) > 1 {
					dup = fmt.Sprintf(" [copy %d of %d]", i+1, len(lf.Copies))
				}
				fmt.Printf("%s  file_id=%s owner=%s password_type=%s size=%d%s\n",
					sanitizeDisplayText(c.Path), sanitizeDisplayText(c.Meta.FileID), sanitizeDisplayText(c.Meta.OwnerUsername),
					c.Meta.PasswordType, c.FileSize, dup)
				run.dryRunListed++
			}
		}
	}
}

// summarize prints the run summary and returns an error when any bundle
// failed or was skipped for a reason other than duplicate_file_id.
func (run *offlineDecryptRun) summarize() error {
	var decryptedAccount, decryptedCustom, failed, skipped, duplicates, inspected int
	for _, o := range run.outcomes {
		switch {
		case o.Reason == "" && run.opts.Inspect:
			inspected++
		case o.Reason == "":
			if o.PasswordType == "custom" {
				decryptedCustom++
			} else {
				decryptedAccount++
			}
		case o.Reason == reasonDuplicateFileID:
			duplicates++
		case isSkipReason(o.Reason):
			skipped++
		default:
			failed++
		}
	}

	switch {
	case run.opts.DryRun:
		fmt.Printf("Dry run: %d bundle(s). Invalid: %d. Non-bundle files: %d.\n", run.dryRunListed, failed+skipped, len(run.nonBundles))
	case run.opts.Inspect:
		fmt.Printf("Inspection finished. Inspected: %d. Failed: %d. Skipped: %d. Non-bundle files: %d.\n",
			inspected, failed, skipped, len(run.nonBundles))
	default:
		fmt.Printf("Offline decrypt finished. Decrypted: %d (account: %d, custom: %d). Failed: %d. Skipped: %d. Duplicates: %d. Non-bundle files: %d.\n",
			decryptedAccount+decryptedCustom, decryptedAccount, decryptedCustom, failed, skipped+duplicates, duplicates, len(run.nonBundles))
	}
	for _, o := range run.outcomes {
		if o.Reason == "" {
			continue
		}
		name := "-"
		if o.Filename != "" {
			name = sanitizeDisplayText(o.Filename)
		}
		marker := "[X]"
		if o.Reason == reasonDuplicateFileID {
			marker = "[-]"
		}
		fmt.Printf("  %s %s: %s (%s)\n", marker, o.Reason, name, sanitizeDisplayText(o.Path))
		if verbose && o.Detail != "" {
			fmt.Printf("      %s\n", sanitizeDisplayText(o.Detail))
		}
	}
	if verbose || run.opts.DryRun {
		for _, path := range run.nonBundles {
			fmt.Printf("  [-] %s: %s\n", reasonNotABundle, sanitizeDisplayText(path))
		}
	}
	if failed > 0 || skipped > 0 {
		return fmt.Errorf("offline decrypt incomplete")
	}
	return nil
}

func isSkipReason(reason string) bool {
	switch reason {
	case reasonAccountKeyUnavailable, reasonTerminalRequired, reasonCancelled, reasonSkipped:
		return true
	}
	return false
}

// singleBundleResult converts the only outcome of a single-bundle run into
// the command's return value.
func (run *offlineDecryptRun) singleBundleResult() error {
	for _, o := range run.outcomes {
		if o.Reason == "" {
			return nil
		}
	}
	if len(run.outcomes) == 0 {
		return fmt.Errorf("bundle was not processed")
	}
	o := run.outcomes[0]
	switch o.Reason {
	case reasonWrongAccountPassword:
		return errors.New("wrong account password: the Account Key does not unlock this bundle")
	case reasonWrongCustomPassword:
		return errors.New("wrong custom password: failed to unwrap the file key")
	case reasonTerminalRequired:
		return errors.New("terminal_required: the custom password must be entered on a terminal or with --password-stdin")
	}
	if o.Detail != "" {
		return errors.New(sanitizeDisplayText(o.Detail))
	}
	return errors.New(o.Reason)
}
