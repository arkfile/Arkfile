package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/arkfile/Arkfile/crypto"
)

// ownerSelectionFlags carries the selection and destination flags shared by
// download and export.
type ownerSelectionFlags struct {
	FileIDs       []string
	Tags          string
	All           bool
	Output        string
	OutputDir     string
	PasswordStdin bool
}

// singleExplicit reports whether the selection is exactly one listed
// --file-id with no scanned selector. Mode follows the selection, not the
// destination: only this case keeps single-target behavior.
func (f ownerSelectionFlags) singleExplicit() bool {
	return !f.All && strings.TrimSpace(f.Tags) == "" && len(dedupeStrings(f.FileIDs)) == 1
}

func (f ownerSelectionFlags) scanned() bool {
	return f.All || strings.TrimSpace(f.Tags) != ""
}

// errEmptyVault marks an --all selection over a vault with no files, which
// callers report and treat as success.
var errEmptyVault = errors.New("no files in the vault")

// validateOwnerSelectionFlags enforces the output flag rules before any
// network call.
func validateOwnerSelectionFlags(f ownerSelectionFlags) error {
	if f.All && (len(f.FileIDs) > 0 || strings.TrimSpace(f.Tags) != "") {
		return fmt.Errorf("--all cannot be combined with --file-id or --tags")
	}
	if !f.All && len(f.FileIDs) == 0 && strings.TrimSpace(f.Tags) == "" {
		return fmt.Errorf("at least one --file-id, --tags, or --all selection is required")
	}
	if f.Output != "" && f.OutputDir != "" {
		return fmt.Errorf("--output and --output-dir are mutually exclusive")
	}
	single := f.singleExplicit()
	if f.Output != "" && !single {
		return fmt.Errorf("--output accepts exactly one --file-id; use --output-dir for multiple or scanned selections")
	}
	if !single && strings.TrimSpace(f.OutputDir) == "" {
		return fmt.Errorf("--output-dir is required for multiple-file, --tags, and --all selections")
	}
	if f.PasswordStdin && !single {
		return fmt.Errorf("--password-stdin is only supported for one explicitly listed --file-id")
	}
	return nil
}

// resolveOwnerSelection returns the selected file IDs in order: explicit
// --file-id values first, then --tags matches or every file for --all, in
// list order, without duplicates. listFiles is only called for scanned
// selections; accountKey is required for --tags.
func resolveOwnerSelection(
	f ownerSelectionFlags,
	sessionUsername string,
	listFiles func() ([]ServerFileInfo, error),
	accountKey []byte,
) ([]string, error) {
	targets := dedupeStrings(f.FileIDs)
	if !f.scanned() {
		return targets, nil
	}

	var filterTags []string
	if strings.TrimSpace(f.Tags) != "" {
		parsed, err := crypto.ParseFilterTags(f.Tags)
		if err != nil {
			return nil, fmt.Errorf("invalid --tags filter: %w", err)
		}
		if accountKey == nil {
			return nil, fmt.Errorf("Account Key required to filter by tags")
		}
		filterTags = parsed
	}

	listed, err := listFiles()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(targets)+len(listed))
	for _, id := range targets {
		seen[id] = struct{}{}
	}
	for _, file := range listed {
		if file.FileID == "" {
			continue
		}
		if _, ok := seen[file.FileID]; ok {
			continue
		}
		if filterTags != nil && !ownerFileHasAllTags(file, sessionUsername, accountKey, filterTags) {
			continue
		}
		targets = append(targets, file.FileID)
		seen[file.FileID] = struct{}{}
	}

	if len(targets) == 0 {
		if f.All {
			return nil, errEmptyVault
		}
		return nil, fmt.Errorf("no files matched the --tags selection")
	}
	return targets, nil
}

func ownerFileHasAllTags(file ServerFileInfo, sessionUsername string, accountKey []byte, filterTags []string) bool {
	owner := file.OwnerUsername
	if owner == "" {
		owner = sessionUsername
	}
	tags := []string{}
	if file.EncryptedTags != "" && file.TagsNonce != "" {
		plaintext, err := decryptMetadataField(
			file.EncryptedTags, file.TagsNonce, accountKey,
			file.FileID, crypto.AADFieldTags, owner,
		)
		if err != nil {
			return false
		}
		if plaintext != "" {
			tags = strings.Split(plaintext, ",")
		}
	}
	return crypto.FileHasAllTags(tags, filterTags)
}

func dedupeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// fetchAllOwnerFiles walks cursor pages from GET /api/files until exhausted.
// pageLimit is the requested server page size (clamped by the server).
// Results are deduplicated by file_id.
func fetchAllOwnerFiles(client *HTTPClient, session *AuthSession, pageLimit int) (*ServerFileListResponse, error) {
	if pageLimit < 1 {
		pageLimit = 100
	}

	merged := &ServerFileListResponse{
		Files: make([]ServerFileInfo, 0),
	}
	seen := make(map[string]struct{})
	cursor := ""

	for {
		page, err := fetchOwnerFilePage(client, session, pageLimit, cursor)
		if err != nil {
			return nil, err
		}
		if merged.Storage == nil {
			merged.Storage = page.Storage
		}
		merged.Limit = page.Limit
		for _, f := range page.Files {
			if f.FileID == "" {
				continue
			}
			if _, ok := seen[f.FileID]; ok {
				continue
			}
			seen[f.FileID] = struct{}{}
			merged.Files = append(merged.Files, f)
		}
		if !page.HasMore || page.NextCursor == nil || *page.NextCursor == "" {
			break
		}
		cursor = *page.NextCursor
	}

	merged.Returned = len(merged.Files)
	merged.HasMore = false
	merged.NextCursor = nil
	return merged, nil
}

func fetchOwnerFilePage(client *HTTPClient, session *AuthSession, pageLimit int, cursor string) (*ServerFileListResponse, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(pageLimit))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	req, err := http.NewRequest("GET", client.baseURL+"/api/files?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create file list request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file list: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if len(body) > 0 {
			return nil, fmt.Errorf("server returned HTTP %d for file list: %s", resp.StatusCode, string(body))
		}
		return nil, fmt.Errorf("server returned HTTP %d for file list", resp.StatusCode)
	}

	var page ServerFileListResponse
	if err := decodeJSONResponse(resp, &page); err != nil {
		return nil, fmt.Errorf("failed to decode file list: %w", err)
	}
	return &page, nil
}
