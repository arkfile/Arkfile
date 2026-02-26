// dedup.go - Client-side upload deduplication logic
// Checks plaintext SHA-256 digest against agent's digest cache before uploading.
// Includes server-side storage verification for stale cache entries.

package main

import (
	"fmt"
	"net/http"
)

// DedupResult represents the result of a deduplication check
type DedupResult struct {
	IsDuplicate bool
	FileID      string // matching file ID if duplicate
	Filename    string // decrypted filename of the matching file (if available)
	SHA256Hex   string // the plaintext SHA-256 that matched
}

// checkDedup checks the plaintext SHA-256 against the agent's digest cache.
// Returns a DedupResult indicating whether the file is a duplicate.
func checkDedup(agentClient *AgentClient, plaintextHash string) (*DedupResult, error) {
	cache, err := agentClient.GetDigestCache()
	if err != nil {
		// If we can't get the cache, proceed with upload (non-fatal)
		logVerbose("Warning: failed to get digest cache: %v", err)
		return &DedupResult{IsDuplicate: false}, nil
	}

	// Search cache for matching digest
	for fileID, cachedHash := range cache {
		if cachedHash == plaintextHash {
			return &DedupResult{
				IsDuplicate: true,
				FileID:      fileID,
				SHA256Hex:   plaintextHash,
			}, nil
		}
	}

	return &DedupResult{IsDuplicate: false, SHA256Hex: plaintextHash}, nil
}

// verifyFileExistsOnServer asks the server to confirm the file is still present
// and intact in backend storage. Returns true if the file exists.
func verifyFileExistsOnServer(client *HTTPClient, session *AuthSession, fileID string) (bool, error) {
	endpoint := fmt.Sprintf("/api/files/%s/meta", fileID)

	req, err := http.NewRequest("GET", client.baseURL+endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)

	resp, err := client.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// 200 = file exists; 404 = file gone; other = treat as unknown (proceed with upload)
	switch {
	case resp.StatusCode == http.StatusOK:
		return true, nil
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	default:
		// On unexpected status, assume file might not exist (proceed with upload)
		logVerbose("Server returned status %d for file verification, treating as not found", resp.StatusCode)
		return false, nil
	}
}

// performDedupCheck runs the full dedup workflow:
// 1. Check agent digest cache
// 2. If match found, verify file still exists on server
// 3. If file gone, remove stale cache entry and return no-duplicate
// 4. If file exists, try to decrypt filename for display
func performDedupCheck(agentClient *AgentClient, httpClient *HTTPClient, session *AuthSession, accountKey []byte, plaintextHash string) (*DedupResult, error) {
	// Step 1: Check cache
	result, err := checkDedup(agentClient, plaintextHash)
	if err != nil {
		return nil, err
	}

	if !result.IsDuplicate {
		return result, nil
	}

	logVerbose("Digest cache match found: file_id=%s", result.FileID)

	// Step 2: Verify file still exists on server
	exists, err := verifyFileExistsOnServer(httpClient, session, result.FileID)
	if err != nil {
		logVerbose("Warning: server verification failed: %v", err)
		// On error, still treat as duplicate (conservative approach)
		return result, nil
	}

	if !exists {
		// Step 3: Stale cache entry - remove and proceed with upload
		logVerbose("File %s no longer exists on server, removing stale digest cache entry", result.FileID)
		if err := agentClient.RemoveDigest(result.FileID); err != nil {
			logVerbose("Warning: failed to remove stale digest: %v", err)
		}
		return &DedupResult{IsDuplicate: false, SHA256Hex: plaintextHash}, nil
	}

	// Step 4: File exists - try to get filename for better error message
	result.Filename = tryDecryptFilename(httpClient, session, accountKey, result.FileID)

	return result, nil
}

// tryDecryptFilename attempts to fetch and decrypt the filename for a file ID.
// Returns empty string on any failure (non-fatal).
func tryDecryptFilename(client *HTTPClient, session *AuthSession, accountKey []byte, fileID string) string {
	endpoint := fmt.Sprintf("/api/files/%s/meta", fileID)

	req, err := http.NewRequest("GET", client.baseURL+endpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+session.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var fileMeta ServerFileInfo
	if err := decodeJSONResponse(resp, &fileMeta); err != nil {
		return ""
	}

	if fileMeta.EncryptedFilename == "" || fileMeta.FilenameNonce == "" {
		return ""
	}

	filename, err := decryptMetadataField(fileMeta.EncryptedFilename, fileMeta.FilenameNonce, accountKey)
	if err != nil {
		return ""
	}

	return filename
}
