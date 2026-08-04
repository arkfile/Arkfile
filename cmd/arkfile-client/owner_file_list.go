package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

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
