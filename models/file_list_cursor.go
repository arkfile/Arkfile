package models

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidOwnerFileListCursor indicates a malformed or unusable list cursor.
var ErrInvalidOwnerFileListCursor = errors.New("invalid file list cursor")

const ownerFileListCursorTimeLayout = "2006-01-02 15:04:05"

type ownerFileListCursorPayload struct {
	UploadDate string `json:"d"`
	FileID     string `json:"i"`
}

// FormatOwnerFileListCursorTime formats an upload time for keyset cursors and SQL binds.
// Matches SQLite CURRENT_TIMESTAMP storage used for file_metadata.upload_date.
func FormatOwnerFileListCursorTime(t time.Time) string {
	return t.UTC().Format(ownerFileListCursorTimeLayout)
}

// EncodeOwnerFileListCursor builds an opaque URL-safe cursor from the last returned row.
func EncodeOwnerFileListCursor(uploadDate time.Time, fileID string) (string, error) {
	fileID = strings.TrimSpace(fileID)
	if fileID == "" {
		return "", ErrInvalidOwnerFileListCursor
	}
	if uploadDate.IsZero() {
		return "", ErrInvalidOwnerFileListCursor
	}
	raw, err := json.Marshal(ownerFileListCursorPayload{
		UploadDate: FormatOwnerFileListCursorTime(uploadDate),
		FileID:     fileID,
	})
	if err != nil {
		return "", fmt.Errorf("encode file list cursor: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// DecodeOwnerFileListCursor parses and validates an opaque owner file list cursor.
func DecodeOwnerFileListCursor(cursor string) (uploadDate time.Time, fileID string, err error) {
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return time.Time{}, "", ErrInvalidOwnerFileListCursor
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", ErrInvalidOwnerFileListCursor
	}
	var payload ownerFileListCursorPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return time.Time{}, "", ErrInvalidOwnerFileListCursor
	}
	payload.FileID = strings.TrimSpace(payload.FileID)
	payload.UploadDate = strings.TrimSpace(payload.UploadDate)
	if payload.FileID == "" || payload.UploadDate == "" {
		return time.Time{}, "", ErrInvalidOwnerFileListCursor
	}
	if len(payload.FileID) > 128 {
		return time.Time{}, "", ErrInvalidOwnerFileListCursor
	}
	parsed, err := time.Parse(ownerFileListCursorTimeLayout, payload.UploadDate)
	if err != nil {
		return time.Time{}, "", ErrInvalidOwnerFileListCursor
	}
	return parsed, payload.FileID, nil
}
