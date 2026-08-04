package models

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestOwnerFileListCursorRoundTrip(t *testing.T) {
	uploadDate := time.Date(2024, 6, 15, 12, 34, 56, 0, time.UTC)
	fileID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

	encoded, err := EncodeOwnerFileListCursor(uploadDate, fileID)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty cursor")
	}

	gotTime, gotID, err := DecodeOwnerFileListCursor(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !gotTime.Equal(uploadDate) {
		t.Fatalf("upload date: got %v want %v", gotTime, uploadDate)
	}
	if gotID != fileID {
		t.Fatalf("file id: got %q want %q", gotID, fileID)
	}
}

func TestDecodeOwnerFileListCursorRejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"not-base64!!!",
		base64.RawURLEncoding.EncodeToString([]byte(`{"d":"bad-date","i":"file-1"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"d":"2024-01-01 12:00:00","i":""}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"d":"","i":"file-1"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)),
	}
	for _, cursor := range cases {
		if _, _, err := DecodeOwnerFileListCursor(cursor); err != ErrInvalidOwnerFileListCursor {
			t.Fatalf("cursor %q: got %v want ErrInvalidOwnerFileListCursor", cursor, err)
		}
	}
}

func TestEncodeOwnerFileListCursorRejectsEmpty(t *testing.T) {
	if _, err := EncodeOwnerFileListCursor(time.Time{}, "file-1"); err != ErrInvalidOwnerFileListCursor {
		t.Fatalf("zero time: got %v", err)
	}
	if _, err := EncodeOwnerFileListCursor(time.Now().UTC(), ""); err != ErrInvalidOwnerFileListCursor {
		t.Fatalf("empty file id: got %v", err)
	}
}
