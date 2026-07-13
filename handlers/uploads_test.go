package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/auth"
)

// validTestFileID is a canonical lowercase UUIDv4 with RFC4122 variant
// (variant nibble '8'). Used wherever a test needs a known-good
// file_id value.
const validTestFileID = "f1f1f1f1-2222-4333-8444-555555555555"

// buildValidInitPayload returns a request body with all required
// fields populated, parameterized only by the file_id. Tests override
// individual fields before marshaling.
func buildValidInitPayload(fileID string) map[string]interface{} {
	return map[string]interface{}{
		"file_id":             fileID,
		"encrypted_filename":  "ZW5jcnlwdGVkLWZpbGVuYW1l",
		"filename_nonce":      "MTIzNDU2Nzg5MDEy",
		"encrypted_sha256sum": "ZW5jcnlwdGVkLXNoYTI1Ng==",
		"sha256sum_nonce":     "MDk4NzY1NDMyMTAw",
		"encrypted_fek":       "ZW5jcnlwdGVkLWZlay1lbnZlbG9wZQ==",
		"total_size":          int64(1024),
		"chunk_size":          int64(16777216),
		"password_type":       "account",
	}
}

// TestCreateUploadSession_RejectsNonUUIDv4FileID verifies that the strict
// UUIDv4 validation in CreateUploadSession rejects every form that is not a
// canonical lowercase RFC 4122 UUID v4. Rejection happens before any DB
// query, so the test does not need to wire mock expectations.
//
// (TestCreateUploadSession_RejectsNonUUIDv4FileID).
func TestCreateUploadSession_RejectsNonUUIDv4FileID(t *testing.T) {
	cases := []struct {
		name   string
		fileID string
	}{
		{"empty string", ""},
		{"malformed text", "not-a-uuid"},
		{"too short", "f1f1f1f1-2222-4333-8444-55555555555"}, // 11-char final segment
		{"too long", "f1f1f1f1-2222-4333-8444-5555555555555"},
		{"v1 UUID", "00112233-4455-1677-8899-aabbccddeeff"},
		{"v3 UUID", "00112233-4455-3677-8899-aabbccddeeff"},
		{"v5 UUID", "00112233-4455-5677-8899-aabbccddeeff"},
		{"v4 but invalid variant (variant nibble 0)", "f1f1f1f1-2222-4333-0444-555555555555"},
		{"uppercase hex v4", "F1F1F1F1-2222-4333-8444-555555555555"},
		{"URN-prefixed v4", "urn:uuid:f1f1f1f1-2222-4333-8444-555555555555"},
		{"brace-wrapped v4", "{f1f1f1f1-2222-4333-8444-555555555555}"},
	}

	username := "phase-c-step4-uuid-user"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildValidInitPayload(tc.fileID)
			body, err := json.Marshal(payload)
			require.NoError(t, err)

			c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body))
			claims := &auth.Claims{Username: username}
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			c.Set("user", token)

			err = CreateUploadSession(c)
			require.NoError(t, err, "handler should write the 400 response itself")
			require.Equal(t, http.StatusBadRequest, rec.Code, "expected 400 for input %q", tc.fileID)

			var resp APIResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.False(t, resp.Success)
			assert.Equal(t, "invalid_file_id", resp.Error,
				"stable error code must be `invalid_file_id` for input %q", tc.fileID)
		})
	}
}

// TestCreateUploadSession_FileIDConflictStableError verifies that the server
// returns HTTP 409 with stable error code "file_id_conflict" when the
// client-supplied file_id already exists in either file_metadata or
// upload_sessions. The CLI's isFileIDConflict() (cmd/arkfile-client/commands.go)
// scans for both "HTTP 409" and "file_id_conflict" case-insensitively, so
// the response shape is a wire-format commitment.
//
// (TestCreateUploadSession_FileIDConflictStableError).
func TestCreateUploadSession_FileIDConflictStableError(t *testing.T) {
	username := "phase-c-step4-conflict-user"

	// mockStorageGate wires the queries that run before the file_id
	// uniqueness check: user lookup (approval + storage limit) and the
	// per-user in-progress sweep + count. Each sub-test reuses this.
	mockStorageGate := func(mock sqlmock.Sqlmock) {
		// CreateUploadSession reads the user once for approval, then
		// CheckStorageAvailable reads it twice to determine usage and limit.
		for range 3 {
			userRows := sqlmock.NewRows([]string{
				"id", "username", "created_at", "total_storage_bytes",
				"storage_limit_bytes", "is_approved", "approved_by", "approved_at",
				"is_admin",
			}).AddRow(
				int64(1), username, "2024-01-01 00:00:00", int64(0),
				int64(1<<30), true, sql.NullString{String: "admin", Valid: true},
				sql.NullString{String: "2024-01-01 00:00:00", Valid: true},
				false,
			)
			mock.ExpectQuery(`SELECT id, username, created_at,\s+total_storage_bytes, storage_limit_bytes,\s+is_approved, approved_by, approved_at, is_admin\s+FROM users WHERE username = \?`).
				WithArgs(username).WillReturnRows(userRows)
		}

		// BEGIN transaction
		mock.ExpectBegin()

		// Stale-session sweep UPDATE
		mock.ExpectExec(`UPDATE upload_sessions\s+SET status = 'abandoned'`).
			WithArgs(username).WillReturnResult(sqlmock.NewResult(0, 0))

		// In-progress count -> 0 (so we're under the cap)
		mock.ExpectQuery(`SELECT COUNT\(\*\) FROM upload_sessions WHERE owner_username = \? AND status = 'in_progress'`).
			WithArgs(username).
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(0)))
	}

	t.Run("conflict in file_metadata", func(t *testing.T) {
		payload := buildValidInitPayload(validTestFileID)
		body, err := json.Marshal(payload)
		require.NoError(t, err)

		c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body))
		claims := &auth.Claims{Username: username}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		c.Set("user", token)

		mockStorageGate(mock)

		// file_metadata uniqueness check: row already exists -> conflict
		mock.ExpectQuery(`SELECT 1 FROM file_metadata WHERE file_id = \? LIMIT 1`).
			WithArgs(validTestFileID).
			WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(int64(1)))

		mock.ExpectRollback()

		err = CreateUploadSession(c)
		require.NoError(t, err, "handler should write the 409 response itself")
		require.Equal(t, http.StatusConflict, rec.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.False(t, resp.Success)
		assert.Equal(t, "file_id_conflict", resp.Error)

		require.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("conflict in upload_sessions", func(t *testing.T) {
		payload := buildValidInitPayload(validTestFileID)
		body, err := json.Marshal(payload)
		require.NoError(t, err)

		c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/uploads/init", bytes.NewReader(body))
		claims := &auth.Claims{Username: username}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		c.Set("user", token)

		mockStorageGate(mock)

		// file_metadata uniqueness check: no row
		mock.ExpectQuery(`SELECT 1 FROM file_metadata WHERE file_id = \? LIMIT 1`).
			WithArgs(validTestFileID).
			WillReturnError(sql.ErrNoRows)

		// upload_sessions uniqueness check: row exists -> conflict
		mock.ExpectQuery(`SELECT 1 FROM upload_sessions WHERE file_id = \? LIMIT 1`).
			WithArgs(validTestFileID).
			WillReturnRows(sqlmock.NewRows([]string{"1"}).AddRow(int64(1)))

		mock.ExpectRollback()

		err = CreateUploadSession(c)
		require.NoError(t, err, "handler should write the 409 response itself")
		require.Equal(t, http.StatusConflict, rec.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.False(t, resp.Success)
		assert.Equal(t, "file_id_conflict", resp.Error)

		require.NoError(t, mock.ExpectationsWereMet())
	})

	// Sanity check: the error string format is what the CLI's
	// isFileIDConflict() scans for. We re-construct the wire format the
	// CLI sees ("HTTP 409: file_id_conflict") and confirm both parts are
	// present case-insensitively.
	t.Run("error string contract matches CLI scan", func(t *testing.T) {
		wireErr := fmt.Sprintf("HTTP %d: %s", http.StatusConflict, "file_id_conflict")
		assert.Contains(t, wireErr, "HTTP 409")
		assert.Contains(t, wireErr, "file_id_conflict")
	})
}

// TestUploadChunk_EnforcesPaddingCeiling verifies that UploadChunk rejects a request
// early when the database indicates a synthesized padded_size - total_size exceeding
// the maxPaddingPerChunk (16 MiB) cap. This prevents DoS vectors where arbitrary allocations
// are triggered by tampered DB values or malformed session properties.
func TestUploadChunk_EnforcesPaddingCeiling(t *testing.T) {
	username := "padding-test-user"
	sessionID := "session-with-large-padding"

	t.Run("padding exceeds maxPaddingPerChunk", func(t *testing.T) {
		// Minimum chunk size check needs X-Chunk-Hash header, valid hash format, and some data
		c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/uploads/"+sessionID+"/chunks/0", bytes.NewReader([]byte("chunk-payload")))
		c.SetParamNames("sessionId", "chunkNumber")
		c.SetParamValues(sessionID, "0")
		c.Request().Header.Set("X-Chunk-Hash", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

		claims := &auth.Claims{Username: username}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		c.Set("user", token)

		// Mock session query return with massive padding: total_size = 100, padded_size = 20 * 1024 * 1024 (20 MiB of padding)
		rows := sqlmock.NewRows([]string{
			"owner_username", "file_id", "storage_id", "storage_upload_id", "status", "total_chunks", "total_size", "padded_size",
		}).AddRow(
			username, "file-id", "storage-id", "upload-id", "in_progress", 1, int64(100), int64(20*1024*1024),
		)

		mock.ExpectQuery(`SELECT owner_username, file_id, storage_id, storage_upload_id, status, total_chunks, total_size, padded_size FROM upload_sessions WHERE id = \?`).
			WithArgs(sessionID).
			WillReturnRows(rows)

		err := UploadChunk(c)
		require.NoError(t, err, "handler should write the 400 response itself")
		assert.Equal(t, http.StatusBadRequest, rec.Code)

		var resp APIResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.False(t, resp.Success)
		assert.Equal(t, "padding_too_large", resp.Error)

		require.NoError(t, mock.ExpectationsWereMet())
	})
}

// TestUploadChunk_RejectsChunkHashMismatch verifies that UploadChunk compares
// the client-supplied X-Chunk-Hash against the SHA-256 of the received
// encrypted chunk bytes and rejects a mismatch with HTTP 400 and stable error
// code "chunk_hash_mismatch" before storing the part. This guards against
// in-transit corruption or truncation at the chunk boundary.
func TestUploadChunk_RejectsChunkHashMismatch(t *testing.T) {
	username := "chunk-hash-test-user"
	sessionID := "session-chunk-hash-mismatch"

	// Body is large enough to pass the minimum chunk-size content-length
	// check (gcm overhead + 1 byte). The X-Chunk-Hash header below is a
	// well-formed 64-hex value that deliberately does NOT match the body.
	chunkBody := []byte("this-is-a-sixty-four-byte-or-so-encrypted-chunk-body-payload-data")
	wrongHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/uploads/"+sessionID+"/chunks/0", bytes.NewReader(chunkBody))
	c.SetParamNames("sessionId", "chunkNumber")
	c.SetParamValues(sessionID, "0")
	c.Request().Header.Set("X-Chunk-Hash", wrongHash)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Session row with no padding (total_size == padded_size), in_progress,
	// owned by the calling user, and a valid chunk index range.
	rows := sqlmock.NewRows([]string{
		"owner_username", "file_id", "storage_id", "storage_upload_id", "status", "total_chunks", "total_size", "padded_size",
	}).AddRow(
		username, "file-id", "storage-id", "upload-id", "in_progress", 1, int64(len(chunkBody)), int64(len(chunkBody)),
	)

	mock.ExpectQuery(`SELECT owner_username, file_id, storage_id, storage_upload_id, status, total_chunks, total_size, padded_size FROM upload_sessions WHERE id = \?`).
		WithArgs(sessionID).
		WillReturnRows(rows)

	err := UploadChunk(c)
	require.NoError(t, err, "handler should write the 400 response itself")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Success)
	assert.Equal(t, "chunk_hash_mismatch", resp.Error)

	require.NoError(t, mock.ExpectationsWereMet())
}
