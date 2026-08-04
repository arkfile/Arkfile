package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/crypto"
	"github.com/google/uuid"
)

const ownerFileSelectColumns = `id, file_id, storage_id, owner_username, COALESCE(encrypted_password_hint, ''), COALESCE(password_hint_nonce, ''),
			   COALESCE(encrypted_tags, ''), COALESCE(tags_nonce, ''), COALESCE(tags_revision, 0), password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_stream_sha256sum, ''), encrypted_fek, size_bytes, padded_size,
			   chunk_count, chunk_size_bytes, upload_date`

// OwnerFilePage is one cursor page of owner files for GET /api/files.
type OwnerFilePage struct {
	Files      []*File
	HasMore    bool
	NextCursor string
}

// SHA-256 fields on File / file_metadata:
//
//	Sha256sumNonce + EncryptedSha256sum
//	  SHA-256 of the user's original PLAINTEXT file. Computed client-side,
//	  encrypted client-side under the account key, and stored as ciphertext
//	  (nonce + ct||tag, base64). The server never sees this value in
//	  plaintext. AAD-bound to (file_id, "encrypted_sha256sum",
//	  owner_username) (see crypto/aad.go:
//	  BuildMetadataFieldAAD with AADFieldSha256), so substituting metadata
//	  between files, fields, or users fails at client decrypt time.
//
//	EncryptedStreamSha256sum
//	  Plaintext hex SHA-256 computed on the server as a running hash over
//	  the already-client-side-encrypted data stream (pre-padding) as chunks
//	  arrive during upload. Not ciphertext and not Account-Key protected.
//	  Returned on upload-complete as encrypted_stream_sha256; omitted from
//	  owner file-metadata JSON. NOT in AAD scope. The AAD label
//	  "encrypted_sha256sum" refers only to EncryptedSha256sum above.
//
//	(See also stored_blob_sha256sum on file_metadata -- SHA-256 of all
//	 bytes written to S3 including crypto-random padding, used for
//	 server-side at-rest integrity checks during download. Plaintext,
//	 server-computed, not surfaced on this struct.)
type File struct {
	ID                       int64          `json:"id"`
	FileID                   string         `json:"file_id"`    // UUID v4 for file identification
	StorageID                string         `json:"storage_id"` // UUID v4 for storage backend
	OwnerUsername            string         `json:"owner_username"`
	EncryptedPasswordHint    string         `json:"encrypted_password_hint,omitempty"`
	PasswordHintNonce        string         `json:"password_hint_nonce,omitempty"`
	EncryptedTags            string         `json:"encrypted_tags,omitempty"`
	TagsNonce                string         `json:"tags_nonce,omitempty"`
	TagsRevision             int64          `json:"tags_revision"`
	PasswordType             string         `json:"password_type"`
	FilenameNonce            string         // Now stored as base64 strings directly
	EncryptedFilename        string         // Now stored as base64 strings directly
	Sha256sumNonce           string         // base64 nonce for EncryptedSha256sum (plaintext-file hash)
	EncryptedSha256sum       string         // base64 ciphertext of SHA-256 of plaintext file; client-encrypted, AAD-bound
	EncryptedStreamSha256sum sql.NullString `json:"-"` // plaintext server-computed hash of pre-padding encrypted stream
	EncryptedFEK             string         // Now stored as base64 strings directly

	SizeBytes      int64         `json:"size_bytes"`       // Pre-padding encrypted stream length (not plaintext file size)
	PaddedSize     sql.NullInt64 `json:"padded_size"`      // Full S3 object length including padding
	ChunkCount     int64         `json:"chunk_count"`      // Number of chunks for chunked downloads
	ChunkSizeBytes int64         `json:"chunk_size_bytes"` // Plaintext chunk size (last chunk may be smaller)
	UploadDate     time.Time     `json:"upload_date"`
}

// FileMetadataListItem is a lightweight owner-only metadata shape for listing
// and local client-side decryption workflows. OwnerUsername is
// included so the client can reconstruct the metadata AAD without an
// additional round-trip; for owner endpoints this always matches the
// authenticated user.
type FileMetadataListItem struct {
	FileID             string    `json:"file_id"`
	OwnerUsername      string    `json:"owner_username"`
	PasswordType       string    `json:"password_type"`
	FilenameNonce      string    `json:"filename_nonce"`
	EncryptedFilename  string    `json:"encrypted_filename"`
	Sha256sumNonce     string    `json:"sha256sum_nonce"`
	EncryptedSha256sum string    `json:"encrypted_sha256sum"`
	SizeBytes          int64     `json:"size_bytes"`
	UploadDate         time.Time `json:"upload_date"`
}

// GenerateStorageID creates a new UUID v4 for storage
func GenerateStorageID() string {
	return uuid.New().String()
}

// GenerateFileID creates a new UUID v4 for file identification
func GenerateFileID() string {
	return uuid.New().String()
}

// CalculateChunkCount returns the number of encrypted chunks for an encrypted
// stream of sizeBytes when each full encrypted chunk spans
// plaintextChunkSizeBytes + AesGcmOverhead() bytes. Empty streams use one chunk.
func CalculateChunkCount(sizeBytes int64, plaintextChunkSizeBytes int64) int64 {
	if sizeBytes <= 0 {
		return 1
	}
	if plaintextChunkSizeBytes <= 0 {
		plaintextChunkSizeBytes = crypto.PlaintextChunkSize()
	}
	encryptedChunkSize := plaintextChunkSizeBytes + int64(crypto.AesGcmOverhead())
	return (sizeBytes + encryptedChunkSize - 1) / encryptedChunkSize
}

// GetFileByFileID retrieves a file record by file_id
func GetFileByFileID(db *sql.DB, fileID string) (*File, error) {
	file := &File{}
	var encryptedStreamSha256sum string
	var sizeBytes interface{}      // Use interface{} to handle both int64 and float64
	var paddedSize interface{}     // Use interface{} to handle RQLite float64 returns
	var chunkCount interface{}     // Use interface{} to handle both int64 and float64
	var chunkSizeBytes interface{} // Use interface{} to handle both int64 and float64
	var uploadDateStr string       // Scan as string first to handle RQLite timestamp format

	var tagsRevision interface{}
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, COALESCE(encrypted_password_hint, ''), COALESCE(password_hint_nonce, ''),
			   COALESCE(encrypted_tags, ''), COALESCE(tags_nonce, ''), COALESCE(tags_revision, 0), password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_stream_sha256sum, ''), encrypted_fek, size_bytes, padded_size,
			   chunk_count, chunk_size_bytes, upload_date
		FROM file_metadata WHERE file_id = ?`,
		fileID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.EncryptedPasswordHint, &file.PasswordHintNonce,
		&file.EncryptedTags, &file.TagsNonce, &tagsRevision, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedStreamSha256sum, &file.EncryptedFEK,
		&sizeBytes, &paddedSize,
		&chunkCount, &chunkSizeBytes, &uploadDateStr,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	file.TagsRevision = coerceInt64(tagsRevision, 0)

	// Convert sizeBytes from interface{} to int64, handling both int64 and float64
	switch v := sizeBytes.(type) {
	case int64:
		file.SizeBytes = v
	case float64:
		file.SizeBytes = int64(v)
	case nil:
		file.SizeBytes = 0
	default:
		return nil, fmt.Errorf("GetFileByFileID: unexpected type for size_bytes: %T", v)
	}

	// Convert paddedSize from interface{} to sql.NullInt64
	switch v := paddedSize.(type) {
	case int64:
		file.PaddedSize = sql.NullInt64{Int64: v, Valid: true}
	case float64:
		file.PaddedSize = sql.NullInt64{Int64: int64(v), Valid: true}
	case nil:
		file.PaddedSize = sql.NullInt64{Valid: false}
	default:
		file.PaddedSize = sql.NullInt64{Valid: false}
	}

	// Convert chunkCount from interface{} to int64
	switch v := chunkCount.(type) {
	case int64:
		file.ChunkCount = v
	case float64:
		file.ChunkCount = int64(v)
	case nil:
		file.ChunkCount = 1
	default:
		file.ChunkCount = 1
	}

	// Convert chunkSizeBytes from interface{} to int64
	switch v := chunkSizeBytes.(type) {
	case int64:
		file.ChunkSizeBytes = v
	case float64:
		file.ChunkSizeBytes = int64(v)
	case nil:
		file.ChunkSizeBytes = crypto.PlaintextChunkSize()
	default:
		file.ChunkSizeBytes = crypto.PlaintextChunkSize()
	}

	// Parse timestamp string to time.Time
	if uploadDateStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else {
			// Fallback to current time if parsing fails
			file.UploadDate = time.Now()
		}
	}

	// Handle the nullable encrypted_stream_sha256sum field
	if encryptedStreamSha256sum != "" {
		file.EncryptedStreamSha256sum = sql.NullString{
			String: encryptedStreamSha256sum,
			Valid:  true,
		}
	} else {
		file.EncryptedStreamSha256sum = sql.NullString{
			String: "",
			Valid:  false,
		}
	}

	return file, nil
}

// GetFileByStorageID retrieves a file record by storage_id
func GetFileByStorageID(db *sql.DB, storageID string) (*File, error) {
	file := &File{}
	var encryptedStreamSha256sum string
	var sizeBytes interface{}      // Use interface{} to handle both int64 and float64
	var paddedSize interface{}     // Use interface{} to handle RQLite float64 returns
	var chunkCount interface{}     // Use interface{} to handle both int64 and float64
	var chunkSizeBytes interface{} // Use interface{} to handle both int64 and float64
	var uploadDateStr string       // Scan as string first to handle RQLite timestamp format

	var tagsRevision interface{}
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, COALESCE(encrypted_password_hint, ''), COALESCE(password_hint_nonce, ''),
			   COALESCE(encrypted_tags, ''), COALESCE(tags_nonce, ''), COALESCE(tags_revision, 0), password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_stream_sha256sum, ''), encrypted_fek, size_bytes, padded_size,
			   chunk_count, chunk_size_bytes, upload_date
		FROM file_metadata WHERE storage_id = ?`,
		storageID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.EncryptedPasswordHint, &file.PasswordHintNonce,
		&file.EncryptedTags, &file.TagsNonce, &tagsRevision, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedStreamSha256sum, &file.EncryptedFEK,
		&sizeBytes, &paddedSize,
		&chunkCount, &chunkSizeBytes, &uploadDateStr,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	file.TagsRevision = coerceInt64(tagsRevision, 0)

	// Convert sizeBytes from interface{} to int64, handling both int64 and float64
	switch v := sizeBytes.(type) {
	case int64:
		file.SizeBytes = v
	case float64:
		file.SizeBytes = int64(v)
	case nil:
		file.SizeBytes = 0
	default:
		return nil, fmt.Errorf("GetFileByStorageID: unexpected type for size_bytes: %T", v)
	}

	// Convert paddedSize from interface{} to sql.NullInt64
	switch v := paddedSize.(type) {
	case int64:
		file.PaddedSize = sql.NullInt64{Int64: v, Valid: true}
	case float64:
		file.PaddedSize = sql.NullInt64{Int64: int64(v), Valid: true}
	case nil:
		file.PaddedSize = sql.NullInt64{Valid: false}
	default:
		file.PaddedSize = sql.NullInt64{Valid: false}
	}

	// Convert chunkCount from interface{} to int64
	switch v := chunkCount.(type) {
	case int64:
		file.ChunkCount = v
	case float64:
		file.ChunkCount = int64(v)
	case nil:
		file.ChunkCount = 1
	default:
		file.ChunkCount = 1
	}

	// Convert chunkSizeBytes from interface{} to int64
	switch v := chunkSizeBytes.(type) {
	case int64:
		file.ChunkSizeBytes = v
	case float64:
		file.ChunkSizeBytes = int64(v)
	case nil:
		file.ChunkSizeBytes = crypto.PlaintextChunkSize()
	default:
		file.ChunkSizeBytes = crypto.PlaintextChunkSize()
	}

	// Parse timestamp string to time.Time
	if uploadDateStr != "" {
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else {
			// Fallback to current time if parsing fails
			file.UploadDate = time.Now()
		}
	}

	// Handle the nullable encrypted_stream_sha256sum field
	if encryptedStreamSha256sum != "" {
		file.EncryptedStreamSha256sum = sql.NullString{
			String: encryptedStreamSha256sum,
			Valid:  true,
		}
	} else {
		file.EncryptedStreamSha256sum = sql.NullString{
			String: "",
			Valid:  false,
		}
	}

	return file, nil
}

// GetFilesByOwnerPage retrieves one page of files owned by a user, newest first.
// cursor is opaque; empty means the first page. limit is the maximum number of
// files to return (the query fetches limit+1 to compute has_more exactly).
func GetFilesByOwnerPage(db *sql.DB, ownerUsername string, limit int, cursor string) (*OwnerFilePage, error) {
	if db == nil {
		return nil, errors.New("database connection is nil")
	}
	if limit < 1 {
		return nil, fmt.Errorf("limit must be at least 1")
	}

	var (
		rows *sql.Rows
		err  error
	)

	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		query := `
			SELECT ` + ownerFileSelectColumns + `
			FROM file_metadata
			WHERE owner_username = ?
			ORDER BY upload_date DESC, file_id DESC
			LIMIT ?`
		rows, err = db.Query(query, ownerUsername, limit+1)
	} else {
		cursorTime, cursorFileID, cerr := DecodeOwnerFileListCursor(cursor)
		if cerr != nil {
			return nil, ErrInvalidOwnerFileListCursor
		}
		cursorTimeStr := FormatOwnerFileListCursorTime(cursorTime)
		query := `
			SELECT ` + ownerFileSelectColumns + `
			FROM file_metadata
			WHERE owner_username = ?
			  AND (upload_date < ? OR (upload_date = ? AND file_id < ?))
			ORDER BY upload_date DESC, file_id DESC
			LIMIT ?`
		rows, err = db.Query(query, ownerUsername, cursorTimeStr, cursorTimeStr, cursorFileID, limit+1)
	}
	if err != nil {
		return nil, fmt.Errorf("sql query failed for user '%s': %w", ownerUsername, err)
	}
	defer rows.Close()

	files := make([]*File, 0, limit)
	for rows.Next() {
		file, scanErr := scanFileRow(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("failed to scan row for user '%s': %w", ownerUsername, scanErr)
		}
		files = append(files, file)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error for user '%s': %w", ownerUsername, err)
	}

	page := &OwnerFilePage{Files: files}
	if len(files) > limit {
		page.HasMore = true
		page.Files = files[:limit]
	}
	if page.HasMore && len(page.Files) > 0 {
		last := page.Files[len(page.Files)-1]
		next, encErr := EncodeOwnerFileListCursor(last.UploadDate, last.FileID)
		if encErr != nil {
			return nil, fmt.Errorf("failed to encode next cursor for user '%s': %w", ownerUsername, encErr)
		}
		page.NextCursor = next
	}
	return page, nil
}

func scanFileRow(scanner interface {
	Scan(dest ...interface{}) error
}) (*File, error) {
	file := &File{}
	var encryptedStreamSha256sum string
	var sizeBytes interface{}
	var paddedSize interface{}
	var chunkCount interface{}
	var chunkSizeBytes interface{}
	var uploadDateStr string
	var tagsRevision interface{}

	err := scanner.Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.EncryptedPasswordHint, &file.PasswordHintNonce,
		&file.EncryptedTags, &file.TagsNonce, &tagsRevision, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedStreamSha256sum, &file.EncryptedFEK,
		&sizeBytes, &paddedSize,
		&chunkCount, &chunkSizeBytes, &uploadDateStr,
	)
	if err != nil {
		return nil, err
	}
	file.TagsRevision = coerceInt64(tagsRevision, 0)

	switch v := sizeBytes.(type) {
	case int64:
		file.SizeBytes = v
	case float64:
		file.SizeBytes = int64(v)
	case nil:
		file.SizeBytes = 0
	default:
		return nil, fmt.Errorf("unexpected type for size_bytes: %T", v)
	}

	switch v := paddedSize.(type) {
	case int64:
		file.PaddedSize = sql.NullInt64{Int64: v, Valid: true}
	case float64:
		file.PaddedSize = sql.NullInt64{Int64: int64(v), Valid: true}
	case nil:
		file.PaddedSize = sql.NullInt64{Valid: false}
	default:
		file.PaddedSize = sql.NullInt64{Valid: false}
	}

	switch v := chunkCount.(type) {
	case int64:
		file.ChunkCount = v
	case float64:
		file.ChunkCount = int64(v)
	case nil:
		file.ChunkCount = 1
	default:
		file.ChunkCount = 1
	}

	switch v := chunkSizeBytes.(type) {
	case int64:
		file.ChunkSizeBytes = v
	case float64:
		file.ChunkSizeBytes = int64(v)
	case nil:
		file.ChunkSizeBytes = crypto.PlaintextChunkSize()
	default:
		file.ChunkSizeBytes = crypto.PlaintextChunkSize()
	}

	if parsedTime, parseErr := time.Parse(ownerFileListCursorTimeLayout, uploadDateStr); parseErr == nil {
		file.UploadDate = parsedTime
	} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
		file.UploadDate = parsedTime
	}

	if encryptedStreamSha256sum != "" {
		file.EncryptedStreamSha256sum = sql.NullString{String: encryptedStreamSha256sum, Valid: true}
	}

	return file, nil
}

// GetFileMetadataBatchByOwner retrieves lightweight metadata for an explicit
// batch of file IDs owned by a specific user.
func GetFileMetadataBatchByOwner(db *sql.DB, ownerUsername string, fileIDs []string) ([]*FileMetadataListItem, error) {
	if db == nil {
		return nil, errors.New("database connection is nil")
	}

	if len(fileIDs) == 0 {
		return []*FileMetadataListItem{}, nil
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(fileIDs)), ",")
	query := fmt.Sprintf(`
		SELECT file_id, owner_username, password_type, filename_nonce, encrypted_filename,
		       sha256sum_nonce, encrypted_sha256sum, size_bytes, upload_date
		FROM file_metadata
		WHERE owner_username = ? AND file_id IN (%s)`, placeholders)

	args := make([]interface{}, 0, len(fileIDs)+1)
	args = append(args, ownerUsername)
	for _, fileID := range fileIDs {
		args = append(args, fileID)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("batch metadata query failed for user '%s': %w", ownerUsername, err)
	}
	defer rows.Close()

	var files []*FileMetadataListItem
	for rows.Next() {
		item, err := scanFileMetadataListItem(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan batch metadata row for user '%s': %w", ownerUsername, err)
		}
		files = append(files, item)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("batch metadata rows iteration error for user '%s': %w", ownerUsername, err)
	}

	return files, nil
}

func scanFileMetadataListItem(scanner interface {
	Scan(dest ...interface{}) error
}) (*FileMetadataListItem, error) {
	item := &FileMetadataListItem{}
	var sizeBytes interface{}
	var uploadDateStr string

	err := scanner.Scan(
		&item.FileID,
		&item.OwnerUsername,
		&item.PasswordType,
		&item.FilenameNonce,
		&item.EncryptedFilename,
		&item.Sha256sumNonce,
		&item.EncryptedSha256sum,
		&sizeBytes,
		&uploadDateStr,
	)
	if err != nil {
		return nil, err
	}

	switch v := sizeBytes.(type) {
	case int64:
		item.SizeBytes = v
	case float64:
		item.SizeBytes = int64(v)
	case nil:
		item.SizeBytes = 0
	default:
		return nil, fmt.Errorf("unexpected type for size_bytes: %T", v)
	}

	if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
		item.UploadDate = parsedTime
	} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
		item.UploadDate = parsedTime
	}

	return item, nil
}

// DeleteFile removes a file record from the database by file_id
func DeleteFile(db *sql.DB, fileID string, ownerUsername string) error {
	result, err := db.Exec(
		"DELETE FROM file_metadata WHERE file_id = ? AND owner_username = ?",
		fileID, ownerUsername,
	)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if affected == 0 {
		return errors.New("file not found or unauthorized")
	}

	return nil
}

// FileMetadataForClient represents the encrypted metadata that gets sent to
// the client. All binary data is Base64-encoded as strings for robust JSON
// transport. OwnerUsername is included so the client can rebuild the
// metadata AAD (encrypted_filename and encrypted_sha256sum decrypt require it).
type FileMetadataForClient struct {
	FileID                string    `json:"file_id"`
	StorageID             string    `json:"storage_id"`
	OwnerUsername         string    `json:"owner_username"`
	EncryptedPasswordHint string    `json:"encrypted_password_hint,omitempty"`
	PasswordHintNonce     string    `json:"password_hint_nonce,omitempty"`
	EncryptedTags         string    `json:"encrypted_tags,omitempty"`
	TagsNonce             string    `json:"tags_nonce,omitempty"`
	TagsRevision          int64     `json:"tags_revision"`
	PasswordType          string    `json:"password_type"`
	FilenameNonce         string    `json:"filename_nonce"`
	EncryptedFilename     string    `json:"encrypted_filename"`
	Sha256sumNonce        string    `json:"sha256sum_nonce"`
	EncryptedSha256sum    string    `json:"encrypted_sha256sum"`
	EncryptedFEK          string    `json:"encrypted_fek"`
	SizeBytes             int64     `json:"size_bytes"`
	UploadDate            time.Time `json:"upload_date"`
}

// ToClientMetadata converts a File to FileMetadataForClient for sending to
// the client. All data is stored as base64 strings directly, so we return
// them as-is.
func (f *File) ToClientMetadata() *FileMetadataForClient {
	return &FileMetadataForClient{
		FileID:                f.FileID,
		StorageID:             f.StorageID,
		OwnerUsername:         f.OwnerUsername,
		EncryptedPasswordHint: f.EncryptedPasswordHint,
		PasswordHintNonce:     f.PasswordHintNonce,
		EncryptedTags:         f.EncryptedTags,
		TagsNonce:             f.TagsNonce,
		TagsRevision:          f.TagsRevision,
		PasswordType:          f.PasswordType,
		FilenameNonce:         f.FilenameNonce,
		EncryptedFilename:     f.EncryptedFilename,
		Sha256sumNonce:        f.Sha256sumNonce,
		EncryptedSha256sum:    f.EncryptedSha256sum,
		EncryptedFEK:          f.EncryptedFEK,
		SizeBytes:             f.SizeBytes,
		UploadDate:            f.UploadDate,
	}
}

// UpdateFileTagsConditionally replaces opaque tags when expectedRevision matches.
// On success it returns the new revision. ErrTagsRevisionConflict means a stale
// expected revision; the ciphertext was not changed.
func UpdateFileTagsConditionally(db *sql.DB, fileID, ownerUsername, encryptedTags, tagsNonce string, expectedRevision int64) (int64, error) {
	if db == nil {
		return 0, errors.New("database connection is nil")
	}
	newRevision := expectedRevision + 1
	result, err := db.Exec(`
		UPDATE file_metadata
		SET encrypted_tags = ?, tags_nonce = ?, tags_revision = ?
		WHERE file_id = ? AND owner_username = ? AND tags_revision = ?`,
		encryptedTags, tagsNonce, newRevision, fileID, ownerUsername, expectedRevision,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to update tags: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read tags update result: %w", err)
	}
	if affected == 0 {
		return 0, ErrTagsRevisionConflict
	}
	return newRevision, nil
}

// ErrTagsRevisionConflict indicates an optimistic-concurrency miss on tags update.
var ErrTagsRevisionConflict = errors.New("tags revision conflict")

func coerceInt64(v interface{}, fallback int64) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case nil:
		return fallback
	default:
		return fallback
	}
}
