package models

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/84adam/Arkfile/crypto"
	"github.com/google/uuid"
)

// SHA-256 fields on File / file_metadata:
//
//	Sha256sumNonce + EncryptedSha256sum
//	  SHA-256 of the user's original PLAINTEXT file. Computed client-side,
//	  encrypted client-side under the account key, and stored as ciphertext
//	  (nonce + ct||tag, base64). The server never sees this value in
//	  plaintext. AAD-bound to (file_id, "sha256sum", owner_username) per
//	  docs/wip/folders-multi-upload-v2.md §3 so cross-row / cross-field
//	  tampering fails at client decrypt time.
//
//	EncryptedFileSha256sum
//	  Despite the "Encrypted" prefix in the column/field name, this value
//	  is NOT ciphertext. It is a plaintext SHA-256 computed on the server
//	  as a running hash over the already-client-side-encrypted data stream
//	  (pre-padding) as chunks arrive during upload. The server holds it
//	  in plaintext by construction. Used by the client as an
//	  anti-equivocation record: at upload completion the server reports
//	  this value; the client can later re-download, re-hash the
//	  ciphertext it receives, and confirm the server is still reporting
//	  the same value. NOT in AAD scope because it is not encrypted. The
//	  name is kept for historical reasons; see the plan doc for details.
//
//	(See also stored_blob_sha256sum on file_metadata — SHA-256 of all
//	 bytes written to S3 including crypto-random padding, used for
//	 server-side at-rest integrity checks during download. Plaintext,
//	 server-computed, not surfaced on this struct.)
type File struct {
	ID                     int64          `json:"id"`
	FileID                 string         `json:"file_id"`    // UUID v4 for file identification
	StorageID              string         `json:"storage_id"` // UUID v4 for storage backend
	OwnerUsername          string         `json:"owner_username"`
	PasswordHint           string         `json:"password_hint,omitempty"`
	PasswordType           string         `json:"password_type"`
	FilenameNonce          string         // Now stored as base64 strings directly
	EncryptedFilename      string         // Now stored as base64 strings directly
	Sha256sumNonce         string         // base64 nonce for EncryptedSha256sum (plaintext-file hash)
	EncryptedSha256sum     string         // base64 ciphertext of SHA-256 of plaintext file; client-encrypted, AAD-bound
	EncryptedFileSha256sum sql.NullString `json:"-"` // PLAINTEXT server-computed hash of encrypted stream; name is historical, not ciphertext
	EncryptedFEK           string         // Now stored as base64 strings directly

	SizeBytes      int64         `json:"size_bytes"`       // Original file size
	PaddedSize     sql.NullInt64 `json:"padded_size"`      // Size with padding for privacy/security
	ChunkCount     int64         `json:"chunk_count"`      // Number of 16MB chunks for chunked downloads
	ChunkSizeBytes int64         `json:"chunk_size_bytes"` // Size of each chunk (16MB default)
	UploadDate     time.Time     `json:"upload_date"`
}

// FileMetadataListItem is a lightweight owner-only metadata shape for listing
// and local client-side decryption workflows.
type FileMetadataListItem struct {
	FileID             string    `json:"file_id"`
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

// CalculateChunkCount calculates the number of chunks needed for a file of given size
func CalculateChunkCount(sizeBytes int64, chunkSizeBytes int64) int64 {
	if sizeBytes <= 0 {
		return 1
	}
	if chunkSizeBytes <= 0 {
		chunkSizeBytes = crypto.PlaintextChunkSize()
	}
	count := sizeBytes / chunkSizeBytes
	if sizeBytes%chunkSizeBytes != 0 {
		count++
	}
	if count == 0 {
		count = 1
	}
	return count
}

// CreateFile creates a new file record in the database with encrypted metadata (base64 strings)
func CreateFile(db *sql.DB, fileID, storageID, ownerUsername, passwordHint, passwordType string,
	filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum string, sizeBytes int64) (*File, error) {

	chunkSizeBytes := crypto.PlaintextChunkSize()
	chunkCount := CalculateChunkCount(sizeBytes, chunkSizeBytes)

	result, err := db.Exec(`
		INSERT INTO file_metadata (
			file_id, storage_id, owner_username, password_hint, password_type,
			filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			size_bytes, chunk_count, chunk_size_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fileID, storageID, ownerUsername, passwordHint, passwordType,
		filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum,
		sizeBytes, chunkCount, chunkSizeBytes,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &File{
		ID:                 id,
		FileID:             fileID,
		StorageID:          storageID,
		OwnerUsername:      ownerUsername,
		PasswordHint:       passwordHint,
		PasswordType:       passwordType,
		FilenameNonce:      filenameNonce,      // Already base64 strings
		EncryptedFilename:  encryptedFilename,  // Already base64 strings
		Sha256sumNonce:     sha256sumNonce,     // Already base64 strings
		EncryptedSha256sum: encryptedSha256sum, // Already base64 strings
		SizeBytes:          sizeBytes,
		ChunkCount:         chunkCount,
		ChunkSizeBytes:     chunkSizeBytes,
		UploadDate:         time.Now(),
	}, nil
}

// GetFileByFileID retrieves a file record by file_id
func GetFileByFileID(db *sql.DB, fileID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var sizeBytes interface{}      // Use interface{} to handle both int64 and float64
	var paddedSize interface{}     // Use interface{} to handle RQLite float64 returns
	var chunkCount interface{}     // Use interface{} to handle both int64 and float64
	var chunkSizeBytes interface{} // Use interface{} to handle both int64 and float64
	var uploadDateStr string       // Scan as string first to handle RQLite timestamp format

	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size,
			   chunk_count, chunk_size_bytes, upload_date
		FROM file_metadata WHERE file_id = ?`,
		fileID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedFileSha256sum, &file.EncryptedFEK,
		&sizeBytes, &paddedSize,
		&chunkCount, &chunkSizeBytes, &uploadDateStr,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

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

	// Handle the nullable encrypted_file_sha256sum field
	if encryptedFileSha256sum != "" {
		file.EncryptedFileSha256sum = sql.NullString{
			String: encryptedFileSha256sum,
			Valid:  true,
		}
	} else {
		file.EncryptedFileSha256sum = sql.NullString{
			String: "",
			Valid:  false,
		}
	}

	return file, nil
}

// GetFileByStorageID retrieves a file record by storage_id
func GetFileByStorageID(db *sql.DB, storageID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var sizeBytes interface{}      // Use interface{} to handle both int64 and float64
	var paddedSize interface{}     // Use interface{} to handle RQLite float64 returns
	var chunkCount interface{}     // Use interface{} to handle both int64 and float64
	var chunkSizeBytes interface{} // Use interface{} to handle both int64 and float64
	var uploadDateStr string       // Scan as string first to handle RQLite timestamp format

	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum,
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size,
			   chunk_count, chunk_size_bytes, upload_date
		FROM file_metadata WHERE storage_id = ?`,
		storageID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedFileSha256sum, &file.EncryptedFEK,
		&sizeBytes, &paddedSize,
		&chunkCount, &chunkSizeBytes, &uploadDateStr,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

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

	// Handle the nullable encrypted_file_sha256sum field
	if encryptedFileSha256sum != "" {
		file.EncryptedFileSha256sum = sql.NullString{
			String: encryptedFileSha256sum,
			Valid:  true,
		}
	} else {
		file.EncryptedFileSha256sum = sql.NullString{
			String: "",
			Valid:  false,
		}
	}

	return file, nil
}

// GetFilesByOwner retrieves all files owned by a specific user
func GetFilesByOwner(db *sql.DB, ownerUsername string) ([]*File, error) {
	if db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size,
			   chunk_count, chunk_size_bytes, upload_date 
		FROM file_metadata WHERE owner_username = ? ORDER BY upload_date DESC`

	rows, err := db.Query(query, ownerUsername)
	if err != nil {
		return nil, fmt.Errorf("sql query failed for user '%s': %w", ownerUsername, err)
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		file := &File{}
		var encryptedFileSha256sum string
		var sizeBytes interface{}
		var paddedSize interface{}
		var chunkCount interface{}
		var chunkSizeBytes interface{}
		var uploadDateStr string

		err := rows.Scan(
			&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
			&file.PasswordHint, &file.PasswordType,
			&file.FilenameNonce, &file.EncryptedFilename,
			&file.Sha256sumNonce, &file.EncryptedSha256sum,
			&encryptedFileSha256sum, &file.EncryptedFEK,
			&sizeBytes, &paddedSize,
			&chunkCount, &chunkSizeBytes, &uploadDateStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan row for user '%s': %w", ownerUsername, err)
		}

		// Convert sizeBytes from interface{} to int64
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
		if parsedTime, parseErr := time.Parse("2006-01-02 15:04:05", uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if parsedTime, parseErr := time.Parse(time.RFC3339, uploadDateStr); parseErr == nil {
			file.UploadDate = parsedTime
		} else if uploadDateStr != "" {
			// Skip if parsing fails - no logging needed in this bulk operation
		}

		// Handle nullable encrypted_file_sha256sum
		if encryptedFileSha256sum != "" {
			file.EncryptedFileSha256sum = sql.NullString{String: encryptedFileSha256sum, Valid: true}
		}

		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error for user '%s': %w", ownerUsername, err)
	}

	return files, nil
}

// GetRecentFileMetadataByOwner retrieves a paginated recent metadata view for
// files owned by a specific user, ordered by upload date descending.
func GetRecentFileMetadataByOwner(db *sql.DB, ownerUsername string, limit, offset int) ([]*FileMetadataListItem, error) {
	if db == nil {
		return nil, errors.New("database connection is nil")
	}

	query := `
		SELECT file_id, password_type, filename_nonce, encrypted_filename,
		       sha256sum_nonce, encrypted_sha256sum, size_bytes, upload_date
		FROM file_metadata
		WHERE owner_username = ?
		ORDER BY upload_date DESC
		LIMIT ? OFFSET ?`

	rows, err := db.Query(query, ownerUsername, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("recent metadata query failed for user '%s': %w", ownerUsername, err)
	}
	defer rows.Close()

	var files []*FileMetadataListItem
	for rows.Next() {
		item, err := scanFileMetadataListItem(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan recent metadata row for user '%s': %w", ownerUsername, err)
		}
		files = append(files, item)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("recent metadata rows iteration error for user '%s': %w", ownerUsername, err)
	}

	return files, nil
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
		SELECT file_id, password_type, filename_nonce, encrypted_filename,
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

// UpdatePasswordHint updates the password hint for a file
func (f *File) UpdatePasswordHint(db *sql.DB, newHint string) error {
	_, err := db.Exec(
		"UPDATE file_metadata SET password_hint = ? WHERE id = ?",
		newHint, f.ID,
	)
	if err != nil {
		return err
	}

	f.PasswordHint = newHint
	return nil
}

// FileMetadataForClient represents the encrypted metadata that gets sent to the client.
// All binary data is Base64-encoded as strings for robust JSON transport.
type FileMetadataForClient struct {
	FileID             string    `json:"file_id"`
	StorageID          string    `json:"storage_id"`
	PasswordHint       string    `json:"password_hint,omitempty"`
	PasswordType       string    `json:"password_type"`
	FilenameNonce      string    `json:"filename_nonce"`
	EncryptedFilename  string    `json:"encrypted_filename"`
	Sha256sumNonce     string    `json:"sha256sum_nonce"`
	EncryptedSha256sum string    `json:"encrypted_sha256sum"`
	EncryptedFEK       string    `json:"encrypted_fek"`
	SizeBytes          int64     `json:"size_bytes"`
	UploadDate         time.Time `json:"upload_date"`
}

// ToClientMetadata converts a File to FileMetadataForClient for sending to the client.
// All data is now stored as base64 strings directly, so we return them as-is.
func (f *File) ToClientMetadata() *FileMetadataForClient {
	return &FileMetadataForClient{
		FileID:             f.FileID,
		StorageID:          f.StorageID,
		PasswordHint:       f.PasswordHint,
		PasswordType:       f.PasswordType,
		FilenameNonce:      f.FilenameNonce,
		EncryptedFilename:  f.EncryptedFilename,
		Sha256sumNonce:     f.Sha256sumNonce,
		EncryptedSha256sum: f.EncryptedSha256sum,
		EncryptedFEK:       f.EncryptedFEK,
		SizeBytes:          f.SizeBytes,
		UploadDate:         f.UploadDate,
	}
}
