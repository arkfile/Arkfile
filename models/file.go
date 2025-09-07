package models

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type File struct {
	ID                     int64          `json:"id"`
	FileID                 string         `json:"file_id"`    // UUID v4 for file identification
	StorageID              string         `json:"storage_id"` // UUID v4 for storage backend
	OwnerUsername          string         `json:"owner_username"`
	PasswordHint           string         `json:"password_hint,omitempty"`
	PasswordType           string         `json:"password_type"`
	FilenameNonce          []byte         `json:"-"`           // Hidden from JSON - 12 bytes
	EncryptedFilename      []byte         `json:"-"`           // Hidden from JSON - encrypted blob
	Sha256sumNonce         []byte         `json:"-"`           // Hidden from JSON - 12 bytes
	EncryptedSha256sum     []byte         `json:"-"`           // Hidden from JSON - encrypted blob (client-side)
	EncryptedFileSha256sum sql.NullString `json:"-"`           // Hidden from JSON - server-side hash (nullable)
	SizeBytes              int64          `json:"size_bytes"`  // Original file size
	PaddedSize             sql.NullInt64  `json:"padded_size"` // Size with padding for privacy/security
	UploadDate             time.Time      `json:"upload_date"`
}

// GenerateStorageID creates a new UUID v4 for storage
func GenerateStorageID() string {
	return uuid.New().String()
}

// GenerateFileID creates a new UUID v4 for file identification
func GenerateFileID() string {
	return uuid.New().String()
}

// CreateFile creates a new file record in the database with encrypted metadata
func CreateFile(db *sql.DB, fileID, storageID, ownerUsername, passwordHint, passwordType string,
	filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum []byte, sizeBytes int64) (*File, error) {

	result, err := db.Exec(`
		INSERT INTO file_metadata (
			file_id, storage_id, owner_username, password_hint, password_type,
			filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, size_bytes
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		fileID, storageID, ownerUsername, passwordHint, passwordType,
		filenameNonce, encryptedFilename, sha256sumNonce, encryptedSha256sum, sizeBytes,
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
		FilenameNonce:      filenameNonce,
		EncryptedFilename:  encryptedFilename,
		Sha256sumNonce:     sha256sumNonce,
		EncryptedSha256sum: encryptedSha256sum,
		SizeBytes:          sizeBytes,
		UploadDate:         time.Now(),
	}, nil
}

// GetFileByFileID retrieves a file record by file_id
func GetFileByFileID(db *sql.DB, fileID string) (*File, error) {
	file := &File{}
	var encryptedFileSha256sum string
	var encryptedFek []byte   // Add missing encrypted_fek field
	var sizeBytes interface{} // Use interface{} to handle both int64 and float64
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date 
		FROM file_metadata WHERE file_id = ?`,
		fileID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedFileSha256sum, &encryptedFek, &sizeBytes, &file.PaddedSize, &file.UploadDate,
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
	var encryptedFek []byte   // Add missing encrypted_fek field
	var sizeBytes interface{} // Use interface{} to handle both int64 and float64
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date 
		FROM file_metadata WHERE storage_id = ?`,
		storageID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&encryptedFileSha256sum, &encryptedFek, &sizeBytes, &file.PaddedSize, &file.UploadDate,
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
	fmt.Printf("GetFilesByOwner: Starting function for user: %s\n", ownerUsername)

	if db == nil {
		return nil, fmt.Errorf("GetFilesByOwner: database connection is nil")
	}

	if ownerUsername == "" {
		return nil, fmt.Errorf("GetFilesByOwner: ownerUsername is empty")
	}

	// Log the SQL query being executed
	query := `
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   COALESCE(encrypted_file_sha256sum, ''), encrypted_fek, size_bytes, padded_size, upload_date 
		FROM file_metadata WHERE owner_username = ? ORDER BY upload_date DESC`

	fmt.Printf("GetFilesByOwner: Executing query: %s with username: %s\n", query, ownerUsername)

	// Enhanced debugging: Test if the table exists and has the expected structure
	var tableExists int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='file_metadata'").Scan(&tableExists)
	if err != nil {
		fmt.Printf("GetFilesByOwner: Table existence check failed: %v\n", err)
		return nil, fmt.Errorf("GetFilesByOwner: failed to check table existence: %v", err)
	}
	if tableExists == 0 {
		fmt.Printf("GetFilesByOwner: Table 'file_metadata' does not exist\n")
		return nil, fmt.Errorf("GetFilesByOwner: table 'file_metadata' does not exist")
	}
	fmt.Printf("GetFilesByOwner: Table 'file_metadata' exists\n")

	// Check column structure
	fmt.Printf("GetFilesByOwner: Checking table column structure\n")
	columnRows, err := db.Query("PRAGMA table_info(file_metadata)")
	if err != nil {
		fmt.Printf("GetFilesByOwner: Failed to get table info: %v\n", err)
		return nil, fmt.Errorf("GetFilesByOwner: failed to get table info: %v", err)
	}
	defer columnRows.Close()

	var columnCount int
	var columnInfo []string
	for columnRows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString

		if err := columnRows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			fmt.Printf("GetFilesByOwner: Failed to scan column info: %v\n", err)
			return nil, fmt.Errorf("GetFilesByOwner: failed to scan column info: %v", err)
		}
		columnCount++
		columnInfo = append(columnInfo, fmt.Sprintf("%s(%s)", name, dataType))
	}
	fmt.Printf("GetFilesByOwner: Found %d columns: %v\n", columnCount, columnInfo)

	if columnCount < 14 {
		fmt.Printf("GetFilesByOwner: Insufficient columns - found %d, expected at least 14\n", columnCount)
		return nil, fmt.Errorf("GetFilesByOwner: table has %d columns, expected at least 14. Columns: %v", columnCount, columnInfo)
	}

	fmt.Printf("GetFilesByOwner: Executing main query for user '%s'\n", ownerUsername)
	rows, err := db.Query(query, ownerUsername)
	if err != nil {
		fmt.Printf("GetFilesByOwner: Main query failed: %v\n", err)
		return nil, fmt.Errorf("GetFilesByOwner: SQL query failed for user '%s': %v", ownerUsername, err)
	}
	defer rows.Close()

	var files []*File
	rowCount := 0
	fmt.Printf("GetFilesByOwner: Starting to process rows\n")
	for rows.Next() {
		rowCount++
		fmt.Printf("GetFilesByOwner: Processing row %d\n", rowCount)
		file := &File{}
		var encryptedFileSha256sum string
		var encryptedFek []byte   // Add missing encrypted_fek field
		var sizeBytes interface{} // Use interface{} to handle both int64 and float64
		err := rows.Scan(
			&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
			&file.PasswordHint, &file.PasswordType,
			&file.FilenameNonce, &file.EncryptedFilename,
			&file.Sha256sumNonce, &file.EncryptedSha256sum,
			&encryptedFileSha256sum, &encryptedFek, &sizeBytes, &file.PaddedSize, &file.UploadDate,
		)
		if err != nil {
			fmt.Printf("GetFilesByOwner: Failed to scan row %d: %v\n", rowCount, err)
			return nil, fmt.Errorf("GetFilesByOwner: failed to scan row %d for user '%s': %v", rowCount, ownerUsername, err)
		}

		// Convert sizeBytes from interface{} to int64, handling both int64 and float64
		switch v := sizeBytes.(type) {
		case int64:
			file.SizeBytes = v
		case float64:
			file.SizeBytes = int64(v)
			fmt.Printf("GetFilesByOwner: Converted size_bytes from float64(%f) to int64(%d)\n", v, file.SizeBytes)
		case nil:
			file.SizeBytes = 0
			fmt.Printf("GetFilesByOwner: size_bytes was null, defaulting to 0\n")
		default:
			fmt.Printf("GetFilesByOwner: Unexpected type for size_bytes: %T, value: %v\n", v, v)
			return nil, fmt.Errorf("GetFilesByOwner: unexpected type for size_bytes: %T", v)
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

		files = append(files, file)
		fmt.Printf("GetFilesByOwner: Successfully processed row %d - file_id: %s\n", rowCount, file.FileID)
	}

	if err = rows.Err(); err != nil {
		fmt.Printf("GetFilesByOwner: Rows iteration error: %v\n", err)
		return nil, fmt.Errorf("GetFilesByOwner: rows iteration error for user '%s' after processing %d rows: %v", ownerUsername, rowCount, err)
	}

	fmt.Printf("GetFilesByOwner: Successfully retrieved %d files for user '%s'\n", len(files), ownerUsername)
	return files, nil
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

// FileMetadataForClient represents the encrypted metadata that gets sent to the client
// The client will decrypt these fields using their OPAQUE export key
type FileMetadataForClient struct {
	FileID             string    `json:"file_id"`
	StorageID          string    `json:"storage_id"`
	FilenameNonce      []byte    `json:"filename_nonce"`
	EncryptedFilename  []byte    `json:"encrypted_filename"`
	Sha256sumNonce     []byte    `json:"sha256sum_nonce"`
	EncryptedSha256sum []byte    `json:"encrypted_sha256sum"`
	SizeBytes          int64     `json:"size_bytes"`
	UploadDate         time.Time `json:"upload_date"`
}

// ToClientMetadata converts a File to FileMetadataForClient for sending to the client
func (f *File) ToClientMetadata() *FileMetadataForClient {
	return &FileMetadataForClient{
		FileID:             f.FileID,
		StorageID:          f.StorageID,
		FilenameNonce:      f.FilenameNonce,
		EncryptedFilename:  f.EncryptedFilename,
		Sha256sumNonce:     f.Sha256sumNonce,
		EncryptedSha256sum: f.EncryptedSha256sum,
		SizeBytes:          f.SizeBytes,
		UploadDate:         f.UploadDate,
	}
}
