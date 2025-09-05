package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

type File struct {
	ID                     int64     `json:"id"`
	FileID                 string    `json:"file_id"`    // UUID v4 for file identification
	StorageID              string    `json:"storage_id"` // UUID v4 for storage backend
	OwnerUsername          string    `json:"owner_username"`
	PasswordHint           string    `json:"password_hint,omitempty"`
	PasswordType           string    `json:"password_type"`
	FilenameNonce          []byte    `json:"-"`          // Hidden from JSON - 12 bytes
	EncryptedFilename      []byte    `json:"-"`          // Hidden from JSON - encrypted blob
	Sha256sumNonce         []byte    `json:"-"`          // Hidden from JSON - 12 bytes
	EncryptedSha256sum     []byte    `json:"-"`          // Hidden from JSON - encrypted blob (client-side)
	EncryptedFileSha256sum string    `json:"-"`          // Hidden from JSON - server-side hash
	SizeBytes              int64     `json:"size_bytes"` // Original file size
	UploadDate             time.Time `json:"upload_date"`
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
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   encrypted_file_sha256sum, size_bytes, upload_date 
		FROM file_metadata WHERE file_id = ?`,
		fileID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&file.EncryptedFileSha256sum, &file.SizeBytes, &file.UploadDate,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// GetFileByStorageID retrieves a file record by storage_id
func GetFileByStorageID(db *sql.DB, storageID string) (*File, error) {
	file := &File{}
	err := db.QueryRow(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   encrypted_file_sha256sum, size_bytes, upload_date 
		FROM file_metadata WHERE storage_id = ?`,
		storageID,
	).Scan(
		&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
		&file.PasswordHint, &file.PasswordType,
		&file.FilenameNonce, &file.EncryptedFilename,
		&file.Sha256sumNonce, &file.EncryptedSha256sum,
		&file.EncryptedFileSha256sum, &file.SizeBytes, &file.UploadDate,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// GetFilesByOwner retrieves all files owned by a specific user
func GetFilesByOwner(db *sql.DB, ownerUsername string) ([]*File, error) {
	rows, err := db.Query(`
		SELECT id, file_id, storage_id, owner_username, password_hint, password_type,
			   filename_nonce, encrypted_filename, sha256sum_nonce, encrypted_sha256sum, 
			   encrypted_file_sha256sum, size_bytes, upload_date 
		FROM file_metadata WHERE owner_username = ? ORDER BY upload_date DESC`,
		ownerUsername,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		file := &File{}
		err := rows.Scan(
			&file.ID, &file.FileID, &file.StorageID, &file.OwnerUsername,
			&file.PasswordHint, &file.PasswordType,
			&file.FilenameNonce, &file.EncryptedFilename,
			&file.Sha256sumNonce, &file.EncryptedSha256sum,
			&file.EncryptedFileSha256sum, &file.SizeBytes, &file.UploadDate,
		)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

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
