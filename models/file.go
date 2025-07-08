package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

type File struct {
	ID           int64     `json:"id"`
	Filename     string    `json:"filename"`
	StorageID    string    `json:"storage_id"` // UUID v4 for storage backend
	OwnerEmail   string    `json:"owner_email"`
	PasswordHint string    `json:"password_hint,omitempty"`
	SizeBytes    int64     `json:"size_bytes"`  // Original file size
	PaddedSize   int64     `json:"padded_size"` // Size after padding
	UploadDate   time.Time `json:"upload_date"`
}

// GenerateStorageID creates a new UUID v4 for storage
func GenerateStorageID() string {
	return uuid.New().String()
}

// CreateFile creates a new file record in the database
func CreateFile(db *sql.DB, filename, ownerEmail, passwordHint string) (*File, error) {
	result, err := db.Exec(
		"INSERT INTO file_metadata (filename, owner_email, password_hint) VALUES (?, ?, ?)",
		filename, ownerEmail, passwordHint,
	)
	if err != nil {
		return nil, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, err
	}

	return &File{
		ID:           id,
		Filename:     filename,
		OwnerEmail:   ownerEmail,
		PasswordHint: passwordHint,
		UploadDate:   time.Now(),
	}, nil
}

// GetFileByFilename retrieves a file record by filename
func GetFileByFilename(db *sql.DB, filename string) (*File, error) {
	file := &File{}
	err := db.QueryRow(
		"SELECT id, filename, owner_email, password_hint, upload_date FROM file_metadata WHERE filename = ?",
		filename,
	).Scan(&file.ID, &file.Filename, &file.OwnerEmail, &file.PasswordHint, &file.UploadDate)

	if err == sql.ErrNoRows {
		return nil, errors.New("file not found")
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// GetFilesByOwner retrieves all files owned by a specific user
func GetFilesByOwner(db *sql.DB, ownerEmail string) ([]*File, error) {
	rows, err := db.Query(
		"SELECT id, filename, owner_email, password_hint, upload_date FROM file_metadata WHERE owner_email = ? ORDER BY upload_date DESC",
		ownerEmail,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		file := &File{}
		err := rows.Scan(&file.ID, &file.Filename, &file.OwnerEmail, &file.PasswordHint, &file.UploadDate)
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

// DeleteFile removes a file record from the database
func DeleteFile(db *sql.DB, filename string, ownerEmail string) error {
	result, err := db.Exec(
		"DELETE FROM file_metadata WHERE filename = ? AND owner_email = ?",
		filename, ownerEmail,
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
