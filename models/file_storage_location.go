package models

import (
	"database/sql"
)

// FileStorageLocation represents a row in the file_storage_locations table.
// Tracks which providers hold a copy of each file's encrypted blob.
type FileStorageLocation struct {
	ID         int64          `json:"id"`
	FileID     string         `json:"file_id"`
	ProviderID string         `json:"provider_id"`
	StorageID  string         `json:"storage_id"`
	Status     string         `json:"status"` // "active", "pending", "failed", "deleted", "delete_failed"
	CreatedAt  sql.NullString `json:"created_at"`
	VerifiedAt sql.NullString `json:"verified_at"`
}

// InsertFileStorageLocation creates a new location record for a file on a provider.
func InsertFileStorageLocation(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, fileID, providerID, storageID, status string) error {
	_, err := db.Exec(`
		INSERT INTO file_storage_locations (file_id, provider_id, storage_id, status)
		VALUES (?, ?, ?, ?)`,
		fileID, providerID, storageID, status,
	)
	return err
}

// UpdateFileStorageLocationStatus updates the status of a file location record.
func UpdateFileStorageLocationStatus(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, fileID, providerID, status string) error {
	_, err := db.Exec(`
		UPDATE file_storage_locations
		SET status = ?
		WHERE file_id = ? AND provider_id = ?`,
		status, fileID, providerID,
	)
	return err
}

// GetFileStorageLocations returns all location records for a given file.
func GetFileStorageLocations(db interface {
	Query(string, ...interface{}) (*sql.Rows, error)
}, fileID string) ([]FileStorageLocation, error) {
	rows, err := db.Query(`
		SELECT id, file_id, provider_id, storage_id, status, created_at, verified_at
		FROM file_storage_locations
		WHERE file_id = ?`, fileID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var locations []FileStorageLocation
	for rows.Next() {
		var loc FileStorageLocation
		if err := rows.Scan(&loc.ID, &loc.FileID, &loc.ProviderID, &loc.StorageID, &loc.Status, &loc.CreatedAt, &loc.VerifiedAt); err != nil {
			return nil, err
		}
		locations = append(locations, loc)
	}
	return locations, rows.Err()
}

// GetActiveFileStorageLocations returns only active location records for a file.
func GetActiveFileStorageLocations(db interface {
	Query(string, ...interface{}) (*sql.Rows, error)
}, fileID string) ([]FileStorageLocation, error) {
	rows, err := db.Query(`
		SELECT id, file_id, provider_id, storage_id, status, created_at, verified_at
		FROM file_storage_locations
		WHERE file_id = ? AND status = 'active'`, fileID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var locations []FileStorageLocation
	for rows.Next() {
		var loc FileStorageLocation
		if err := rows.Scan(&loc.ID, &loc.FileID, &loc.ProviderID, &loc.StorageID, &loc.Status, &loc.CreatedAt, &loc.VerifiedAt); err != nil {
			return nil, err
		}
		locations = append(locations, loc)
	}
	return locations, rows.Err()
}

// CountFilesByProvider returns the count of active files on a given provider.
func CountFilesByProvider(db interface {
	QueryRow(string, ...interface{}) *sql.Row
}, providerID string) (int64, error) {
	var count int64
	err := db.QueryRow(`
		SELECT COUNT(*) FROM file_storage_locations
		WHERE provider_id = ? AND status = 'active'`, providerID,
	).Scan(&count)
	return count, err
}

// BackfillFileStorageLocations populates location records for files that don't have one yet.
// This is used on startup to ensure every existing file has at least one location record
// pointing to the current primary provider. Idempotent: skips files that already have locations.
func BackfillFileStorageLocations(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, primaryProviderID string) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO file_storage_locations (file_id, provider_id, storage_id, status, created_at)
		SELECT file_id, ?, storage_id, 'active', upload_date
		FROM file_metadata
		WHERE file_id NOT IN (SELECT file_id FROM file_storage_locations)`,
		primaryProviderID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// RecalculateProviderStats recalculates total_objects and total_size_bytes for a provider
// from the file_storage_locations and file_metadata tables.
func RecalculateProviderStats(db interface {
	QueryRow(string, ...interface{}) *sql.Row
	Exec(string, ...interface{}) (sql.Result, error)
}, providerID string) error {
	// Scan as interface{} because rqlite returns COUNT/SUM as float64
	var totalObjectsRaw, totalSizeBytesRaw interface{}

	err := db.QueryRow(`
		SELECT COUNT(*), COALESCE(SUM(fm.padded_size), 0)
		FROM file_storage_locations fsl
		JOIN file_metadata fm ON fsl.file_id = fm.file_id
		WHERE fsl.provider_id = ? AND fsl.status = 'active'`,
		providerID,
	).Scan(&totalObjectsRaw, &totalSizeBytesRaw)
	if err != nil {
		return err
	}

	totalObjects := toInt64Raw(totalObjectsRaw)
	totalSizeBytes := toInt64Raw(totalSizeBytesRaw)

	return UpdateStorageProviderStats(db, providerID, totalObjects, totalSizeBytes)
}

// toInt64Raw converts rqlite numeric types (float64, int64) to int64.
func toInt64Raw(v interface{}) int64 {
	switch val := v.(type) {
	case int64:
		return val
	case float64:
		return int64(val)
	case nil:
		return 0
	default:
		return 0
	}
}
