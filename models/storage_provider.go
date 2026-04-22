package models

import (
	"database/sql"
	"time"
)

// StorageProviderRecord represents a row in the storage_providers table.
type StorageProviderRecord struct {
	ProviderID     string         `json:"provider_id"`
	ProviderType   string         `json:"provider_type"`
	BucketName     string         `json:"bucket_name"`
	Endpoint       string         `json:"endpoint"`
	Region         string         `json:"region"`
	Role           string         `json:"role"`
	EnvVarPrefix   string         `json:"env_var_prefix"`
	IsActive       bool           `json:"is_active"`
	TotalObjects   int64          `json:"total_objects"`
	TotalSizeBytes int64          `json:"total_size_bytes"`
	CostPerTBCents sql.NullInt64  `json:"cost_per_tb_cents"`
	LastVerifiedAt sql.NullString `json:"last_verified_at"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// UpsertStorageProvider inserts or updates a storage provider record.
// On conflict (provider_id already exists), updates metadata fields but preserves
// the existing role assignment (DB is authoritative for roles after first startup).
func UpsertStorageProvider(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
	QueryRow(string, ...interface{}) *sql.Row
}, p *StorageProviderRecord) error {
	// Check if a record already exists
	var existingRole string
	err := db.QueryRow("SELECT role FROM storage_providers WHERE provider_id = ?", p.ProviderID).Scan(&existingRole)

	if err == sql.ErrNoRows {
		// New provider: insert with the specified role
		_, err = db.Exec(`
			INSERT INTO storage_providers (provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix, is_active)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			p.ProviderID, p.ProviderType, p.BucketName, p.Endpoint, p.Region, p.Role, p.EnvVarPrefix, p.IsActive,
		)
		return err
	} else if err != nil {
		return err
	}

	// Existing provider: update metadata but preserve DB-authoritative role
	_, err = db.Exec(`
		UPDATE storage_providers
		SET provider_type = ?, bucket_name = ?, endpoint = ?, region = ?, env_var_prefix = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP
		WHERE provider_id = ?`,
		p.ProviderType, p.BucketName, p.Endpoint, p.Region, p.EnvVarPrefix, p.IsActive, p.ProviderID,
	)
	return err
}

// GetStorageProviderByID retrieves a storage provider by its ID.
func GetStorageProviderByID(db interface {
	QueryRow(string, ...interface{}) *sql.Row
}, providerID string) (*StorageProviderRecord, error) {
	p := &StorageProviderRecord{}
	err := db.QueryRow(`
		SELECT provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix,
		       is_active, total_objects, total_size_bytes, cost_per_tb_cents, last_verified_at,
		       created_at, updated_at
		FROM storage_providers WHERE provider_id = ?`, providerID,
	).Scan(
		&p.ProviderID, &p.ProviderType, &p.BucketName, &p.Endpoint, &p.Region, &p.Role, &p.EnvVarPrefix,
		&p.IsActive, &p.TotalObjects, &p.TotalSizeBytes, &p.CostPerTBCents, &p.LastVerifiedAt,
		&p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetStorageProviderRole returns the role of a provider from the DB.
// Returns "" and sql.ErrNoRows if not found.
func GetStorageProviderRole(db interface {
	QueryRow(string, ...interface{}) *sql.Row
}, providerID string) (string, error) {
	var role string
	err := db.QueryRow("SELECT role FROM storage_providers WHERE provider_id = ?", providerID).Scan(&role)
	return role, err
}

// UpdateStorageProviderStats updates the cached object count and size for a provider.
func UpdateStorageProviderStats(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, providerID string, totalObjects int64, totalSizeBytes int64) error {
	_, err := db.Exec(`
		UPDATE storage_providers
		SET total_objects = ?, total_size_bytes = ?, updated_at = CURRENT_TIMESTAMP
		WHERE provider_id = ?`,
		totalObjects, totalSizeBytes, providerID,
	)
	return err
}

// IncrementStorageProviderStats adds to the cached object count and size for a provider.
func IncrementStorageProviderStats(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, providerID string, objectsDelta int64, sizeBytesDelta int64) error {
	_, err := db.Exec(`
		UPDATE storage_providers
		SET total_objects = total_objects + ?, total_size_bytes = total_size_bytes + ?, updated_at = CURRENT_TIMESTAMP
		WHERE provider_id = ?`,
		objectsDelta, sizeBytesDelta, providerID,
	)
	return err
}
