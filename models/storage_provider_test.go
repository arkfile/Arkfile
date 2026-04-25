package models

import (
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpsertStorageProvider_Insert(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// SELECT role returns no rows (new provider)
	mock.ExpectQuery(`SELECT role FROM storage_providers WHERE provider_id = \?`).
		WithArgs("new-provider").
		WillReturnError(sql.ErrNoRows)

	// INSERT new provider
	mock.ExpectExec(`INSERT INTO storage_providers`).
		WithArgs("new-provider", "s3", "my-bucket", "https://s3.example.com", "us-east-1", "primary", "S3_PRIMARY", true).
		WillReturnResult(sqlmock.NewResult(1, 1))

	p := &StorageProviderRecord{
		ProviderID:   "new-provider",
		ProviderType: "s3",
		BucketName:   "my-bucket",
		Endpoint:     "https://s3.example.com",
		Region:       "us-east-1",
		Role:         "primary",
		EnvVarPrefix: "S3_PRIMARY",
		IsActive:     true,
	}
	err = UpsertStorageProvider(db, p)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpsertStorageProvider_Update(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// SELECT role returns existing role (provider exists)
	mock.ExpectQuery(`SELECT role FROM storage_providers WHERE provider_id = \?`).
		WithArgs("existing-provider").
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("primary"))

	// UPDATE metadata (preserves existing role)
	mock.ExpectExec(`UPDATE storage_providers`).
		WithArgs("s3", "updated-bucket", "https://new-endpoint.com", "eu-west-1", "S3_UPDATED", true, "existing-provider").
		WillReturnResult(sqlmock.NewResult(0, 1))

	p := &StorageProviderRecord{
		ProviderID:   "existing-provider",
		ProviderType: "s3",
		BucketName:   "updated-bucket",
		Endpoint:     "https://new-endpoint.com",
		Region:       "eu-west-1",
		Role:         "secondary", // This should be ignored for existing provider
		EnvVarPrefix: "S3_UPDATED",
		IsActive:     true,
	}
	err = UpsertStorageProvider(db, p)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetStorageProviderByID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{
		"provider_id", "provider_type", "bucket_name", "endpoint", "region", "role", "env_var_prefix",
		"is_active", "total_objects", "total_size_bytes", "cost_per_tb_cents", "last_verified_at",
		"created_at", "updated_at",
	}).AddRow(
		"prov-1", "seaweedfs", "arkfile", "http://localhost:8333", "", "primary", "SEAWEEDFS",
		true, int64(100), int64(1048576), nil, nil,
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
	)

	mock.ExpectQuery(`SELECT provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix`).
		WithArgs("prov-1").
		WillReturnRows(rows)

	p, err := GetStorageProviderByID(db, "prov-1")
	assert.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "prov-1", p.ProviderID)
	assert.Equal(t, "seaweedfs", p.ProviderType)
	assert.Equal(t, "primary", p.Role)
	assert.Equal(t, int64(100), p.TotalObjects)
	assert.Equal(t, int64(1048576), p.TotalSizeBytes)
	assert.True(t, p.IsActive)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetStorageProviderByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT provider_id, provider_type, bucket_name, endpoint, region, role, env_var_prefix`).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	p, err := GetStorageProviderByID(db, "nonexistent")
	assert.Error(t, err)
	assert.Nil(t, p)
	assert.Equal(t, sql.ErrNoRows, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetStorageProviderRole(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT role FROM storage_providers WHERE provider_id = \?`).
		WithArgs("prov-1").
		WillReturnRows(sqlmock.NewRows([]string{"role"}).AddRow("secondary"))

	role, err := GetStorageProviderRole(db, "prov-1")
	assert.NoError(t, err)
	assert.Equal(t, "secondary", role)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetStorageProviderRole_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT role FROM storage_providers WHERE provider_id = \?`).
		WithArgs("nonexistent").
		WillReturnError(sql.ErrNoRows)

	role, err := GetStorageProviderRole(db, "nonexistent")
	assert.Error(t, err)
	assert.Empty(t, role)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateStorageProviderStats(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE storage_providers`).
		WithArgs(int64(50), int64(5242880), "prov-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpdateStorageProviderStats(db, "prov-1", 50, 5242880)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncrementStorageProviderStats(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE storage_providers`).
		WithArgs(int64(1), int64(1024), "prov-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = IncrementStorageProviderStats(db, "prov-1", 1, 1024)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncrementStorageProviderStats_Decrement(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE storage_providers`).
		WithArgs(int64(-1), int64(-2048), "prov-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = IncrementStorageProviderStats(db, "prov-1", -1, -2048)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
