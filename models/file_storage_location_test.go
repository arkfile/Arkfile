package models

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInsertFileStorageLocation(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`INSERT INTO file_storage_locations`).
		WithArgs("file-1", "provider-1", "stor-1", "active").
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = InsertFileStorageLocation(db, "file-1", "provider-1", "stor-1", "active")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestInsertFileStorageLocation_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`INSERT INTO file_storage_locations`).
		WithArgs("file-1", "provider-1", "stor-1", "pending").
		WillReturnError(assert.AnError)

	err = InsertFileStorageLocation(db, "file-1", "provider-1", "stor-1", "pending")
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetActiveFileStorageLocations(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "file_id", "provider_id", "storage_id", "status", "created_at", "verified_at"}).
		AddRow(int64(1), "file-1", "prov-primary", "stor-1", "active", "2026-01-01 00:00:00", nil).
		AddRow(int64(2), "file-1", "prov-secondary", "stor-1", "active", "2026-01-01 00:00:00", "2026-01-02 00:00:00")

	mock.ExpectQuery(`SELECT id, file_id, provider_id, storage_id, status, created_at, verified_at FROM file_storage_locations WHERE file_id = \? AND status = 'active'`).
		WithArgs("file-1").
		WillReturnRows(rows)

	locations, err := GetActiveFileStorageLocations(db, "file-1")
	assert.NoError(t, err)
	assert.Len(t, locations, 2)
	assert.Equal(t, "prov-primary", locations[0].ProviderID)
	assert.Equal(t, "prov-secondary", locations[1].ProviderID)
	assert.Equal(t, "active", locations[0].Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetActiveFileStorageLocations_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "file_id", "provider_id", "storage_id", "status", "created_at", "verified_at"})
	mock.ExpectQuery(`SELECT id, file_id, provider_id, storage_id, status, created_at, verified_at FROM file_storage_locations WHERE file_id = \? AND status = 'active'`).
		WithArgs("file-no-locs").
		WillReturnRows(rows)

	locations, err := GetActiveFileStorageLocations(db, "file-no-locs")
	assert.NoError(t, err)
	assert.Empty(t, locations)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestUpdateFileStorageLocationStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`UPDATE file_storage_locations`).
		WithArgs("deleted", "file-1", "prov-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = UpdateFileStorageLocationStatus(db, "file-1", "prov-1", "deleted")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBackfillFileStorageLocations(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectExec(`INSERT INTO file_storage_locations`).
		WithArgs("primary-provider").
		WillReturnResult(sqlmock.NewResult(0, 5))

	affected, err := BackfillFileStorageLocations(db, "primary-provider")
	assert.NoError(t, err)
	assert.Equal(t, int64(5), affected)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBackfillFileStorageLocations_Idempotent(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Second call should affect 0 rows (all files already have locations)
	mock.ExpectExec(`INSERT INTO file_storage_locations`).
		WithArgs("primary-provider").
		WillReturnResult(sqlmock.NewResult(0, 0))

	affected, err := BackfillFileStorageLocations(db, "primary-provider")
	assert.NoError(t, err)
	assert.Equal(t, int64(0), affected)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRecalculateProviderStats(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Mock the COUNT/SUM query
	mock.ExpectQuery(`SELECT COUNT\(\*\), COALESCE\(SUM\(fm.padded_size\), 0\)`).
		WithArgs("prov-1").
		WillReturnRows(sqlmock.NewRows([]string{"count", "sum"}).AddRow(int64(10), int64(1048576)))

	// Mock the UpdateStorageProviderStats UPDATE
	mock.ExpectExec(`UPDATE storage_providers`).
		WithArgs(int64(10), int64(1048576), "prov-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = RecalculateProviderStats(db, "prov-1")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetFileStorageLocations(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "file_id", "provider_id", "storage_id", "status", "created_at", "verified_at"}).
		AddRow(int64(1), "file-1", "prov-1", "stor-1", "active", "2026-01-01", nil).
		AddRow(int64(2), "file-1", "prov-2", "stor-1", "failed", "2026-01-01", nil)

	mock.ExpectQuery(`SELECT id, file_id, provider_id, storage_id, status, created_at, verified_at FROM file_storage_locations WHERE file_id = \?`).
		WithArgs("file-1").
		WillReturnRows(rows)

	locations, err := GetFileStorageLocations(db, "file-1")
	assert.NoError(t, err)
	assert.Len(t, locations, 2)
	// GetFileStorageLocations returns ALL statuses, not just active
	assert.Equal(t, "active", locations[0].Status)
	assert.Equal(t, "failed", locations[1].Status)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCountFilesByProvider(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM file_storage_locations`).
		WithArgs("prov-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(42)))

	count, err := CountFilesByProvider(db, "prov-1")
	assert.NoError(t, err)
	assert.Equal(t, int64(42), count)
	assert.NoError(t, mock.ExpectationsWereMet())
}
