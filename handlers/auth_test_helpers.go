package handlers

import (
	"io"
	"net/http/httptest"
	"testing"

	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/storage"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/labstack/echo/v4"
)

// setupTestEnv creates a test environment with Echo context, response recorder, mock DB, and mock storage
func setupTestEnv(t *testing.T, method, path string, body io.Reader) (echo.Context, *httptest.ResponseRecorder, sqlmock.Sqlmock, *storage.MockObjectStorageProvider) {
	// Initialize loggers for testing
	logging.InitFallbackConsoleLogging()

	e := echo.New()
	req := httptest.NewRequest(method, path, body)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}

	// Replace global DB with mock
	originalDB := database.DB
	database.DB = db

	t.Cleanup(func() {
		database.DB = originalDB
		db.Close()
	})

	// Create mock storage and registry
	mockStorage := &storage.MockObjectStorageProvider{}

	// Replace global storage registry with mock
	originalRegistry := storage.Registry
	storage.Registry = storage.NewProviderRegistry(mockStorage, "mock-test")

	t.Cleanup(func() {
		storage.Registry = originalRegistry
	})

	return c, rec, mock, mockStorage
}

// NOTE: TestOPAQUEProvider was removed from this file.
// The OPAQUE handlers call auth package functions directly via CGO (no interface).
// To unit-test OPAQUE handlers, an OPAQUEOperations interface would need to be
// introduced in the auth package first. See docs/wip/fix-go-unit-tests2.md
// "Deferred: OPAQUE Handler Unit Tests" section for details.
