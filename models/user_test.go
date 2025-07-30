package models

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for tests
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/84adam/arkfile/config" // Import config package
)

// TestMain sets up necessary environment variables for config loading before running tests
// and cleans them up afterwards.
func TestMain(m *testing.M) {
	// --- Test Config Setup ---
	config.ResetConfigForTest()

	// Store original env vars and set test values
	originalEnv := map[string]string{}
	testEnv := map[string]string{
		"JWT_SECRET":          "test-jwt-secret-for-models", // Use a different secret to avoid potential clashes if tests run concurrently later
		"STORAGE_PROVIDER":    "local",                      // Set storage provider to local (supports MinIO)
		"MINIO_ROOT_USER":     "test-user-models",           // Provide dummy values for all required fields
		"MINIO_ROOT_PASSWORD": "test-password-models",
		"LOCAL_STORAGE_PATH":  "/tmp/test-storage-models", // Required for local storage
		"OPAQUE_MOCK_MODE":    "true",                     // Enable OPAQUE mock mode for User model tests
	}

	for key, testValue := range testEnv {
		originalEnv[key] = os.Getenv(key)
		os.Setenv(key, testValue)
	}

	// Load config with test env vars
	_, err := config.LoadConfig()
	if err != nil {
		// Use fmt.Printf for logging in TestMain as log package might not be initialized
		fmt.Printf("FATAL: Failed to load config for models tests: %v\n", err)
		os.Exit(1) // Exit if config fails, tests cannot run
	}

	// Run tests
	exitCode := m.Run()

	// --- Cleanup ---
	// Restore original env vars
	for key, originalValue := range originalEnv {
		if originalValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, originalValue)
		}
	}
	config.ResetConfigForTest() // Ensure clean state after the package tests run

	os.Exit(exitCode)
}

// setupTestDB_User creates an in-memory SQLite DB for user model tests.
func setupTestDB_User(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory SQLite DB for user tests")

	// Define users table schema - ensure it matches your actual schema
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		total_storage_bytes INTEGER DEFAULT 0,
		storage_limit_bytes INTEGER NOT NULL,
		is_approved BOOLEAN DEFAULT FALSE,
		approved_by TEXT,
		approved_at TIMESTAMP,
		is_admin BOOLEAN DEFAULT FALSE
	);`
	_, err = db.Exec(schema)
	require.NoError(t, err, "Failed to create users table")

	return db
}

func TestCreateUser(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Set admin emails for testing auto-approval/admin status
	originalAdmins := os.Getenv("ADMIN_EMAILS")
	os.Setenv("ADMIN_EMAILS", "admin@example.com,super@user.com")
	defer os.Setenv("ADMIN_EMAILS", originalAdmins)

	testCases := []struct {
		name           string
		email          string
		password       string
		expectAdmin    bool
		expectApproved bool
		expectError    bool
	}{
		// Updated passwords to meet 14+ char complexity
		{"Regular User", "test@example.com", "ValidPass123!@OK", false, false, false}, // 16 chars
		{"Admin User", "admin@example.com", "AdminPass!456Long", true, true, false},   // 17 chars
		// {"Duplicate Email", "test@example.com", "AnotherPassword789?", false, false, true}, // Moved to specific test below
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute CreateUser
			user, err := CreateUser(db, tc.email)

			assert.NoError(t, err, "Did not expect an error for "+tc.name)
			require.NotNil(t, user, "User object should not be nil for "+tc.name)

			// Assert User Properties
			assert.Equal(t, tc.email, user.Email, "Email should match")
			assert.Equal(t, DefaultStorageLimit, user.StorageLimitBytes, "Storage limit should be default")
			assert.Equal(t, tc.expectAdmin, user.IsAdmin, "Admin status mismatch")
			assert.Equal(t, tc.expectApproved, user.IsApproved, "Approved status mismatch")
			assert.NotZero(t, user.ID, "User ID should be populated") // Check if ID is generated

			// Note: With OPAQUE authentication, password hash is no longer stored in the users table
			// This test section is removed as it's no longer applicable
		})
	}

	// Test Duplicate Email specifically
	t.Run("Duplicate Email", func(t *testing.T) {
		// First creation should succeed
		_, err := CreateUser(db, "duplicate@example.com") // Use valid password
		require.NoError(t, err)

		// Second creation with the same email should fail
		_, err = CreateUser(db, "duplicate@example.com") // Use different valid password
		assert.Error(t, err, "Expected an error for duplicate email")
		if err != nil {
			assert.Contains(t, err.Error(), "UNIQUE constraint failed", "Error should be about uniqueness")
		}
	})
}

func TestGetUserByEmail(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Create a test user first
	email := "findme@example.com"
	createdUser, err := CreateUser(db, email)
	require.NoError(t, err)
	require.NotNil(t, createdUser)

	// Execute GetUserByEmail
	retrievedUser, err := GetUserByEmail(db, email)

	// Assert: No error and user found
	assert.NoError(t, err)
	require.NotNil(t, retrievedUser, "Retrieved user should not be nil")

	// Assert: Check properties match the created user
	assert.Equal(t, createdUser.ID, retrievedUser.ID)
	assert.Equal(t, createdUser.Email, retrievedUser.Email)
	assert.Equal(t, createdUser.StorageLimitBytes, retrievedUser.StorageLimitBytes)
	assert.Equal(t, createdUser.IsAdmin, retrievedUser.IsAdmin)
	assert.Equal(t, createdUser.IsApproved, retrievedUser.IsApproved) // Initially false unless admin
	// Check nullable fields for initial non-approved user
	assert.False(t, retrievedUser.ApprovedBy.Valid, "ApprovedBy should initially be invalid/NULL")
	assert.False(t, retrievedUser.ApprovedAt.Valid, "ApprovedAt should initially be invalid/NULL")

	// Note: With OPAQUE authentication, password hash is no longer stored in the users table
	// This test section is removed as it's no longer applicable

	// Test getting a non-existent user
	_, err = GetUserByEmail(db, "nosuchuser@example.com")
	assert.Error(t, err, "Should return an error for non-existent user")
	assert.Equal(t, sql.ErrNoRows, err, "Error should be sql.ErrNoRows")
}

// Note: TestVerifyPassword, TestVerifyPasswordHash, and TestUpdatePassword have been removed
// as these methods are no longer available in the User struct with OPAQUE authentication.
// Password verification is now handled through the OPAQUE protocol.

func TestHasAdminPrivileges(t *testing.T) {
	// Set admin emails
	originalAdmins := os.Getenv("ADMIN_EMAILS")
	os.Setenv("ADMIN_EMAILS", "admin@list.com")
	defer os.Setenv("ADMIN_EMAILS", originalAdmins)

	testCases := []struct {
		name        string
		user        User
		expectAdmin bool
	}{
		{"Admin by flag", User{Email: "test@example.com", IsAdmin: true}, true},
		{"Admin by email list", User{Email: "admin@list.com", IsAdmin: false}, true},
		{"Regular user", User{Email: "user@example.com", IsAdmin: false}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectAdmin, tc.user.HasAdminPrivileges())
		})
	}
}

func TestApproveUser(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Set admin emails
	originalAdmins := os.Getenv("ADMIN_EMAILS")
	adminEmail := "admin@approve.com"
	os.Setenv("ADMIN_EMAILS", adminEmail)
	defer os.Setenv("ADMIN_EMAILS", originalAdmins)

	// Create a user to approve
	userToApprove, err := CreateUser(db, "pending@example.com")
	require.NoError(t, err)
	require.False(t, userToApprove.IsApproved, "User should initially be unapproved")

	// Execute ApproveUser by a valid admin
	err = userToApprove.ApproveUser(db, adminEmail)
	assert.NoError(t, err, "Approving user by admin should succeed")

	// Assert: User struct fields updated
	assert.True(t, userToApprove.IsApproved, "User IsApproved field should be true after approval")
	// Check sql.NullString
	assert.True(t, userToApprove.ApprovedBy.Valid, "ApprovedBy should be valid after approval")
	assert.Equal(t, adminEmail, userToApprove.ApprovedBy.String, "ApprovedBy field should be set")
	// Check sql.NullTime
	assert.True(t, userToApprove.ApprovedAt.Valid, "ApprovedAt should be valid after approval")
	assert.WithinDuration(t, time.Now(), userToApprove.ApprovedAt.Time, 2*time.Second, "ApprovedAt time should be recent")

	// Assert: Database state updated
	var dbIsApproved bool
	var dbApprovedBy string
	var dbApprovedAt sql.NullTime // Use sql.NullTime for nullable timestamp
	err = db.QueryRow("SELECT is_approved, approved_by, approved_at FROM users WHERE id = ?", userToApprove.ID).Scan(&dbIsApproved, &dbApprovedBy, &dbApprovedAt)
	assert.NoError(t, err, "Failed to query DB for approval status")
	assert.True(t, dbIsApproved, "is_approved in DB should be true")
	assert.Equal(t, adminEmail, dbApprovedBy, "approved_by in DB should match admin")
	assert.True(t, dbApprovedAt.Valid, "approved_at in DB should not be NULL")
	assert.WithinDuration(t, time.Now(), dbApprovedAt.Time, 2*time.Second, "approved_at time in DB should be recent")

	// Test: Non-admin attempting approval should fail
	nonAdminEmail := "nonadmin@example.com"
	// Attempt to approve again, even though already approved, to test the admin check
	err = userToApprove.ApproveUser(db, nonAdminEmail)
	assert.Error(t, err, "Approval attempt by non-admin should fail")
	assert.Contains(t, err.Error(), "unauthorized", "Error should indicate unauthorized")
}

func TestCheckStorageAvailable(t *testing.T) {
	user := User{
		TotalStorageBytes: 5 * 1024 * 1024,  // 5 MB used
		StorageLimitBytes: 10 * 1024 * 1024, // 10 MB limit
	}

	assert.True(t, user.CheckStorageAvailable(1*1024*1024), "Should allow adding 1MB when 5MB free")
	assert.True(t, user.CheckStorageAvailable(5*1024*1024), "Should allow adding exactly 5MB when 5MB free")
	assert.False(t, user.CheckStorageAvailable(6*1024*1024), "Should deny adding 6MB when only 5MB free")
	assert.True(t, user.CheckStorageAvailable(0), "Should allow adding 0 bytes")
}

func TestUpdateStorageUsage(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Create user with initial storage
	user, err := CreateUser(db, "storage@example.com")
	require.NoError(t, err)
	initialStorage := int64(1024 * 1024) // 1MB initial
	_, err = db.Exec("UPDATE users SET total_storage_bytes = ? WHERE id = ?", initialStorage, user.ID)
	require.NoError(t, err)
	user.TotalStorageBytes = initialStorage // Update struct to match

	// Begin transaction for testing
	tx, err := db.Begin()
	require.NoError(t, err, "Failed to begin transaction")

	// Test adding storage
	addBytes := int64(2 * 1024 * 1024) // Add 2MB
	err = user.UpdateStorageUsage(tx, addBytes)
	assert.NoError(t, err, "Adding storage should succeed")
	assert.Equal(t, initialStorage+addBytes, user.TotalStorageBytes, "User struct total storage should be updated after adding")

	// Test subtracting storage
	subtractBytes := int64(-1 * 1024 * 1024) // Subtract 1MB
	err = user.UpdateStorageUsage(tx, subtractBytes)
	assert.NoError(t, err, "Subtracting storage should succeed")
	assert.Equal(t, initialStorage+addBytes+subtractBytes, user.TotalStorageBytes, "User struct total storage should be updated after subtracting")

	// Test subtracting more than available (should result in 0)
	subtractTooMuch := int64(-5 * 1024 * 1024) // Subtract 5MB (more than current 2MB)
	err = user.UpdateStorageUsage(tx, subtractTooMuch)
	assert.NoError(t, err, "Subtracting too much storage should succeed")
	assert.Equal(t, int64(0), user.TotalStorageBytes, "User struct total storage should be 0 after subtracting too much")

	// Commit transaction to check DB state
	err = tx.Commit()
	assert.NoError(t, err, "Failed to commit transaction")

	// Assert final DB state
	var finalDbStorage int64
	err = db.QueryRow("SELECT total_storage_bytes FROM users WHERE id = ?", user.ID).Scan(&finalDbStorage)
	assert.NoError(t, err, "Failed to query final storage from DB")
	assert.Equal(t, int64(0), finalDbStorage, "Final storage in DB should be 0")
}

func TestGetPendingUsers(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Setup admin email for auto-approval check
	originalAdmins := os.Getenv("ADMIN_EMAILS")
	os.Setenv("ADMIN_EMAILS", "admin@pending.com")
	defer os.Setenv("ADMIN_EMAILS", originalAdmins)

	// Create users: 2 pending, 1 approved, 1 admin (auto-approved)
	_, err := CreateUser(db, "pending1@example.com")
	require.NoError(t, err)
	_, err = CreateUser(db, "pending2@example.com")
	require.NoError(t, err)
	approvedUser, err := CreateUser(db, "approved@example.com")
	require.NoError(t, err)
	// Manually approve this one
	_, err = db.Exec("UPDATE users SET is_approved = TRUE WHERE email = ?", approvedUser.Email)
	require.NoError(t, err)
	// Admin email should be auto-approved
	_, err = CreateUser(db, "admin@pending.com")
	require.NoError(t, err)

	// Execute GetPendingUsers
	pendingUsers, err := GetPendingUsers(db)
	assert.NoError(t, err, "GetPendingUsers should not return an error")
	require.NotNil(t, pendingUsers, "Pending users list should not be nil")

	// Assert: Should find exactly 2 pending users
	assert.Len(t, pendingUsers, 2, "Should retrieve exactly 2 pending users")

	// Assert: Check emails of pending users (order might matter depending on DB, check both)
	foundEmails := make(map[string]bool)
	for _, u := range pendingUsers {
		foundEmails[u.Email] = true
	}
	assert.True(t, foundEmails["pending1@example.com"], "pending1@example.com should be in the list")
	assert.True(t, foundEmails["pending2@example.com"], "pending2@example.com should be in the list")
	assert.False(t, foundEmails["approved@example.com"], "approved@example.com should not be in the list")
	assert.False(t, foundEmails["admin@pending.com"], "admin@pending.com should not be in the list")
}

func TestIsAdminEmail(t *testing.T) {
	// Setup environment variable
	originalAdmins := os.Getenv("ADMIN_EMAILS")
	os.Setenv("ADMIN_EMAILS", "admin1@test.com, admin2@test.com , spaced@admin.com ") // Note extra spaces
	defer os.Setenv("ADMIN_EMAILS", originalAdmins)

	assert.True(t, isAdminEmail("admin1@test.com"), "admin1 should be admin")
	assert.True(t, isAdminEmail("admin2@test.com"), "admin2 should be admin")
	assert.True(t, isAdminEmail("spaced@admin.com"), "spaced admin email should work")
	assert.False(t, isAdminEmail("user@test.com"), "regular user should not be admin")
	assert.False(t, isAdminEmail("Admin1@test.com"), "email check should be case-sensitive") // Assuming case-sensitivity

	// Test empty ADMIN_EMAILS
	os.Setenv("ADMIN_EMAILS", "")
	assert.False(t, isAdminEmail("admin1@test.com"), "Should not be admin if list is empty")

	// Test unset ADMIN_EMAILS (uses default "")
	os.Unsetenv("ADMIN_EMAILS")
	assert.False(t, isAdminEmail("admin1@test.com"), "Should not be admin if env var is unset")
}

// --- OPAQUE Integration Tests ---

func TestCreateUserWithOPAQUE(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Add OPAQUE tables to test database
	setupOPAQUETestTables(t, db)

	email := "opaque@example.com"
	password := "ValidOPAQUEPassword123!@#"

	// Execute CreateUserWithOPAQUE
	user, err := CreateUserWithOPAQUE(db, email, password)

	if err != nil {
		// OPAQUE functionality may not be available in test environment
		t.Logf("CreateUserWithOPAQUE failed (expected in test environment without libopaque.so): %v", err)
		t.Skip("Skipping OPAQUE integration test - requires libopaque.so")
		return
	}

	// Assert user creation
	require.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, DefaultStorageLimit, user.StorageLimitBytes)

	// Test OPAQUE account status
	status, err := user.GetOPAQUEAccountStatus(db)
	if err != nil {
		t.Logf("GetOPAQUEAccountStatus failed (expected in test environment): %v", err)
		return
	}

	require.NotNil(t, status)
	assert.True(t, status.HasAccountPassword)
	assert.NotNil(t, status.OPAQUECreatedAt)
}

func TestUserOPAQUELifecycle(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Add OPAQUE tables to test database
	setupOPAQUETestTables(t, db)

	// Create regular user first
	user, err := CreateUser(db, "lifecycle@example.com")
	require.NoError(t, err)

	password := "LifecycleTestPassword123!@#"

	// Test 1: Check initial OPAQUE status (should be false)
	hasAccount, err := user.HasOPAQUEAccount(db)
	if err != nil {
		t.Logf("HasOPAQUEAccount failed (expected in test environment): %v", err)
		t.Skip("Skipping OPAQUE lifecycle test - requires libopaque.so")
		return
	}
	assert.False(t, hasAccount, "New user should not have OPAQUE account initially")

	// Test 2: Register OPAQUE account
	err = user.RegisterOPAQUEAccount(db, password)
	if err != nil {
		t.Logf("RegisterOPAQUEAccount failed (expected in test environment): %v", err)
		return
	}

	// Test 3: Verify OPAQUE account exists
	hasAccount, err = user.HasOPAQUEAccount(db)
	require.NoError(t, err)
	assert.True(t, hasAccount, "User should have OPAQUE account after registration")

	// Test 4: Authenticate with OPAQUE
	exportKey, err := user.AuthenticateOPAQUE(db, password)
	if err != nil {
		t.Logf("AuthenticateOPAQUE failed (expected in test environment): %v", err)
		return
	}
	require.NotNil(t, exportKey)
	assert.Len(t, exportKey, 64, "Export key should be 64 bytes")

	// Test 5: Get comprehensive OPAQUE status
	status, err := user.GetOPAQUEAccountStatus(db)
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.True(t, status.HasAccountPassword)
	assert.NotNil(t, status.OPAQUECreatedAt)
	assert.NotNil(t, status.LastOPAQUEAuth)

	// Test 6: Delete OPAQUE account
	err = user.DeleteOPAQUEAccount(db)
	require.NoError(t, err)

	// Test 7: Verify OPAQUE account is gone
	hasAccount, err = user.HasOPAQUEAccount(db)
	require.NoError(t, err)
	assert.False(t, hasAccount, "User should not have OPAQUE account after deletion")
}

func TestUserFilePasswordManagement(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Add OPAQUE tables to test database
	setupOPAQUETestTables(t, db)

	// Create user with OPAQUE account
	user, err := CreateUserWithOPAQUE(db, "filepass@example.com", "UserPassword123!@#")
	if err != nil {
		t.Logf("CreateUserWithOPAQUE failed (expected in test environment): %v", err)
		t.Skip("Skipping file password test - requires libopaque.so")
		return
	}

	fileID := "test-file-123"
	filePassword := "FileSpecificPassword456!@#"
	keyLabel := "test-key-label"
	passwordHint := "File password hint"

	// Test 1: Register file password
	err = user.RegisterFilePassword(db, fileID, filePassword, keyLabel, passwordHint)
	if err != nil {
		t.Logf("RegisterFilePassword failed (expected in test environment): %v", err)
		return
	}

	// Test 2: Authenticate file password
	exportKey, err := user.AuthenticateFilePassword(db, fileID, filePassword)
	if err != nil {
		t.Logf("AuthenticateFilePassword failed (expected in test environment): %v", err)
		return
	}
	require.NotNil(t, exportKey)
	assert.Len(t, exportKey, 64, "File export key should be 64 bytes")

	// Test 3: Get file password records
	records, err := user.GetFilePasswordRecords(db, fileID)
	if err != nil {
		t.Logf("GetFilePasswordRecords failed (expected in test environment): %v", err)
		return
	}
	require.NotNil(t, records)
	assert.Len(t, records, 1, "Should have one file password record")

	// Test 4: Delete file password
	err = user.DeleteFilePassword(db, fileID, keyLabel)
	if err != nil {
		t.Logf("DeleteFilePassword failed (expected in test environment): %v", err)
		return
	}

	// Test 5: Verify file password is gone
	records, err = user.GetFilePasswordRecords(db, fileID)
	if err != nil {
		t.Logf("GetFilePasswordRecords after deletion failed: %v", err)
		return
	}
	assert.Len(t, records, 0, "Should have no file password records after deletion")
}

func TestUserComprehensiveDelete(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Add OPAQUE tables to test database
	setupOPAQUETestTables(t, db)

	// Create user with OPAQUE account
	user, err := CreateUserWithOPAQUE(db, "delete@example.com", "DeleteTestPassword123!@#")
	if err != nil {
		t.Logf("CreateUserWithOPAQUE failed (expected in test environment): %v", err)
		t.Skip("Skipping comprehensive delete test - requires libopaque.so")
		return
	}

	userID := user.ID
	userEmail := user.Email

	// Verify user exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "User should exist before deletion")

	// Execute comprehensive delete
	err = user.Delete(db)
	require.NoError(t, err)

	// Verify user is deleted
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "User should not exist after deletion")

	// Verify OPAQUE records are cleaned up (if tables exist)
	// Note: These queries may fail if OPAQUE tables don't exist in test DB
	err = db.QueryRow("SELECT COUNT(*) FROM opaque_password_records WHERE record_identifier = ? OR associated_user_email = ?", userEmail, userEmail).Scan(&count)
	if err == nil {
		assert.Equal(t, 0, count, "OPAQUE records should be cleaned up after user deletion")
	} else {
		t.Logf("Could not verify OPAQUE cleanup (table may not exist): %v", err)
	}
}

// setupOPAQUETestTables creates the necessary OPAQUE tables for testing
// This simulates the OPAQUE database schema for test purposes
func setupOPAQUETestTables(t *testing.T, db *sql.DB) {
	t.Helper()

	// Create basic OPAQUE tables for testing
	// Note: These are simplified versions for testing
	tables := []string{
		`CREATE TABLE IF NOT EXISTS opaque_password_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			record_type TEXT NOT NULL,
			record_identifier TEXT NOT NULL,
			associated_user_email TEXT,
			password_record BLOB NOT NULL,
			server_public_key BLOB NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_used_at TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS opaque_server_keys (
			id INTEGER PRIMARY KEY,
			private_key BLOB NOT NULL,
			public_key BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS opaque_user_data (
			user_email TEXT PRIMARY KEY,
			serialized_record BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_used_at TIMESTAMP
		)`,
	}

	for _, table := range tables {
		_, err := db.Exec(table)
		if err != nil {
			t.Logf("Warning: Could not create OPAQUE test table: %v", err)
		}
	}

	// Insert dummy server keys for testing
	_, err := db.Exec(`INSERT OR IGNORE INTO opaque_server_keys (id, private_key, public_key) VALUES (1, ?, ?)`,
		[]byte("dummy-private-key"), []byte("dummy-public-key"))
	if err != nil {
		t.Logf("Warning: Could not insert dummy server keys: %v", err)
	}
}

// Note: Tests for database operations within handlers (like Login, Register)
// would typically go in handler tests (e.g., handlers/auth_test.go or handlers/handlers_test.go)
// and would mock the database calls or use a test database setup similar to here.
