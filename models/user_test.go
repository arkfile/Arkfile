package models

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3" // Import SQLite driver
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// setupTestDB_User creates an in-memory SQLite DB for user model tests.
func setupTestDB_User(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err, "Failed to open in-memory SQLite DB for user tests")

	// Define users table schema - ensure it matches your actual schema
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
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
			user, err := CreateUser(db, tc.email, tc.password)

			assert.NoError(t, err, "Did not expect an error for "+tc.name)
			require.NotNil(t, user, "User object should not be nil for "+tc.name)

			// Assert User Properties
			assert.Equal(t, tc.email, user.Email, "Email should match")
			assert.Equal(t, DefaultStorageLimit, user.StorageLimit, "Storage limit should be default")
			assert.Equal(t, tc.expectAdmin, user.IsAdmin, "Admin status mismatch")
			assert.Equal(t, tc.expectApproved, user.IsApproved, "Approved status mismatch")
			assert.NotZero(t, user.ID, "User ID should be populated") // Check if ID is generated

			// Assert Password Hashing in DB
			var dbPasswordHash string
			err = db.QueryRow("SELECT password FROM users WHERE email = ?", tc.email).Scan(&dbPasswordHash)
			assert.NoError(t, err, "Failed to retrieve password hash from DB")
			// Verify the stored hash corresponds to the provided password
			err = bcrypt.CompareHashAndPassword([]byte(dbPasswordHash), []byte(tc.password))
			assert.NoError(t, err, "Stored password hash should match the provided password")
		})
	}

	// Test Duplicate Email specifically
	t.Run("Duplicate Email", func(t *testing.T) {
		// First creation should succeed
		_, err := CreateUser(db, "duplicate@example.com", "PasswordOne!Valid14") // Use valid password
		require.NoError(t, err)

		// Second creation with the same email should fail
		_, err = CreateUser(db, "duplicate@example.com", "PasswordTwo?AlsoValid14") // Use different valid password
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
	password := "PasswordToFind1!abc" // Make password valid complex
	createdUser, err := CreateUser(db, email, password)
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
	assert.Equal(t, createdUser.StorageLimit, retrievedUser.StorageLimit)
	assert.Equal(t, createdUser.IsAdmin, retrievedUser.IsAdmin)
	assert.Equal(t, createdUser.IsApproved, retrievedUser.IsApproved) // Initially false unless admin
	// Check nullable fields for initial non-approved user
	assert.False(t, retrievedUser.ApprovedBy.Valid, "ApprovedBy should initially be invalid/NULL")
	assert.False(t, retrievedUser.ApprovedAt.Valid, "ApprovedAt should initially be invalid/NULL")

	// Compare password hash directly from DB as the struct field might be empty or different
	assert.NotEmpty(t, retrievedUser.Password, "Password hash should be populated in retrieved user")
	err = bcrypt.CompareHashAndPassword([]byte(retrievedUser.Password), []byte(password))
	assert.NoError(t, err, "Retrieved password hash should match original password")

	// Test getting a non-existent user
	_, err = GetUserByEmail(db, "nosuchuser@example.com")
	assert.Error(t, err, "Should return an error for non-existent user")
	// Check specific error type if possible, otherwise message content
	if err != nil { // Avoid panicking if err is nil
		assert.Contains(t, err.Error(), "user not found", "Error message should indicate user not found")
	}
}

func TestVerifyPassword(t *testing.T) {
	// No DB needed, just need a User struct with a valid password hash
	password := "CorrectPassword123?"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &User{Password: string(hashedPassword)}

	// Assert: Correct password should verify
	assert.True(t, user.VerifyPassword(password), "Correct password should verify successfully")

	// Assert: Incorrect password should fail verification
	assert.False(t, user.VerifyPassword("WrongPassword!"), "Incorrect password should fail verification")
}

func TestUpdatePassword(t *testing.T) {
	db := setupTestDB_User(t)
	defer db.Close()

	// Create user
	email := "updatepass@example.com"
	initialPassword := "InitialPass1!def" // Make password valid complex
	user, err := CreateUser(db, email, initialPassword)
	require.NoError(t, err)

	newPassword := "NewSecurePass?789xyz" // Make new password valid complex

	// Execute UpdatePassword
	err = user.UpdatePassword(db, newPassword)
	assert.NoError(t, err, "Updating password should not produce an error")

	// Refresh user data from DB to ensure password hash is correct for further checks if needed
	// Although not strictly necessary for *this* test's assertions, it's good practice
	refreshedUser, err := GetUserByEmail(db, user.Email)
	require.NoError(t, err, "Failed to refresh user after password update")
	user = refreshedUser // Update the user variable

	// Assert: Verify the new password in the database
	var updatedHash string
	err = db.QueryRow("SELECT password FROM users WHERE id = ?", user.ID).Scan(&updatedHash)
	assert.NoError(t, err, "Failed to retrieve updated password hash from DB")

	// Check if the new hash matches the new password
	err = bcrypt.CompareHashAndPassword([]byte(updatedHash), []byte(newPassword))
	assert.NoError(t, err, "New password hash in DB should match the new password")

	// Check if the new hash DOES NOT match the old password
	err = bcrypt.CompareHashAndPassword([]byte(updatedHash), []byte(initialPassword))
	assert.Error(t, err, "New password hash should NOT match the old password")
}

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
	userToApprove, err := CreateUser(db, "pending@example.com", "PendingPass1!uvw") // Make password valid complex
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
		TotalStorage: 5 * 1024 * 1024,  // 5 MB used
		StorageLimit: 10 * 1024 * 1024, // 10 MB limit
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
	user, err := CreateUser(db, "storage@example.com", "StoragePass1!")
	require.NoError(t, err)
	initialStorage := int64(1024 * 1024) // 1MB initial
	_, err = db.Exec("UPDATE users SET total_storage_bytes = ? WHERE id = ?", initialStorage, user.ID)
	require.NoError(t, err)
	user.TotalStorage = initialStorage // Update struct to match

	// Begin transaction for testing
	tx, err := db.Begin()
	require.NoError(t, err, "Failed to begin transaction")

	// Test adding storage
	addBytes := int64(2 * 1024 * 1024) // Add 2MB
	err = user.UpdateStorageUsage(tx, addBytes)
	assert.NoError(t, err, "Adding storage should succeed")
	assert.Equal(t, initialStorage+addBytes, user.TotalStorage, "User struct total storage should be updated after adding")

	// Test subtracting storage
	subtractBytes := int64(-1 * 1024 * 1024) // Subtract 1MB
	err = user.UpdateStorageUsage(tx, subtractBytes)
	assert.NoError(t, err, "Subtracting storage should succeed")
	assert.Equal(t, initialStorage+addBytes+subtractBytes, user.TotalStorage, "User struct total storage should be updated after subtracting")

	// Test subtracting more than available (should result in 0)
	subtractTooMuch := int64(-5 * 1024 * 1024) // Subtract 5MB (more than current 2MB)
	err = user.UpdateStorageUsage(tx, subtractTooMuch)
	assert.NoError(t, err, "Subtracting too much storage should succeed")
	assert.Equal(t, int64(0), user.TotalStorage, "User struct total storage should be 0 after subtracting too much")

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

	// Create users: 2 pending, 1 approved, 1 admin (auto-approved) - Use valid passwords
	_, err := CreateUser(db, "pending1@example.com", "Pass1!MoreCharsNeeded")
	require.NoError(t, err)
	_, err = CreateUser(db, "pending2@example.com", "Pass2!AlsoMoreChars")
	require.NoError(t, err)
	approvedUser, err := CreateUser(db, "approved@example.com", "Pass3!ComplexEnough")
	require.NoError(t, err)
	// Manually approve this one
	_, err = db.Exec("UPDATE users SET is_approved = TRUE WHERE email = ?", approvedUser.Email)
	require.NoError(t, err)
	// Admin email uses different password
	_, err = CreateUser(db, "admin@pending.com", "Pass4!AdminIsComplex") // Should be auto-approved
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

// Note: Tests for database operations within handlers (like Login, Register)
// would typically go in handler tests (e.g., handlers/auth_test.go or handlers/handlers_test.go)
// and would mock the database calls or use a test database setup similar to here.
