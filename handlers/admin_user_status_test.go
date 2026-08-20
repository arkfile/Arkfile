package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/crypto"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	jwt "github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupAdminUserStatusDB(t *testing.T) *sql.DB {
	t.Helper()
	logging.InitFallbackConsoleLogging()
	crypto.SetUserSecretMasterForTest(make([]byte, 32))

	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			username_folded TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			total_storage_bytes INTEGER DEFAULT 0,
			storage_limit_bytes INTEGER NOT NULL,
			is_approved BOOLEAN DEFAULT FALSE,
			approved_by TEXT,
			approved_at TIMESTAMP,
			is_admin BOOLEAN DEFAULT FALSE,
			deleted_at TIMESTAMP,
			last_login TIMESTAMP
		);
		CREATE TABLE user_mfa_credentials (
			credential_id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			method_type TEXT NOT NULL DEFAULT 'totp',
			credential_data BLOB NOT NULL,
			enabled BOOLEAN DEFAULT FALSE,
			setup_completed BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_used DATETIME,
			UNIQUE (username, method_type)
		);
		CREATE TABLE user_mfa_backup_codes (
			username TEXT NOT NULL,
			code_index INTEGER NOT NULL,
			code_hash BLOB NOT NULL,
			used_at TIMESTAMP,
			PRIMARY KEY (username, code_index),
			UNIQUE (username, code_hash)
		);
		CREATE TABLE file_metadata (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_id TEXT UNIQUE NOT NULL,
			storage_id TEXT UNIQUE NOT NULL,
			owner_username TEXT NOT NULL,
			password_type TEXT NOT NULL DEFAULT 'account',
			filename_nonce TEXT NOT NULL DEFAULT '',
			encrypted_filename TEXT NOT NULL DEFAULT '',
			sha256sum_nonce TEXT NOT NULL DEFAULT '',
			encrypted_sha256sum TEXT NOT NULL DEFAULT '',
			encrypted_fek TEXT NOT NULL DEFAULT '',
			size_bytes INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE opaque_user_data (
			username TEXT PRIMARY KEY,
			opaque_user_record BLOB NOT NULL
		);
		CREATE TABLE refresh_tokens (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			revoked BOOLEAN DEFAULT FALSE
		);
		CREATE TABLE revoked_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			token_id TEXT NOT NULL UNIQUE,
			username TEXT NOT NULL,
			revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			reason TEXT
		);
		CREATE TABLE admin_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			admin_username TEXT NOT NULL,
			action TEXT NOT NULL,
			target_username TEXT,
			details TEXT,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`
	_, err = db.Exec(schema)
	require.NoError(t, err)

	original := database.DB
	database.DB = db
	t.Cleanup(func() {
		database.DB = original
		db.Close()
	})
	return db
}

func insertAdminStatusUser(t *testing.T, db *sql.DB, username string, isAdmin, isApproved bool, used, limit int64, registered string) {
	t.Helper()
	adminFlag := 0
	if isAdmin {
		adminFlag = 1
	}
	approvedFlag := 0
	if isApproved {
		approvedFlag = 1
	}
	_, err := db.Exec(`INSERT INTO users (
		username, username_folded, created_at, registration_date,
		total_storage_bytes, storage_limit_bytes, is_approved, is_admin
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		username, username, registered, registered, used, limit, approvedFlag, adminFlag)
	require.NoError(t, err)
}

func seedCompletedTOTP(t *testing.T, username string) {
	t.Helper()
	setup, err := auth.GenerateMFASetup(username)
	require.NoError(t, err)
	require.NoError(t, auth.StoreMFASetup(database.DB, username, setup))
	code, err := totp.GenerateCode(setup.Secret, time.Now().UTC())
	require.NoError(t, err)
	require.NoError(t, auth.CompleteMFASetup(database.DB, username, code))
}

func seedCompletedWebAuthnRow(t *testing.T, db *sql.DB, username, credID string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO user_mfa_credentials (
		credential_id, username, method_type, credential_data, enabled, setup_completed
	) VALUES (?, ?, 'webauthn', ?, 1, 1)`, credID, username, []byte{0x00})
	require.NoError(t, err)
}

func seedListUsersMFAFixture(t *testing.T, db *sql.DB) string {
	t.Helper()
	const adminUsername = "list-admin"
	insertAdminStatusUser(t, db, adminUsername, true, true, 0, models.DefaultStorageLimit, "2026-04-16 12:00:00")
	insertAdminStatusUser(t, db, "totp-user", false, true, 0, models.DefaultStorageLimit, "2026-04-17 12:00:00")
	insertAdminStatusUser(t, db, "hw-user", false, true, 0, models.DefaultStorageLimit, "2026-04-18 12:00:00")
	insertAdminStatusUser(t, db, "both-user", false, true, 47710208, models.DefaultStorageLimit, "2026-04-19 12:00:00")
	insertAdminStatusUser(t, db, "pending-user", false, false, 0, models.DefaultStorageLimit, "2026-04-20 12:00:00")
	insertAdminStatusUser(t, db, "incomplete-user", false, true, 0, models.DefaultStorageLimit, "2026-04-21 12:00:00")

	seedCompletedTOTP(t, "totp-user")
	seedCompletedWebAuthnRow(t, db, "hw-user", "hw-cred")
	seedCompletedTOTP(t, "both-user")
	seedCompletedWebAuthnRow(t, db, "both-user", "both-hw")
	_, err := db.Exec(`INSERT INTO user_mfa_credentials (
		credential_id, username, method_type, credential_data, enabled, setup_completed
	) VALUES ('pending-totp', 'incomplete-user', 'totp', ?, 0, 0)`, []byte{0x01})
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO file_metadata (file_id, storage_id, owner_username) VALUES ('file-1', 'store-1', 'both-user')`)
	require.NoError(t, err)
	return adminUsername
}

func listUsersNames(t *testing.T, db *sql.DB, adminUsername, rawQuery string) []string {
	t.Helper()
	path := "/admin/users"
	if rawQuery != "" {
		path += "?" + rawQuery
	}
	c, rec, _, _ := setupTestEnv(t, http.MethodGet, path, nil)
	database.DB = db
	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)
	require.NoError(t, ListUsers(c))
	require.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	usersList, ok := data["users"].([]interface{})
	require.True(t, ok)
	names := make([]string, 0, len(usersList))
	for _, item := range usersList {
		row, ok := item.(map[string]interface{})
		require.True(t, ok)
		name, _ := row["username"].(string)
		names = append(names, name)
	}
	return names
}

func TestListUsers_MFAAggregationNoDuplicateRows(t *testing.T) {
	db := setupAdminUserStatusDB(t)
	adminUsername := seedListUsersMFAFixture(t, db)

	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/admin/users", nil)
	database.DB = db
	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	require.NoError(t, ListUsers(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok)
	usersList, ok := data["users"].([]interface{})
	require.True(t, ok)
	assert.Len(t, usersList, 6)

	byName := map[string]map[string]interface{}{}
	for _, item := range usersList {
		row, ok := item.(map[string]interface{})
		require.True(t, ok)
		name, _ := row["username"].(string)
		_, exists := byName[name]
		assert.False(t, exists, "duplicate list row for %s", name)
		byName[name] = row
	}

	assert.Equal(t, true, byName["totp-user"]["mfa_enabled"])
	assert.Equal(t, []interface{}{"totp"}, byName["totp-user"]["mfa_methods"])
	assert.Equal(t, true, byName["hw-user"]["mfa_enabled"])
	assert.Equal(t, []interface{}{"webauthn"}, byName["hw-user"]["mfa_methods"])
	assert.Equal(t, true, byName["both-user"]["mfa_enabled"])
	assert.Equal(t, []interface{}{"totp", "webauthn"}, byName["both-user"]["mfa_methods"])
	assert.Equal(t, float64(1), byName["both-user"]["file_count"])
	assert.Equal(t, false, byName["pending-user"]["mfa_enabled"])
	assert.Equal(t, []interface{}{}, byName["pending-user"]["mfa_methods"])
	assert.Equal(t, false, byName["incomplete-user"]["mfa_enabled"])
	assert.Equal(t, []interface{}{}, byName["incomplete-user"]["mfa_methods"])
}

func TestListUsers_MFAAndMinFilesFilters(t *testing.T) {
	db := setupAdminUserStatusDB(t)
	adminUsername := seedListUsersMFAFixture(t, db)

	mfaYes := listUsersNames(t, db, adminUsername, "mfa=true")
	assert.ElementsMatch(t, []string{"totp-user", "hw-user", "both-user"}, mfaYes)

	mfaNo := listUsersNames(t, db, adminUsername, "mfa=false")
	assert.ElementsMatch(t, []string{"list-admin", "pending-user", "incomplete-user"}, mfaNo)

	minFiles := listUsersNames(t, db, adminUsername, "min_files=1")
	assert.Equal(t, []string{"both-user"}, minFiles)

	combined := listUsersNames(t, db, adminUsername, "mfa=true&min_files=1")
	assert.Equal(t, []string{"both-user"}, combined)

	empty := listUsersNames(t, db, adminUsername, "min_files=2")
	assert.Empty(t, empty)
}

func TestListUsers_InvalidFilters(t *testing.T) {
	adminUsername := "admin-user"
	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/admin/users?mfa=maybe", nil)
	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)
	require.NoError(t, ListUsers(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	c, rec, _, _ = setupTestEnv(t, http.MethodGet, "/admin/users?min_files=-1", nil)
	c.Set("user", adminToken)
	require.NoError(t, ListUsers(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAdminGetUserStatus_MFAMethodsAndStorage(t *testing.T) {
	db := setupAdminUserStatusDB(t)
	const adminUsername = "status-admin"
	const targetUsername = "username00"
	used := int64(47710208)
	insertAdminStatusUser(t, db, adminUsername, true, true, 0, models.DefaultStorageLimit, "2026-08-18 00:00:00")
	insertAdminStatusUser(t, db, targetUsername, false, true, used, models.DefaultStorageLimit, "2026-08-18 00:00:37")
	seedCompletedTOTP(t, targetUsername)
	_, err := db.Exec(`INSERT INTO file_metadata (file_id, storage_id, owner_username) VALUES ('file-a', 'store-a', ?)`, targetUsername)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO opaque_user_data (username, opaque_user_record) VALUES (?, ?)`, targetUsername, []byte("opaque"))
	require.NoError(t, err)

	c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/admin/users/"+targetUsername+"/status", nil)
	database.DB = db
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)
	adminClaims := &auth.Claims{Username: adminUsername}
	adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
	c.Set("user", adminToken)

	require.NoError(t, AdminGetUserStatus(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Exists bool `json:"exists"`
			User   struct {
				Username             string  `json:"username"`
				IsApproved           bool    `json:"is_approved"`
				IsAdmin              bool    `json:"is_admin"`
				FileCount            int64   `json:"file_count"`
				StorageLimitBytes    int64   `json:"storage_limit_bytes"`
				TotalStorageBytes    int64   `json:"total_storage_bytes"`
				TotalStorageReadable string  `json:"total_storage_readable"`
				UsagePercent         float64 `json:"usage_percent"`
			} `json:"user"`
			MFA struct {
				Present        bool     `json:"present"`
				Decryptable    bool     `json:"decryptable"`
				Enabled        bool     `json:"enabled"`
				SetupCompleted bool     `json:"setup_completed"`
				Methods        []string `json:"methods"`
			} `json:"mfa"`
			OPAQUE struct {
				HasAccount bool `json:"has_account"`
			} `json:"opaque"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.True(t, resp.Data.Exists)
	assert.Equal(t, targetUsername, resp.Data.User.Username)
	assert.True(t, resp.Data.User.IsApproved)
	assert.False(t, resp.Data.User.IsAdmin)
	assert.Equal(t, int64(1), resp.Data.User.FileCount)
	assert.Equal(t, models.DefaultStorageLimit, resp.Data.User.StorageLimitBytes)
	assert.Equal(t, used, resp.Data.User.TotalStorageBytes)
	assert.InDelta(t, (float64(used)/float64(models.DefaultStorageLimit))*100, resp.Data.User.UsagePercent, 0.01)
	assert.Equal(t, []string{"totp"}, resp.Data.MFA.Methods)
	assert.True(t, resp.Data.MFA.Present)
	assert.True(t, resp.Data.MFA.Decryptable)
	assert.True(t, resp.Data.MFA.Enabled)
	assert.True(t, resp.Data.MFA.SetupCompleted)
	assert.True(t, resp.Data.OPAQUE.HasAccount)
}

func TestAdminGetUserStatus_WebAuthnAndBothMethods(t *testing.T) {
	db := setupAdminUserStatusDB(t)
	const adminUsername = "status-admin"
	insertAdminStatusUser(t, db, adminUsername, true, true, 0, models.DefaultStorageLimit, "2026-08-18 00:00:00")
	insertAdminStatusUser(t, db, "hw-only", false, true, 0, models.DefaultStorageLimit, "2026-08-18 00:00:00")
	insertAdminStatusUser(t, db, "both-user", false, true, 0, models.DefaultStorageLimit, "2026-08-18 00:00:00")
	seedCompletedWebAuthnRow(t, db, "hw-only", "hw-only-cred")
	seedCompletedTOTP(t, "both-user")
	seedCompletedWebAuthnRow(t, db, "both-user", "both-hw")

	invoke := func(username string) AdminUserStatusResponse {
		c, rec, _, _ := setupTestEnv(t, http.MethodGet, "/admin/users/"+username+"/status", nil)
		database.DB = db
		c.SetParamNames("username")
		c.SetParamValues(username)
		adminClaims := &auth.Claims{Username: adminUsername}
		adminToken := jwt.NewWithClaims(jwt.SigningMethodHS256, adminClaims)
		c.Set("user", adminToken)
		require.NoError(t, AdminGetUserStatus(c))
		require.Equal(t, http.StatusOK, rec.Code)
		var resp struct {
			Data AdminUserStatusResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Data
	}

	hw := invoke("hw-only")
	require.NotNil(t, hw.MFA)
	assert.Equal(t, []string{"webauthn"}, hw.MFA.Methods)
	assert.True(t, hw.MFA.Present)
	assert.True(t, hw.MFA.Enabled)
	assert.True(t, hw.MFA.SetupCompleted)

	both := invoke("both-user")
	require.NotNil(t, both.MFA)
	assert.Equal(t, []string{"totp", "webauthn"}, both.MFA.Methods)
	assert.True(t, both.MFA.Decryptable)
}

func TestCompletedMFAMethodTypesOrder(t *testing.T) {
	db := setupAdminUserStatusDB(t)
	insertAdminStatusUser(t, db, "order-user", false, true, 0, models.DefaultStorageLimit, "2026-08-18 00:00:00")
	seedCompletedWebAuthnRow(t, db, "order-user", "order-hw")
	seedCompletedTOTP(t, "order-user")

	methods, err := completedMFAMethodTypes(db, "order-user")
	require.NoError(t, err)
	assert.Equal(t, []string{"totp", "webauthn"}, methods)
}
