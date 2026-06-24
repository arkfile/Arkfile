package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupReregDB installs an in-memory DB with the tables the re-registration
// handlers touch and points database.DB at it for the duration of the test.
func setupReregDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)

	schema := `
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			total_storage_bytes INTEGER DEFAULT 0,
			storage_limit_bytes INTEGER NOT NULL DEFAULT 1073741824,
			is_approved BOOLEAN DEFAULT TRUE,
			approved_by TEXT,
			approved_at TIMESTAMP,
			is_admin BOOLEAN DEFAULT FALSE,
			requires_reregistration BOOLEAN NOT NULL DEFAULT FALSE,
			deleted_at TIMESTAMP
		);
		CREATE TABLE opaque_user_data (
			username TEXT PRIMARY KEY,
			opaque_user_record BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE file_metadata (
			file_id TEXT PRIMARY KEY,
			owner_username TEXT NOT NULL,
			encrypted_filename TEXT NOT NULL,
			filename_nonce TEXT NOT NULL
		);
		CREATE TABLE refresh_tokens (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL,
			token_hash TEXT,
			expires_at TIMESTAMP,
			revoked BOOLEAN DEFAULT FALSE
		);
		CREATE TABLE user_jwt_revocations (
			username TEXT PRIMARY KEY,
			revoked_at TIMESTAMP NOT NULL,
			reason TEXT
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

func insertReregUser(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO users (username, is_approved) VALUES (?, 1)`, username)
	require.NoError(t, err)
}

func insertOpaqueRecord(t *testing.T, db *sql.DB, username string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO opaque_user_data (username, opaque_user_record) VALUES (?, ?)`, username, []byte("dummy-record"))
	require.NoError(t, err)
}

// setReregTokenOnContext puts a re-registration-tier token claim set on the
// echo context so GetUsernameFromToken resolves the ceremony actor.
func setReregTokenOnContext(c echo.Context, username string) {
	c.Set("user", &jwt.Token{Claims: &auth.Claims{Username: username}})
}

func TestAdminFlagUserReregistration_DeletesOpaqueAndSetsFlag(t *testing.T) {
	db := setupReregDB(t)
	const admin = "admin12345"
	const target = "target1234"
	insertReregUser(t, db, admin)
	insertReregUser(t, db, target)
	insertOpaqueRecord(t, db, target)

	e := echo.New()
	body, _ := json.Marshal(map[string]interface{}{"confirm": true})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+target+"/flag-reregistration", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues(target)
	setReregTokenOnContext(c, admin)

	require.NoError(t, AdminFlagUserReregistration(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	// OPAQUE record removed, flag set, users row preserved.
	var opaqueCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data WHERE username = ?`, target).Scan(&opaqueCount))
	assert.Equal(t, 0, opaqueCount)

	var flag bool
	require.NoError(t, db.QueryRow(`SELECT requires_reregistration FROM users WHERE username = ?`, target).Scan(&flag))
	assert.True(t, flag)

	var userCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, target).Scan(&userCount))
	assert.Equal(t, 1, userCount, "users row must be preserved")
}

func TestAdminFlagUserReregistration_RequiresConfirm(t *testing.T) {
	db := setupReregDB(t)
	const admin = "admin12345"
	const target = "target1234"
	insertReregUser(t, db, admin)
	insertReregUser(t, db, target)
	insertOpaqueRecord(t, db, target)

	e := echo.New()
	body, _ := json.Marshal(map[string]interface{}{"confirm": false})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+target+"/flag-reregistration", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetParamNames("username")
	c.SetParamValues(target)
	setReregTokenOnContext(c, admin)

	require.NoError(t, AdminFlagUserReregistration(c))
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Nothing changed.
	var opaqueCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data WHERE username = ?`, target).Scan(&opaqueCount))
	assert.Equal(t, 1, opaqueCount)
}

func TestAdminFlagAllUsersReregistration_FlagsEveryone(t *testing.T) {
	db := setupReregDB(t)
	const admin = "admin12345"
	users := []string{"alpha12345", "bravo12345", "charlie123"}
	insertReregUser(t, db, admin)
	for _, u := range users {
		insertReregUser(t, db, u)
		insertOpaqueRecord(t, db, u)
	}

	e := echo.New()
	body, _ := json.Marshal(map[string]interface{}{"confirm": true})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/users/flag-reregistration-all", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	setReregTokenOnContext(c, admin)

	require.NoError(t, AdminFlagAllUsersReregistration(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	var remaining int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data`).Scan(&remaining))
	assert.Equal(t, 0, remaining, "all OPAQUE records cleared")

	var flagged int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM users WHERE requires_reregistration = 1`).Scan(&flagged))
	assert.Equal(t, len(users)+1, flagged, "admin and all users flagged")
}

func TestRespondAccountRequiresReregistration_WithFiles_IncludesVerifier(t *testing.T) {
	db := setupReregDB(t)
	const target = "haver12345"
	insertReregUser(t, db, target)
	_, err := db.Exec(`INSERT INTO file_metadata (file_id, owner_username, encrypted_filename, filename_nonce)
		VALUES (?, ?, ?, ?)`, "file-1", target, "enc-fn", "nonce-fn")
	require.NoError(t, err)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/login/response", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	require.NoError(t, respondAccountRequiresReregistration(c, target))
	assert.Equal(t, http.StatusConflict, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, CodeAccountRequiresReregistration, resp["error"])

	data := resp["data"].(map[string]interface{})
	assert.NotEmpty(t, data["reregistration_token"])
	assert.Equal(t, float64(1), data["file_count"])

	verifier, ok := data["verifier"].(map[string]interface{})
	require.True(t, ok, "verifier sample must be present when the user owns files")
	assert.Equal(t, "file-1", verifier["file_id"])
	assert.Equal(t, target, verifier["owner_username"])
	assert.Equal(t, "enc-fn", verifier["encrypted_filename"])
	assert.Equal(t, "nonce-fn", verifier["filename_nonce"])
}

func TestRespondAccountRequiresReregistration_NoFiles_OmitsVerifier(t *testing.T) {
	db := setupReregDB(t)
	const target = "nofiles123"
	insertReregUser(t, db, target)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/login/response", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	require.NoError(t, respondAccountRequiresReregistration(c, target))
	assert.Equal(t, http.StatusConflict, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, float64(0), data["file_count"])
	_, hasVerifier := data["verifier"]
	assert.False(t, hasVerifier, "no verifier when the user owns no files")
}

func TestReregisterResponse_RejectsUnflaggedAccount(t *testing.T) {
	db := setupReregDB(t)
	const target = "unflagged1"
	insertReregUser(t, db, target) // requires_reregistration defaults to false

	e := echo.New()
	body, _ := json.Marshal(map[string]string{"registration_request": "AAAA"})
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/reregister/response", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	setReregTokenOnContext(c, target)

	require.NoError(t, ReregisterResponse(c))
	assert.Equal(t, http.StatusConflict, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, CodeReregistrationTokenInvalid, resp["error"])
}

func TestReregisterFinalize_RejectsUnflaggedAccount(t *testing.T) {
	db := setupReregDB(t)
	const target = "unflagged2"
	insertReregUser(t, db, target)

	e := echo.New()
	body, _ := json.Marshal(map[string]string{"session_id": "sid", "registration_record": "AAAA"})
	req := httptest.NewRequest(http.MethodPost, "/api/opaque/reregister/finalize", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	setReregTokenOnContext(c, target)

	require.NoError(t, ReregisterFinalize(c))
	assert.Equal(t, http.StatusConflict, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, CodeReregistrationTokenInvalid, resp["error"])
}
