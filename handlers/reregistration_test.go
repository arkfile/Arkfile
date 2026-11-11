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
			account_kdf_salt TEXT NOT NULL DEFAULT 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
			account_kdf_profile INTEGER NOT NULL DEFAULT 1,
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
	var salt string
	var profile int
	require.NoError(t, db.QueryRow(
		`SELECT account_kdf_salt, account_kdf_profile FROM users WHERE username = ?`,
		target,
	).Scan(&salt, &profile))
	assert.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", salt)
	assert.Equal(t, 1, profile)
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

	require.NoError(t, respondAccountRequiresReregistration(c, target, ""))
	assert.Equal(t, http.StatusConflict, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, CodeAccountRequiresReregistration, resp["error"])

	data := resp["data"].(map[string]interface{})
	assert.NotEmpty(t, data["reregistration_token"])
	assert.Equal(t, float64(1), data["file_count"])
	assert.Equal(t, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", data["account_kdf_salt"])
	assert.Equal(t, float64(1), data["account_kdf_profile"])

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

	require.NoError(t, respondAccountRequiresReregistration(c, target, ""))
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

func insertReregAdmin(t *testing.T, db *sql.DB, username string, flagged bool) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO users (username, is_approved, is_admin, requires_reregistration) VALUES (?, 1, 1, ?)`,
		username, flagged,
	)
	require.NoError(t, err)
}

func reregCeremonyContext(path string, body interface{}, claims *auth.Claims) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user", &jwt.Token{Claims: claims})
	return c, rec
}

func reregErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	code, _ := resp["error"].(string)
	return code
}

func TestAdminReregister_RefusesUnmarkedHandoffToken(t *testing.T) {
	db := setupReregDB(t)
	const admin = "flaggedadm1"
	insertReregAdmin(t, db, admin, true)

	cases := []struct {
		name    string
		path    string
		body    interface{}
		handler echo.HandlerFunc
	}{
		{"response", "/api/admin/reregister/response", map[string]string{"registration_request": "AAAA"}, AdminReregisterResponse},
		{"finalize", "/api/admin/reregister/finalize", map[string]string{"session_id": "sid", "registration_record": "AAAA"}, AdminReregisterFinalize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := reregCeremonyContext(tc.path, tc.body, &auth.Claims{Username: admin})
			require.NoError(t, tc.handler(c))
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, CodeReregistrationTokenInvalid, reregErrorCode(t, rec))
		})
	}

	var flag bool
	require.NoError(t, db.QueryRow(`SELECT requires_reregistration FROM users WHERE username = ?`, admin).Scan(&flag))
	assert.True(t, flag, "a refused ceremony must leave the flag set")
}

func TestAdminReregister_RefusesMarkedTokenForNonAdmin(t *testing.T) {
	db := setupReregDB(t)
	const user = "plainuser01"
	_, err := db.Exec(`INSERT INTO users (username, is_approved, requires_reregistration) VALUES (?, 1, 1)`, user)
	require.NoError(t, err)

	c, rec := reregCeremonyContext(
		"/api/admin/reregister/response",
		map[string]string{"registration_request": "AAAA"},
		&auth.Claims{Username: user, LoginKind: auth.LoginKindAdmin},
	)
	require.NoError(t, AdminReregisterResponse(c))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, CodeReregistrationTokenInvalid, reregErrorCode(t, rec))
}

func TestAdminReregister_MarkedTokenPassesGuard(t *testing.T) {
	db := setupReregDB(t)
	const admin = "unflagged-adm"
	insertReregAdmin(t, db, admin, false)

	c, rec := reregCeremonyContext(
		"/api/admin/reregister/response",
		map[string]string{"registration_request": "AAAA"},
		&auth.Claims{Username: admin, LoginKind: auth.LoginKindAdmin},
	)
	require.NoError(t, AdminReregisterResponse(c))
	// The guard accepted the marked admin token; the flag check refuses next.
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, CodeReregistrationTokenInvalid, reregErrorCode(t, rec))
}

func TestPublicReregister_RefusesAdminAccounts(t *testing.T) {
	db := setupReregDB(t)
	const admin = "flaggedadm2"
	insertReregAdmin(t, db, admin, true)

	cases := []struct {
		name    string
		path    string
		body    interface{}
		handler echo.HandlerFunc
	}{
		{"response", "/api/opaque/reregister/response", map[string]string{"registration_request": "AAAA"}, ReregisterResponse},
		{"finalize", "/api/opaque/reregister/finalize", map[string]string{"session_id": "sid", "registration_record": "AAAA"}, ReregisterFinalize},
	}
	for _, tc := range cases {
		for _, loginKind := range []string{"", auth.LoginKindAdmin} {
			t.Run(tc.name+"/"+loginKind, func(t *testing.T) {
				c, rec := reregCeremonyContext(tc.path, tc.body, &auth.Claims{Username: admin, LoginKind: loginKind})
				require.NoError(t, tc.handler(c))
				assert.Equal(t, http.StatusForbidden, rec.Code)
			})
		}
	}

	var opaqueCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM opaque_user_data WHERE username = ?`, admin).Scan(&opaqueCount))
	assert.Equal(t, 0, opaqueCount, "no OPAQUE record may be written for a refused admin")
}

func TestRespondAccountRequiresReregistration_AdminTokenIsMarked(t *testing.T) {
	db := setupReregDB(t)
	const admin = "flaggedadm3"
	insertReregAdmin(t, db, admin, true)

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/login/response", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	require.NoError(t, respondAccountRequiresReregistration(c, admin, auth.LoginKindAdmin))
	assert.Equal(t, http.StatusConflict, rec.Code)
	for _, cookie := range rec.Result().Cookies() {
		assert.True(t, cookie.MaxAge < 0 || cookie.Value == "", "marked admin handoff must not set cookie %s", cookie.Name)
	}

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data := resp["data"].(map[string]interface{})
	tokenString, _ := data["reregistration_token"].(string)
	require.NotEmpty(t, tokenString)
	claims := &auth.Claims{}
	_, _, err := jwt.NewParser().ParseUnverified(tokenString, claims)
	require.NoError(t, err)
	assert.Equal(t, auth.LoginKindAdmin, claims.LoginKind)
	assert.Equal(t, admin, claims.Username)
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
