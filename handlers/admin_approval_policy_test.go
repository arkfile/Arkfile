package handlers

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/database"
)

const approvalPolicyAdminUser = "policy-admin"

func newApprovalPolicyDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			username_folded TEXT UNIQUE NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			total_storage_bytes BIGINT NOT NULL DEFAULT 0,
			storage_limit_bytes BIGINT NOT NULL DEFAULT 1073741824,
			is_approved BOOLEAN NOT NULL DEFAULT 1,
			approved_by TEXT,
			approved_at TIMESTAMP,
			is_admin BOOLEAN NOT NULL DEFAULT 0,
			deleted_at TIMESTAMP DEFAULT NULL
		);
		CREATE TABLE system_settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_by TEXT
		);
		CREATE TABLE admin_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			admin_username TEXT NOT NULL,
			action TEXT NOT NULL,
			target_username TEXT,
			details TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO users (username, username_folded, is_admin, is_approved) VALUES (?, ?, 1, 1)`,
		approvalPolicyAdminUser, approvalPolicyAdminUser,
	)
	require.NoError(t, err)
	return db
}

func approvalPolicyContext(t *testing.T, method, path string, body []byte) (echo.Context, *httptest.ResponseRecorder) {
	t.Helper()
	e := echo.New()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user", jwt.NewWithClaims(jwt.SigningMethodHS256, &auth.Claims{Username: approvalPolicyAdminUser}))
	return c, rec
}

func TestApprovalPolicy_GetDefaultsToEnvFallback(t *testing.T) {
	db := newApprovalPolicyDB(t)
	defer db.Close()
	origDB := database.DB
	database.DB = db
	defer func() { database.DB = origDB }()

	config.ResetConfigForTest()
	defer config.ResetConfigForTest()
	// Establish a known live state without relying on env-loaded config (which
	// is not loaded in this isolated test). With no system_settings row yet,
	// GET should report this live value with source "env".
	config.SetRequireApproval(false)
	assert.False(t, config.RequireApproval())

	c, rec := approvalPolicyContext(t, http.MethodGet, "/api/admin/system/approval-policy", nil)
	require.NoError(t, AdminGetApprovalPolicy(c))
	assert.Equal(t, http.StatusOK, rec.Code)

	resp := parseApprovalPolicyResponse(t, rec)
	assert.False(t, resp["require_approval"].(bool))
	assert.Equal(t, "env", resp["source"])
}

func parseApprovalPolicyResponse(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var apiResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &apiResp))
	data, ok := apiResp.Data.(map[string]interface{})
	require.True(t, ok, "response data should be an object: %v", apiResp.Data)
	return data
}

func TestApprovalPolicy_SetPersistsAndAppliesLive(t *testing.T) {
	db := newApprovalPolicyDB(t)
	defer db.Close()
	origDB := database.DB
	database.DB = db
	defer func() { database.DB = origDB }()

	config.ResetConfigForTest()
	defer config.ResetConfigForTest()
	config.SetRequireApproval(false)

	// Flip to require_approval=true.
	body := []byte(`{"require_approval":true}`)
	c, rec := approvalPolicyContext(t, http.MethodPost, "/api/admin/system/approval-policy", body)
	require.NoError(t, AdminSetApprovalPolicy(c))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, config.RequireApproval(), "live state should reflect the new policy")

	// Persisted row exists.
	var value string
	require.NoError(t, db.QueryRow(`SELECT value FROM system_settings WHERE key = ?`, "require_approval").Scan(&value))
	assert.Equal(t, "true", value)

	// GET now reports source=system_settings.
	c2, rec2 := approvalPolicyContext(t, http.MethodGet, "/api/admin/system/approval-policy", nil)
	require.NoError(t, AdminGetApprovalPolicy(c2))
	resp := parseApprovalPolicyResponse(t, rec2)
	assert.True(t, resp["require_approval"].(bool))
	assert.Equal(t, "system_settings", resp["source"])

	// Flip back to false.
	bodyFalse := []byte(`{"require_approval":false}`)
	c3, rec3 := approvalPolicyContext(t, http.MethodPost, "/api/admin/system/approval-policy", bodyFalse)
	require.NoError(t, AdminSetApprovalPolicy(c3))
	assert.Equal(t, http.StatusOK, rec3.Code)
	assert.False(t, config.RequireApproval())
}

func TestApprovalPolicy_SetRejectsMissingField(t *testing.T) {
	db := newApprovalPolicyDB(t)
	defer db.Close()
	origDB := database.DB
	database.DB = db
	defer func() { database.DB = origDB }()

	c, rec := approvalPolicyContext(t, http.MethodPost, "/api/admin/system/approval-policy", []byte(`{}`))
	err := AdminSetApprovalPolicy(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
