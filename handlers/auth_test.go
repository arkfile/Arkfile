package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/models"
	"github.com/DATA-DOG/go-sqlmock"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- Logout handler tests --

// TestLogout_Success verifies successful logout clears refresh token and returns 200
func TestLogout_Success(t *testing.T) {
	username := "logout-user"
	refreshToken := "test-refresh-token-uuid"

	body, _ := json.Marshal(map[string]string{"refresh_token": refreshToken})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/logout", bytes.NewReader(body))

	// Set authenticated user context
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: RevokeRefreshToken does: UPDATE refresh_tokens SET revoked = true WHERE token_hash = ?
	revokeSQL := `UPDATE refresh_tokens SET revoked = true WHERE token_hash = \?`
	mock.ExpectExec(revokeSQL).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock: LogUserAction
	logSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logSQL).WithArgs(username, "logged out", "").WillReturnResult(sqlmock.NewResult(1, 1))

	err := Logout(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Verify response
	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "Logged out")

	// Verify session cookies were cleared (clearSessionCookies sets MaxAge=-1 + expired Expires).
	// We check for the new __Host-arkfile-* cookie names (Phase B).
	cookies := rec.Result().Cookies()
	clearedNames := map[string]bool{}
	for _, cookie := range cookies {
		switch cookie.Name {
		case CookieFullToken, CookieTempToken, CookieRefresh, CookieCSRF:
			clearedNames[cookie.Name] = true
			assert.Equal(t, "", cookie.Value, "session cookie %s value should be empty", cookie.Name)
		}
	}
	assert.True(t, len(clearedNames) > 0, "at least one __Host-arkfile-* session cookie should be cleared on logout")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogout_NoRefreshToken verifies logout works even without a refresh token in the body
func TestLogout_NoRefreshToken(t *testing.T) {
	username := "logout-user-no-rt"

	body, _ := json.Marshal(map[string]string{})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/logout", bytes.NewReader(body))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// No RevokeRefreshToken call expected since refresh_token is empty

	// Mock: LogUserAction
	logSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logSQL).WithArgs(username, "logged out", "").WillReturnResult(sqlmock.NewResult(1, 1))

	err := Logout(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestLogout_InvalidBody verifies malformed body returns 400
func TestLogout_InvalidBody(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/logout", bytes.NewReader([]byte("{invalid json")))

	err := Logout(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// -- TOTPStatus handler tests --

// TestTOTPStatus_Enabled verifies correct response when TOTP is enabled
func TestTOTPStatus_Enabled(t *testing.T) {
	username := "totp-enabled-user"

	c, rec, mock, _ := setupTestEnv(t, http.MethodGet, "/api/mfa/status", nil)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: HasCompletedMFA
	countSQL := `SELECT COUNT\(\*\) FROM user_mfa_credentials WHERE username = \? AND enabled = 1 AND setup_completed = 1`
	countRows := sqlmock.NewRows([]string{"count"}).AddRow(1)
	mock.ExpectQuery(countSQL).WithArgs(username).WillReturnRows(countRows)

	methodSQL := `SELECT credential_id, method_type, credential_data FROM user_mfa_credentials WHERE username = \? AND enabled = 1 AND setup_completed = 1 ORDER BY created_at ASC`
	methodRows := sqlmock.NewRows([]string{"credential_id", "method_type", "credential_data"}).
		AddRow("cred-1", "totp", []byte("encrypted"))
	mock.ExpectQuery(methodSQL).WithArgs(username).WillReturnRows(methodRows)

	listSQL := `SELECT credential_id, method_type, credential_data, created_at, last_used FROM user_mfa_credentials WHERE username = \? AND setup_completed = 1 ORDER BY created_at ASC`
	listRows := sqlmock.NewRows([]string{"credential_id", "method_type", "credential_data", "created_at", "last_used"}).
		AddRow("cred-1", "totp", []byte("encrypted"), time.Now(), nil)
	mock.ExpectQuery(listSQL).WithArgs(username).WillReturnRows(listRows)

	err := MFAStatus(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	data := resp["data"].(map[string]interface{})
	assert.Equal(t, true, data["enabled"])
	assert.Equal(t, false, data["setup_required"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestTOTPStatus_NotEnabled verifies correct response when TOTP is not enabled
func TestTOTPStatus_NotEnabled(t *testing.T) {
	username := "totp-disabled-user"

	c, rec, mock, _ := setupTestEnv(t, http.MethodGet, "/api/mfa/status", nil)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: HasCompletedMFA - no completed rows
	countSQL := `SELECT COUNT\(\*\) FROM user_mfa_credentials WHERE username = \? AND enabled = 1 AND setup_completed = 1`
	mock.ExpectQuery(countSQL).WithArgs(username).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	methodSQL := `SELECT credential_id, method_type, credential_data FROM user_mfa_credentials WHERE username = \? AND enabled = 1 AND setup_completed = 1 ORDER BY created_at ASC`
	mock.ExpectQuery(methodSQL).WithArgs(username).WillReturnRows(sqlmock.NewRows([]string{"credential_id", "method_type", "credential_data"}))

	pendingSQL := `SELECT method_type FROM user_mfa_credentials WHERE username = \? AND setup_completed = 0 ORDER BY created_at DESC LIMIT 1`
	mock.ExpectQuery(pendingSQL).WithArgs(username).WillReturnRows(sqlmock.NewRows([]string{"method_type"}))

	listSQL := `SELECT credential_id, method_type, credential_data, created_at, last_used FROM user_mfa_credentials WHERE username = \? AND setup_completed = 1 ORDER BY created_at ASC`
	mock.ExpectQuery(listSQL).WithArgs(username).WillReturnRows(sqlmock.NewRows([]string{"credential_id", "method_type", "credential_data", "created_at", "last_used"}))

	err := MFAStatus(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	data := resp["data"].(map[string]interface{})
	assert.Equal(t, false, data["enabled"])
	assert.Equal(t, true, data["setup_required"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

// -- TOTPAuth handler tests --

// TestTOTPAuth_EmptyCode verifies empty TOTP code is rejected
func TestTOTPAuth_EmptyCode(t *testing.T) {
	username := "totp-auth-user"

	body, _ := json.Marshal(map[string]string{"code": ""})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/auth", bytes.NewReader(body))

	// Set up token that requires TOTP (RequiresMFA is a claim field, not a header)
	claims := &auth.Claims{
		Username:     username,
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := MFAAuth(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "TOTP code is required")
}

// TestTOTPAuth_InvalidCodeLength verifies wrong-length TOTP code is rejected
func TestTOTPAuth_InvalidCodeLength(t *testing.T) {
	username := "totp-auth-user"

	body, _ := json.Marshal(map[string]string{"code": "1234"}) // 4 digits, not 6
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/auth", bytes.NewReader(body))

	claims := &auth.Claims{
		Username:     username,
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := MFAAuth(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "6 digits")
}

// TestTOTPAuth_InvalidBackupCodeLength verifies wrong-length backup code is rejected
func TestTOTPAuth_InvalidBackupCodeLength(t *testing.T) {
	username := "totp-auth-user"

	body, _ := json.Marshal(map[string]interface{}{
		"code":      "short",
		"is_backup": true,
	})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/auth", bytes.NewReader(body))

	claims := &auth.Claims{
		Username:     username,
		RequiresMFA: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := MFAAuth(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "10 characters")
}

// TestTOTPAuth_InvalidRequestFormat verifies malformed JSON is rejected
func TestTOTPAuth_InvalidRequestFormat(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/auth", bytes.NewReader([]byte("{bad json")))

	err := MFAAuth(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// -- TOTPReset handler tests --

// TestTOTPReset_EmptyBackupCode verifies empty backup code is rejected
func TestTOTPReset_EmptyBackupCode(t *testing.T) {
	username := "totp-reset-user"

	body, _ := json.Marshal(map[string]string{"backup_code": ""})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/reset", bytes.NewReader(body))

	// Ensure claims do NOT have reset audience so empty backup code is rejected
	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := MFAReset(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "backup code")
}

// TestTOTPReset_InvalidBackupCodeLength verifies wrong-length backup code is rejected
func TestTOTPReset_InvalidBackupCodeLength(t *testing.T) {
	username := "totp-reset-user"

	body, _ := json.Marshal(map[string]string{"backup_code": "short"})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/reset", bytes.NewReader(body))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := MFAReset(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "10 characters")
}

// TestTOTPReset_InvalidRequestFormat verifies malformed JSON is rejected
func TestTOTPReset_InvalidRequestFormat(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/mfa/reset", bytes.NewReader([]byte("{bad json")))

	claims := &auth.Claims{Username: "totp-reset-user"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := MFAReset(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// -- RevokeToken handler tests --

// TestRevokeToken_EmptyToken verifies empty token in request body is rejected
func TestRevokeToken_EmptyToken(t *testing.T) {
	username := "revoke-user"

	body, _ := json.Marshal(map[string]string{"token": "", "reason": "test"})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/revoke", bytes.NewReader(body))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := RevokeToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Token is required")
}

// TestRevokeToken_InvalidRequestFormat verifies malformed JSON is rejected
func TestRevokeToken_InvalidRequestFormat(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/revoke", bytes.NewReader([]byte("{bad")))

	claims := &auth.Claims{Username: "revoke-user"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := RevokeToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// -- RevokeAllTokens handler tests --

// TestRevokeAllTokens_DefaultReason verifies RevokeAllTokens revokes refresh tokens AND JWTs immediately.
func TestRevokeAllTokens_DefaultReason(t *testing.T) {
	username := "revoke-all-user"

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/revoke-all", nil)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: RevokeAllUserTokens (refresh tokens)
	revokeRefreshSQL := `UPDATE refresh_tokens SET revoked = true WHERE username = \?`
	mock.ExpectExec(revokeRefreshSQL).WithArgs(username).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock: RevokeAllUserJWTTokens - writes user_jwt_revocations
	revokeJWTSQL := `INSERT INTO user_jwt_revocations \(username, revoked_at, reason\)
		 VALUES \(\?, \?, \?\)
		 ON CONFLICT\(username\) DO UPDATE SET revoked_at = excluded.revoked_at, reason = excluded.reason`
	mock.ExpectExec(revokeJWTSQL).WithArgs(username, sqlmock.AnyArg(), "user revoke-all").WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock: LogUserAction
	logSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logSQL).WithArgs(username, "revoked all tokens", "").WillReturnResult(sqlmock.NewResult(1, 1))

	err := RevokeAllTokens(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "revoked")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// -- RefreshToken handler tests --

// TestRefreshToken_EmptyToken verifies empty refresh token is rejected
func TestRefreshToken_EmptyToken(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"refresh_token": ""})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Refresh token not found")
}

// TestRefreshToken_InvalidBody verifies malformed JSON returns 400
func TestRefreshToken_InvalidBody(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader([]byte("{bad")))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestRefreshToken_ExpiredToken verifies expired refresh token is rejected
func TestRefreshToken_ExpiredToken(t *testing.T) {
	refreshTokenValue := "expired-refresh-token-uuid"

	body, _ := json.Marshal(map[string]string{"refresh_token": refreshTokenValue})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))

	// Mock: ValidateRefreshToken new SELECT (8 columns including family fields)
	validateSQL := `SELECT id, username, expires_at, revoked, last_used, family_id, superseded_by_hash, family_revoked_at FROM refresh_tokens WHERE token_hash = \?`
	expiredTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	rows := sqlmock.NewRows([]string{"id", "username", "expires_at", "revoked", "last_used", "family_id", "superseded_by_hash", "family_revoked_at"}).
		AddRow("token-id", "testuser", expiredTime, false, nil, "family-1", nil, nil)
	mock.ExpectQuery(validateSQL).WithArgs(sqlmock.AnyArg()).WillReturnRows(rows)

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "expired")
}

// TestRefreshToken_RevokedToken verifies revoked refresh token is rejected
func TestRefreshToken_RevokedToken(t *testing.T) {
	refreshTokenValue := "revoked-refresh-token-uuid"

	body, _ := json.Marshal(map[string]string{"refresh_token": refreshTokenValue})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))

	// Mock: ValidateRefreshToken new SELECT - token not found (no rows)
	validateSQL := `SELECT id, username, expires_at, revoked, last_used, family_id, superseded_by_hash, family_revoked_at FROM refresh_tokens WHERE token_hash = \?`
	mock.ExpectQuery(validateSQL).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{
		"id", "username", "expires_at", "revoked", "last_used", "family_id", "superseded_by_hash", "family_revoked_at",
	}))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// -- AdminForceLogout handler tests --

// TestAdminForceLogout_MissingUsername verifies missing username param returns 400
func TestAdminForceLogout_MissingUsername(t *testing.T) {
	adminUsername := "admin-force-logout"

	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/admin/force-logout/", nil)

	claims := &auth.Claims{Username: adminUsername}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := AdminForceLogout(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Username is required")
}

// TestAdminForceLogout_Success verifies successful force-logout revokes tokens and logs events
func TestAdminForceLogout_Success(t *testing.T) {
	adminUsername := "admin-force-logout"
	targetUsername := "target-force-logout"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/api/admin/users/:username/force-logout", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	claims := &auth.Claims{Username: adminUsername}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock RevokeAllUserTokens (updates refresh_tokens)
	mockDB.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE username = \?`).
		WithArgs(targetUsername).
		WillReturnResult(sqlmock.NewResult(0, 2))

	// Mock RevokeAllUserJWTTokens (writes user_jwt_revocations)
	mockDB.ExpectExec(`INSERT INTO user_jwt_revocations`).
		WithArgs(targetUsername, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock LogUserAction for target user
	mockDB.ExpectExec(`INSERT INTO user_activity`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock LogUserAction for admin user
	mockDB.ExpectExec(`INSERT INTO user_activity`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := AdminForceLogout(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "force-logged out successfully")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// TestAdminForceLogout_TokenRevocationError verifies 500 when token revocation fails
func TestAdminForceLogout_TokenRevocationError(t *testing.T) {
	adminUsername := "admin-force-logout"
	targetUsername := "target-force-logout"

	c, rec, mockDB, _ := setupTestEnv(t, http.MethodPost, "/api/admin/users/:username/force-logout", nil)
	c.SetParamNames("username")
	c.SetParamValues(targetUsername)

	claims := &auth.Claims{Username: adminUsername}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock RevokeAllUserTokens fails
	mockDB.ExpectExec(`UPDATE refresh_tokens SET revoked = true WHERE username = \?`).
		WithArgs(targetUsername).
		WillReturnError(fmt.Errorf("database error"))

	err := AdminForceLogout(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "Failed to revoke user tokens")

	assert.NoError(t, mockDB.ExpectationsWereMet())
}

// -- Success-path tests (require TestMain for JWT Ed25519 keys) --

// TestRefreshToken_Success verifies valid refresh token issues new JWT + new refresh token.
// ValidateRefreshToken now handles rotation atomically: SELECT (8 cols) + INSERT new + UPDATE superseded.
func TestRefreshToken_Success(t *testing.T) {
	refreshTokenValue := "valid-refresh-token-uuid-for-success-test"
	username := "refresh-success-user"

	body, _ := json.Marshal(map[string]string{"refresh_token": refreshTokenValue})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))

	// Mock: ValidateRefreshToken SELECT (8-column family-aware query)
	validateSQL := `SELECT id, username, expires_at, revoked, last_used, family_id, superseded_by_hash, family_revoked_at FROM refresh_tokens WHERE token_hash = \?`
	futureExpiry := time.Now().Add(14 * 24 * time.Hour).Format(time.RFC3339)
	rows := sqlmock.NewRows([]string{
		"id", "username", "expires_at", "revoked", "last_used",
		"family_id", "superseded_by_hash", "family_revoked_at",
	}).AddRow("token-id-1", username, futureExpiry, false, nil, "fam-abc", nil, nil)
	mock.ExpectQuery(validateSQL).WithArgs(sqlmock.AnyArg()).WillReturnRows(rows)

	// Mock: ValidateRefreshToken INSERT new token (10-column insert with family fields)
	insertNewSQL := `INSERT INTO refresh_tokens`
	mock.ExpectExec(insertNewSQL).WithArgs(
		sqlmock.AnyArg(), username, sqlmock.AnyArg(), sqlmock.AnyArg(),
		sqlmock.AnyArg(), false, nil, "fam-abc", nil, nil,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock: ValidateRefreshToken UPDATE superseded_by_hash on consumed row
	updateSupersededSQL := `UPDATE refresh_tokens SET superseded_by_hash = \?, last_used = \? WHERE id = \?`
	mock.ExpectExec(updateSupersededSQL).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "token-id-1").WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock: GetUserByUsername for approval gate after refresh
	getUserSQL := `SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = \? AND deleted_at IS NULL`
	mock.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, username, time.Now(), int64(0), models.DefaultStorageLimit, true, nil, nil, false))

	// Mock: LogUserAction
	logSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logSQL).WithArgs(username, "refreshed token", "").WillReturnResult(sqlmock.NewResult(1, 1))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	data, ok := resp["data"].(map[string]interface{})
	require.True(t, ok, "response should contain 'data' object, got: %v", resp)
	assert.NotEmpty(t, data["token"], "new JWT token should be returned")
	assert.NotEmpty(t, data["refresh_token"], "new refresh token should be returned")
	assert.NotNil(t, data["expires_at"], "expiration should be set")

	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRefreshToken_UnapprovedUser verifies unapproved users cannot rotate refresh tokens.
func TestRefreshToken_UnapprovedUser(t *testing.T) {
	refreshTokenValue := "valid-refresh-token-unapproved"
	username := "pending-user"

	body, _ := json.Marshal(map[string]string{"refresh_token": refreshTokenValue})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))

	validateSQL := `SELECT id, username, expires_at, revoked, last_used, family_id, superseded_by_hash, family_revoked_at FROM refresh_tokens WHERE token_hash = \?`
	futureExpiry := time.Now().Add(14 * 24 * time.Hour).Format(time.RFC3339)
	rows := sqlmock.NewRows([]string{
		"id", "username", "expires_at", "revoked", "last_used",
		"family_id", "superseded_by_hash", "family_revoked_at",
	}).AddRow("token-id-1", username, futureExpiry, false, nil, "fam-abc", nil, nil)
	mock.ExpectQuery(validateSQL).WithArgs(sqlmock.AnyArg()).WillReturnRows(rows)

	insertNewSQL := `INSERT INTO refresh_tokens`
	mock.ExpectExec(insertNewSQL).WithArgs(
		sqlmock.AnyArg(), username, sqlmock.AnyArg(), sqlmock.AnyArg(),
		sqlmock.AnyArg(), false, nil, "fam-abc", nil, nil,
	).WillReturnResult(sqlmock.NewResult(1, 1))

	updateSupersededSQL := `UPDATE refresh_tokens SET superseded_by_hash = \?, last_used = \? WHERE id = \?`
	mock.ExpectExec(updateSupersededSQL).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "token-id-1").WillReturnResult(sqlmock.NewResult(0, 1))

	getUserSQL := `SELECT id, username, created_at,
		       total_storage_bytes, storage_limit_bytes,
		       is_approved, approved_by, approved_at, is_admin
		FROM users WHERE username = \? AND deleted_at IS NULL`
	mock.ExpectQuery(getUserSQL).WithArgs(username).WillReturnRows(
		sqlmock.NewRows([]string{"id", "username", "created_at", "total_storage_bytes", "storage_limit_bytes", "is_approved", "approved_by", "approved_at", "is_admin"}).
			AddRow(1, username, time.Now(), int64(0), models.DefaultStorageLimit, false, nil, nil, false))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "Account pending approval", resp["message"])

	assert.NoError(t, mock.ExpectationsWereMet())
}

// Suppress unused import warnings
var _ = models.ErrRefreshTokenExpired
