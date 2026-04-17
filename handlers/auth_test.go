package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/models"
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

	// Verify cookie was cleared (set to expired)
	cookies := rec.Result().Cookies()
	foundClear := false
	for _, cookie := range cookies {
		if cookie.Name == "refreshToken" {
			foundClear = true
			assert.Equal(t, "", cookie.Value, "refresh token cookie value should be empty")
			assert.True(t, cookie.Expires.Before(time.Now()), "cookie should be expired")
		}
	}
	assert.True(t, foundClear, "refreshToken cookie should be set (cleared)")

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

	c, rec, mock, _ := setupTestEnv(t, http.MethodGet, "/api/auth/totp/status", nil)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: IsUserTOTPEnabled query - actual SQL is:
	// SELECT enabled, setup_completed FROM user_totp WHERE username = ?
	totpSQL := `SELECT enabled, setup_completed FROM user_totp WHERE username = \?`
	totpRows := sqlmock.NewRows([]string{"enabled", "setup_completed"}).AddRow(true, true)
	mock.ExpectQuery(totpSQL).WithArgs(username).WillReturnRows(totpRows)

	err := TOTPStatus(c)
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

	c, rec, mock, _ := setupTestEnv(t, http.MethodGet, "/api/auth/totp/status", nil)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: IsUserTOTPEnabled - no rows = not enabled
	totpSQL := `SELECT enabled, setup_completed FROM user_totp WHERE username = \?`
	mock.ExpectQuery(totpSQL).WithArgs(username).WillReturnRows(sqlmock.NewRows([]string{"enabled", "setup_completed"}))

	err := TOTPStatus(c)
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
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/auth", bytes.NewReader(body))

	// Set up token that requires TOTP (RequiresTOTP is a claim field, not a header)
	claims := &auth.Claims{
		Username:     username,
		RequiresTOTP: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := TOTPAuth(c)
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
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/auth", bytes.NewReader(body))

	claims := &auth.Claims{
		Username:     username,
		RequiresTOTP: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := TOTPAuth(c)
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
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/auth", bytes.NewReader(body))

	claims := &auth.Claims{
		Username:     username,
		RequiresTOTP: true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := TOTPAuth(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "10 characters")
}

// TestTOTPAuth_InvalidRequestFormat verifies malformed JSON is rejected
func TestTOTPAuth_InvalidRequestFormat(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/auth", bytes.NewReader([]byte("{bad json")))

	err := TOTPAuth(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// -- TOTPReset handler tests --

// TestTOTPReset_EmptyBackupCode verifies empty backup code is rejected
func TestTOTPReset_EmptyBackupCode(t *testing.T) {
	username := "totp-reset-user"

	body, _ := json.Marshal(map[string]string{"backup_code": ""})
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/reset", bytes.NewReader(body))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := TOTPReset(c)
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
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/reset", bytes.NewReader(body))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := TOTPReset(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "10 characters")
}

// TestTOTPReset_InvalidRequestFormat verifies malformed JSON is rejected
func TestTOTPReset_InvalidRequestFormat(t *testing.T) {
	c, rec, _, _ := setupTestEnv(t, http.MethodPost, "/api/auth/totp/reset", bytes.NewReader([]byte("{bad json")))

	claims := &auth.Claims{Username: "totp-reset-user"}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	err := TOTPReset(c)
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

// -- RevokeAllRefreshTokens handler tests --

// TestRevokeAllRefreshTokens_Success verifies all refresh tokens are revoked
func TestRevokeAllRefreshTokens_Success(t *testing.T) {
	username := "revoke-all-user"

	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/revoke-all", nil)

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: RevokeAllUserTokens (models.RevokeAllUserTokens)
	revokeSQL := `UPDATE refresh_tokens SET revoked = true WHERE username = \?`
	mock.ExpectExec(revokeSQL).WithArgs(username).WillReturnResult(sqlmock.NewResult(0, 3))

	// Mock: LogUserAction
	logSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logSQL).WithArgs(username, "revoked all refresh tokens", "").WillReturnResult(sqlmock.NewResult(1, 1))

	err := RevokeAllRefreshTokens(c)
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

	// Mock: ValidateRefreshToken - returns expired
	// Actual SQL: SELECT id, username, expires_at, revoked, last_used FROM refresh_tokens WHERE token_hash = ?
	validateSQL := `SELECT id, username, expires_at, revoked, last_used FROM refresh_tokens WHERE token_hash = \?`
	expiredTime := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	rows := sqlmock.NewRows([]string{"id", "username", "expires_at", "revoked", "last_used"}).
		AddRow("token-id", "testuser", expiredTime, false, nil)
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

	// Mock: ValidateRefreshToken - token not found (no rows returned)
	validateSQL := `SELECT id, username, expires_at, revoked, last_used FROM refresh_tokens WHERE token_hash = \?`
	mock.ExpectQuery(validateSQL).WithArgs(sqlmock.AnyArg()).WillReturnRows(sqlmock.NewRows([]string{
		"id", "username", "expires_at", "revoked", "last_used",
	}))

	err := RefreshToken(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// -- ForceRevokeAllTokens handler tests --

// TestForceRevokeAllTokens_EmptyReason verifies default reason is used when none provided
func TestForceRevokeAllTokens_EmptyReason(t *testing.T) {
	username := "force-revoke-user"

	body, _ := json.Marshal(map[string]string{"reason": ""})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/force-revoke", bytes.NewReader(body))

	claims := &auth.Claims{Username: username}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	c.Set("user", token)

	// Mock: RevokeAllUserTokens
	revokeRefreshSQL := `UPDATE refresh_tokens SET revoked = true WHERE username = \?`
	mock.ExpectExec(revokeRefreshSQL).WithArgs(username).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock: RevokeAllUserJWTTokens - inserts into revoked_tokens
	revokeJWTSQL := `INSERT INTO revoked_tokens \(token_id, username, expires_at, reason\) VALUES \(\?, \?, \?, \?\)`
	mock.ExpectExec(revokeJWTSQL).WithArgs(sqlmock.AnyArg(), username, sqlmock.AnyArg(), "security-critical revocation").WillReturnResult(sqlmock.NewResult(1, 1))

	// Mock: LogUserAction
	logSQL := `INSERT INTO user_activity \(username, action, target\) VALUES \(\?, \?, \?\)`
	mock.ExpectExec(logSQL).WithArgs(username, "force revoked all tokens", "security-critical revocation").WillReturnResult(sqlmock.NewResult(1, 1))

	err := ForceRevokeAllTokens(c)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "revoked")

	assert.NoError(t, mock.ExpectationsWereMet())
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

	// Mock RevokeAllUserJWTTokens (inserts into revoked_tokens)
	mockDB.ExpectExec(`INSERT INTO revoked_tokens`).
		WithArgs(sqlmock.AnyArg(), targetUsername, sqlmock.AnyArg(), sqlmock.AnyArg()).
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

// TestRefreshToken_Success verifies valid refresh token issues new JWT + new refresh token
func TestRefreshToken_Success(t *testing.T) {
	refreshTokenValue := "valid-refresh-token-uuid-for-success-test"
	username := "refresh-success-user"

	body, _ := json.Marshal(map[string]string{"refresh_token": refreshTokenValue})
	c, rec, mock, _ := setupTestEnv(t, http.MethodPost, "/api/auth/refresh", bytes.NewReader(body))

	// Mock: ValidateRefreshToken - valid, non-expired, non-revoked
	validateSQL := `SELECT id, username, expires_at, revoked, last_used FROM refresh_tokens WHERE token_hash = \?`
	futureExpiry := time.Now().Add(14 * 24 * time.Hour).Format(time.RFC3339)
	rows := sqlmock.NewRows([]string{"id", "username", "expires_at", "revoked", "last_used"}).
		AddRow("token-id-1", username, futureExpiry, false, nil)
	mock.ExpectQuery(validateSQL).WithArgs(sqlmock.AnyArg()).WillReturnRows(rows)

	// Mock: ValidateRefreshToken sliding window UPDATE
	updateExpirySQL := `UPDATE refresh_tokens SET expires_at = \?, last_used = \? WHERE id = \?`
	mock.ExpectExec(updateExpirySQL).WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), "token-id-1").WillReturnResult(sqlmock.NewResult(0, 1))

	// Note: IsUserJWTRevoked checks in-memory cache first. For a fresh username,
	// the cache returns "not revoked" without hitting the DB, so no mock needed.

	// auth.GenerateToken() works thanks to TestMain (Ed25519 keys initialized)

	// Mock: RevokeRefreshToken (old token rotation)
	revokeOldSQL := `UPDATE refresh_tokens SET revoked = true WHERE token_hash = \?`
	mock.ExpectExec(revokeOldSQL).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))

	// Mock: CreateRefreshToken (new token) - actual INSERT has 7 columns
	insertNewSQL := `INSERT INTO refresh_tokens \(id, username, token_hash, expires_at, created_at, revoked, last_used\) VALUES \(\?, \?, \?, \?, \?, \?, \?\)`
	mock.ExpectExec(insertNewSQL).WithArgs(sqlmock.AnyArg(), username, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), false, nil).WillReturnResult(sqlmock.NewResult(1, 1))

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

// Suppress unused import warnings
var _ = models.ErrRefreshTokenExpired
