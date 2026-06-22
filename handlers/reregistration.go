package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// Stable error codes for the OPAQUE re-registration contract. Clients branch on
// these rather than parsing human-readable messages.
const (
	CodeAccountRequiresReregistration = "account_requires_reregistration"
	CodeReregistrationTokenInvalid    = "reregistration_token_invalid"
)

// reregistrationVerifier is a single account-key-encrypted metadata sample the
// client uses to confirm, before finalizing, that the entered password still
// derives the Account Key that wraps the user's existing files. The sample is
// account-key-encrypted, so it reveals no filename or content to the server or
// to anyone who receives it.
type reregistrationVerifier struct {
	FileID            string `json:"file_id"`
	OwnerUsername     string `json:"owner_username"`
	EncryptedFilename string `json:"encrypted_filename"`
	FilenameNonce     string `json:"filename_nonce"`
}

// respondAccountRequiresReregistration is returned from the login response step
// when an account has been flagged for OPAQUE credential rotation. It carries a
// short-lived handoff token authorizing only the ceremony, the authoritative
// count of files the user owns (so the client knows whether the pre-finalize
// password-match check is required), and, when the user owns files, one verifier
// sample for that check.
func respondAccountRequiresReregistration(c echo.Context, username string) error {
	handoffToken, expiresAt, err := auth.GenerateReregistrationToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to issue re-registration handoff token for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	fileCount, err := ownedFileCount(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to count files for %s during re-registration: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Authentication failed")
	}

	// Browser clients carry the handoff token automatically via the temp cookie
	// (CookieTokenMiddleware copies it into the Authorization header). Clear any
	// stale full/refresh cookies first so the full-tier cookie does not take
	// precedence over the handoff token during the ceremony. CLI clients instead
	// read reregistration_token from the body and send it as a Bearer token.
	clearSessionCookies(c)
	issueTempCookie(c, handoffToken)

	data := map[string]interface{}{
		"reregistration_token": handoffToken,
		"expires_at":           expiresAt.UTC().Format(time.RFC3339),
		"file_count":           fileCount,
	}

	if fileCount > 0 {
		verifier, vErr := reregistrationVerifierSample(database.DB, username)
		if vErr != nil {
			logging.ErrorLogger.Printf("Failed to load re-registration verifier for %s: %v", username, vErr)
			return JSONError(c, http.StatusInternalServerError, "Authentication failed")
		}
		if verifier != nil {
			data["verifier"] = verifier
		}
	}

	logging.LogSecurityEvent(
		logging.EventOpaqueLoginFailure,
		nil,
		&username,
		nil,
		map[string]interface{}{
			"operation": "account_requires_reregistration",
			"username":  username,
		},
	)

	return JSONErrorCodeData(c, http.StatusConflict, CodeAccountRequiresReregistration,
		"This account needs a one-time security re-registration after an OPAQUE server key update. Your files, shares, and settings are safe; sign in with your existing account password to reconnect.",
		data)
}

// ownedFileCount returns the authoritative number of files the user owns. File
// ownership rows are server-side plaintext, so this is a trustworthy signal for
// whether the client must run the password-match check.
func ownedFileCount(db *sql.DB, username string) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM file_metadata WHERE owner_username = ?`, username).Scan(&count)
	return count, err
}

// reregistrationVerifierSample returns one account-key-encrypted filename sample
// for the user, or nil if the user owns no files.
func reregistrationVerifierSample(db *sql.DB, username string) (*reregistrationVerifier, error) {
	v := &reregistrationVerifier{OwnerUsername: username}
	err := db.QueryRow(
		`SELECT file_id, encrypted_filename, filename_nonce FROM file_metadata WHERE owner_username = ? LIMIT 1`,
		username,
	).Scan(&v.FileID, &v.EncryptedFilename, &v.FilenameNonce)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

// ReregisterResponse is the first step of the OPAQUE re-registration ceremony. It
// is gated by the handoff token (aud=arkfile-reregistration). Unlike normal
// registration it does not reject the existing username; it runs the OPAQUE
// registration response under the current server keys for an account that is
// flagged for re-registration.
func ReregisterResponse(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return JSONErrorCode(c, http.StatusUnauthorized, CodeReregistrationTokenInvalid, "Re-registration token is missing or invalid")
	}

	flagged, err := models.UserRequiresReregistration(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Re-registration flag check failed for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration failed")
	}
	if !flagged {
		return JSONErrorCode(c, http.StatusConflict, CodeReregistrationTokenInvalid, "Account is not awaiting re-registration")
	}

	var request struct {
		RegistrationRequest string `json:"registration_request"` // base64 encoded
	}
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	registrationRequest, err := base64.StdEncoding.DecodeString(request.RegistrationRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration request encoding")
	}

	registrationResponse, registrationSecret, err := auth.CreateRegistrationResponse(registrationRequest)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create re-registration response for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration response creation failed")
	}

	sessionID, err := auth.CreateAuthSession(database.DB, username, "reregistration", registrationSecret)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create re-registration session for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed")
	}

	return JSONResponse(c, http.StatusOK, "Re-registration initiated", map[string]interface{}{
		"session_id":            sessionID,
		"registration_response": base64.StdEncoding.EncodeToString(registrationResponse),
	})
}

// ReregisterFinalize completes the ceremony. It replaces the single
// opaque_user_data record in place (without creating any user or child rows),
// clears the re-registration flag, and continues into the existing MFA flow,
// since the user's second-factor enrollment is preserved.
func ReregisterFinalize(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return JSONErrorCode(c, http.StatusUnauthorized, CodeReregistrationTokenInvalid, "Re-registration token is missing or invalid")
	}

	var request struct {
		SessionID          string `json:"session_id"`
		RegistrationRecord string `json:"registration_record"` // base64 encoded
	}
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}

	flagged, err := models.UserRequiresReregistration(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Re-registration flag check failed for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration failed")
	}
	if !flagged {
		return JSONErrorCode(c, http.StatusConflict, CodeReregistrationTokenInvalid, "Account is not awaiting re-registration")
	}

	sessionUsername, registrationSecret, err := auth.ValidateAuthSession(database.DB, request.SessionID, "reregistration")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid re-registration session for %s: %v", username, err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session")
	}
	if sessionUsername != username {
		logging.ErrorLogger.Printf("Username mismatch in re-registration: session=%s, token=%s", sessionUsername, username)
		return JSONError(c, http.StatusBadRequest, "Username mismatch")
	}

	registrationRecord, err := base64.StdEncoding.DecodeString(request.RegistrationRecord)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration record encoding")
	}

	userRecord, err := auth.StoreUserRecord(registrationSecret, registrationRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store re-registration record for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store user record")
	}

	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("Failed to start re-registration transaction for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration failed")
	}
	defer tx.Rollback()

	// Replace only the OPAQUE record. The users row and every child row
	// (files, MFA, shares, credits, contact info) are left untouched.
	if _, err := tx.Exec(`
		INSERT INTO opaque_user_data (username, opaque_user_record, created_at, updated_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(username) DO UPDATE SET
			opaque_user_record = excluded.opaque_user_record,
			updated_at = CURRENT_TIMESTAMP`,
		username, hex.EncodeToString(userRecord)); err != nil {
		logging.ErrorLogger.Printf("Failed to replace OPAQUE record for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store OPAQUE record")
	}

	if err := models.SetUserRequiresReregistration(tx, username, false); err != nil {
		logging.ErrorLogger.Printf("Failed to clear re-registration flag for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration failed")
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Failed to commit re-registration for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration failed")
	}

	if err := auth.DeleteAuthSession(database.DB, request.SessionID); err != nil {
		logging.ErrorLogger.Printf("Warning: failed to delete re-registration session for %s: %v", username, err)
	}

	database.LogUserAction(username, "completed OPAQUE re-registration", "")
	logging.LogSecurityEvent(
		logging.EventOpaqueLoginSuccess,
		nil,
		&username,
		nil,
		map[string]interface{}{
			"operation": "opaque_reregistration_complete",
			"username":  username,
		},
	)

	// The user's MFA enrollment is preserved, so continue into the existing
	// second-factor flow exactly as a normal login does.
	tempToken, _, err := auth.GenerateTemporaryMFAToken(username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate MFA token after re-registration for %s: %v", username, err)
		return JSONError(c, http.StatusInternalServerError, "Re-registration succeeded but session setup failed")
	}
	issueTempCookie(c, tempToken)

	mfaMethod, _ := auth.GetUserMFAMethodType(database.DB, username)

	return JSONResponse(c, http.StatusOK, "Re-registration complete. Second factor required.", map[string]interface{}{
		"requires_mfa": true,
		"temp_token":   tempToken,
		"auth_method":  "OPAQUE",
		"mfa_method":   mfaMethod,
	})
}
