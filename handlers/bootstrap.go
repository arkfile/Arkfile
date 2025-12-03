package handlers

import (
	"encoding/base64"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/84adam/Arkfile/utils"
)

// BootstrapRegisterInitRequest represents the initial bootstrap registration request
type BootstrapRegisterInitRequest struct {
	BootstrapToken      string `json:"bootstrap_token"`
	Username            string `json:"username"`
	RegistrationRequest string `json:"registration_request"` // base64 encoded
}

// BootstrapRegisterFinalizeRequest represents the final bootstrap registration request
type BootstrapRegisterFinalizeRequest struct {
	BootstrapToken     string `json:"bootstrap_token"`
	SessionID          string `json:"session_id"`
	Username           string `json:"username"`
	RegistrationRecord string `json:"registration_record"` // base64 encoded
}

// BootstrapRegisterResponse handles the first step of OPAQUE registration for the bootstrap admin.
func BootstrapRegisterResponse(c echo.Context) error {
	// SECURITY: Strict localhost-only check
	ip := c.RealIP()
	if ip != "127.0.0.1" && ip != "::1" {
		logging.ErrorLogger.Printf("SECURITY ALERT: Bootstrap attempt from non-local IP: %s", ip)
		return JSONError(c, http.StatusForbidden, "Bootstrap endpoints only accessible from localhost", "")
	}

	var request BootstrapRegisterInitRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// 1. Validate Bootstrap Token
	isValid, err := auth.ValidateBootstrapToken(request.BootstrapToken)
	if err != nil {
		logging.ErrorLogger.Printf("Bootstrap token validation error: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to validate token", "")
	}
	if !isValid {
		return JSONError(c, http.StatusUnauthorized, "Invalid bootstrap token", "")
	}

	// 2. Validate Username
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required", "")
	}
	if err := utils.ValidateUsername(request.Username); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid username: "+err.Error(), err.Error())
	}

	// 3. Check if user already exists
	exists, err := models.UserExists(database.DB, request.Username)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Database error", err.Error())
	}
	if exists {
		return JSONError(c, http.StatusConflict, "User already exists", "")
	}

	// 4. Decode registration request from client
	registrationRequest, err := base64.StdEncoding.DecodeString(request.RegistrationRequest)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration request encoding", err.Error())
	}

	// 5. Create server registration response (OPAQUE)
	registrationResponse, registrationSecret, err := auth.CreateRegistrationResponse(registrationRequest)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create registration response: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Registration response creation failed", err.Error())
	}

	// 6. Create session for multi-step protocol
	// We use a specific "bootstrap_registration" type to distinguish from normal registration
	sessionID, err := auth.CreateAuthSession(database.DB, request.Username, "bootstrap_registration", registrationSecret)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create bootstrap session for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Session creation failed", err.Error())
	}

	// 7. Encode response for transmission
	responseB64 := base64.StdEncoding.EncodeToString(registrationResponse)

	return JSONResponse(c, http.StatusOK, "Bootstrap registration initiated", map[string]interface{}{
		"session_id":            sessionID,
		"registration_response": responseB64,
	})
}

// BootstrapRegisterFinalize completes the OPAQUE registration for the bootstrap admin.
func BootstrapRegisterFinalize(c echo.Context) error {
	// SECURITY: Strict localhost-only check
	ip := c.RealIP()
	if ip != "127.0.0.1" && ip != "::1" {
		logging.ErrorLogger.Printf("SECURITY ALERT: Bootstrap attempt from non-local IP: %s", ip)
		return JSONError(c, http.StatusForbidden, "Bootstrap endpoints only accessible from localhost", "")
	}

	var request BootstrapRegisterFinalizeRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format", err.Error())
	}

	// 1. Validate Bootstrap Token
	isValid, err := auth.ValidateBootstrapToken(request.BootstrapToken)
	if err != nil {
		logging.ErrorLogger.Printf("Bootstrap token validation error: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to validate token", "")
	}
	if !isValid {
		return JSONError(c, http.StatusUnauthorized, "Invalid bootstrap token", "")
	}

	// 2. Validate session and get registration secret
	sessionUsername, registrationSecret, err := auth.ValidateAuthSession(database.DB, request.SessionID, "bootstrap_registration")
	if err != nil {
		logging.ErrorLogger.Printf("Invalid bootstrap session: %v", err)
		return JSONError(c, http.StatusUnauthorized, "Invalid or expired session", err.Error())
	}

	// 3. Verify username matches session
	if sessionUsername != request.Username {
		return JSONError(c, http.StatusBadRequest, "Username mismatch", "")
	}

	// 4. Decode registration record
	registrationRecord, err := base64.StdEncoding.DecodeString(request.RegistrationRecord)
	if err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid registration record encoding", err.Error())
	}

	// 5. Store user record with server secret (OPAQUE)
	userRecord, err := auth.StoreUserRecord(registrationSecret, registrationRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store user record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store user record", err.Error())
	}

	// 6. Create Admin User in Database
	// Start transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Transaction failed", err.Error())
	}
	defer tx.Rollback()

	// Create user
	userID, err := models.CreateUser(tx, request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to create user %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "User creation failed", err.Error())
	}

	// Set as Admin and Approved
	_, err = tx.Exec("UPDATE users SET is_admin = 1, is_approved = 1 WHERE id = ?", userID)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to set admin privileges for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to set admin privileges", err.Error())
	}

	// Store OPAQUE record
	_, err = tx.Exec(`
		INSERT INTO opaque_user_data 
		(username, opaque_user_record, created_at)
		VALUES (?, ?, CURRENT_TIMESTAMP)`,
		request.Username, userRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to store OPAQUE record for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to store OPAQUE record", err.Error())
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Commit failed", err.Error())
	}

	// 7. Cleanup Session
	auth.DeleteAuthSession(database.DB, request.SessionID)

	// 8. DO NOT delete bootstrap token yet - it will be deleted after first admin login (proof-of-life)

	// 9. Generate temporary token for TOTP setup
	tempToken, _, err := auth.GenerateTemporaryTOTPToken(request.Username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to generate temporary TOTP token for %s: %v", request.Username, err)
		return JSONError(c, http.StatusInternalServerError, "Registration succeeded but setup token creation failed", err.Error())
	}

	logging.InfoLogger.Printf("BOOTSTRAP: Admin user %s created successfully via OPAQUE.", request.Username)

	return JSONResponse(c, http.StatusCreated, "Admin account created successfully. Two-factor authentication setup is required.", map[string]interface{}{
		"requires_totp_setup": true,
		"requires_totp":       true,
		"temp_token":          tempToken,
		"auth_method":         "OPAQUE",
		"username":            request.Username,
		"is_admin":            true,
	})
}
