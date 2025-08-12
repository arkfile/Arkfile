package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// AdminCleanupRequest represents the request payload for test user cleanup
type AdminCleanupRequest struct {
	Username string `json:"username" validate:"required"`
	Confirm  bool   `json:"confirm" validate:"required"`
}

// AdminCleanupResponse represents the response from test user cleanup
type AdminCleanupResponse struct {
	Success       bool                   `json:"success"`
	TablesCleared map[string]int         `json:"tables_cleaned"`
	TotalRows     int                    `json:"total_rows_affected"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// AdminApproveRequest represents the request payload for user approval
type AdminApproveRequest struct {
	ApprovedBy string `json:"approved_by" validate:"required"`
}

// AdminApproveResponse represents the response from user approval
type AdminApproveResponse struct {
	Success    bool      `json:"success"`
	Username   string    `json:"username"`
	IsApproved bool      `json:"is_approved"`
	ApprovedBy string    `json:"approved_by"`
	ApprovedAt time.Time `json:"approved_at"`
}

// AdminUserStatusResponse represents the comprehensive user status response
type AdminUserStatusResponse struct {
	Exists   bool                   `json:"exists"`
	Username string                 `json:"username,omitempty"`
	User     *AdminUserInfo         `json:"user,omitempty"`
	TOTP     *AdminTOTPStatus       `json:"totp,omitempty"`
	OPAQUE   *AdminOPAQUEStatus     `json:"opaque,omitempty"`
	Tokens   *AdminTokenStatus      `json:"tokens,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// AdminUserInfo represents basic user information
type AdminUserInfo struct {
	ID         int64     `json:"id"`
	Username   string    `json:"username"`
	Email      *string   `json:"email,omitempty"`
	IsApproved bool      `json:"is_approved"`
	IsAdmin    bool      `json:"is_admin"`
	CreatedAt  time.Time `json:"created_at"`
}

// AdminTOTPStatus represents TOTP status information
type AdminTOTPStatus struct {
	Present        bool `json:"present"`
	Decryptable    bool `json:"decryptable"`
	Enabled        bool `json:"enabled"`
	SetupCompleted bool `json:"setup_completed"`
}

// AdminOPAQUEStatus represents OPAQUE status information
type AdminOPAQUEStatus struct {
	HasAccount   bool `json:"has_account"`
	RecordsCount int  `json:"records_count"`
}

// AdminTokenStatus represents token status information
type AdminTokenStatus struct {
	ActiveRefreshTokens int `json:"active_refresh_tokens"`
	RevokedTokens       int `json:"revoked_tokens"`
}

// AdminCleanupTestUser performs comprehensive cleanup of test user data
func AdminCleanupTestUser(c echo.Context) error {
	// Parse request
	var req AdminCleanupRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	// Validate request
	if req.Username == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
	}

	if !req.Confirm {
		return echo.NewHTTPError(http.StatusBadRequest, "Confirmation is required for cleanup operation")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Perform cleanup in a transaction
	tx, err := database.DB.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start cleanup transaction")
	}
	defer tx.Rollback()

	tablesCleared := make(map[string]int)
	totalRows := 0

	// Cleanup operations with proper error handling
	cleanupOperations := []struct {
		table string
		query string
	}{
		{"users", "DELETE FROM users WHERE username = ?"},
		{"opaque_user_data", "DELETE FROM opaque_user_data WHERE username = ?"},
		{"opaque_password_records", "DELETE FROM opaque_password_records WHERE record_identifier = ? OR associated_username = ?"},
		{"user_totp", "DELETE FROM user_totp WHERE username = ?"},
		{"refresh_tokens", "DELETE FROM refresh_tokens WHERE username = ?"},
		{"totp_usage_log", "DELETE FROM totp_usage_log WHERE username = ?"},
		{"totp_backup_usage", "DELETE FROM totp_backup_usage WHERE username = ?"},
		{"revoked_tokens", "DELETE FROM revoked_tokens WHERE username = ?"},
		{"user_activity", "DELETE FROM user_activity WHERE username = ?"},
	}

	for _, op := range cleanupOperations {
		var result sql.Result
		var err error

		// Handle tables that need different parameter patterns
		if op.table == "opaque_password_records" {
			result, err = tx.Exec(op.query, req.Username, req.Username)
		} else {
			result, err = tx.Exec(op.query, req.Username)
		}

		if err != nil {
			// Log error but continue with other tables
			logging.ErrorLogger.Printf("Admin cleanup failed for table %s: %v", op.table, err)
			tablesCleared[op.table] = 0
		} else {
			rowsAffected, _ := result.RowsAffected()
			rowsAffectedInt := int(rowsAffected)
			tablesCleared[op.table] = rowsAffectedInt
			totalRows += rowsAffectedInt
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Admin cleanup transaction commit failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to complete cleanup operation")
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":           "test_user_cleanup",
			"target_username":     req.Username,
			"tables_cleaned":      len(tablesCleared),
			"total_rows_affected": totalRows,
		},
	)

	response := AdminCleanupResponse{
		Success:       true,
		TablesCleared: tablesCleared,
		TotalRows:     totalRows,
		Details: map[string]interface{}{
			"cleanup_timestamp": time.Now().UTC(),
			"admin_username":    adminUsername,
		},
	}

	return c.JSON(http.StatusOK, response)
}

// AdminTOTPDecryptCheck provides TOTP diagnostic information for development
func AdminTOTPDecryptCheck(c echo.Context) error {
	// Only available in debug mode
	debugMode := strings.ToLower(os.Getenv("DEBUG_MODE"))
	if debugMode != "true" && debugMode != "1" {
		return echo.NewHTTPError(http.StatusNotFound, "Endpoint not available")
	}

	targetUsername := c.Param("username")
	if targetUsername == "" {
		// Use current user if no username specified
		targetUsername = auth.GetUsernameFromToken(c)
		if targetUsername == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "Username required")
		}
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Use the diagnostic helper we added to auth/totp.go
	present, decryptable, enabled, setupCompleted, err := auth.CanDecryptTOTPSecret(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("TOTP decrypt check failed for %s: %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to check TOTP decrypt status")
	}

	// Get additional metadata for debugging
	var createdAt, lastUsed interface{}
	err = database.DB.QueryRow(`
		SELECT created_at, last_used 
		FROM user_totp 
		WHERE username = ?`,
		targetUsername,
	).Scan(&createdAt, &lastUsed)

	response := map[string]interface{}{
		"username":        targetUsername,
		"present":         present,
		"decryptable":     decryptable,
		"enabled":         enabled,
		"setup_completed": setupCompleted,
		"created_at":      createdAt,
		"last_used":       lastUsed,
		"debug_info": map[string]interface{}{
			"checked_by":    adminUsername,
			"checked_at":    time.Now().UTC(),
			"debug_enabled": true,
		},
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "totp_decrypt_check",
			"target_username": targetUsername,
			"present":         present,
			"decryptable":     decryptable,
		},
	)

	return c.JSON(http.StatusOK, response)
}

// AdminApproveUser approves a specific user for testing
func AdminApproveUser(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter is required")
	}

	// Parse request
	var req AdminApproveRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if req.ApprovedBy == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "approved_by field is required")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Get the target user
	user, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("User '%s' not found", targetUsername))
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Approve the user using the existing method
	if err := user.ApproveUser(database.DB, req.ApprovedBy); err != nil {
		logging.ErrorLogger.Printf("Admin user approval failed: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to approve user")
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "user_approval",
			"target_username": targetUsername,
			"approved_by":     req.ApprovedBy,
		},
	)

	response := AdminApproveResponse{
		Success:    true,
		Username:   user.Username,
		IsApproved: user.IsApproved,
		ApprovedBy: req.ApprovedBy,
		ApprovedAt: user.ApprovedAt.Time,
	}

	return c.JSON(http.StatusOK, response)
}

// AdminGetUserStatus returns comprehensive user status information
func AdminGetUserStatus(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter is required")
	}

	// Get admin username for audit logging
	adminUsername := auth.GetUsernameFromToken(c)

	// Get the target user
	user, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		if err == sql.ErrNoRows {
			// User doesn't exist
			response := AdminUserStatusResponse{
				Exists:   false,
				Username: targetUsername,
			}
			return c.JSON(http.StatusOK, response)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve user")
	}

	// Build comprehensive status response
	response := AdminUserStatusResponse{
		Exists:   true,
		Username: targetUsername,
		User: &AdminUserInfo{
			ID:         user.ID,
			Username:   user.Username,
			Email:      user.Email,
			IsApproved: user.IsApproved,
			IsAdmin:    user.IsAdmin,
			CreatedAt:  user.CreatedAt,
		},
	}

	// Get comprehensive TOTP status using diagnostic helper
	present, decryptable, enabled, setupCompleted, err := auth.CanDecryptTOTPSecret(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get TOTP diagnostic status for %s: %v", targetUsername, err)
		response.Details = map[string]interface{}{
			"totp_status_error": "Failed to retrieve TOTP diagnostic status",
		}
	} else {
		response.TOTP = &AdminTOTPStatus{
			Present:        present,
			Decryptable:    decryptable,
			Enabled:        enabled,
			SetupCompleted: setupCompleted,
		}
	}

	// Get OPAQUE status
	opaqueStatus, err := user.GetOPAQUEAccountStatus(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get OPAQUE status for %s: %v", targetUsername, err)
		if response.Details == nil {
			response.Details = make(map[string]interface{})
		}
		response.Details["opaque_status_error"] = "Failed to retrieve OPAQUE status"
	} else {
		response.OPAQUE = &AdminOPAQUEStatus{
			HasAccount:   opaqueStatus.HasAccountPassword,
			RecordsCount: opaqueStatus.FilePasswordCount,
		}
	}

	// Get token status
	var activeTokens, revokedTokens int
	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM refresh_tokens WHERE username = ? AND revoked = 0",
		targetUsername,
	).Scan(&activeTokens)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get active tokens for %s: %v", targetUsername, err)
		activeTokens = 0
	}

	err = database.DB.QueryRow(
		"SELECT COUNT(*) FROM revoked_tokens WHERE username = ?",
		targetUsername,
	).Scan(&revokedTokens)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get revoked tokens for %s: %v", targetUsername, err)
		revokedTokens = 0
	}

	response.Tokens = &AdminTokenStatus{
		ActiveRefreshTokens: activeTokens,
		RevokedTokens:       revokedTokens,
	}

	// Log admin action for audit trail
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "user_status_check",
			"target_username": targetUsername,
		},
	)

	return c.JSON(http.StatusOK, response)
}
