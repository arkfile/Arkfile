package handlers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/84adam/arkfile/auth"
	"github.com/84adam/arkfile/database"
	"github.com/84adam/arkfile/logging"
	"github.com/84adam/arkfile/models"
)

// GetPendingUsers returns a list of users pending approval
func GetPendingUsers(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	user, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
	}

	if !user.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get pending users
	users, err := models.GetPendingUsers(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get pending users: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get pending users")
	}

	return c.JSON(http.StatusOK, users)
}

// ApproveUser handles user approval by admin
func ApproveUser(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target user's email
	targetEmail := c.Param("email")
	if targetEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email parameter required")
	}

	// Get target user
	user, err := models.GetUserByEmail(database.DB, targetEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	// Approve user
	if err := user.ApproveUser(database.DB, adminEmail); err != nil {
		logging.ErrorLogger.Printf("Failed to approve user: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to approve user")
	}

	// Log admin action
	database.LogAdminAction(adminEmail, "approve_user", targetEmail, "")
	logging.InfoLogger.Printf("User approved: %s by %s", targetEmail, adminEmail)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "User approved successfully",
	})
}

// UpdateUserStorageLimit handles admin updates to user storage limits
func UpdateUserStorageLimit(c echo.Context) error {
	adminEmail := auth.GetEmailFromToken(c)

	// Check admin privileges
	admin, err := models.GetUserByEmail(database.DB, adminEmail)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get admin user")
	}

	if !admin.HasAdminPrivileges() {
		return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
	}

	// Get target user's email
	targetEmail := c.Param("email")
	if targetEmail == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Email parameter required")
	}

	// Parse new limit
	var request struct {
		StorageLimit int64 `json:"storage_limit_bytes"`
	}
	if err := c.Bind(&request); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}

	if request.StorageLimit <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Storage limit must be positive")
	}

	// Update storage limit
	_, err = database.DB.Exec(
		"UPDATE users SET storage_limit_bytes = ? WHERE email = ?",
		request.StorageLimit, targetEmail,
	)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to update storage limit: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to update storage limit")
	}

	// Log admin action
	database.LogAdminAction(adminEmail, "update_storage_limit", targetEmail,
		fmt.Sprintf("New limit: %d bytes", request.StorageLimit))
	logging.InfoLogger.Printf("Storage limit updated for %s by %s: %d bytes",
		targetEmail, adminEmail, request.StorageLimit)

	return c.JSON(http.StatusOK, map[string]string{
		"message": "Storage limit updated successfully",
	})
}
