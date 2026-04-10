// contact_info.go - Handlers for user contact information management
// Contact info is encrypted server-side with a key derived from the master key.
// Users can set, view, and delete their own contact info.
// Admins can view any user's contact info for operational communication.

package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// GetContactInfo handles GET /api/user/contact-info
// Returns the authenticated user's own contact information.
func GetContactInfo(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	info, err := models.GetContactInfo(database.DB, username)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get contact info for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve contact information")
	}

	if info == nil {
		return JSONResponse(c, http.StatusOK, "No contact information set", map[string]interface{}{
			"has_contact_info": false,
		})
	}

	return JSONResponse(c, http.StatusOK, "Contact information retrieved", map[string]interface{}{
		"has_contact_info": true,
		"contact_info":     info,
	})
}

// PutContactInfo handles PUT /api/user/contact-info
// Creates or updates the authenticated user's contact information.
func PutContactInfo(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	// Read and limit request body
	body, err := io.ReadAll(io.LimitReader(c.Request().Body, int64(models.MaxContactInfoSize+1024)))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Failed to read request body")
	}

	if len(body) > models.MaxContactInfoSize {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Contact information exceeds maximum size")
	}

	// Parse contact info
	var info models.ContactInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid JSON format")
	}

	// Validate
	if err := info.Validate(); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Save (encrypts and stores)
	if err := models.SaveContactInfo(database.DB, username, &info); err != nil {
		logging.ErrorLogger.Printf("Failed to save contact info for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save contact information")
	}

	return JSONResponse(c, http.StatusOK, "Contact information saved", nil)
}

// DeleteContactInfo handles DELETE /api/user/contact-info
// Deletes the authenticated user's contact information.
func DeleteContactInfo(c echo.Context) error {
	username := auth.GetUsernameFromToken(c)
	if username == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication required")
	}

	if err := models.DeleteContactInfo(database.DB, username); err != nil {
		if err.Error() == "no contact info found for user" {
			return echo.NewHTTPError(http.StatusNotFound, "No contact information to delete")
		}
		logging.ErrorLogger.Printf("Failed to delete contact info for %s: %v", username, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete contact information")
	}

	return JSONResponse(c, http.StatusOK, "Contact information deleted", nil)
}

// AdminGetContactInfo handles GET /api/admin/users/:username/contact-info
// Returns contact information for any user (admin only).
func AdminGetContactInfo(c echo.Context) error {
	targetUsername := c.Param("username")
	if targetUsername == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Username parameter required")
	}

	adminUsername := auth.GetUsernameFromToken(c)
	logging.InfoLogger.Printf("Admin contact info request: admin=%s target=%s", adminUsername, targetUsername)

	// Verify target user exists
	_, err := models.GetUserByUsername(database.DB, targetUsername)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "User not found")
	}

	info, err := models.GetContactInfo(database.DB, targetUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to get contact info for %s (admin request): %v", targetUsername, err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to retrieve contact information")
	}

	if info == nil {
		return JSONResponse(c, http.StatusOK, "No contact information set for this user", map[string]interface{}{
			"username":         targetUsername,
			"has_contact_info": false,
		})
	}

	return JSONResponse(c, http.StatusOK, "Contact information retrieved", map[string]interface{}{
		"username":         targetUsername,
		"has_contact_info": true,
		"contact_info":     info,
	})
}
