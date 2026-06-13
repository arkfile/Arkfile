package handlers

import (
	"net/http"
	"time"

	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/labstack/echo/v4"
)

// AdminPrepareTier3MasterRotation issues a single-use mandate for offline Tier-3 master rotation.
func AdminPrepareTier3MasterRotation(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	mandate, expiresAt, err := auth.IssueTier3RotationMandate(database.DB, adminUsername)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to issue Tier-3 rotation mandate for %s: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to issue rotation mandate")
	}

	logging.LogSecurityEvent(
		logging.EventKeyRotation,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":  "tier3_master_rotation_prepare",
			"expires_at": expiresAt.UTC().Format(time.RFC3339),
		},
	)

	return JSONResponse(c, http.StatusOK, "Tier-3 rotation mandate issued", map[string]interface{}{
		"mandate":    mandate,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
}
