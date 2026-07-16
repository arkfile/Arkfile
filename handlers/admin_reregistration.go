package handlers

import (
	"database/sql"
	"net/http"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
)

// AdminFlagReregistrationRequest is the body for flagging account(s) for OPAQUE
// re-registration. Confirmation is mandatory because the action ends the
// affected sessions and forces an interactive re-registration on next login.
type AdminFlagReregistrationRequest struct {
	Confirm bool `json:"confirm"`
}

// flagUserForReregistration performs the per-user state change used by both the
// single-user and all-users admin paths: it removes the account's OPAQUE record
// (so the next login lands on the flagged re-registration branch) and sets the
// re-registration flag, atomically. It does not touch files, MFA, shares, or any
// other user data.
func flagUserForReregistration(tx *sql.Tx, username string) error {
	if _, err := tx.Exec(`DELETE FROM opaque_user_data WHERE username = ?`, username); err != nil {
		return err
	}
	return models.SetUserRequiresReregistration(tx, username, true)
}

// forceLogoutUser revokes the user's refresh tokens and outstanding JWTs.
func forceLogoutUser(username, reason string) error {
	return terminateUserSessions(username, reason)
}

// AdminFlagUserReregistration flags a single account for OPAQUE re-registration.
// This is the routine path operators use when rotating one account's OPAQUE
// credentials. The user keeps all files, shares, MFA enrollment, and settings;
// only their OPAQUE record is replaced, during the next sign-in.
func AdminFlagUserReregistration(c echo.Context) error {
	targetUsername := c.Param("username")
	adminUsername := auth.GetUsernameFromToken(c)

	if targetUsername == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}

	var req AdminFlagReregistrationRequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}
	if !req.Confirm {
		return JSONError(c, http.StatusBadRequest, "Confirmation is required to flag a user for re-registration")
	}

	if _, err := models.GetUserByUsername(database.DB, targetUsername); err != nil {
		return JSONError(c, http.StatusNotFound, "User not found")
	}

	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to begin re-registration flag tx for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag user for re-registration")
	}
	defer tx.Rollback()

	if err := flagUserForReregistration(tx, targetUsername); err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to flag %s for re-registration: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag user for re-registration")
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to commit re-registration flag for %s: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag user for re-registration")
	}

	if err := forceLogoutUser(targetUsername, "admin opaque re-registration"); err != nil {
		logging.ErrorLogger.Printf("Admin %s flagged %s but failed to revoke sessions: %v", adminUsername, targetUsername, err)
		return JSONError(c, http.StatusInternalServerError, "User flagged but failed to revoke sessions; run force-logout manually")
	}

	database.LogUserAction(targetUsername, "flagged for OPAQUE re-registration by admin", adminUsername)
	database.LogUserAction(adminUsername, "flagged user for OPAQUE re-registration", targetUsername)
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "admin_flag_reregistration",
			"target_username": targetUsername,
			"force_logout":    true,
		},
	)

	return JSONResponse(c, http.StatusOK, "User flagged for OPAQUE re-registration", map[string]interface{}{
		"username":     targetUsername,
		"force_logout": true,
	})
}

// AdminFlagAllUsersReregistration flags every active account for OPAQUE
// re-registration. Used when rotating the OPAQUE server keys for the whole
// deployment. Every user re-registers (interactively, on next login) without
// losing files, shares, MFA, or settings.
func AdminFlagAllUsersReregistration(c echo.Context) error {
	adminUsername := auth.GetUsernameFromToken(c)

	var req AdminFlagReregistrationRequest
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}
	if !req.Confirm {
		return JSONError(c, http.StatusBadRequest, "Confirmation is required to flag all users for re-registration")
	}

	usernames, err := allActiveUsernames(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to list users for re-registration: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag users for re-registration")
	}

	tx, err := database.DB.Begin()
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to begin all-users re-registration tx: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag users for re-registration")
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM opaque_user_data`); err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to clear OPAQUE records for all users: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag users for re-registration")
	}

	flagged, err := models.FlagAllUsersForReregistration(tx)
	if err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to flag all users for re-registration: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag users for re-registration")
	}

	if err := tx.Commit(); err != nil {
		logging.ErrorLogger.Printf("Admin %s failed to commit all-users re-registration: %v", adminUsername, err)
		return JSONError(c, http.StatusInternalServerError, "Failed to flag users for re-registration")
	}

	// Force-logout every account so the rotation takes effect immediately.
	revokeFailures := 0
	for _, username := range usernames {
		if err := forceLogoutUser(username, "admin opaque re-registration (all users)"); err != nil {
			revokeFailures++
			logging.ErrorLogger.Printf("Admin %s flagged all users but failed to revoke sessions for %s: %v", adminUsername, username, err)
		}
	}

	database.LogUserAction(adminUsername, "flagged all users for OPAQUE re-registration", "")
	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":       "admin_flag_reregistration_all",
			"users_flagged":   flagged,
			"revoke_failures": revokeFailures,
		},
	)

	return JSONResponse(c, http.StatusOK, "All users flagged for OPAQUE re-registration", map[string]interface{}{
		"users_flagged":   flagged,
		"revoke_failures": revokeFailures,
	})
}

// allActiveUsernames returns every non-deleted username for the force-logout sweep.
func allActiveUsernames(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT username FROM users WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var usernames []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		usernames = append(usernames, u)
	}
	return usernames, rows.Err()
}
