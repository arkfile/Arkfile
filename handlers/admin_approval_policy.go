package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/arkfile/Arkfile/config"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/logging"
)

// systemSettingsRequireApprovalKey is the system_settings key for the live
// auto-approval policy.
const systemSettingsRequireApprovalKey = "require_approval"

// AdminGetApprovalPolicy returns the current auto-approval policy and whether
// it is the persisted system_settings value or the env-default fallback.
func AdminGetApprovalPolicy(c echo.Context) error {
	if _, errResp := requireAdminWithUsername(c); errResp != nil {
		return errResp
	}

	value, source, err := readRequireApprovalSetting(database.DB)
	if err != nil {
		logging.ErrorLogger.Printf("Failed to read approval policy: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to read approval policy")
	}

	return JSONResponse(c, http.StatusOK, "Approval policy", map[string]interface{}{
		"require_approval": value,
		"source":           source,
	})
}

// AdminSetApprovalPolicy updates the instance-wide auto-approval policy live.
// require_approval=true means new registrations require explicit admin
// approval; false means they are auto-approved at registration time. The value
// is persisted in system_settings so it survives restarts, and applied to the
// in-memory live state so it takes effect immediately.
func AdminSetApprovalPolicy(c echo.Context) error {
	adminUsername, errResp := requireAdminWithUsername(c)
	if errResp != nil {
		return errResp
	}

	var req struct {
		RequireApproval *bool `json:"require_approval"`
	}
	if err := c.Bind(&req); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request format")
	}
	if req.RequireApproval == nil {
		return JSONError(c, http.StatusBadRequest, "require_approval field is required")
	}

	if err := writeRequireApprovalSetting(database.DB, *req.RequireApproval, adminUsername); err != nil {
		logging.ErrorLogger.Printf("Failed to persist approval policy: %v", err)
		return JSONError(c, http.StatusInternalServerError, "Failed to update approval policy")
	}

	config.SetRequireApproval(*req.RequireApproval)

	logging.LogSecurityEvent(
		logging.EventAdminAccess,
		nil,
		&adminUsername,
		nil,
		map[string]interface{}{
			"operation":        "set_approval_policy",
			"require_approval": *req.RequireApproval,
		},
	)
	if err := LogAdminAction(database.DB, adminUsername, "set_approval_policy", "",
		fmt.Sprintf("require_approval=%t", *req.RequireApproval)); err != nil {
		logging.ErrorLogger.Printf("Failed to log approval policy action: %v", err)
	}

	return JSONResponse(c, http.StatusOK, "Approval policy updated", map[string]interface{}{
		"require_approval": *req.RequireApproval,
	})
}

// readRequireApprovalSetting returns the persisted require_approval value and
// its source ("system_settings" or "env"). When no row exists yet, the current
// live config.RequireApproval() value is reported with source "env".
func readRequireApprovalSetting(db *sql.DB) (bool, string, error) {
	var valueStr string
	err := db.QueryRow(
		`SELECT value FROM system_settings WHERE key = ?`,
		systemSettingsRequireApprovalKey,
	).Scan(&valueStr)
	if err == sql.ErrNoRows {
		return config.RequireApproval(), "env", nil
	}
	if err != nil {
		return false, "", err
	}
	parsed, perr := parseStrictBool(valueStr)
	if perr != nil {
		return false, "", fmt.Errorf("invalid stored require_approval value %q: %w", valueStr, perr)
	}
	return parsed, "system_settings", nil
}

// writeRequireApprovalSetting upserts the require_approval row.
func writeRequireApprovalSetting(db *sql.DB, enabled bool, updatedBy string) error {
	valueStr := "false"
	if enabled {
		valueStr = "true"
	}
	_, err := db.Exec(
		`INSERT INTO system_settings (key, value, updated_by, updated_at)
		 VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		systemSettingsRequireApprovalKey, valueStr, updatedBy,
	)
	return err
}

// parseStrictBool parses only "true"/"false" (case-insensitive, trimmed).
func parseStrictBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1":
		return true, nil
	case "false", "0":
		return false, nil
	default:
		return false, fmt.Errorf("must be \"true\" or \"false\"")
	}
}
