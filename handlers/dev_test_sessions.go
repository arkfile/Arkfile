package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/arkfile/Arkfile/auth"
	"github.com/arkfile/Arkfile/database"
	"github.com/arkfile/Arkfile/models"
	"github.com/labstack/echo/v4"
)

type sessionClockShiftRequest struct {
	Username    string `json:"username"`
	FamilyID    string `json:"family_id,omitempty"`
	IdleSeconds int64  `json:"idle_seconds,omitempty"`
	AgeSeconds  int64  `json:"age_seconds,omitempty"`
}

type ownSessionClockShiftRequest struct {
	IdleSeconds int64 `json:"idle_seconds,omitempty"`
	AgeSeconds  int64 `json:"age_seconds,omitempty"`
}

func validateSessionClockOffsets(idleSeconds, ageSeconds int64) error {
	const maxShiftSeconds = int64((365 * 24 * time.Hour) / time.Second)
	if idleSeconds < 0 || ageSeconds < 0 {
		return fmt.Errorf("clock offsets cannot be negative")
	}
	if idleSeconds == 0 && ageSeconds == 0 {
		return fmt.Errorf("at least one clock offset is required")
	}
	if idleSeconds > maxShiftSeconds || ageSeconds > maxShiftSeconds {
		return fmt.Errorf("clock offsets cannot exceed 365 days")
	}
	return nil
}

func AdminShiftSessionClocks(c echo.Context) error {
	var request sessionClockShiftRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}
	if request.Username == "" {
		return JSONError(c, http.StatusBadRequest, "Username is required")
	}
	if err := validateSessionClockOffsets(request.IdleSeconds, request.AgeSeconds); err != nil {
		return JSONError(c, http.StatusBadRequest, err.Error())
	}

	query := "SELECT family_id FROM session_families WHERE username = ? AND ended_at IS NULL"
	args := []interface{}{request.Username}
	if request.FamilyID != "" {
		query += " AND family_id = ?"
		args = append(args, request.FamilyID)
	}

	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to find session families")
	}
	var familyIDs []string
	for rows.Next() {
		var familyID string
		if err := rows.Scan(&familyID); err != nil {
			rows.Close()
			return JSONError(c, http.StatusInternalServerError, "Failed to read session family")
		}
		familyIDs = append(familyIDs, familyID)
	}
	if err := rows.Close(); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to read session families")
	}
	if err := rows.Err(); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to read session families")
	}
	if len(familyIDs) == 0 {
		return JSONError(c, http.StatusNotFound, "No active session family found")
	}

	now := time.Now()
	for _, familyID := range familyIDs {
		err := models.ShiftSessionFamilyClocks(
			database.DB,
			familyID,
			now,
			time.Duration(request.IdleSeconds)*time.Second,
			time.Duration(request.AgeSeconds)*time.Second,
		)
		if err != nil {
			if err == sql.ErrNoRows {
				return JSONError(c, http.StatusNotFound, "Session family not found")
			}
			return JSONError(c, http.StatusInternalServerError, "Failed to shift session clocks")
		}
	}

	return JSONResponse(c, http.StatusOK, "Session clocks shifted", map[string]interface{}{
		"families_shifted": len(familyIDs),
	})
}

func ShiftOwnSessionClocks(c echo.Context) error {
	var request ownSessionClockShiftRequest
	if err := c.Bind(&request); err != nil {
		return JSONError(c, http.StatusBadRequest, "Invalid request")
	}
	if err := validateSessionClockOffsets(request.IdleSeconds, request.AgeSeconds); err != nil {
		return JSONError(c, http.StatusBadRequest, err.Error())
	}

	claims, ok := auth.GetClaimsFromContext(c)
	if !ok || claims.FamilyID == "" {
		return JSONError(c, http.StatusUnauthorized, "Session identity is missing")
	}
	if err := models.ShiftSessionFamilyClocks(
		database.DB,
		claims.FamilyID,
		time.Now(),
		time.Duration(request.IdleSeconds)*time.Second,
		time.Duration(request.AgeSeconds)*time.Second,
	); err != nil {
		return JSONError(c, http.StatusInternalServerError, "Failed to shift session clocks")
	}
	return JSONResponse(c, http.StatusOK, "Session clocks shifted", nil)
}
