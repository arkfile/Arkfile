package handlers

import (
	"github.com/labstack/echo/v4"
)

// APIResponse is the standard JSON shape for handler responses.
//
// The Error field carries a stable, machine-readable code such as
// "file_id_conflict", "invalid_file_id", or "too_many_in_progress_uploads".
// Clients programme against this code; Message carries an optional
// human-readable explanation that may include user-visible details.
// Data carries operation-specific structured payload on success or on
// errors that need to return additional context (e.g. current counts).
type APIResponse struct {
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// JSONResponse sends a success JSON response with optional structured data.
func JSONResponse(c echo.Context, status int, message string, data interface{}) error {
	return c.JSON(status, APIResponse{
		Success: status >= 200 && status < 300,
		Message: message,
		Data:    data,
	})
}

// JSONError sends a JSON error response with only a human-readable message.
// Prefer JSONErrorCode for any error condition a client should react to
// programmatically; JSONError is for free-form error text.
func JSONError(c echo.Context, status int, message string) error {
	return c.JSON(status, APIResponse{
		Success: false,
		Message: message,
	})
}

// JSONErrorCode sends a JSON error response with a stable machine-readable
// error code and an optional human-readable message. The stable code is the
// contract clients programme against (e.g. retry loops, branching UI).
func JSONErrorCode(c echo.Context, status int, code, message string) error {
	return c.JSON(status, APIResponse{
		Success: false,
		Error:   code,
		Message: message,
	})
}

// JSONErrorCodeData sends a JSON error response with a stable code, a
// human-readable message, and structured Data for callers that need extra
// context (e.g. current quota counters on a 429 response).
func JSONErrorCodeData(c echo.Context, status int, code, message string, data interface{}) error {
	return c.JSON(status, APIResponse{
		Success: false,
		Error:   code,
		Message: message,
		Data:    data,
	})
}
