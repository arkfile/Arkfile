package handlers

import (
	"github.com/labstack/echo/v4"
)

// APIResponse represents the standard API response structure
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// JSONResponse sends a standard JSON response
func JSONResponse(c echo.Context, status int, message string, data interface{}) error {
	response := APIResponse{
		Success: status >= 200 && status < 300,
		Message: message,
		Data:    data,
	}
	return c.JSON(status, response)
}

// JSONError sends a standard JSON error response
func JSONError(c echo.Context, status int, message string) error {
	response := APIResponse{
		Success: false,
		Message: message,
	}
	return c.JSON(status, response)
}
