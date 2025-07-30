//go:build mock
// +build mock

package auth

// GetOPAQUEServer returns mock server status for testing
func GetOPAQUEServer() (bool, error) {
	// In mock mode, always return that server is available
	return true, nil
}
