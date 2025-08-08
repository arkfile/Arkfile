package utils

import (
	"os"
	"strings"
)

// isProductionEnvironment detects if the application is running in production
func IsProductionEnvironment() bool {
	// Check environment variables
	envVars := []string{"ENVIRONMENT", "NODE_ENV", "GO_ENV"}

	for _, envVar := range envVars {
		value := strings.ToLower(os.Getenv(envVar))
		if value == "production" || value == "prod" {
			return true
		}
	}

	// Check domain-based detection
	if isDomainProduction() {
		return true
	}

	// Check port-based detection
	if isPortProduction() {
		return true
	}

	return false
}

// isDomainProduction checks if running on production domain
func isDomainProduction() bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}

	hostname = strings.ToLower(hostname)
	return strings.Contains(hostname, "prod") ||
		strings.Contains(hostname, "production")
}

// isPortProduction checks if running on production ports
func isPortProduction() bool {
	port := os.Getenv("PORT")
	return port == "443" || port == "80"
}

// IsDevAdminAccount checks if a username is a development admin account
func IsDevAdminAccount(username string) bool {
	devAdminAccounts := []string{
		"arkfile-dev-admin",
		"admin.dev.user",
		"admin.demo.user",
	}

	for _, devAdmin := range devAdminAccounts {
		if username == devAdmin {
			return true
		}
	}

	return false
}
