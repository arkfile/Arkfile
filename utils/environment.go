package utils

import (
	"os"
	"strings"
)

// IsProductionEnvironment checks if the application is running in production
func IsProductionEnvironment() bool {
	// Check multiple environment variable patterns
	envVars := []string{"ENVIRONMENT", "NODE_ENV", "GO_ENV", "ENV"}

	for _, envVar := range envVars {
		value := strings.ToLower(os.Getenv(envVar))
		if value == "production" || value == "prod" {
			return true
		}
	}

	// Additional production indicators
	return isDomainProduction() || isPortProduction()
}

// isDomainProduction checks if running on a production-like domain
func isDomainProduction() bool {
	hostname, err := os.Hostname()
	if err != nil {
		return false
	}

	hostname = strings.ToLower(hostname)
	productionIndicators := []string{"prod", "production", "live"}

	for _, indicator := range productionIndicators {
		if strings.Contains(hostname, indicator) {
			return true
		}
	}

	return false
}

// isPortProduction checks if running on production-typical ports
func isPortProduction() bool {
	port := os.Getenv("PORT")
	productionPorts := []string{"443", "80", "8443"}

	for _, prodPort := range productionPorts {
		if port == prodPort {
			return true
		}
	}

	return false
}

// IsDevAdminAccount checks if a username is a development admin account
func IsDevAdminAccount(username string) bool {
	devAdminAccounts := []string{
		"arkfile-dev-admin",
		"admin.dev.user",
		"admin.demo.user",
		"test-admin",
		"dev-admin",
	}

	username = strings.ToLower(username)
	for _, devAdmin := range devAdminAccounts {
		if username == strings.ToLower(devAdmin) {
			return true
		}
	}

	return false
}

// GetEnvironmentName returns the current environment name
func GetEnvironmentName() string {
	envVars := []string{"ENVIRONMENT", "NODE_ENV", "GO_ENV", "ENV"}

	for _, envVar := range envVars {
		value := os.Getenv(envVar)
		if value != "" {
			return strings.ToLower(value)
		}
	}

	if IsProductionEnvironment() {
		return "production"
	}

	return "development"
}
