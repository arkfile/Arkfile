package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/arkfile/Arkfile/cli/jsonutil"
)

func handleSystemStatusCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("system-status", flag.ExitOnError)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin system-status

Show system status, metrics, and health information.

EXAMPLES:
    arkfile-admin system-status
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Get system status
	resp, err := client.makeRequest("GET", "/api/admin/system/status", nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to get system status: %w", err)
	}

	// Display system status
	status := resp.Data
	fmt.Printf("System Status\n")
	fmt.Printf("================\n\n")

	if uptime, ok := status["uptime"].(string); ok {
		fmt.Printf("Uptime: %s\n", uptime)
	}
	if version, ok := status["version"].(string); ok {
		fmt.Printf("Version: %s\n", version)
	}
	if goVersion, ok := status["go_version"].(string); ok {
		fmt.Printf("Go Version: %s\n", goVersion)
	}

	fmt.Printf("\nStorage Statistics\n")
	fmt.Printf("====================\n")
	if storage, ok := status["storage"].(map[string]interface{}); ok {
		if totalFiles, ok := storage["total_files"].(float64); ok {
			fmt.Printf("Total Files: %.0f\n", totalFiles)
		}
		if totalSize, ok := storage["total_size_bytes"].(float64); ok {
			fmt.Printf("Total Size: %s\n", formatFileSize(int64(totalSize)))
		}
		if avgFileSize, ok := storage["average_file_size_bytes"].(float64); ok {
			fmt.Printf("Average File Size: %s\n", formatFileSize(int64(avgFileSize)))
		}
	}

	fmt.Printf("\nUser Statistics\n")
	fmt.Printf("=================\n")
	if users, ok := status["users"].(map[string]interface{}); ok {
		if totalUsers, ok := users["total_users"].(float64); ok {
			fmt.Printf("Total Users: %.0f\n", totalUsers)
		}
		if activeUsers, ok := users["active_users"].(float64); ok {
			fmt.Printf("Active Users: %.0f\n", activeUsers)
		}
		if adminUsers, ok := users["admin_users"].(float64); ok {
			fmt.Printf("Admin Users: %.0f\n", adminUsers)
		}
		if pendingUsers, ok := users["pending_approval"].(float64); ok {
			fmt.Printf("Pending Approval: %.0f\n", pendingUsers)
		}
	}

	fmt.Printf("\nSecurity Status\n")
	fmt.Printf("=================\n")
	if security, ok := status["security"].(map[string]interface{}); ok {
		if mfaUsers, ok := security["mfa_enabled_users"].(float64); ok {
			fmt.Printf("MFA Enabled Users: %.0f\n", mfaUsers)
		}
	}

	return nil
}

// handleHealthCheckCommand performs comprehensive system health check
func handleHealthCheckCommand(client *HTTPClient, config *AdminConfig, args []string) error {
	fs := flag.NewFlagSet("health-check", flag.ExitOnError)
	var (
		detailed = fs.Bool("detailed", false, "Show detailed health information")
	)

	fs.Usage = func() {
		fmt.Printf(`Usage: arkfile-admin health-check [FLAGS]

Perform comprehensive system health check.

FLAGS:
    --detailed          Show detailed health information
    --help             Show this help message

EXAMPLES:
    arkfile-admin health-check
    arkfile-admin health-check --detailed
`)
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Load admin session
	session, err := requireAdminSession(config)
	if err != nil {
		return err
	}

	// Perform health check
	params := ""
	if *detailed {
		params = "?detailed=true"
	}

	resp, err := client.makeRequest("GET", "/api/admin/system/health"+params, nil, session.AccessToken)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}

	// Display health results
	health := resp.Data
	fmt.Printf("System Health Check\n")
	fmt.Printf("=====================\n\n")

	if overall, ok := health["status"].(string); ok {
		statusIcon := "OK"
		if overall != "healthy" {
			statusIcon = "[X]"
		}
		fmt.Printf("Overall Status: %s %s\n\n", statusIcon, strings.ToUpper(overall))
	}

	// Display component health
	if checks, ok := health["checks"].(map[string]interface{}); ok {
		fmt.Printf("Component Health:\n")
		fmt.Printf("-----------------\n")

		for component, status := range checks {
			statusMap := status.(map[string]interface{})
			statusStr := statusMap["status"].(string)
			statusIcon := "OK"
			if statusStr != "healthy" {
				statusIcon = "[X]"
			}

			fmt.Printf("%-15s %s %s", component+":", statusIcon, statusStr)

			if *detailed {
				if message, ok := statusMap["message"].(string); ok && message != "" {
					fmt.Printf(" - %s", message)
				}
			}
			fmt.Println()
		}
	}

	return nil
}

