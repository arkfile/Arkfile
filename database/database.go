package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/rqlite/gorqlite/stdlib"
)

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

var (
	DB *sql.DB
)

func InitDB() {
	var err error

	// Get rqlite connection details from environment
	nodes := os.Getenv("RQLITE_NODES")
	username := os.Getenv("RQLITE_USERNAME")
	password := os.Getenv("RQLITE_PASSWORD")

	if nodes == "" {
		nodes = "localhost:4001"
	}

	if username == "" || password == "" {
		log.Fatal("RQLITE_USERNAME and RQLITE_PASSWORD must be set")
	}

	// Build connection string with authentication
	nodeList := strings.Split(nodes, ",")
	dsn := fmt.Sprintf("http://%s:%s@%s", username, password, nodeList[0])
	if len(nodeList) > 1 {
		dsn += "?disableClusterDiscovery=false"
		for i := 1; i < len(nodeList); i++ {
			dsn += fmt.Sprintf("&node=%s", nodeList[i])
		}
	}

	// Open connection to rqlite cluster
	DB, err = sql.Open("rqlite", dsn)
	if err != nil {
		log.Fatal("Failed to connect to rqlite:", err)
	}

	// Test connection
	if err = DB.Ping(); err != nil {
		log.Fatal("Failed to ping rqlite:", err)
	}

	createTables()
}

func createTables() {
	// Apply the complete unified schema in a single operation
	createUnifiedSchema()
}

// createUnifiedSchema reads and executes the complete unified schema file
func createUnifiedSchema() {
	// Check if unified_schema.sql exists - try multiple locations
	possiblePaths := []string{
		"database/unified_schema.sql",              // Development/source directory
		"/opt/arkfile/database/unified_schema.sql", // Production deployment
		"./database/unified_schema.sql",            // Current working directory
	}

	var schemaPath string
	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			schemaPath = path
			break
		}
	}

	if schemaPath == "" {
		log.Fatal("Critical: unified_schema.sql file not found - cannot initialize database")
		return
	}

	log.Printf("Loading unified database schema from: %s", schemaPath)

	// Read the complete schema file
	schemaSQL, err := os.ReadFile(schemaPath)
	if err != nil {
		log.Fatalf("Critical: Failed to read unified schema: %v", err)
		return
	}

	// Temporarily disable foreign key constraints during schema creation
	// This prevents issues with table creation order
	_, err = DB.Exec("PRAGMA foreign_keys = OFF")
	if err != nil {
		log.Printf("Warning: Could not disable foreign keys: %v", err)
	}

	// Execute the entire schema as a single operation - simpler and more reliable
	log.Printf("Executing unified database schema as single operation")
	_, err = DB.Exec(string(schemaSQL))
	if err != nil {
		log.Fatalf("Critical: Failed to execute unified schema: %v", err)
		return
	}

	// Re-enable foreign key constraints
	_, err = DB.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		log.Printf("Warning: Could not re-enable foreign keys: %v", err)
	}

	log.Println("Successfully applied complete unified database schema")
}

// splitSQLStatements splits a SQL file into individual statements
// This handles multi-line statements properly by splitting on semicolons outside of string literals
func splitSQLStatements(sql string) []string {
	var statements []string
	var current strings.Builder
	inString := false
	inComment := false
	var stringChar rune

	lines := strings.Split(sql, "\n")

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Skip empty lines and comment-only lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "--") {
			continue
		}

		// Process character by character to handle strings and comments
		for i, r := range line {
			switch r {
			case '-':
				// Check for start of comment
				if !inString && i < len(line)-1 && line[i+1] == '-' {
					inComment = true
				}
				if !inComment {
					current.WriteRune(r)
				}
			case '\'', '"':
				if !inComment {
					if !inString {
						inString = true
						stringChar = r
					} else if r == stringChar {
						// Check if it's escaped
						if i > 0 && line[i-1] != '\\' {
							inString = false
						}
					}
					current.WriteRune(r)
				}
			case ';':
				if !inString && !inComment {
					current.WriteRune(r)
					// End of statement
					stmt := strings.TrimSpace(current.String())
					if stmt != "" && !strings.HasPrefix(stmt, "--") {
						statements = append(statements, stmt)
					}
					current.Reset()
				} else if !inComment {
					current.WriteRune(r)
				}
			default:
				if !inComment {
					current.WriteRune(r)
				}
			}
		}

		// Reset comment flag at end of line, add newline if we're building a statement
		inComment = false
		if current.Len() > 0 {
			current.WriteRune('\n')
		}
	}

	// Add any remaining content
	if current.Len() > 0 {
		stmt := strings.TrimSpace(current.String())
		if stmt != "" && !strings.HasPrefix(stmt, "--") {
			statements = append(statements, stmt)
		}
	}

	return statements
}

// Log user actions
func LogUserAction(username, action, target string) error {
	_, err := DB.Exec(
		"INSERT INTO user_activity (username, action, target) VALUES (?, ?, ?)",
		username, action, target,
	)
	return err
}

// Log admin actions
func LogAdminAction(adminUsername, action, targetUsername, details string) error {
	_, err := DB.Exec(
		"INSERT INTO admin_logs (admin_username, action, target_username, details) VALUES (?, ?, ?, ?)",
		adminUsername, action, targetUsername, details,
	)
	return err
}

func LogAdminActionWithTx(tx *sql.Tx, adminUsername, action, targetUsername, details string) error {
	_, err := tx.Exec(
		"INSERT INTO admin_logs (admin_username, action, target_username, details) VALUES (?, ?, ?, ?)",
		adminUsername, action, targetUsername, details,
	)
	return err
}

// ApplyRateLimitingSchema is deprecated - rate limiting schema is now included in unified_schema.sql
// This function is kept for backwards compatibility but does nothing
func ApplyRateLimitingSchema() error {
	log.Println("Rate limiting schema is now included in unified schema - no separate application needed")
	return nil
}
