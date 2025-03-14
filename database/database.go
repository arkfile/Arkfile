package database

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/rqlite/gorqlite/stdlib"
)

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
	// Users table
	userTable := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_storage_bytes BIGINT NOT NULL DEFAULT 0,
        storage_limit_bytes BIGINT NOT NULL DEFAULT 10737418240,
        is_approved BOOLEAN NOT NULL DEFAULT false,
        approved_by TEXT,
        approved_at TIMESTAMP,
        is_admin BOOLEAN NOT NULL DEFAULT false
    );`

	// File metadata table
	fileMetadataTable := `CREATE TABLE IF NOT EXISTS file_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT UNIQUE NOT NULL,
        owner_email TEXT NOT NULL,
        password_hint TEXT,
        password_type TEXT NOT NULL DEFAULT 'custom',
        sha256sum CHAR(64) NOT NULL,
        size_bytes BIGINT NOT NULL DEFAULT 0,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_email) REFERENCES users(email)
    );
    
    -- Create index for faster lookups by hash
    CREATE INDEX IF NOT EXISTS idx_file_metadata_sha256sum ON file_metadata(sha256sum);
    `

	// Access logs table
	accessLogsTable := `CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        action TEXT NOT NULL,
        filename TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_email) REFERENCES users(email)
    );`

	// Admin actions logs table
	adminLogsTable := `CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_email TEXT NOT NULL,
        action TEXT NOT NULL,
        target_email TEXT NOT NULL,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_email) REFERENCES users(email),
        FOREIGN KEY (target_email) REFERENCES users(email)
    );`

	tables := []string{userTable, fileMetadataTable, accessLogsTable, adminLogsTable}

	for _, table := range tables {
		_, err := DB.Exec(table)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Log user actions
func LogUserAction(email, action, filename string) error {
	_, err := DB.Exec(
		"INSERT INTO access_logs (user_email, action, filename) VALUES (?, ?, ?)",
		email, action, filename,
	)
	return err
}

// Log admin actions
func LogAdminAction(adminEmail, action, targetEmail, details string) error {
	_, err := DB.Exec(
		"INSERT INTO admin_logs (admin_email, action, target_email, details) VALUES (?, ?, ?, ?)",
		adminEmail, action, targetEmail, details,
	)
	return err
}
