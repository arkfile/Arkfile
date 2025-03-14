package database

import (
	"database/sql"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/84adam/arkfile/crypto"
	_ "modernc.org/sqlite"
)

var (
	DB       *sql.DB
	dbCrypto *crypto.DatabaseCrypto
)

func InitDB() {
	var err error

	// Get database path based on environment
	dbPath := getDBPath()
	encryptedPath := dbPath + ".enc"

	// Initialize crypto with key from environment
	dbKey := os.Getenv("DB_ENCRYPTION_KEY")
	if dbKey == "" {
		log.Fatal("DB_ENCRYPTION_KEY not set")
	}

	dbCrypto, err = crypto.NewDatabaseCrypto(dbKey)
	if err != nil {
		log.Fatal("Failed to initialize database encryption:", err)
	}

	// If encrypted database exists, decrypt it
	if _, err := os.Stat(encryptedPath); err == nil {
		log.Println("Decrypting database...")
		if err := dbCrypto.Decrypt(encryptedPath, dbPath); err != nil {
			log.Fatal("Failed to decrypt database:", err)
		}
		log.Println("Database decrypted successfully")
	}

	// Open database
	DB, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	if err = DB.Ping(); err != nil {
		log.Fatal(err)
	}

	createTables()
	registerShutdownHandler(dbPath, encryptedPath)
}

func getDBPath() string {
	// Get database path based on environment
	host := os.Getenv("HOST")
	testDomain := os.Getenv("TEST_DOMAIN")

	var dbPath string
	if host == testDomain {
		dbPath = os.Getenv("TEST_DB_PATH")
	} else {
		dbPath = os.Getenv("PROD_DB_PATH")
	}

	// Fallback if env vars aren't set
	if dbPath == "" {
		dbPath = "./arkfile.db"
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0750); err != nil {
		log.Fatal("Failed to create database directory:", err)
	}

	return dbPath
}

func registerShutdownHandler(dbPath, encryptedPath string) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down, encrypting database...")

		// Close database connection
		if err := DB.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}

		// Encrypt the database
		if err := dbCrypto.Encrypt(dbPath, encryptedPath); err != nil {
			log.Printf("Failed to encrypt database: %v", err)
			os.Exit(1)
		}

		// Remove unencrypted database
		if err := os.Remove(dbPath); err != nil {
			log.Printf("Failed to remove unencrypted database: %v", err)
			os.Exit(1)
		}

		log.Println("Database encrypted successfully")
		os.Exit(0)
	}()
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
