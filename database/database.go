package database

import (
    "database/sql"
    "log"
    "os"

    _ "modernc.org/sqlite"
)

var DB *sql.DB

func InitDB() {
    var err error
    
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

    DB, err = sql.Open("sqlite", dbPath)
    if err != nil {
        log.Fatal(err)
    }

    err = DB.Ping()
    if err != nil {
        log.Fatal(err)
    }

    createTables()
}

func createTables() {
    // Users table
    userTable := `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`

    // File metadata table
    fileMetadataTable := `CREATE TABLE IF NOT EXISTS file_metadata (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT UNIQUE NOT NULL,
        owner_email TEXT NOT NULL,
        password_hint TEXT,
        upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_email) REFERENCES users(email)
    );`

    // Access logs table
    accessLogsTable := `CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email TEXT NOT NULL,
        action TEXT NOT NULL,
        filename TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_email) REFERENCES users(email)
    );`

    tables := []string{userTable, fileMetadataTable, accessLogsTable}

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
