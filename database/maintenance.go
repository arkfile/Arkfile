package database

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	_ "github.com/rqlite/gorqlite/stdlib"
)

// OpenMaintenanceDB connects to rqlite using credentials from the environment.
func OpenMaintenanceDB() (*sql.DB, error) {
	nodes := os.Getenv("RQLITE_NODES")
	if nodes == "" {
		if addr := os.Getenv("RQLITE_ADDRESS"); addr != "" {
			nodes = strings.TrimPrefix(strings.TrimPrefix(addr, "https://"), "http://")
		}
	}
	if nodes == "" {
		nodes = "localhost:4001"
	}

	username := os.Getenv("RQLITE_USERNAME")
	password := os.Getenv("RQLITE_PASSWORD")
	if username == "" || password == "" {
		return nil, fmt.Errorf("RQLITE_USERNAME and RQLITE_PASSWORD must be set")
	}

	nodeList := strings.Split(nodes, ",")
	dsn := fmt.Sprintf("http://%s:%s@%s", username, password, strings.TrimSpace(nodeList[0]))
	if len(nodeList) > 1 {
		dsn += "?disableClusterDiscovery=false"
		for i := 1; i < len(nodeList); i++ {
			dsn += fmt.Sprintf("&node=%s", strings.TrimSpace(nodeList[i]))
		}
	}

	db, err := sql.Open("rqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetConnMaxLifetime(2 * time.Minute)

	const maxRetries = 10
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err = db.Ping(); err == nil {
			return db, nil
		}
		if attempt < maxRetries {
			time.Sleep(2 * time.Second)
		}
	}
	_ = db.Close()
	return nil, fmt.Errorf("failed to connect to rqlite: %w", err)
}

// LoadSecretsEnvFile loads KEY=VALUE pairs from a secrets.env file into the process environment.
func LoadSecretsEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open secrets env file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" {
			_ = os.Setenv(key, value)
		}
	}
	return scanner.Err()
}
