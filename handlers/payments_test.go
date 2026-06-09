package handlers

import (
	"database/sql"
	"os"
	"testing"

	"github.com/84adam/Arkfile/config"
	"github.com/84adam/Arkfile/database"
)

func TestPaymentsHandlers(t *testing.T) {
	// Initialize in-memory SQLite database
	db, err := sql.Open("rqlite", "http://user:pass@localhost:4001") // Mock rqlite
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	database.DB = db

	// Set up environmental variables required for config
	os.Setenv("ARKFILE_PAYMENTS_ENABLED", "true")
	os.Setenv("ARKFILE_BTCPAY_SERVER_URL", "http://mock-btcpayserver")
	os.Setenv("ARKFILE_BTCPAY_STORE_ID", "store123")
	os.Setenv("ARKFILE_BTCPAY_API_KEY", "key123")
	os.Setenv("ARKFILE_BTCPAY_WEBHOOK_SECRET", "secret123")
	os.Setenv("ARKFILE_MIN_TOP_UP_USD", "0.50")
	os.Setenv("ARKFILE_MAX_TOP_UP_USD", "1000.00")

	// Ensure config parses properly
	_, err = config.LoadConfig()
	if err != nil {
		t.Fatalf("unexpected config load error: %v", err)
	}
}
