package logging

import (
	"database/sql"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/84adam/Arkfile/crypto"
	_ "github.com/mattn/go-sqlite3"
)

func TestMain(m *testing.M) {
	// Setup in-memory SQLite DB for KeyManager
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		fmt.Printf("FATAL: Failed to open in-memory DB: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Create system_keys table
	_, err = db.Exec(`
		CREATE TABLE system_keys (
			key_id TEXT PRIMARY KEY,
			key_type TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			nonce BLOB NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		fmt.Printf("FATAL: Failed to create system_keys table: %v\n", err)
		os.Exit(1)
	}

	// Set Master Key for KeyManager
	masterKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	os.Setenv("ARKFILE_MASTER_KEY", masterKey)

	// Initialize KeyManager
	if err := crypto.InitKeyManager(db); err != nil {
		fmt.Printf("FATAL: Failed to initialize KeyManager: %v\n", err)
		os.Exit(1)
	}

	// Initialize Loggers
	InitFallbackConsoleLogging()

	// Run tests
	exitCode := m.Run()

	// Cleanup
	os.Unsetenv("ARKFILE_MASTER_KEY")
	os.Exit(exitCode)
}

func createTestService(t *testing.T) *EntityIDService {
	config := EntityIDConfig{
		RotationPeriod:  24 * time.Hour,
		RetentionDays:   90,
		CleanupInterval: 24 * time.Hour,
	}

	service, err := NewEntityIDService(config)
	if err != nil {
		t.Fatalf("Failed to create EntityIDService: %v", err)
	}
	return service
}

func TestEntityIDGeneration(t *testing.T) {
	service := createTestService(t)

	tests := []struct {
		name string
		ip   net.IP
	}{
		{
			name: "IPv4 Address",
			ip:   net.ParseIP("192.168.1.100"),
		},
		{
			name: "IPv6 Address",
			ip:   net.ParseIP("2001:db8::1"),
		},
		{
			name: "Localhost IPv4",
			ip:   net.ParseIP("127.0.0.1"),
		},
		{
			name: "Localhost IPv6",
			ip:   net.ParseIP("::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entityID := service.GetEntityID(tt.ip)

			// Verify entity ID is not empty
			if entityID == "" {
				t.Errorf("Entity ID should not be empty for IP %s", tt.ip.String())
			}

			// Verify entity ID is consistent for same IP
			entityID2 := service.GetEntityID(tt.ip)
			if entityID != entityID2 {
				t.Errorf("Entity ID should be consistent for same IP: %s != %s", entityID, entityID2)
			}

			// Verify entity ID length (should be 16 characters for hex)
			if len(entityID) != 16 {
				t.Errorf("Entity ID should be 16 characters long, got %d", len(entityID))
			}
		})
	}
}

func TestEntityIDUniqueness(t *testing.T) {
	service := createTestService(t)

	// Test different IPs produce different entity IDs
	ip1 := net.ParseIP("192.168.1.100")
	ip2 := net.ParseIP("192.168.1.101")
	ip3 := net.ParseIP("10.0.0.1")

	entityID1 := service.GetEntityID(ip1)
	entityID2 := service.GetEntityID(ip2)
	entityID3 := service.GetEntityID(ip3)

	// All entity IDs should be different
	if entityID1 == entityID2 {
		t.Errorf("Different IPs should produce different entity IDs: %s == %s", entityID1, entityID2)
	}

	if entityID1 == entityID3 {
		t.Errorf("Different IPs should produce different entity IDs: %s == %s", entityID1, entityID3)
	}

	if entityID2 == entityID3 {
		t.Errorf("Different IPs should produce different entity IDs: %s == %s", entityID2, entityID3)
	}
}

func TestEntityIDTimeWindow(t *testing.T) {
	service := createTestService(t)

	// Test time window generation
	timeWindow := service.GetCurrentTimeWindow()

	// Verify time window format (should be YYYY-MM-DD)
	expectedFormat := "2006-01-02"
	expectedTimeWindow := time.Now().UTC().Format(expectedFormat)

	if timeWindow != expectedTimeWindow {
		t.Errorf("Expected time window %s, got %s", expectedTimeWindow, timeWindow)
	}

	// Test time window for specific date
	testTime := time.Date(2025, 6, 20, 14, 30, 0, 0, time.UTC)
	expectedTestWindow := "2025-06-20"
	testWindow := service.GetTimeWindowForTime(testTime)

	if testWindow != expectedTestWindow {
		t.Errorf("Expected test time window %s, got %s", expectedTestWindow, testWindow)
	}
}

func TestEntityIDMasterKeyImpact(t *testing.T) {
	// Test that different services produce different entity IDs
	service1 := createTestService(t)
	service2 := createTestService(t)

	// Manually change the master secret of service2 to simulate a different service
	// In a real scenario, different services would have different master keys in the DB
	// or use different key IDs.
	service2.masterSecret = []byte("different_master_secret_for_test_01")

	testIP := net.ParseIP("192.168.1.100")

	entityID1 := service1.GetEntityID(testIP)
	entityID2 := service2.GetEntityID(testIP)

	// Since they have different master keys, entity IDs should be different
	if entityID1 == entityID2 {
		t.Errorf("Different services should produce different entity IDs for same IP: %s == %s", entityID1, entityID2)
	}
}

func TestEntityIDAnonymity(t *testing.T) {
	service := createTestService(t)

	testIP := net.ParseIP("192.168.1.100")
	entityID := service.GetEntityID(testIP)

	// Verify entity ID doesn't contain the original IP
	ipString := testIP.String()
	if contains(entityID, ipString) {
		t.Errorf("Entity ID should not contain original IP address: %s contains %s", entityID, ipString)
	}

	// Verify entity ID doesn't contain obvious IP fragments
	ipParts := []string{"192", "168", "100"}
	for _, part := range ipParts {
		if contains(entityID, part) {
			t.Errorf("Entity ID should not contain IP address fragments: %s contains %s", entityID, part)
		}
	}
}

func TestEntityIDConsistencyAcrossTimeWindows(t *testing.T) {
	service := createTestService(t)

	testIP := net.ParseIP("192.168.1.100")

	// Get entity ID for current time window
	entityID1 := service.GetEntityID(testIP)

	// Entity ID should be the same when called multiple times in same time window
	entityID2 := service.GetEntityID(testIP)

	if entityID1 != entityID2 {
		t.Errorf("Entity ID should be consistent within same time window: %s != %s", entityID1, entityID2)
	}
}

func TestEntityIDServiceInitialization(t *testing.T) {
	// Test basic initialization
	config := EntityIDConfig{
		RotationPeriod:  24 * time.Hour,
		RetentionDays:   90,
		CleanupInterval: 1 * time.Hour,
	}

	service, err := NewEntityIDService(config)
	if err != nil {
		t.Fatalf("Failed to create EntityIDService: %v", err)
	}

	// Test that it can generate entity IDs
	testIP := net.ParseIP("192.168.1.100")
	entityID := service.GetEntityID(testIP)
	if entityID == "" {
		t.Errorf("Service should generate non-empty entity ID")
	}

	if len(entityID) != 16 {
		t.Errorf("Entity ID should be 16 characters long, got %d", len(entityID))
	}
}

func TestEntityIDCorrelationResistance(t *testing.T) {
	service := createTestService(t)

	// Test that consecutive IPs don't produce similar entity IDs
	var entityIDs []string

	for i := 100; i < 110; i++ {
		ip := net.ParseIP("192.168.1." + string(rune(48+i-100))) // Convert to ASCII
		if ip == nil {
			// Fallback to manual IP construction
			ip = net.IPv4(192, 168, 1, byte(i))
		}
		entityID := service.GetEntityID(ip)
		entityIDs = append(entityIDs, entityID)
	}

	// Check that entity IDs don't have obvious patterns
	for i := 0; i < len(entityIDs)-1; i++ {
		// Check that consecutive entity IDs don't share long common prefixes
		commonPrefix := longestCommonPrefix(entityIDs[i], entityIDs[i+1])
		if len(commonPrefix) > 4 { // Allow some randomness but not too much similarity
			t.Errorf("Consecutive entity IDs should not share long prefixes: %s and %s share '%s'",
				entityIDs[i], entityIDs[i+1], commonPrefix)
		}
	}
}

func TestEntityIDValidation(t *testing.T) {
	// Test the ValidateEntityID function
	validIDs := []string{
		"1234567890abcdef",
		"0000000000000000",
		"ffffffffffffffff",
	}

	invalidIDs := []string{
		"",
		"123",
		"1234567890abcdefg", // too long
		"1234567890abcdeg",  // invalid hex character
		"12345678-90abcdef", // contains dash
	}

	for _, id := range validIDs {
		if !ValidateEntityID(id) {
			t.Errorf("Valid entity ID '%s' failed validation", id)
		}
	}

	for _, id := range invalidIDs {
		if ValidateEntityID(id) {
			t.Errorf("Invalid entity ID '%s' passed validation", id)
		}
	}
}

func TestEntityIDServiceCleanup(t *testing.T) {
	service := createTestService(t)

	// Test cleanup (should not error)
	err := service.CleanupOldWindows(30)
	if err != nil {
		t.Errorf("Cleanup should not error: %v", err)
	}
}

func TestEntityIDMasterSecretHash(t *testing.T) {
	service := createTestService(t)

	hash := service.GetMasterSecretHash()
	if hash == "" {
		t.Errorf("Master secret hash should not be empty")
	}

	if len(hash) != 16 { // 8 bytes as hex = 16 characters
		t.Errorf("Master secret hash should be 16 characters long, got %d", len(hash))
	}
}

// Helper functions for tests
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func longestCommonPrefix(s1, s2 string) string {
	minLen := len(s1)
	if len(s2) < minLen {
		minLen = len(s2)
	}

	for i := 0; i < minLen; i++ {
		if s1[i] != s2[i] {
			return s1[:i]
		}
	}
	return s1[:minLen]
}

func BenchmarkEntityIDGeneration(b *testing.B) {
	config := EntityIDConfig{
		RotationPeriod: 24 * time.Hour,
		RetentionDays:  90,
	}

	service, err := NewEntityIDService(config)
	if err != nil {
		b.Fatalf("Failed to create EntityIDService: %v", err)
	}

	testIP := net.ParseIP("192.168.1.100")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.GetEntityID(testIP)
	}
}

func BenchmarkEntityIDGenerationDifferentIPs(b *testing.B) {
	config := EntityIDConfig{
		RotationPeriod: 24 * time.Hour,
		RetentionDays:  90,
	}

	service, err := NewEntityIDService(config)
	if err != nil {
		b.Fatalf("Failed to create EntityIDService: %v", err)
	}

	ips := make([]net.IP, 1000)
	for i := 0; i < 1000; i++ {
		ips[i] = net.IPv4(192, 168, byte(i/256), byte(i%256))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.GetEntityID(ips[i%1000])
	}
}
