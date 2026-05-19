package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type ConformanceVector struct {
	Password    string `json:"password"`
	SaltHex     string `json:"salt_hex"`
	MemoryKiB   uint32 `json:"m_kib"`
	Time        uint32 `json:"t"`
	Parallel    uint8  `json:"p"`
	KeyLen      uint32 `json:"dk"`
	ExpectedHex string `json:"expected_hex"`
}

func TestArgon2ConformanceFixtureGeneration(t *testing.T) {
	password := "arkfile-conformance-password-v1"
	// 32-byte salt: hex representation of "arkfile-conformance-salt-vector-v1" (truncated to 32 bytes)
	saltHex := "61726b66696c652d636f6e666f726d616e63652d73616c742d766563746f722d" // hex of "arkfile-conformance-salt-vector-" (32 bytes)
	salt := make([]byte, 32)
	copy(salt, []byte("arkfile-conformance-salt-vector-"))

	// Sourced from UnifiedArgonSecure (65536, 3, 1)
	m := UnifiedArgonSecure.Memory
	timeI := UnifiedArgonSecure.Time
	threads := UnifiedArgonSecure.Threads
	keyLen := UnifiedArgonSecure.KeyLen

	derived, err := DeriveArgon2IDKey([]byte(password), salt, keyLen, m, timeI, threads)
	if err != nil {
		t.Fatalf("Failed to derive Argon2ID key: %v", err)
	}

	expectedHex := hex.EncodeToString(derived)

	vector := ConformanceVector{
		Password:    password,
		SaltHex:     saltHex,
		MemoryKiB:   m,
		Time:        timeI,
		Parallel:    threads,
		KeyLen:      keyLen,
		ExpectedHex: expectedHex,
	}

	data, err := json.MarshalIndent(vector, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Make sure testdata directory exists
	dir := filepath.Join("testdata")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create testdata directory: %v", err)
	}

	filePath := filepath.Join(dir, "argon2-conformance-vectors.json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		t.Fatalf("Failed to write conformance fixture file: %v", err)
	}

	t.Logf("Exported conformance fixture to %s", filePath)

	// Regression self-check: read back and verify we match ourselves
	readData, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read back fixture: %v", err)
	}

	var parsedVector ConformanceVector
	if err := json.Unmarshal(readData, &parsedVector); err != nil {
		t.Fatalf("Failed to unmarshal read back fixture: %v", err)
	}

	if parsedVector.ExpectedHex != expectedHex {
		t.Errorf("Read back hex mismatch: %s != %s", parsedVector.ExpectedHex, expectedHex)
	}
}
