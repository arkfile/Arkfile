package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// createTestAgent creates an agent with a temp socket path for testing
func createTestAgent(t *testing.T) *Agent {
	t.Helper()
	tempDir := t.TempDir()
	socketPath := filepath.Join(tempDir, "test-agent.sock")

	agent := &Agent{
		socketPath:  socketPath,
		digestCache: make(map[string]string),
		stopChan:    make(chan struct{}),
	}
	agent.accessCountReset.Store(time.Now().Unix())
	return agent
}

// sendAgentRequest sends a JSON request to the agent and returns the response
func sendAgentRequest(t *testing.T, socketPath string, req AgentRequest) AgentResponse {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to connect to agent: %v", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	var resp AgentResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	return resp
}

// TestAgent_StoreAndRetrieveAccountKey tests storing and retrieving an account key
func TestAgent_StoreAndRetrieveAccountKey(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	// Generate a test key
	testKey := make([]byte, 32)
	rand.Read(testKey)
	testKeyB64 := base64.StdEncoding.EncodeToString(testKey)
	tokenHash := hashToken("test-access-token-123")

	// Store the key
	storeResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "store_account_key",
		Params: map[string]interface{}{
			"account_key": testKeyB64,
			"username":    "testuser",
			"token_hash":  tokenHash,
			"ttl_hours":   float64(1),
		},
	})
	if !storeResp.Success {
		t.Fatalf("store failed: %s", storeResp.Error)
	}

	// Retrieve the key with correct token
	getResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_account_key",
		Params: map[string]interface{}{
			"token_hash": tokenHash,
		},
	})
	if !getResp.Success {
		t.Fatalf("get failed: %s", getResp.Error)
	}

	retrievedB64, ok := getResp.Result["account_key"].(string)
	if !ok {
		t.Fatal("missing account_key in response")
	}

	retrievedKey, err := base64.StdEncoding.DecodeString(retrievedB64)
	if err != nil {
		t.Fatalf("failed to decode retrieved key: %v", err)
	}

	if !bytes.Equal(testKey, retrievedKey) {
		t.Error("retrieved key does not match stored key")
	}

	// Verify metadata
	if getResp.Result["username"] != "testuser" {
		t.Errorf("username mismatch: got %v", getResp.Result["username"])
	}
	if getResp.Result["context"] != "account" {
		t.Errorf("context mismatch: got %v", getResp.Result["context"])
	}
}

// TestAgent_RetrieveWithWrongToken tests that wrong access token triggers security wipe
func TestAgent_RetrieveWithWrongToken(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	testKey := make([]byte, 32)
	rand.Read(testKey)
	correctTokenHash := hashToken("correct-token")
	wrongTokenHash := hashToken("wrong-token")

	// Store with correct token
	storeResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "store_account_key",
		Params: map[string]interface{}{
			"account_key": base64.StdEncoding.EncodeToString(testKey),
			"username":    "testuser",
			"token_hash":  correctTokenHash,
			"ttl_hours":   float64(1),
		},
	})
	if !storeResp.Success {
		t.Fatalf("store failed: %s", storeResp.Error)
	}

	// Try to retrieve with wrong token - should wipe and fail
	getResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_account_key",
		Params: map[string]interface{}{
			"token_hash": wrongTokenHash,
		},
	})
	if getResp.Success {
		t.Fatal("get with wrong token should fail")
	}
	if getResp.Error == "" {
		t.Error("error message should not be empty")
	}

	// Verify key was wiped - subsequent get with correct token should also fail
	getResp2 := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_account_key",
		Params: map[string]interface{}{
			"token_hash": correctTokenHash,
		},
	})
	if getResp2.Success {
		t.Fatal("key should have been wiped after session mismatch")
	}
}

// TestAgent_KeyExpiration tests that expired keys are not returned
func TestAgent_KeyExpiration(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	testKey := make([]byte, 32)
	rand.Read(testKey)
	tokenHash := hashToken("test-token")

	// Store the key
	storeResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "store_account_key",
		Params: map[string]interface{}{
			"account_key": base64.StdEncoding.EncodeToString(testKey),
			"username":    "testuser",
			"token_hash":  tokenHash,
			"ttl_hours":   float64(1),
		},
	})
	if !storeResp.Success {
		t.Fatalf("store failed: %s", storeResp.Error)
	}

	// Manually expire the key by setting expiresAt to the past
	agent.mu.Lock()
	if agent.keyEntry != nil {
		agent.keyEntry.expiresAt = time.Now().Add(-1 * time.Minute)
	}
	agent.mu.Unlock()

	// Try to retrieve - should fail due to expiration
	getResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_account_key",
		Params: map[string]interface{}{
			"token_hash": tokenHash,
		},
	})
	if getResp.Success {
		t.Fatal("get should fail for expired key")
	}
	if getResp.Error == "" {
		t.Error("error should mention expiration")
	}
}

// TestAgent_WipeAllSensitiveData tests that clear wipes all data
func TestAgent_WipeAllSensitiveData(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	testKey := make([]byte, 32)
	rand.Read(testKey)
	tokenHash := hashToken("test-token")

	// Store key and digest
	sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "store_account_key",
		Params: map[string]interface{}{
			"account_key": base64.StdEncoding.EncodeToString(testKey),
			"username":    "testuser",
			"token_hash":  tokenHash,
			"ttl_hours":   float64(1),
		},
	})

	sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "add_digest",
		Params: map[string]interface{}{
			"file_id":   "file-1",
			"sha256hex": "abcdef1234567890",
		},
	})

	// Clear everything
	clearResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "clear",
	})
	if !clearResp.Success {
		t.Fatalf("clear failed: %s", clearResp.Error)
	}

	// Verify key is gone
	getResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_account_key",
		Params: map[string]interface{}{
			"token_hash": tokenHash,
		},
	})
	if getResp.Success {
		t.Fatal("key should be wiped after clear")
	}

	// Verify digest cache is gone
	digestResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_digest_cache",
	})
	if !digestResp.Success {
		t.Fatalf("get_digest_cache failed: %s", digestResp.Error)
	}
	digestCache, ok := digestResp.Result["digest_cache"].(map[string]interface{})
	if ok && len(digestCache) > 0 {
		t.Error("digest cache should be empty after clear")
	}
}

// TestAgent_StoreAndRetrieveDigestCache tests bulk digest cache store/retrieve
func TestAgent_StoreAndRetrieveDigestCache(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	// Store bulk digest cache
	storeResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "store_digest_cache",
		Params: map[string]interface{}{
			"digest_cache": map[string]interface{}{
				"file-1": "aabbccdd11223344",
				"file-2": "eeff00112233aabb",
			},
		},
	})
	if !storeResp.Success {
		t.Fatalf("store_digest_cache failed: %s", storeResp.Error)
	}

	// Retrieve
	getResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_digest_cache",
	})
	if !getResp.Success {
		t.Fatalf("get_digest_cache failed: %s", getResp.Error)
	}

	cache, ok := getResp.Result["digest_cache"].(map[string]interface{})
	if !ok {
		t.Fatal("missing digest_cache in response")
	}
	if cache["file-1"] != "aabbccdd11223344" {
		t.Errorf("file-1 digest mismatch: got %v", cache["file-1"])
	}
	if cache["file-2"] != "eeff00112233aabb" {
		t.Errorf("file-2 digest mismatch: got %v", cache["file-2"])
	}
}

// TestAgent_AddRemoveDigest tests adding and removing individual digests
func TestAgent_AddRemoveDigest(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	// Add a digest
	addResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "add_digest",
		Params: map[string]interface{}{
			"file_id":   "file-new",
			"sha256hex": "1122334455667788",
		},
	})
	if !addResp.Success {
		t.Fatalf("add_digest failed: %s", addResp.Error)
	}

	// Verify it's there
	getResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_digest_cache",
	})
	cache := getResp.Result["digest_cache"].(map[string]interface{})
	if cache["file-new"] != "1122334455667788" {
		t.Errorf("added digest not found")
	}

	// Remove it
	removeResp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "remove_digest",
		Params: map[string]interface{}{
			"file_id": "file-new",
		},
	})
	if !removeResp.Success {
		t.Fatalf("remove_digest failed: %s", removeResp.Error)
	}

	// Verify it's gone
	getResp2 := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "get_digest_cache",
	})
	cache2 := getResp2.Result["digest_cache"].(map[string]interface{})
	if _, exists := cache2["file-new"]; exists {
		t.Error("removed digest should not exist")
	}
}

// TestValidateSocketSecurity tests socket permission/ownership validation
func TestValidateSocketSecurity(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test socket-like file with correct permissions
	socketPath := filepath.Join(tempDir, "test.sock")
	f, err := os.Create(socketPath)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	f.Close()

	// Set correct permissions (0600)
	os.Chmod(socketPath, 0600)

	uid := os.Getuid()

	// Should pass with correct UID
	err = validateSocketSecurity(socketPath, uid)
	if err != nil {
		t.Errorf("validation should pass for correct UID and permissions: %v", err)
	}

	// Should fail with wrong UID
	err = validateSocketSecurity(socketPath, uid+1)
	if err == nil {
		t.Error("validation should fail for wrong UID")
	}

	// Should fail with wrong permissions
	os.Chmod(socketPath, 0644)
	err = validateSocketSecurity(socketPath, uid)
	if err == nil {
		t.Error("validation should fail for insecure permissions (0644)")
	}

	// Should fail for nonexistent file
	err = validateSocketSecurity(filepath.Join(tempDir, "nonexistent.sock"), uid)
	if err == nil {
		t.Error("validation should fail for nonexistent socket")
	}
}

// TestAgent_Ping tests basic agent liveness check
func TestAgent_Ping(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	resp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "ping",
	})
	if !resp.Success {
		t.Fatalf("ping failed: %s", resp.Error)
	}
	if resp.Result["status"] != "ok" {
		t.Errorf("ping status should be 'ok', got %v", resp.Result["status"])
	}
}

// TestAgent_Status tests status reporting
func TestAgent_Status(t *testing.T) {
	agent := createTestAgent(t)
	if err := agent.Start(); err != nil {
		t.Fatalf("agent start failed: %v", err)
	}
	defer agent.Stop()

	// Status with no key
	resp := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "status",
	})
	if !resp.Success {
		t.Fatalf("status failed: %s", resp.Error)
	}
	if resp.Result["key_stored"] != false {
		t.Error("key_stored should be false when no key is stored")
	}

	// Store a key and check status again
	testKey := make([]byte, 32)
	rand.Read(testKey)
	sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "store_account_key",
		Params: map[string]interface{}{
			"account_key": base64.StdEncoding.EncodeToString(testKey),
			"username":    "statususer",
			"token_hash":  hashToken("status-token"),
			"ttl_hours":   float64(2),
		},
	})

	resp2 := sendAgentRequest(t, agent.socketPath, AgentRequest{
		Method: "status",
	})
	if !resp2.Success {
		t.Fatalf("status failed: %s", resp2.Error)
	}
	if resp2.Result["key_stored"] != true {
		t.Error("key_stored should be true after storing a key")
	}
	if resp2.Result["key_username"] != "statususer" {
		t.Errorf("key_username mismatch: got %v", resp2.Result["key_username"])
	}
}

// TestHashToken tests token hashing consistency
func TestHashToken(t *testing.T) {
	token := "test-access-token-abc123"

	hash1 := hashToken(token)
	hash2 := hashToken(token)

	if hash1 != hash2 {
		t.Error("same token should produce same hash")
	}

	// Different token should produce different hash
	hash3 := hashToken("different-token")
	if hash1 == hash3 {
		t.Error("different tokens should produce different hashes")
	}

	// Hash should be 64 hex characters (SHA-256 = 32 bytes = 64 hex chars)
	if len(hash1) != 64 {
		t.Errorf("hash should be 64 hex chars, got %d", len(hash1))
	}
}
