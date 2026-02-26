// arkfile-client agent - Background daemon to securely hold AccountKey and digest cache in memory
// This agent provides secure key storage and dedup digest caching for CLI operations
// without requiring repeated password entry for account-encrypted file operations.

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Agent holds the AccountKey and digest cache in memory and serves requests via Unix socket
type Agent struct {
	socketPath  string
	listener    net.Listener
	accountKey  []byte
	digestCache map[string]string // fileID -> plaintext SHA-256 hex digest
	mu          sync.RWMutex
	running     bool
	stopChan    chan struct{}
}

// AgentRequest represents a request to the agent
type AgentRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params"`
}

// AgentResponse represents a response from the agent
type AgentResponse struct {
	Success bool                   `json:"success"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// AgentClient provides methods to communicate with the agent
type AgentClient struct {
	socketPath string
}

// NewAgent creates a new agent instance
func NewAgent() (*Agent, error) {
	socketPath, err := getAgentSocketPath()
	if err != nil {
		return nil, err
	}

	return &Agent{
		socketPath:  socketPath,
		digestCache: make(map[string]string),
		stopChan:    make(chan struct{}),
	}, nil
}

// getAgentSocketPath returns the UID-specific socket path
func getAgentSocketPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	arkfileDir := filepath.Join(homeDir, ".arkfile")
	if err := os.MkdirAll(arkfileDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create .arkfile directory: %w", err)
	}

	// Use UID-specific socket path for multi-user isolation
	uid := os.Getuid()
	return filepath.Join(arkfileDir, fmt.Sprintf("agent-%d.sock", uid)), nil
}

// Start starts the agent daemon
func (a *Agent) Start() error {
	// Check if agent is already running
	if _, err := os.Stat(a.socketPath); err == nil {
		// Try to connect to existing agent
		conn, err := net.Dial("unix", a.socketPath)
		if err == nil {
			conn.Close()
			// Agent is already running
			return nil
		}
		// Socket exists but agent not running, remove stale socket
		os.Remove(a.socketPath)
	}

	// Start listening on Unix socket
	listener, err := net.Listen("unix", a.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}

	// Set socket permissions to 0600 (owner only)
	if err := os.Chmod(a.socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	a.listener = listener
	a.running = true

	// Run agent in background goroutine
	go a.serve()

	return nil
}

// Stop stops the agent daemon
func (a *Agent) Stop() error {
	a.running = false
	close(a.stopChan)

	if a.listener != nil {
		a.listener.Close()
	}

	// Securely clear the account key and digest cache
	a.mu.Lock()
	if a.accountKey != nil {
		for i := range a.accountKey {
			a.accountKey[i] = 0
		}
		a.accountKey = nil
	}
	a.digestCache = nil
	a.mu.Unlock()

	// Remove socket file
	os.Remove(a.socketPath)

	return nil
}

// GetSocketPath returns the socket path
func (a *Agent) GetSocketPath() string {
	return a.socketPath
}

// serve handles incoming connections
func (a *Agent) serve() {
	defer a.listener.Close()
	defer os.Remove(a.socketPath)

	for a.running {
		conn, err := a.listener.Accept()
		if err != nil {
			if a.running {
				logVerbose("Agent accept error: %v", err)
			}
			continue
		}

		go a.handleConnection(conn)
	}
}

// handleConnection processes a single request
func (a *Agent) handleConnection(conn net.Conn) {
	defer conn.Close()

	var req AgentRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		a.sendError(conn, fmt.Sprintf("invalid request: %v", err))
		return
	}

	switch req.Method {
	case "ping":
		a.handlePing(conn)
	case "store_account_key":
		a.handleStoreAccountKey(conn, req.Params)
	case "get_account_key":
		a.handleGetAccountKey(conn)
	case "store_digest_cache":
		a.handleStoreDigestCache(conn, req.Params)
	case "get_digest_cache":
		a.handleGetDigestCache(conn)
	case "add_digest":
		a.handleAddDigest(conn, req.Params)
	case "remove_digest":
		a.handleRemoveDigest(conn, req.Params)
	case "clear":
		a.handleClear(conn)
	case "stop":
		a.handleStop(conn)
	default:
		a.sendError(conn, fmt.Sprintf("unknown method: %s", req.Method))
	}
}

// handlePing responds to ping requests
func (a *Agent) handlePing(conn net.Conn) {
	a.sendSuccess(conn, map[string]interface{}{
		"status": "ok",
	})
}

// handleStoreAccountKey stores the AccountKey in memory
func (a *Agent) handleStoreAccountKey(conn net.Conn, params map[string]interface{}) {
	accountKeyB64, ok := params["account_key"].(string)
	if !ok {
		a.sendError(conn, "account_key parameter required")
		return
	}

	accountKey, err := base64.StdEncoding.DecodeString(accountKeyB64)
	if err != nil {
		a.sendError(conn, fmt.Sprintf("invalid base64: %v", err))
		return
	}

	a.mu.Lock()
	// Clear any existing key first
	if a.accountKey != nil {
		for i := range a.accountKey {
			a.accountKey[i] = 0
		}
	}
	a.accountKey = accountKey
	a.mu.Unlock()

	a.sendSuccess(conn, nil)
}

// handleGetAccountKey retrieves the AccountKey
func (a *Agent) handleGetAccountKey(conn net.Conn) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.accountKey == nil {
		a.sendError(conn, "account key not set")
		return
	}

	result := map[string]interface{}{
		"account_key": base64.StdEncoding.EncodeToString(a.accountKey),
	}

	a.sendSuccess(conn, result)
}

// handleStoreDigestCache bulk-stores the digest cache (used after login)
func (a *Agent) handleStoreDigestCache(conn net.Conn, params map[string]interface{}) {
	cacheRaw, ok := params["digest_cache"].(map[string]interface{})
	if !ok {
		a.sendError(conn, "digest_cache parameter required (map of fileID -> sha256hex)")
		return
	}

	a.mu.Lock()
	a.digestCache = make(map[string]string, len(cacheRaw))
	for fileID, hashVal := range cacheRaw {
		if hashStr, ok := hashVal.(string); ok {
			a.digestCache[fileID] = hashStr
		}
	}
	a.mu.Unlock()

	a.sendSuccess(conn, nil)
}

// handleGetDigestCache retrieves the full digest cache
func (a *Agent) handleGetDigestCache(conn net.Conn) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Convert to interface map for JSON serialization
	cacheResult := make(map[string]interface{}, len(a.digestCache))
	for k, v := range a.digestCache {
		cacheResult[k] = v
	}

	a.sendSuccess(conn, map[string]interface{}{
		"digest_cache": cacheResult,
	})
}

// handleAddDigest adds a single digest entry (used after successful upload)
func (a *Agent) handleAddDigest(conn net.Conn, params map[string]interface{}) {
	fileID, ok := params["file_id"].(string)
	if !ok || fileID == "" {
		a.sendError(conn, "file_id parameter required")
		return
	}

	sha256hex, ok := params["sha256hex"].(string)
	if !ok || sha256hex == "" {
		a.sendError(conn, "sha256hex parameter required")
		return
	}

	a.mu.Lock()
	if a.digestCache == nil {
		a.digestCache = make(map[string]string)
	}
	a.digestCache[fileID] = sha256hex
	a.mu.Unlock()

	a.sendSuccess(conn, nil)
}

// handleRemoveDigest removes a single digest entry (used after file deletion)
func (a *Agent) handleRemoveDigest(conn net.Conn, params map[string]interface{}) {
	fileID, ok := params["file_id"].(string)
	if !ok || fileID == "" {
		a.sendError(conn, "file_id parameter required")
		return
	}

	a.mu.Lock()
	delete(a.digestCache, fileID)
	a.mu.Unlock()

	a.sendSuccess(conn, nil)
}

// handleClear clears the AccountKey and digest cache from memory
func (a *Agent) handleClear(conn net.Conn) {
	a.mu.Lock()
	if a.accountKey != nil {
		for i := range a.accountKey {
			a.accountKey[i] = 0
		}
		a.accountKey = nil
	}
	a.digestCache = nil
	a.mu.Unlock()

	a.sendSuccess(conn, nil)
}

// handleStop stops the agent
func (a *Agent) handleStop(conn net.Conn) {
	a.sendSuccess(conn, nil)
	a.running = false
	a.listener.Close()
}

// sendSuccess sends a success response
func (a *Agent) sendSuccess(conn net.Conn, result map[string]interface{}) {
	resp := AgentResponse{
		Success: true,
		Result:  result,
	}
	json.NewEncoder(conn).Encode(resp)
}

// sendError sends an error response
func (a *Agent) sendError(conn net.Conn, errMsg string) {
	resp := AgentResponse{
		Success: false,
		Error:   errMsg,
	}
	json.NewEncoder(conn).Encode(resp)
}

// NewAgentClient creates a new agent client
func NewAgentClient() (*AgentClient, error) {
	socketPath, err := getAgentSocketPath()
	if err != nil {
		return nil, err
	}

	return &AgentClient{
		socketPath: socketPath,
	}, nil
}

// validateSocketSecurity ensures socket is owned by current user with correct permissions
func validateSocketSecurity(socketPath string, expectedUID int) error {
	info, err := os.Stat(socketPath)
	if err != nil {
		return fmt.Errorf("failed to stat socket: %w", err)
	}

	// Check ownership
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("failed to get socket stat info")
	}

	if int(stat.Uid) != expectedUID {
		return fmt.Errorf("socket owner mismatch: expected UID %d, got %d", expectedUID, stat.Uid)
	}

	// Check permissions (must be exactly 0600)
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("insecure socket permissions: %o (expected 0600)", info.Mode().Perm())
	}

	return nil
}

// connect establishes a connection to the agent with security validation
func (c *AgentClient) connect() (net.Conn, error) {
	uid := os.Getuid()

	// Validate socket ownership and permissions before connecting
	if err := validateSocketSecurity(c.socketPath, uid); err != nil {
		return nil, fmt.Errorf("socket security validation failed: %w", err)
	}

	conn, err := net.Dial("unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to agent: %w", err)
	}

	return conn, nil
}

// sendRequest sends a request to the agent and returns the response
func (c *AgentClient) sendRequest(method string, params map[string]interface{}) (*AgentResponse, error) {
	conn, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := AgentRequest{
		Method: method,
		Params: params,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	var resp AgentResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &resp, nil
}

// Ping checks if the agent is running
func (c *AgentClient) Ping() error {
	resp, err := c.sendRequest("ping", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("ping failed: %s", resp.Error)
	}

	return nil
}

// StoreAccountKey stores the account key in the agent
func (c *AgentClient) StoreAccountKey(accountKey []byte) error {
	resp, err := c.sendRequest("store_account_key", map[string]interface{}{
		"account_key": base64.StdEncoding.EncodeToString(accountKey),
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("store failed: %s", resp.Error)
	}

	return nil
}

// GetAccountKey retrieves the account key from the agent
func (c *AgentClient) GetAccountKey() ([]byte, error) {
	resp, err := c.sendRequest("get_account_key", nil)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("get failed: %s", resp.Error)
	}

	accountKeyB64, ok := resp.Result["account_key"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid response: missing account_key")
	}

	return base64.StdEncoding.DecodeString(accountKeyB64)
}

// StoreDigestCache bulk-stores the digest cache in the agent (used after login)
func (c *AgentClient) StoreDigestCache(cache map[string]string) error {
	// Convert to interface map for JSON serialization
	cacheParam := make(map[string]interface{}, len(cache))
	for k, v := range cache {
		cacheParam[k] = v
	}

	resp, err := c.sendRequest("store_digest_cache", map[string]interface{}{
		"digest_cache": cacheParam,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("store digest cache failed: %s", resp.Error)
	}

	return nil
}

// GetDigestCache retrieves the full digest cache from the agent
func (c *AgentClient) GetDigestCache() (map[string]string, error) {
	resp, err := c.sendRequest("get_digest_cache", nil)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("get digest cache failed: %s", resp.Error)
	}

	cacheRaw, ok := resp.Result["digest_cache"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid response: missing digest_cache")
	}

	cache := make(map[string]string, len(cacheRaw))
	for k, v := range cacheRaw {
		if str, ok := v.(string); ok {
			cache[k] = str
		}
	}

	return cache, nil
}

// AddDigest adds a single digest entry to the agent cache (used after successful upload)
func (c *AgentClient) AddDigest(fileID, sha256hex string) error {
	resp, err := c.sendRequest("add_digest", map[string]interface{}{
		"file_id":   fileID,
		"sha256hex": sha256hex,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("add digest failed: %s", resp.Error)
	}

	return nil
}

// RemoveDigest removes a single digest entry from the agent cache (used after file deletion)
func (c *AgentClient) RemoveDigest(fileID string) error {
	resp, err := c.sendRequest("remove_digest", map[string]interface{}{
		"file_id": fileID,
	})
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("remove digest failed: %s", resp.Error)
	}

	return nil
}

// Clear clears the account key and digest cache from the agent
func (c *AgentClient) Clear() error {
	resp, err := c.sendRequest("clear", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("clear failed: %s", resp.Error)
	}

	return nil
}

// Stop stops the agent
func (c *AgentClient) Stop() error {
	resp, err := c.sendRequest("stop", nil)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("stop failed: %s", resp.Error)
	}

	return nil
}
