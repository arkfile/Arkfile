# Phase 1: OPAQUE Implementation & Legacy Removal

**Status**: Planning  
**Duration Estimate**: 2-3 weeks  
**Test Coverage Target**: Maintain 80%+ coverage across all affected areas  

## Overview

**Goal**: Replace placeholder OPAQUE functions with real protocol implementation and completely remove legacy authentication system.

**Key Decisions**:
- Implement real OPAQUE protocol first (highest priority)
- No backward compatibility needed (app not deployed yet)
- Use full privacy-first capability detection from `crypto/capability_negotiation.go`
- Maintain comprehensive test coverage across server-side, WASM, and frontend

## Implementation Steps

### Step 1: Research & Dependencies (1-2 days)

#### 1.1 OPAQUE Library Selection
**Research Go OPAQUE implementations:**
- Evaluate `github.com/bytemare/opaque` (most mature)
- Check `github.com/cloudflare/circl/oprf` for OPRF primitives
- Assess compatibility with existing `crypto/` package architecture

**Decision Criteria:**
- Production readiness and security audit status
- API compatibility with our device capability system
- WASM compilation support
- License compatibility

#### 1.2 Integration Architecture Planning
**Map OPAQUE flow to existing crypto/ structure:**
- Identify where OPAQUE registration fits with `crypto/capability_negotiation.go`
- Plan session key derivation integration with `crypto/session.go`
- Design envelope encryption compatibility with `crypto/envelope.go`

### Step 2: Crypto Package OPAQUE Implementation (3-4 days)

#### 2.1 Create crypto/opaque.go
**Core OPAQUE Implementation:**
```go
// crypto/opaque.go

package crypto

import (
    "encoding/base64"
    "fmt"
    "time"
    
    // Selected OPAQUE library will be imported here
)

// OpaqueServer manages OPAQUE protocol operations
type OpaqueServer struct {
    privateKey []byte
    config     OpaqueConfig
}

// OpaqueConfig defines OPAQUE protocol parameters
type OpaqueConfig struct {
    Suite           string           // OPAQUE-3DH with P256_SHA256_SSWU_RO_
    DeviceProfile   DeviceCapability
    ClientHardening ArgonProfile     // Client-side Argon2ID parameters
    ServerHardening ArgonProfile     // Server-side Argon2ID parameters
}

// Registration flow types
type RegistrationRequest struct {
    Username       string    `json:"username"`
    RegistrationData []byte  `json:"registration_data"`
    DeviceCapability string  `json:"device_capability"`
    ClientProof    []byte    `json:"client_proof"`
}

type RegistrationResponse struct {
    RegistrationState []byte `json:"registration_state"`
    ServerPublicKey   []byte `json:"server_public_key"`
    Suite            string  `json:"suite"`
}

type RegistrationRecord struct {
    Username     string    `json:"username"`
    Envelope     []byte    `json:"envelope"`
    PublicKey    []byte    `json:"public_key"`
    CreatedAt    time.Time `json:"created_at"`
}

// Authentication flow types
type AuthenticationChallenge struct {
    Username      string `json:"username"`
    ServerMessage []byte `json:"server_message"`
    Suite        string  `json:"suite"`
}

type AuthenticationRequest struct {
    Username      string `json:"username"`
    ClientMessage []byte `json:"client_message"`
    ClientProof   []byte `json:"client_proof"`
}

type AuthenticationResult struct {
    Username     string `json:"username"`
    SessionKey   []byte `json:"session_key"`
    ExportKey    []byte `json:"export_key"`
    Authenticated bool  `json:"authenticated"`
}

// Core OPAQUE protocol methods
func NewOpaqueServer(privateKey []byte) *OpaqueServer {
    return &OpaqueServer{
        privateKey: privateKey,
        config: OpaqueConfig{
            Suite: "OPAQUE-3DH", // Default suite
        },
    }
}

// Client-side registration flow
func (os *OpaqueServer) BeginRegistration(username string, clientData []byte) (*RegistrationResponse, error) {
    // Implementation will use selected OPAQUE library
    // Apply client-side Argon2ID hardening based on device capability
    // Return server response for client
    return nil, fmt.Errorf("not implemented")
}

func (os *OpaqueServer) FinalizeRegistration(regRequest *RegistrationRequest) (*RegistrationRecord, error) {
    // Complete registration process
    // Apply server-side Argon2ID hardening
    // Store registration record
    return nil, fmt.Errorf("not implemented")
}

// Client-side authentication flow  
func (os *OpaqueServer) BeginAuthentication(username string) (*AuthenticationChallenge, error) {
    // Initiate OPAQUE authentication
    // Retrieve user registration record
    // Generate authentication challenge
    return nil, fmt.Errorf("not implemented")
}

func (os *OpaqueServer) FinalizeAuthentication(authRequest *AuthenticationRequest) (*AuthenticationResult, error) {
    // Complete authentication process
    // Verify client proof
    // Derive session and export keys
    return nil, fmt.Errorf("not implemented")
}

// Integration with existing crypto package
func (os *OpaqueServer) SelectParametersForDevice(capability DeviceCapability) OpaqueConfig {
    config := OpaqueConfig{
        Suite:         "OPAQUE-3DH",
        DeviceProfile: capability,
    }
    
    // Select appropriate Argon2ID parameters based on device capability
    switch capability {
    case DeviceMinimal:
        config.ClientHardening = ArgonProfile{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}
        config.ServerHardening = ArgonMaximum // Always use maximum on server
    case DeviceInteractive:
        config.ClientHardening = ArgonInteractive
        config.ServerHardening = ArgonMaximum
    case DeviceBalanced:
        config.ClientHardening = ArgonBalanced
        config.ServerHardening = ArgonMaximum
    case DeviceMaximum:
        config.ClientHardening = ArgonMaximum
        config.ServerHardening = ArgonMaximum
    default:
        config.ClientHardening = ArgonInteractive // Safe default
        config.ServerHardening = ArgonMaximum
    }
    
    return config
}

func (os *OpaqueServer) DeriveSessionKey(opaqueResult *AuthenticationResult) ([]byte, error) {
    // Use existing session.go functions
    return DeriveSessionKey(opaqueResult.ExportKey, SessionKeyContext)
}

// Server key management
func GenerateOpaqueServerKey() ([]byte, error) {
    // Generate cryptographically secure server private key
    return nil, fmt.Errorf("not implemented")
}

func LoadOpaqueServerKey(keyPath string) ([]byte, error) {
    // Load server key from secure storage
    return nil, fmt.Errorf("not implemented")
}
```

#### 2.2 Integration with Existing Systems
**Enhance crypto/capability_negotiation.go:**
```go
// Add OPAQUE-specific parameter selection
func (cn *CapabilityNegotiator) SelectOpaqueParameters(capability DeviceProfile) OpaqueConfig {
    // Use device capability to choose appropriate Argon2ID parameters
    // for both client-side and server-side hardening
    
    baseConfig := OpaqueConfig{
        Suite:         "OPAQUE-3DH",
        DeviceProfile: capability.DeviceClass,
    }
    
    // Map device profile to capability enum
    var deviceCap DeviceCapability
    switch {
    case capability.ComputeProfile.LogicalCores >= 16:
        deviceCap = DeviceMaximum
    case capability.ComputeProfile.LogicalCores >= 8:
        deviceCap = DeviceBalanced
    case capability.ComputeProfile.LogicalCores >= 4:
        deviceCap = DeviceInteractive
    default:
        deviceCap = DeviceMinimal
    }
    
    // Apply battery-aware adjustments
    if capability.BatteryProfile.HasBattery && 
       capability.BatteryProfile.PowerMode == PowerModePowerSaver {
        // Reduce client-side parameters for battery life
        if deviceCap > DeviceMinimal {
            deviceCap--
        }
    }
    
    return selectOpaqueConfigForCapability(deviceCap)
}

func selectOpaqueConfigForCapability(capability DeviceCapability) OpaqueConfig {
    config := OpaqueConfig{
        Suite: "OPAQUE-3DH",
        DeviceProfile: capability,
        ServerHardening: ArgonMaximum, // Always maximum on server
    }
    
    switch capability {
    case DeviceMinimal:
        config.ClientHardening = ArgonProfile{Time: 1, Memory: 16 * 1024, Threads: 1, KeyLen: 32}
    case DeviceInteractive:
        config.ClientHardening = ArgonInteractive
    case DeviceBalanced:
        config.ClientHardening = ArgonBalanced
    case DeviceMaximum:
        config.ClientHardening = ArgonMaximum
    default:
        config.ClientHardening = ArgonInteractive
    }
    
    return config
}
```

**Enhance crypto/session.go:**
```go
// Add OPAQUE session key derivation
func DeriveSessionKeyFromOpaque(opaqueExportKey []byte, userEmail string) ([]byte, error) {
    if len(opaqueExportKey) == 0 {
        return nil, fmt.Errorf("OPAQUE export key cannot be empty")
    }
    
    // Use HKDF with OPAQUE export key and user context for domain separation
    context := fmt.Sprintf("%s:%s", SessionKeyContext, userEmail)
    return DeriveSessionKey(opaqueExportKey, context)
}

// Validate OPAQUE-derived session key
func ValidateOpaqueSessionKey(sessionKey []byte, userEmail string) error {
    if err := ValidateSessionKey(sessionKey); err != nil {
        return fmt.Errorf("invalid OPAQUE session key: %w", err)
    }
    
    if userEmail == "" {
        return fmt.Errorf("user email required for OPAQUE session validation")
    }
    
    return nil
}
```

#### 2.3 Create Comprehensive Test Suite
**File: crypto/opaque_test.go**
```go
package crypto

import (
    "testing"
    "time"
)

// Test complete OPAQUE protocol flow
func TestOpaqueRegistrationFlow(t *testing.T) {
    // Test full registration flow from client request to storage
    server := NewOpaqueServer(generateTestServerKey(t))
    
    // Test registration initiation
    regResp, err := server.BeginRegistration("test@example.com", []byte("test-client-data"))
    if err != nil {
        t.Fatalf("BeginRegistration failed: %v", err)
    }
    
    // Test registration completion
    regReq := &RegistrationRequest{
        Username: "test@example.com",
        RegistrationData: regResp.RegistrationState,
        DeviceCapability: "interactive",
        ClientProof: []byte("test-proof"),
    }
    
    record, err := server.FinalizeRegistration(regReq)
    if err != nil {
        t.Fatalf("FinalizeRegistration failed: %v", err)
    }
    
    if record.Username != "test@example.com" {
        t.Errorf("Expected username test@example.com, got %s", record.Username)
    }
}

func TestOpaqueAuthenticationFlow(t *testing.T) {
    // Test full authentication flow
    server := NewOpaqueServer(generateTestServerKey(t))
    
    // First register a user
    setupTestUser(t, server, "test@example.com")
    
    // Test authentication initiation
    challenge, err := server.BeginAuthentication("test@example.com")
    if err != nil {
        t.Fatalf("BeginAuthentication failed: %v", err)
    }
    
    // Test authentication completion
    authReq := &AuthenticationRequest{
        Username: "test@example.com",
        ClientMessage: challenge.ServerMessage, // Simulate client response
        ClientProof: []byte("test-client-proof"),
    }
    
    result, err := server.FinalizeAuthentication(authReq)
    if err != nil {
        t.Fatalf("FinalizeAuthentication failed: %v", err)
    }
    
    if !result.Authenticated {
        t.Error("Authentication should have succeeded")
    }
    
    if len(result.SessionKey) == 0 {
        t.Error("Session key should be generated")
    }
}

func TestOpaqueDeviceCapabilityIntegration(t *testing.T) {
    server := NewOpaqueServer(generateTestServerKey(t))
    
    testCases := []struct {
        capability DeviceCapability
        expectedMemory uint32
    }{
        {DeviceMinimal, 16 * 1024},
        {DeviceInteractive, 32 * 1024},
        {DeviceBalanced, 64 * 1024},
        {DeviceMaximum, 128 * 1024},
    }
    
    for _, tc := range testCases {
        config := server.SelectParametersForDevice(tc.capability)
        if config.ClientHardening.Memory != tc.expectedMemory {
            t.Errorf("Device %s: expected memory %d, got %d", 
                tc.capability.String(), tc.expectedMemory, config.ClientHardening.Memory)
        }
        
        // Server should always use maximum hardening
        if config.ServerHardening.Memory != ArgonMaximum.Memory {
            t.Error("Server should always use maximum hardening")
        }
    }
}

func TestOpaqueSessionKeyDerivation(t *testing.T) {
    server := NewOpaqueServer(generateTestServerKey(t))
    
    // Create mock authentication result
    authResult := &AuthenticationResult{
        Username: "test@example.com",
        ExportKey: []byte("mock-export-key-32-bytes-long!!"),
        Authenticated: true,
    }
    
    sessionKey, err := server.DeriveSessionKey(authResult)
    if err != nil {
        t.Fatalf("DeriveSessionKey failed: %v", err)
    }
    
    if len(sessionKey) != 32 {
        t.Errorf("Expected 32-byte session key, got %d bytes", len(sessionKey))
    }
    
    // Test session key validation
    err = ValidateOpaqueSessionKey(sessionKey, "test@example.com")
    if err != nil {
        t.Errorf("Session key validation failed: %v", err)
    }
}

func TestOpaqueParameterSelection(t *testing.T) {
    negotiator := NewCapabilityNegotiator(true) // Privacy-first mode
    
    // Test device profiles
    testProfiles := []DeviceProfile{
        createTestDeviceProfile(1, 1024),   // Minimal
        createTestDeviceProfile(4, 4096),   // Interactive
        createTestDeviceProfile(8, 8192),   // Balanced
        createTestDeviceProfile(16, 16384), // Maximum
    }
    
    for _, profile := range testProfiles {
        config := negotiator.SelectOpaqueParameters(profile)
        
        // Validate configuration
        if config.Suite != "OPAQUE-3DH" {
            t.Errorf("Expected OPAQUE-3DH suite, got %s", config.Suite)
        }
        
        // Validate client hardening is appropriate for device
        if config.ClientHardening.Memory == 0 {
            t.Error("Client hardening parameters should be set")
        }
    }
}

// Security and compatibility tests
func TestOpaqueReplayResistance(t *testing.T) {
    // Test that OPAQUE resists replay attacks
    server := NewOpaqueServer(generateTestServerKey(t))
    
    // Register user and get authentication challenge
    setupTestUser(t, server, "test@example.com")
    challenge, _ := server.BeginAuthentication("test@example.com")
    
    // Create authentication request
    authReq := &AuthenticationRequest{
        Username: "test@example.com",
        ClientMessage: challenge.ServerMessage,
        ClientProof: []byte("test-proof"),
    }
    
    // First authentication should succeed
    result1, err := server.FinalizeAuthentication(authReq)
    if err != nil {
        t.Fatalf("First authentication failed: %v", err)
    }
    
    // Replay the same request - should fail
    result2, err := server.FinalizeAuthentication(authReq)
    if err == nil && result2.Authenticated {
        t.Error("Replay attack should be prevented")
    }
}

func TestOpaqueServerStateIsolation(t *testing.T) {
    // Test that server state is properly isolated between users
    server := NewOpaqueServer(generateTestServerKey(t))
    
    // Register two users
    setupTestUser(t, server, "user1@example.com")
    setupTestUser(t, server, "user2@example.com")
    
    // Get challenges for both users
    challenge1, _ := server.BeginAuthentication("user1@example.com")
    challenge2, _ := server.BeginAuthentication("user2@example.com")
    
    // Cross-user authentication should fail
    authReq := &AuthenticationRequest{
        Username: "user1@example.com",
        ClientMessage: challenge2.ServerMessage, // Wrong challenge
        ClientProof: []byte("test-proof"),
    }
    
    result, err := server.FinalizeAuthentication(authReq)
    if err == nil && result.Authenticated {
        t.Error("Cross-user authentication should fail")
    }
}

func TestOpaqueCapabilityAdaptation(t *testing.T) {
    // Test that OPAQUE adapts to different device capabilities
    server := NewOpaqueServer(generateTestServerKey(t))
    
    capabilities := []DeviceCapability{
        DeviceMinimal, DeviceInteractive, DeviceBalanced, DeviceMaximum,
    }
    
    for _, cap := range capabilities {
        config := server.SelectParametersForDevice(cap)
        
        // Verify that parameters scale with capability
        if cap == DeviceMinimal && config.ClientHardening.Memory >= 32*1024 {
            t.Error("Minimal device should use less memory")
        }
        
        if cap == DeviceMaximum && config.ClientHardening.Memory < 64*1024 {
            t.Error("Maximum device should use more memory")
        }
        
        // Server should always use maximum
        if config.ServerHardening.Memory != ArgonMaximum.Memory {
            t.Error("Server should always use maximum hardening")
        }
    }
}

// Helper functions for tests
func generateTestServerKey(t *testing.T) []byte {
    // Generate test key - in real implementation this would be cryptographically secure
    return []byte("test-server-key-32-bytes-long!!")
}

func setupTestUser(t *testing.T, server *OpaqueServer, username string) {
    // Setup test user registration - implementation depends on selected OPAQUE library
    // This would typically involve the full registration flow
}

func createTestDeviceProfile(cores int, memoryMB int) DeviceProfile {
    return DeviceProfile{
        DeviceClass: DeviceDesktop,
        ComputeProfile: ComputeProfile{
            LogicalCores: cores,
            RecommendedThreads: min(cores, 4),
            ProfileName: "test",
        },
        MemoryProfile: MemoryProfile{
            AvailableGB: float64(memoryMB) / 1024,
            RecommendedMB: memoryMB,
            ProfileName: "test",
        },
        BatteryProfile: BatteryProfile{
            HasBattery: false,
            PowerMode: PowerModePluggedIn,
            ProfileName: "test",
        },
        Detected: time.Now(),
        UserConsent: true,
    }
}

func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

### Step 3: WASM Interface Implementation (2-3 days)

#### 3.1 Enhance crypto/wasm_shim.go
**Add comprehensive OPAQUE exports:**
```go
// Add to existing crypto/wasm_shim.go

// Device capability with privacy-first consent
func requestCapabilityConsentJS(this js.Value, args []js.Value) interface{} {
    // Use existing capability_negotiation.go for privacy-first detection
    negotiator := NewCapabilityNegotiator(true) // Privacy-first mode
    
    // Request user consent for capability detection
    err := negotiator.RequestUserConsent()
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": err.Error(),
        }
    }
    
    // Get consent dialog data
    return map[string]interface{}{
        "success": true,
        "title": "🔒 Optimize Security for Your Device",
        "message": `Arkfile can optimize password security based on your device capabilities.

We will check:
• Available memory (for optimal encryption strength)
• CPU cores (for parallel processing)
• Device type (mobile vs desktop optimization)
• Browser capabilities

This information:
✓ Stays on your device
✓ Is never sent to servers
✓ Only determines encryption strength
✓ Can be overridden manually`,
        "options": []interface{}{
            "Allow automatic optimization (recommended)",
            "Choose security level manually",
            "Use maximum security (may be slow on older devices)",
        },
    }
}

func detectDeviceCapabilityPrivacyFirstJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 1 {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid arguments: expected user consent choice",
        }
    }
    
    choice := args[0].String()
    negotiator := NewCapabilityNegotiator(true)
    
    var capability DeviceProfile
    var err error
    
    switch choice {
    case "allow":
        negotiator.userConsent = true
        capability, err = negotiator.DetectCapabilities()
    case "manual":
        // Return manual selection options
        return map[string]interface{}{
            "success": true,
            "manual": true,
            "options": []string{"minimal", "interactive", "balanced", "maximum"},
        }
    case "maximum":
        capability = createMaximumSecurityProfile()
    default:
        capability = createInteractiveProfile() // Safe default
    }
    
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": err.Error(),
        }
    }
    
    return map[string]interface{}{
        "success": true,
        "capability": capability.DeviceClass.String(),
        "summary": capability.GetCapabilitySummary(),
        "parameters": negotiator.SelectCryptoParameters(capability),
    }
}

// OPAQUE registration flow
func opaqueBeginRegistrationJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 3 {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid arguments: expected email, password, capability",
        }
    }
    
    email := args[0].String()
    password := args[1].String()
    capability := args[2].String()
    
    // Convert capability string to enum
    var deviceCap DeviceCapability
    switch capability {
    case "minimal":
        deviceCap = DeviceMinimal
    case "interactive":
        deviceCap = DeviceInteractive
    case "balanced":
        deviceCap = DeviceBalanced
    case "maximum":
        deviceCap = DeviceMaximum
    default:
        deviceCap = DeviceInteractive
    }
    
    // Create OPAQUE server instance (this would be a singleton in real implementation)
    server := createOpaqueServerInstance()
    
    // Apply client-side Argon2ID hardening based on device capability
    config := server.SelectParametersForDevice(deviceCap)
    hardenedPassword := DeriveKeyArgon2ID([]byte(password), generateClientSalt(), config.ClientHardening)
    
    // Begin OPAQUE registration
    response, err := server.BeginRegistration(email, hardenedPassword)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": err.Error(),
        }
    }
    
    return map[string]interface{}{
        "success": true,
        "email": email,
        "registrationData": base64.StdEncoding.EncodeToString(response.RegistrationState),
        "serverPublicKey": base64.StdEncoding.EncodeToString(response.ServerPublicKey),
        "suite": response.Suite,
        "deviceCapability": capability,
    }
}

func opaqueFinalizeRegistrationJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 1 {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid arguments: expected server response",
        }
    }
    
    serverResponse := args[0]
    
    // Extract server response data
    regData, err := base64.StdEncoding.DecodeString(serverResponse.Get("registrationData").String())
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid registration data",
        }
    }
    
    // Create registration request
    request := &RegistrationRequest{
        Username: serverResponse.Get("email").String(),
        RegistrationData: regData,
        DeviceCapability: serverResponse.Get("deviceCapability").String(),
        ClientProof: generateClientProof(), // Implementation specific
    }
    
    // Finalize registration
    server := createOpaqueServerInstance()
    record, err := server.FinalizeRegistration(request)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": err.Error(),
        }
    }
    
    return map[string]interface{}{
        "success": true,
        "username": record.Username,
        "registered": true,
    }
}

// OPAQUE authentication flow  
func opaqueBeginAuthenticationJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 2 {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid arguments: expected email, password",
        }
    }
    
    email := args[0].String()
    password := args[1].String()
    
    // Get device capability (could be cached from registration)
    capability := getStoredDeviceCapability() // Implementation specific
    
    // Create OPAQUE server instance
    server := createOpaqueServerInstance()
    
    // Apply client-side Argon2ID hardening
    config := server.SelectParametersForDevice(capability)
    hardenedPassword := DeriveKeyArgon2ID([]byte(password), getStoredClientSalt(email), config.ClientHardening)
    
    // Begin OPAQUE authentication
    challenge, err := server.BeginAuthentication(email)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": err.Error(),
        }
    }
    
    return map[string]interface{}{
        "success": true,
        "email": email,
        "challenge": base64.StdEncoding.EncodeToString(challenge.ServerMessage),
        "suite": challenge.Suite,
        "clientData": base64.StdEncoding.EncodeToString(hardenedPassword),
    }
}

func opaqueFinalizeAuthenticationJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 1 {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid arguments: expected server response",
        }
    }
    
    serverResponse := args[0]
    
    // Extract authentication data
    challenge, err := base64.StdEncoding.DecodeString(serverResponse.Get("challenge").String())
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid challenge data",
        }
    }
    
    clientData, err := base64.StdEncoding.DecodeString(serverResponse.Get("clientData").String())
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid client data",
        }
    }
    
    // Create authentication request
    request := &AuthenticationRequest{
        Username: serverResponse.Get("email").String(),
        ClientMessage: challenge,
        ClientProof: clientData,
    }
    
    // Finalize authentication
    server := createOpaqueServerInstance()
    result, err := server.FinalizeAuthentication(request)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": err.Error(),
        }
    }
    
    if !result.Authenticated {
        return map[string]interface{}{
            "success": false,
            "error": "Authentication failed",
        }
    }
    
    // Derive session key
    sessionKey, err := DeriveSessionKeyFromOpaque(result.ExportKey, result.Username)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": "Session key derivation failed",
        }
    }
    
    return map[string]interface{}{
        "success": true,
        "username": result.Username,
        "sessionKey": base64.StdEncoding.EncodeToString(sessionKey),
        "authenticated": true,
    }
}

// Session management
func createOpaqueSessionContextJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 2 {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid arguments: expected sessionKey, userEmail",
        }
    }
    
    sessionKeyB64 := args[0].String()
    userEmail := args[1].String()
    
    sessionKey, err := base64.StdEncoding.DecodeString(sessionKeyB64)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": "Invalid session key",
        }
    }
    
    // Validate session key
    err = ValidateOpaqueSessionKey(sessionKey, userEmail)
    if err != nil {
        return map[string]interface{}{
            "success": false,
            "error": "Session validation failed: " + err.Error(),
        }
    }
    
    // Create session context
    sessionInfo := CreateSessionKeyInfo(userEmail, "OPAQUE", sessionKey)
    
    return map[string]interface{}{
        "success": true,
        "userEmail": userEmail,
        "sessionValid": sessionInfo.IsValid,
        "keyLength": sessionInfo.KeyLength,
        "expiresAt": time.Now().Add(24 * time.Hour).Unix(), // 24 hour sessions
    }
}

func validateOpaqueSessionJS(this js.Value, args []js.Value) interface{} {
    if len(args) != 2 {
        return map[string]interface{}{
            "valid": false,
            "error": "Invalid arguments: expected sessionKey, userEmail",
        }
    }
    
    sessionKeyB64 := args[0].String()
    userEmail := args[1].String()
    
    sessionKey, err := base64.StdEncoding.DecodeString(sessionKeyB64)
    if err != nil {
        return map[string]interface{}{
            "valid": false,
            "error": "Invalid session key format",
        }
    }
    
    // Validate session key
    err = ValidateOpaqueSessionKey(sessionKey, userEmail)
    
    return map[string]interface{}{
        "valid": err == nil,
        "error": func() string {
            if err != nil {
                return err.Error()
            }
            return ""
        }(),
    }
}

// Helper functions for WASM implementation
func createOpaqueServerInstance() *OpaqueServer {
    // In real implementation, this would be a singleton with proper key management
    // For now, return a mock instance
    return NewOpaqueServer([]byte("mock-server-key-32-bytes-long!!"))
}

func generateClientSalt() []byte {
    // Generate cryptographically secure salt
    salt, _ := GenerateSalt(32)
    return salt
}

func generateClientProof() []byte {
    // Generate client proof - implementation specific to OPAQUE library
    return []byte("mock-client-proof")
}

func getStoredDeviceCapability() DeviceCapability {
    // In real implementation, this would be stored from registration
    // For now, return a reasonable default
    return DeviceInteractive
}

func getStoredClientSalt(email string) []byte {
    // In real implementation, this would be retrieved from secure storage
    // For now, generate deterministic salt from email
    hash := sha256.Sum256([]byte("client-salt:" + email))
    return hash[:]
}

func createMaximumSecurityProfile() DeviceProfile {
    return DeviceProfile{
        DeviceClass: DeviceDesktop,
        ComputeProfile: ComputeProfile{
            LogicalCores: 16,
            RecommendedThreads: 4,
            ProfileName: "maximum_security",
        },
        MemoryProfile: MemoryProfile{
            AvailableGB: 16.0,
            RecommendedMB: 128,
            ProfileName: "maximum_security",
        },
        BatteryProfile: BatteryProfile{
            HasBattery: false,
            PowerMode: PowerModePluggedIn,
            ProfileName: "maximum_security",
        },
        Detected: time.Now(),
        UserConsent: false, // User chose maximum, no detection needed
    }
}

func createInteractiveProfile() DeviceProfile {
    return DeviceProfile{
        DeviceClass: DeviceDesktop,
        ComputeProfile: ComputeProfile{
            LogicalCores: 4,
            RecommendedThreads: 2,
            ProfileName: "interactive_default",
        },
        MemoryProfile: MemoryProfile{
            AvailableGB: 4.0,
            RecommendedMB: 32,
            ProfileName: "interactive_default",
        },
        BatteryProfile: BatteryProfile{
            HasBattery: false,
            PowerMode: PowerModeBalanced,
            ProfileName: "interactive_default",
        },
        Detected: time.Now(),
        UserConsent: false, // Default profile
    }
}

// Register OPAQUE functions with JavaScript
func RegisterOpaqueWASMFunctions() {
    // Device capability functions
    js.Global().Set("requestCapabilityConsentWASM", js.FuncOf(requestCapabilityConsentJS))
    js.Global().Set("detectDeviceCapabilityPrivacyFirstWASM", js.FuncOf(detectDeviceCapabilityPrivacyFirstJS))
    
    // OPAQUE registration functions
    js.Global().Set("opaqueBeginRegistrationWASM", js.FuncOf(opaqueBeginRegistrationJS))
    js.Global().Set("opaqueFinalizeRegistrationWASM", js.FuncOf(opaqueFinalizeRegistrationJS))
    
    // OPAQUE authentication functions
    js.Global().Set("opaqueBeginAuthenticationWASM", js.FuncOf(opaqueBeginAuthenticationJS))
    js.Global().Set("opaqueFinalizeAuthenticationWASM", js.FuncOf(opaqueFinalizeAuthenticationJS))
    
    // Session management functions
    js.Global().Set("createOpaqueSessionContextWASM", js.FuncOf(createOpaqueSessionContextJS))
    js.Global().Set("validateOpaqueSessionWASM", js.FuncOf(validateOpaqueSessionJS))
}
```

#### 3.2 Update client/main.go WASM Registration
**Replace placeholder functions:**
```go
func main() {
    // Remove old placeholder functions
    // js.Global().Set("opaqueRegisterFlow", js.FuncOf(opaqueRegisterFlow))
    // js.Global().Set("opaqueLoginFlow", js.FuncOf(opaqueLoginFlow))
    // js.Global().Set("requestDeviceCapabilityPermission", js.FuncOf(requestDeviceCapabilityPermission))
    // js.Global().Set("detectDeviceCapabilityWithPermission", js.FuncOf(detectDeviceCapabilityWithPermission))
    
    // Add real OPAQUE implementations from crypto/wasm_shim.go
    crypto.RegisterOpaqueWASMFunctions()
    
    // Keep existing file encryption functions (temporarily)
    js.Global().Set("encryptFile", js.FuncOf(encryptFile))
    js.Global().Set("decryptFile", js.FuncOf(decryptFile))
    js.Global().Set("encryptFileMultiKey", js.FuncOf(encryptFileMultiKey))
    js.Global().Set("decryptFileMultiKey", js.FuncOf(decryptFileMultiKey))
    
    // Keep existing utility functions
    js.Global().Set("generateSalt", js.FuncOf(generateSalt))
    js.Global().Set("calculateSHA256", js.FuncOf(calculateSHA256))
    js.Global().Set("validatePasswordComplexity", js.FuncOf(validatePasswordComplexity))
    js.Global().Set("hashPasswordArgon2ID", js.FuncOf(hashPasswordArgon2ID))
    js.Global().Set("generatePasswordSalt", js.FuncOf(generatePasswordSalt))
    js.Global().Set("deriveSessionKey", js.FuncOf(deriveSessionKey))

    // Keep the program running
    select {}
}
```

#### 3.3 Create WASM Test Suite
**File: client/opaque_wasm_test.js**
```javascript
// Test OPAQUE WASM integration
async function testOpaqueRegistrationWASM() {
    console.log("Testing OPAQUE Registration WASM...");
    
    // Test device capability consent
    const consentResult = await requestCapabilityConsentWASM();
    assert(consentResult.success, "Capability consent should succeed");
    assert(consentResult.title.includes("Optimize Security"), "Should have capability dialog");
    
    // Test capability detection
    const capabilityResult = await detectDeviceCapabilityPrivacyFirstWASM("allow");
    assert(capabilityResult.success, "Capability detection should succeed");
    assert(typeof capabilityResult.capability === "string", "Should return capability string");
    
    // Test OPAQUE registration
    const regResult = await opaqueBeginRegistrationWASM(
        "test@example.com", 
        "TestPassword123!SecurePass", 
        capabilityResult.capability
    );
    assert(regResult.success, "OPAQUE registration should begin");
    assert(regResult.email === "test@example.com", "Should preserve email");
    assert(regResult.registrationData, "Should have registration data");
    
    console.log("✅ OPAQUE Registration WASM tests passed");
}

async function testOpaqueAuthenticationWASM() {
    console.log("Testing OPAQUE Authentication WASM...");
    
    // First register a user (mock)
    const regResult = await opaqueBeginRegistrationWASM(
        "auth-test@example.com", 
        "AuthTestPass123!Secure", 
        "interactive"
    );
    
    // Complete registration (mock server response)
    const mockServerResponse = {
        email: regResult.email,
        registrationData: regResult.registrationData,
        deviceCapability: regResult.deviceCapability,
        success: true
    };
    
    const finalizeResult = await opaqueFinalizeRegistrationWASM(mockServerResponse);
    assert(finalizeResult.success, "Registration finalization should succeed");
    
    // Test authentication
    const authResult = await opaqueBeginAuthenticationWASM(
        "auth-test@example.com", 
        "AuthTestPass123!Secure"
    );
    assert(authResult.success, "Authentication should begin");
    assert(authResult.challenge, "Should have authentication challenge");
    
    console.log("✅ OPAQUE Authentication WASM tests passed");
}

async function testDeviceCapabilityDetectionWASM() {
    console.log("Testing Device Capability Detection WASM...");
    
    // Test privacy-first consent
    const consentResult = await requestCapabilityConsentWASM();
    assert(consentResult.success, "Consent request should succeed");
    assert(Array.isArray(consentResult.options), "Should have consent options");
    assert(consentResult.options.length === 3, "Should have 3 consent options");
    
    // Test capability detection with consent
    const allowResult = await detectDeviceCapabilityPrivacyFirstWASM("allow");
    assert(allowResult.success, "Detection with consent should succeed");
    assert(allowResult.capability, "Should detect capability");
    
    // Test manual selection
    const manualResult = await detectDeviceCapabilityPrivacyFirstWASM("manual");
    assert(manualResult.success, "Manual selection should succeed");
    assert(manualResult.manual === true, "Should indicate manual mode");
    assert(Array.isArray(manualResult.options), "Should have manual options");
    
    // Test maximum security selection
    const maxResult = await detectDeviceCapabilityPrivacyFirstWASM("maximum");
    assert(maxResult.success, "Maximum security should succeed");
    assert(maxResult.capability === "desktop", "Should use maximum profile");
    
    console.log("✅ Device Capability Detection WASM tests passed");
}

async function testSessionContextManagementWASM() {
    console.log("Testing Session Context Management WASM...");
    
    // Mock session key (base64 encoded)
    const mockSessionKey = btoa("mock-session-key-32-bytes-long!!");
    const userEmail = "session-test@example.com";
    
    // Test session context creation
    const contextResult = await createOpaqueSessionContextWASM(mockSessionKey, userEmail);
    assert(contextResult.success, "Session context creation should succeed");
    assert(contextResult.userEmail === userEmail, "Should preserve user email");
    assert(contextResult.sessionValid, "Session should be valid");
    assert(typeof contextResult.expiresAt === "number", "Should have expiration time");
    
    // Test session validation
    const validationResult = await validateOpaqueSessionWASM(mockSessionKey, userEmail);
    assert(validationResult.valid, "Session validation should succeed");
    assert(!validationResult.error, "Should not have validation errors");
    
    // Test invalid session key
    const invalidResult = await validateOpaqueSessionWASM("invalid-key", userEmail);
    assert(!invalidResult.valid, "Invalid session should fail validation");
    assert(invalidResult.error, "Should have validation error");
    
    console.log("✅ Session Context Management WASM tests passed");
}

// Integration tests with existing crypto functions
async function testOpaqueWithFileEncryption() {
    console.log("Testing OPAQUE integration with file encryption...");
    
    // Mock OPAQUE authentication to get session key
    const mockSessionKey = btoa("opaque-session-key-32-bytes-long!");
    const userEmail = "file-test@example.com";
    
    // Create session context
    const sessionResult = await createOpaqueSessionContextWASM(mockSessionKey, userEmail);
    assert(sessionResult.success, "Session creation should succeed");
    
    // Test file encryption with OPAQUE session key
    const testFileData = new TextEncoder().encode("Test file content for OPAQUE encryption");
    const encryptedData = encryptFile(testFileData, atob(mockSessionKey), "account");
    assert(typeof encryptedData === "string", "Should return encrypted data");
    
    // Test file decryption with OPAQUE session key
    const decryptedData = decryptFile(encryptedData, atob(mockSessionKey));
    assert(typeof decryptedData === "string", "Should return decrypted data");
    
    // Verify content integrity
    const decryptedBytes = Uint8Array.from(atob(decryptedData), c => c.charCodeAt(0));
    const originalText = new TextDecoder().decode(decryptedBytes);
    assert(originalText === "Test file content for OPAQUE encryption", "Content should match");
    
    console.log("✅ OPAQUE-File Encryption integration tests passed");
}

async function testOpaqueWithMultiKeyEncryption() {
    console.log("Testing OPAQUE integration with multi-key encryption...");
    
    // Mock OPAQUE session key
    const opaqueSessionKey = btoa("opaque-multi-key-session-32-bytes!");
    
    // Test multi-key encryption with OPAQUE primary key
    const testFileData = new TextEncoder().encode("Multi-key test file with OPAQUE");
    const additionalKeys = [
        { password: "SharePassword123!Secure", id: "share-key-1" },
        { password: "BackupPassword456!Safe", id: "backup-key-1" }
    ];
    
    const encryptedData = encryptFileMultiKey(
        testFileData, 
        atob(opaqueSessionKey), 
        "account", 
        additionalKeys
    );
    assert(typeof encryptedData === "string", "Should return multi-key encrypted data");
    
    // Test decryption with OPAQUE session key
    const decryptedWithOpaque = decryptFileMultiKey(encryptedData, atob(opaqueSessionKey));
    assert(typeof decryptedWithOpaque === "string", "Should decrypt with OPAQUE key");
    
    // Test decryption with additional key
    const decryptedWithShare = decryptFileMultiKey(encryptedData, "SharePassword123!Secure");
    assert(typeof decryptedWithShare === "string", "Should decrypt with share key");
    
    console.log("✅ OPAQUE-Multi-key Encryption integration tests passed");
}

// Test runner for all OPAQUE WASM tests
async function runOpaqueWASMTests() {
    console.log("🧪 Running OPAQUE WASM Test Suite...");
    
    try {
        await testOpaqueRegistrationWASM();
        await testOpaqueAuthenticationWASM();
        await testDeviceCapabilityDetectionWASM();
        await testSessionContextManagementWASM();
        await testOpaqueWithFileEncryption();
        await testOpaqueWithMultiKeyEncryption();
        
        console.log("🎉 All OPAQUE WASM tests passed!");
        return true;
    } catch (error) {
        console.error("❌ OPAQUE WASM tests failed:", error);
        return false;
    }
}

// Helper function for assertions
function assert(condition, message) {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}
```

## Step 4: Server-Side Integration (2-3 days)

### 4.1 Update Database Schema
**Add OPAQUE tables (replace legacy):**
```sql
-- Remove legacy tables
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS password_hashes;

-- Add OPAQUE registration storage
CREATE TABLE opaque_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    registration_record BLOB NOT NULL,
    device_capability TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    approved BOOLEAN DEFAULT FALSE
);

-- Add OPAQUE server configuration
CREATE TABLE opaque_server_config (
    id INTEGER PRIMARY KEY,
    private_key BLOB NOT NULL,
    public_key BLOB NOT NULL,
    suite_config TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE
);

-- Add OPAQUE authentication sessions
CREATE TABLE opaque_auth_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    session_id TEXT UNIQUE NOT NULL,
    challenge_data BLOB NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed BOOLEAN DEFAULT FALSE
);

-- Index for performance
CREATE INDEX idx_opaque_registrations_email ON opaque_registrations(email);
CREATE INDEX idx_opaque_auth_sessions_email ON opaque_auth_sessions(email);
CREATE INDEX idx_opaque_auth_sessions_session_id ON opaque_auth_sessions(session_id);
```

### 4.2 Update Authentication Handlers
**File: handlers/auth.go**
```go
// Remove legacy functions
// func login(w http.ResponseWriter, r *http.Request)
// func register(w http.ResponseWriter, r *http.Request)

// Add OPAQUE handlers
func opaqueBeginRegistration(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Email           string `json:"email"`
        RegistrationData string `json:"registrationData"`
        DeviceCapability string `json:"deviceCapability"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Validate email format
    if !isValidEmail(request.Email) {
        http.Error(w, "Invalid email format", http.StatusBadRequest)
        return
    }
    
    // Check if user already exists
    exists, err := checkUserExists(request.Email)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    if exists {
        http.Error(w, "User already exists", http.StatusConflict)
        return
    }
    
    // Process OPAQUE registration
    server := getOpaqueServerInstance()
    
    regData, err := base64.StdEncoding.DecodeString(request.RegistrationData)
    if err != nil {
        http.Error(w, "Invalid registration data", http.StatusBadRequest)
        return
    }
    
    // Store registration request
    err = storeRegistrationRequest(request.Email, regData, request.DeviceCapability)
    if err != nil {
        http.Error(w, "Failed to store registration", http.StatusInternalServerError)
        return
    }
    
    // Return success response
    response := map[string]interface{}{
        "success": true,
        "email": request.Email,
        "message": "Registration initiated successfully",
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func opaqueFinalizeRegistration(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Email       string `json:"email"`
        ClientProof string `json:"clientProof"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Retrieve registration data
    regData, capability, err := getRegistrationRequest(request.Email)
    if err != nil {
        http.Error(w, "Registration not found", http.StatusNotFound)
        return
    }
    
    // Finalize OPAQUE registration
    server := getOpaqueServerInstance()
    
    clientProof, err := base64.StdEncoding.DecodeString(request.ClientProof)
    if err != nil {
        http.Error(w, "Invalid client proof", http.StatusBadRequest)
        return
    }
    
    regRequest := &crypto.RegistrationRequest{
        Username: request.Email,
        RegistrationData: regData,
        DeviceCapability: capability,
        ClientProof: clientProof,
    }
    
    record, err := server.FinalizeRegistration(regRequest)
    if err != nil {
        http.Error(w, "Registration failed", http.StatusInternalServerError)
        return
    }
    
    // Store final registration record
    err = storeRegistrationRecord(record)
    if err != nil {
        http.Error(w, "Failed to store registration", http.StatusInternalServerError)
        return
    }
    
    // Clean up temporary registration data
    cleanupRegistrationRequest(request.Email)
    
    response := map[string]interface{}{
        "success": true,
        "username": record.Username,
        "registered": true,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func opaqueBeginAuthentication(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Email string `json:"email"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Check if user exists
    exists, err := checkUserExists(request.Email)
    if err != nil {
        http.Error(w, "Database error", http.StatusInternalServerError)
        return
    }
    if !exists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    
    // Begin OPAQUE authentication
    server := getOpaqueServerInstance()
    challenge, err := server.BeginAuthentication(request.Email)
    if err != nil {
        http.Error(w, "Authentication failed", http.StatusInternalServerError)
        return
    }
    
    // Store authentication session
    sessionID := generateSessionID()
    err = storeAuthenticationSession(request.Email, sessionID, challenge.ServerMessage)
    if err != nil {
        http.Error(w, "Failed to store session", http.StatusInternalServerError)
        return
    }
    
    response := map[string]interface{}{
        "success": true,
        "challenge": base64.StdEncoding.EncodeToString(challenge.ServerMessage),
        "sessionId": sessionID,
        "suite": challenge.Suite,
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

func opaqueFinalizeAuthentication(w http.ResponseWriter, r *http.Request) {
    var request struct {
        Email         string `json:"email"`
        SessionID     string `json:"sessionId"`
        ClientMessage string `json:"clientMessage"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Retrieve authentication session
    challengeData, err := getAuthenticationSession(request.Email, request.SessionID)
    if err != nil {
        http.Error(w, "Session not found", http.StatusNotFound)
        return
    }
    
    // Finalize OPAQUE authentication
    server := getOpaqueServerInstance()
    
    clientMessage, err := base64.StdEncoding.DecodeString(request.ClientMessage)
    if err != nil {
        http.Error(w, "Invalid client message", http.StatusBadRequest)
        return
    }
    
    authRequest := &crypto.AuthenticationRequest{
        Username: request.Email,
        ClientMessage: clientMessage,
        ClientProof: challengeData,
    }
    
    result, err := server.FinalizeAuthentication(authRequest)
    if err != nil {
        http.Error(w, "Authentication failed", http.StatusUnauthorized)
        return
    }
    
    if !result.Authenticated {
        http.Error(w, "Authentication failed", http.StatusUnauthorized)
        return
    }
    
    // Generate JWT tokens
    sessionKey, err := crypto.DeriveSessionKeyFromOpaque(result.ExportKey, result.Username)
    if err != nil {
        http.Error(w, "Session key derivation failed", http.StatusInternalServerError)
        return
    }
    
    accessToken, refreshToken, err := generateTokens(result.Username, sessionKey)
    if err != nil {
        http.Error(w, "Token generation failed", http.StatusInternalServerError)
        return
    }
    
    // Set secure cookies
    setSecureCookies(w, accessToken, refreshToken)
    
    // Clean up authentication session
    cleanupAuthenticationSession(request.Email, request.SessionID)
    
    response := map[string]interface{}{
        "success": true,
        "username": result.Username,
        "authenticated": true,
        "sessionKey": base64.StdEncoding.EncodeToString(sessionKey),
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}

// Enhanced capability detection endpoint
func opaqueCapabilityDetection(w http.ResponseWriter, r *http.Request) {
    var request struct {
        UserAgent    string `json:"userAgent"`
        Consent      bool   `json:"consent"`
        ManualChoice string `json:"manualChoice"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Use capability negotiation for privacy-first detection
    negotiator := crypto.NewCapabilityNegotiator(true)
    
    var capability crypto.DeviceProfile
    var err error
    
    if request.Consent {
        // Detect capabilities with user consent
        capability, err = negotiator.DetectCapabilitiesFromUserAgent(request.UserAgent)
    } else if request.ManualChoice != "" {
        // Use manual selection
        capability = negotiator.CreateProfileFromChoice(request.ManualChoice)
    } else {
        // Use safe default
        capability = negotiator.GetDefaultProfile()
    }
    
    if err != nil {
        http.Error(w, "Capability detection failed", http.StatusInternalServerError)
        return
    }
    
    // Select OPAQUE parameters
    config := negotiator.SelectOpaqueParameters(capability)
    
    response := map[string]interface{}{
        "success": true,
        "capability": capability.DeviceClass.String(),
        "profile": capability.GetCapabilitySummary(),
        "parameters": map[string]interface{}{
            "clientMemory": config.ClientHardening.Memory,
            "clientTime": config.ClientHardening.Time,
            "clientThreads": config.ClientHardening.Threads,
            "suite": config.Suite,
        },
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(response)
}
```

## Step 5: Client-Side JavaScript Cleanup (1-2 days)

### 5.1 Remove Legacy Functions from app.js
**Delete these functions (~300 lines):**
```javascript
// REMOVE - Legacy authentication
async function legacyLogin() { /* ... */ }
async function legacyRegister() { /* ... */ }

// REMOVE - Placeholder OPAQUE (replace with real calls)
async function opaqueLogin() { /* ... */ }
async function opaqueRegister() { /* ... */ }

// REMOVE - Device capability detection (move to WASM)
async function detectDeviceCapability() { /* ... */ }
async function requestDeviceCapabilityConsent() { /* ... */ }
function handleCapabilityConsent() { /* ... */ }

// REMOVE - Session key derivation (move to WASM)
function deriveSessionKey() { /* ... */ }
```

### 5.2 Replace with WASM Interface Calls
**Add simplified OPAQUE interface:**
```javascript
// Simplified OPAQUE registration
async function register() {
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    try {
        // Get device capability with privacy-first consent
        const capability = await requestCapabilityConsentWASM();
        
        // Handle user choice
        let capabilityChoice = "interactive"; // default
        if (capability.success) {
            capabilityChoice = await showCapabilityDialog(capability);
        }
        
        // Begin OPAQUE registration
        const regResult = await opaqueBeginRegistrationWASM(email, password, capabilityChoice);
        if (!regResult.success) {
            throw new Error(regResult.error);
        }
        
        // Send to server
        const response = await fetch('/api/opaque/register/begin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: regResult.email,
                registrationData: regResult.registrationData,
                deviceCapability: regResult.deviceCapability
            })
        });
        
        if (!response.ok) {
            throw new Error('Registration failed');
        }
        
        // Finalize registration
        const serverResp = await response.json();
        const finalResult = await opaqueFinalizeRegistrationWASM(serverResp);
        
        if (finalResult.success) {
            showRegistrationSuccess();
        } else {
            throw new Error(finalResult.error);
        }
        
    } catch (error) {
        showError('Registration failed: ' + error.message);
    }
}

// Simplified OPAQUE authentication  
async function login() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    try {
        // Begin OPAQUE authentication
        const authResult = await opaqueBeginAuthenticationWASM(email, password);
        if (!authResult.success) {
            throw new Error(authResult.error);
        }
        
        // Send to server
        const response = await fetch('/api/opaque/authenticate/begin', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: authResult.email
            })
        });
        
        if (!response.ok) {
            throw new Error('Authentication failed');
        }
        
        const serverChallenge = await response.json();
        
        // Finalize authentication
        const finalResult = await opaqueFinalizeAuthenticationWASM({
            email: authResult.email,
            challenge: serverChallenge.challenge,
            clientData: authResult.clientData
        });
        
        if (finalResult.success && finalResult.authenticated) {
            // Setup session
            const sessionResult = await createOpaqueSessionContextWASM(
                finalResult.sessionKey, 
                finalResult.username
            );
            
            if (sessionResult.success) {
                setupUserSession(finalResult.username, finalResult.sessionKey);
                showLoginSuccess();
            } else {
                throw new Error('Session setup failed');
            }
        } else {
            throw new Error('Authentication failed');
        }
        
    } catch (error) {
        showError('Login failed: ' + error.message);
    }
}

// Device capability dialog helper
async function showCapabilityDialog(capabilityData) {
    return new Promise((resolve) => {
        const modal = createCapabilityModal(capabilityData);
        document.body.appendChild(modal);
        
        modal.addEventListener('choice', (event) => {
            document.body.removeChild(modal);
            resolve(event.detail.choice);
        });
    });
}

function createCapabilityModal(data) {
    const modal = document.createElement('div');
    modal.className = 'capability-modal';
    modal.innerHTML = `
        <div class="capability-content">
            <h3>${data.title}</h3>
            <p>${data.message}</p>
            <div class="capability-options">
                ${data.options.map((option, index) => 
                    `<button class="capability-btn" data-choice="${index}">${option}</button>`
                ).join('')}
            </div>
        </div>
    `;
    
    modal.addEventListener('click', (e) => {
        if (e.target.classList.contains('capability-btn')) {
            const choice = e.target.dataset.choice;
            const choiceMap = ['allow', 'manual', 'maximum'];
            modal.dispatchEvent(new CustomEvent('choice', { 
                detail: { choice: choiceMap[choice] || 'interactive' }
            }));
        }
    });
    
    return modal;
}
```

## Step 6: Integration Testing & Validation (1-2 days)

### 6.1 Comprehensive Integration Tests
**Create integration test scenarios:**
```bash
#!/bin/bash
# scripts/test-opaque-integration.sh

echo "🧪 Testing OPAQUE Integration..."

# Start test environment
./scripts/setup-test-environment.sh

# Test OPAQUE server key generation
echo "Testing OPAQUE server key generation..."
go test -v ./crypto -run TestGenerateOpaqueServerKey

# Test OPAQUE registration flow
echo "Testing OPAQUE registration flow..."
go test -v ./crypto -run TestOpaqueRegistrationFlow

# Test OPAQUE authentication flow
echo "Testing OPAQUE authentication flow..."
go test -v ./crypto -run TestOpaqueAuthenticationFlow

# Test device capability integration
echo "Testing device capability integration..."
go test -v ./crypto -run TestOpaqueDeviceCapabilityIntegration

# Test WASM integration
echo "Testing WASM integration..."
cd client && node opaque_wasm_test.js

# Test server-side handlers
echo "Testing server-side OPAQUE handlers..."
go test -v ./handlers -run TestOpaqueHandlers

echo "✅ OPAQUE integration tests completed"
```

```bash
#!/bin/bash
# scripts/test-capability-detection.sh

echo "🔍 Testing Device Capability Detection..."

# Test privacy-first capability detection
echo "Testing privacy-first detection..."
go test -v ./crypto -run TestCapabilityNegotiatorPrivacyFirst

# Test device profiling
echo "Testing device profiling..."
go test -v ./crypto -run TestDeviceProfileCreation

# Test OPAQUE parameter selection
echo "Testing OPAQUE parameter selection..."
go test -v ./crypto -run TestOpaqueParameterSelection

# Test WASM capability functions
echo "Testing WASM capability functions..."
cd client && node -e "
const { runCapabilityDetectionTests } = require('./capability_detection_test.js');
runCapabilityDetectionTests().then(success => {
    process.exit(success ? 0 : 1);
});
"

echo "✅ Capability detection tests completed"
```

```bash
#!/bin/bash
# scripts/test-session-management.sh

echo "🔐 Testing Session Management..."

# Test OPAQUE session key derivation
echo "Testing session key derivation..."
go test -v ./crypto -run TestOpaqueSessionKeyDerivation

# Test session validation
echo "Testing session validation..."
go test -v ./crypto -run TestValidateOpaqueSessionKey

# Test JWT integration with OPAQUE
echo "Testing JWT integration..."
go test -v ./handlers -run TestOpaqueJWTIntegration

# Test session security properties
echo "Testing session security..."
go test -v ./crypto -run TestOpaqueSessionSecurity

echo "✅ Session management tests completed"
```

### 6.2 Security Validation
**Security property verification:**
```go
// security_validation_test.go
package main

import (
    "testing"
    "crypto/rand"
    "bytes"
)

func TestOpaquePasswordNeverTransmitted(t *testing.T) {
    // Test that passwords are never sent to server in any form
    server := setupTestServer()
    defer server.Close()
    
    password := "TestPassword123!SecurePass"
    
    // Capture all network traffic during registration
    trafficCapture := captureNetworkTraffic(server.URL)
    
    // Perform OPAQUE registration
    result := performOpaqueRegistration("test@example.com", password)
    
    // Verify password never appears in network traffic
    networkData := trafficCapture.GetCapturedData()
    
    if bytes.Contains(networkData, []byte(password)) {
        t.Error("Password found in network traffic - OPAQUE property violated")
    }
    
    // Verify no password hashes in network traffic
    passwordHash := sha256.Sum256([]byte(password))
    if bytes.Contains(networkData, passwordHash[:]) {
        t.Error("Password hash found in network traffic - OPAQUE property violated")
    }
}

func TestOpaqueSessionKeyProperDerivation(t *testing.T) {
    // Test that session keys are properly derived from OPAQUE export key
    server := NewOpaqueServer(generateTestServerKey(t))
    
    // Mock successful authentication
    authResult := &AuthenticationResult{
        Username: "test@example.com",
        ExportKey: make([]byte, 32),
        Authenticated: true,
    }
    rand.Read(authResult.ExportKey)
    
    // Derive session key
    sessionKey1, err := DeriveSessionKeyFromOpaque(authResult.ExportKey, "test@example.com")
    if err != nil {
        t.Fatalf("Session key derivation failed: %v", err)
    }
    
    // Derive again with same inputs - should be identical
    sessionKey2, err := DeriveSessionKeyFromOpaque(authResult.ExportKey, "test@example.com")
    if err != nil {
        t.Fatalf("Second session key derivation failed: %v", err)
    }
    
    if !bytes.Equal(sessionKey1, sessionKey2) {
        t.Error("Session key derivation is not deterministic")
    }
    
    // Derive with different user - should be different
    sessionKey3, err := DeriveSessionKeyFromOpaque(authResult.ExportKey, "other@example.com")
    if err != nil {
        t.Fatalf("Third session key derivation failed: %v", err)
    }
    
    if bytes.Equal(sessionKey1, sessionKey3) {
        t.Error("Session keys should be different for different users")
    }
}

func TestDeviceCapabilityPrivacyCompliance(t *testing.T) {
    // Test that device capability detection respects privacy requirements
    negotiator := NewCapabilityNegotiator(true) // Privacy-first mode
    
    // Without consent, should not perform detection
    profile, err := negotiator.DetectCapabilities()
    if err == nil {
        t.Error("Capability detection should fail without user consent")
    }
    
    // With consent, should perform detection
    negotiator.SetUserConsent(true)
    profile, err = negotiator.DetectCapabilities()
    if err != nil {
        t.Errorf("Capability detection should succeed with consent: %v", err)
    }
    
    // Verify profile contains consent flag
    if !profile.UserConsent {
        t.Error("Profile should indicate user consent was given")
    }
}
```

### 6.3 Performance Benchmarking
**OPAQUE performance across device capabilities:**
```go
// performance_benchmark_test.go
package main

import (
    "testing"
    "time"
)

func BenchmarkOpaqueRegistrationMinimal(b *testing.B) {
    server := NewOpaqueServer(generateTestServerKey(nil))
    config := server.SelectParametersForDevice(DeviceMinimal)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        email := fmt.Sprintf("user%d@example.com", i)
        password := []byte("TestPassword123!SecurePass")
        
        // Apply client-side hardening
        hardenedPassword := DeriveKeyArgon2ID(password, generateTestSalt(), config.ClientHardening)
        
        // Perform registration
        _, err := server.BeginRegistration(email, hardenedPassword)
        if err != nil {
            b.Fatalf("Registration failed: %v", err)
        }
    }
}

func BenchmarkOpaqueRegistrationInteractive(b *testing.B) {
    server := NewOpaqueServer(generateTestServerKey(nil))
    config := server.SelectParametersForDevice(DeviceInteractive)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        email := fmt.Sprintf("user%d@example.com", i)
        password := []byte("TestPassword123!SecurePass")
        
        hardenedPassword := DeriveKeyArgon2ID(password, generateTestSalt(), config.ClientHardening)
        _, err := server.BeginRegistration(email, hardenedPassword)
        if err != nil {
            b.Fatalf("Registration failed: %v", err)
        }
    }
}

func BenchmarkOpaqueRegistrationMaximum(b *testing.B) {
    server := NewOpaqueServer(generateTestServerKey(nil))
    config := server.SelectParametersForDevice(DeviceMaximum)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        email := fmt.Sprintf("user%d@example.com", i)
        password := []byte("TestPassword123!SecurePass")
        
        hardenedPassword := DeriveKeyArgon2ID(password, generateTestSalt(), config.ClientHardening)
        _, err := server.BeginRegistration(email, hardenedPassword)
        if err != nil {
            b.Fatalf("Registration failed: %v", err)
        }
    }
}

func TestOpaquePerformanceAcrossCapabilities(t *testing.T) {
    capabilities := []struct{
        name string
        capability DeviceCapability
        maxTime time.Duration
    }{
        {"Minimal", DeviceMinimal, 2 * time.Second},
        {"Interactive", DeviceInteractive, 5 * time.Second},
        {"Balanced", DeviceBalanced, 10 * time.Second},
        {"Maximum", DeviceMaximum, 30 * time.Second},
    }
    
    server := NewOpaqueServer(generateTestServerKey(t))
    
    for _, tc := range capabilities {
        t.Run(tc.name, func(t *testing.T) {
            config := server.SelectParametersForDevice(tc.capability)
            
            start := time.Now()
            
            // Simulate client-side hardening
            password := []byte("TestPassword123!SecurePass")
            hardenedPassword := DeriveKeyArgon2ID(password, generateTestSalt(), config.ClientHardening)
            
            // Perform registration
            _, err := server.BeginRegistration("test@example.com", hardenedPassword)
            
            duration := time.Since(start)
            
            if err != nil {
                t.Errorf("Registration failed for %s: %v", tc.name, err)
            }
            
            if duration > tc.maxTime {
                t.Errorf("Registration too slow for %s: %v > %v", tc.name, duration, tc.maxTime)
            }
            
            t.Logf("Registration time for %s: %v", tc.name, duration)
        })
    }
}
```

## Step 7: Documentation & Cleanup (1 day)

### 7.1 Create WIP Documentation
**Create new documentation under docs/wip/:**
- **docs/wip/phase1-opaque-implementation.md** - Complete OPAQUE implementation details
- **docs/wip/opaque-api-endpoints.md** - Detailed API documentation for new OPAQUE endpoints
- **docs/wip/device-capability-privacy.md** - Privacy-first capability detection implementation
- **docs/wip/opaque-security-properties.md** - Security analysis and validation results

### 7.2 Minimal Updates to Main Documentation
**Only essential updates to existing docs:**

**docs/security.md** - Single line update:
- Update "OPAQUE Protocol Implementation" section status from "planned" to "implemented"

**docs/api.md** - Brief endpoint updates:
- Add new OPAQUE endpoints to API reference (just the endpoint paths and basic purpose)
- Mark legacy endpoints as "deprecated/removed"

### 7.3 Code Cleanup
**Remove legacy files and functions:**
- Clean up commented-out code
- Remove unused imports  
- Update build scripts
- Clean up test files

## Deliverables & Success Criteria

### Code Deliverables
1. **crypto/opaque.go** - Full OPAQUE protocol implementation ✅
2. **crypto/wasm_shim.go** - Enhanced with real OPAQUE exports ✅
3. **Updated client/main.
