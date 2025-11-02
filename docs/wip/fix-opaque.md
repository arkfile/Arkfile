# Zero-Knowledge OPAQUE Implementation Refactoring Plan

**Status**: Planning Phase  
**Priority**: High - Security Architecture  
**Complexity**: High - Multi-layer refactoring required

> **⚠️ IMPORTANT: READ FIRST**  
> Before beginning any work on this project, you MUST read `docs/AGENTS.md` for critical project guidelines, coding standards, and architectural principles.

---

<INITIAL_PLAN>

# Zero-Knowledge OPAQUE Implementation Refactoring Plan from Claude 4.5 Sonnet LLM

## Executive Summary

This document outlines the complete refactoring plan to migrate from the current "OPAQUE-inspired" password storage implementation to a true zero-knowledge OPAQUE protocol implementation. The current system sends passwords to the server (defeating zero-knowledge), while the target implementation will ensure passwords never leave the client.

**Key Principle**: NEVER roll our own crypto. Rely entirely on the battle-tested libopaque C library.

**Note**: This is a greenfield application with no production deployments. We can implement the correct zero-knowledge OPAQUE protocol directly without backward compatibility concerns.

## Security Architecture Principles

### Zero-Knowledge Design

**The server CANNOT and MUST NOT:**
- See plaintext passwords (at any point in the protocol)
- Decrypt user files
- See original filenames
- Access file content
- Recover user passwords from stored data

**The client MUST:**
- Perform all encryption in WASM
- Keep passwords in WASM memory only
- Never send passwords to the server (use zero-knowledge OPAQUE)
- Encrypt all metadata client-side
- Handle all cryptographic operations locally

### Zero-Knowledge Verification Checklist

After implementation, verify:

- [ ] Password never transmitted to server in any form
- [ ] Server cannot decrypt any user files
- [ ] Server cannot see original filenames
- [ ] Server cannot access file content
- [ ] All encryption happens client-side in WASM
- [ ] Password stored only in WASM memory (never localStorage)
- [ ] OPAQUE protocol uses multi-step zero-knowledge flow
- [ ] Export keys managed entirely client-side

### File Encryption Architecture

```
Upload Flow:
1. User selects file
2. WASM encrypts file using password from memory
3. WASM encrypts metadata (filename, hash)
4. Only ENCRYPTED data sent to server
5. Server stores encrypted file (cannot decrypt)

Download Flow:
1. Client requests file
2. Server sends encrypted file
3. WASM decrypts using password from memory
4. User gets original file
```

## Current vs Target Architecture

### Current Flow (INSECURE - Password Revealed)
```
Registration:
1. Client → Server: {username, password} [PLAINTEXT PASSWORD!]
2. Server: opaque_Register(password, serverPrivateKey)
3. Server: Store user_record in database

Authentication:
1. Client → Server: {username, password} [PLAINTEXT PASSWORD!]
2. Server: opaque_Authenticate(password, user_record)
3. Server: Return session_key
```

### Target Flow (SECURE - Zero-Knowledge)
```
Registration (4 steps):
1. Client (WASM): sec, req = CreateRegistrationRequest(password)
   Client → Server: {username, req}
2. Server: ssec, resp = CreateRegistrationResponse(req, skS)
   Server → Client: {resp}
3. Client (WASM): recU, export_key = FinalizeRequest(sec, resp, ids)
   Client → Server: {recU}
   Client: Store export_key locally
4. Server: rec = StoreUserRecord(ssec, recU)
   Server: Store rec in database

Authentication (3-4 steps):
1. Client (WASM): sec, req = CreateCredentialRequest(password)
   Client → Server: {username, req}
2. Server: resp, sk, ssec = CreateCredentialResponse(req, rec, ids, context)
   Server → Client: {resp}
3. Client (WASM): sk, authU, export_key = RecoverCredentials(resp, sec, context, ids)
   Client → Server: {authU}
   Client: Use export_key for session
4. Server: UserAuth(ssec, authU)
   Server: Validate and return tokens
```

## Phase 1: Backend Infrastructure

### 1.1 Go Wrapper Functions (auth/opaque_cgo.go)

**Add new CGO wrapper functions** for multi-step protocol:

```go
// Registration Step 1 (Client-side simulation for testing)
func libopaqueCreateRegistrationRequest(password []byte) ([]byte, []byte, error) {
    usrCtx := make([]byte, OPAQUE_USER_SESSION_SECRET_LEN + len(password))
    M := make([]byte, crypto_core_ristretto255_BYTES)
    
    cPassword := C.CBytes(password)
    defer C.free(cPassword)
    
    ret := C.arkfile_opaque_create_registration_request(
        (*C.uint8_t)(cPassword),
        C.uint16_t(len(password)),
        (*C.uint8_t)(unsafe.Pointer(&usrCtx[0])),
        (*C.uint8_t)(unsafe.Pointer(&M[0])),
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("registration request failed: %d", ret)
    }
    
    return usrCtx, M, nil
}

// Registration Step 2 (Server-side)
func libopaqueCreateRegistrationResponse(M []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
    rsec := make([]byte, OPAQUE_REGISTER_SECRET_LEN)
    rpub := make([]byte, OPAQUE_REGISTER_PUBLIC_LEN)
    
    ret := C.arkfile_opaque_create_registration_response(
        (*C.uint8_t)(unsafe.Pointer(&M[0])),
        (*C.uint8_t)(unsafe.Pointer(&serverPrivateKey[0])),
        (*C.uint8_t)(unsafe.Pointer(&rsec[0])),
        (*C.uint8_t)(unsafe.Pointer(&rpub[0])),
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("registration response failed: %d", ret)
    }
    
    return rsec, rpub, nil
}

// Registration Step 3 (Client-side simulation for testing)
func libopaqueFinalize Request(usrCtx []byte, rpub []byte) ([]byte, []byte, error) {
    rrec := make([]byte, OPAQUE_REGISTRATION_RECORD_LEN)
    exportKey := make([]byte, crypto_hash_sha512_BYTES)
    
    ret := C.arkfile_opaque_finalize_request(
        (*C.uint8_t)(unsafe.Pointer(&usrCtx[0])),
        (*C.uint8_t)(unsafe.Pointer(&rpub[0])),
        (*C.uint8_t)(unsafe.Pointer(&rrec[0])),
        (*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("finalize request failed: %d", ret)
    }
    
    return rrec, exportKey, nil
}

// Registration Step 4 (Server-side)
func libopaqueStoreUserRecord(rsec []byte, rrec []byte) ([]byte, error) {
    rec := make([]byte, OPAQUE_USER_RECORD_LEN)
    
    ret := C.arkfile_opaque_store_user_record(
        (*C.uint8_t)(unsafe.Pointer(&rsec[0])),
        (*C.uint8_t)(unsafe.Pointer(&rrec[0])),
        (*C.uint8_t)(unsafe.Pointer(&rec[0])),
    )
    
    if ret != 0 {
        return nil, fmt.Errorf("store user record failed: %d", ret)
    }
    
    return rec, nil
}

// Authentication Step 1 (Client-side simulation for testing)
func libopaqueCreateCredentialRequest(password []byte) ([]byte, []byte, error) {
    sec := make([]byte, OPAQUE_USER_SESSION_SECRET_LEN + len(password))
    pub := make([]byte, OPAQUE_USER_SESSION_PUBLIC_LEN)
    
    cPassword := C.CBytes(password)
    defer C.free(cPassword)
    
    ret := C.arkfile_opaque_create_credential_request(
        (*C.uint8_t)(cPassword),
        C.uint16_t(len(password)),
        (*C.uint8_t)(unsafe.Pointer(&sec[0])),
        (*C.uint8_t)(unsafe.Pointer(&pub[0])),
    )
    
    if ret != 0 {
        return nil, nil, fmt.Errorf("credential request failed: %d", ret)
    }
    
    return sec, pub, nil
}

// Authentication Step 2 (Server-side)
func libopaqueCreateCredentialResponse(pub []byte, rec []byte) ([]byte, []byte, []byte, error) {
    resp := make([]byte, OPAQUE_SERVER_SESSION_LEN)
    sk := make([]byte, OPAQUE_SHARED_SECRETBYTES)
    authU := make([]byte, crypto_auth_hmacsha512_BYTES)
    
    ret := C.arkfile_opaque_create_credential_response(
        (*C.uint8_t)(unsafe.Pointer(&pub[0])),
        (*C.uint8_t)(unsafe.Pointer(&rec[0])),
        (*C.uint8_t)(unsafe.Pointer(&resp[0])),
        (*C.uint8_t)(unsafe.Pointer(&sk[0])),
        (*C.uint8_t)(unsafe.Pointer(&authU[0])),
    )
    
    if ret != 0 {
        return nil, nil, nil, fmt.Errorf("credential response failed: %d", ret)
    }
    
    return resp, sk, authU, nil
}

// Authentication Step 3 (Client-side simulation for testing)
func libopaqueRecoverCredentials(resp []byte, sec []byte) ([]byte, []byte, []byte, error) {
    sk := make([]byte, OPAQUE_SHARED_SECRETBYTES)
    authU := make([]byte, crypto_auth_hmacsha512_BYTES)
    exportKey := make([]byte, crypto_hash_sha512_BYTES)
    
    ret := C.arkfile_opaque_recover_credentials(
        (*C.uint8_t)(unsafe.Pointer(&resp[0])),
        (*C.uint8_t)(unsafe.Pointer(&sec[0])),
        (*C.uint8_t)(unsafe.Pointer(&sk[0])),
        (*C.uint8_t)(unsafe.Pointer(&authU[0])),
        (*C.uint8_t)(unsafe.Pointer(&exportKey[0])),
    )
    
    if ret != 0 {
        return nil, nil, nil, fmt.Errorf("recover credentials failed: %d", ret)
    }
    
    return sk, authU, exportKey, nil
}

// Authentication Step 4 (Server-side)
func libopaqueUserAuth(authUServer []byte, authUClient []byte) error {
    ret := C.arkfile_opaque_user_auth(
        (*C.uint8_t)(unsafe.Pointer(&authUServer[0])),
        (*C.uint8_t)(unsafe.Pointer(&authUClient[0])),
    )
    
    if ret != 0 {
        return fmt.Errorf("user auth failed: %d", ret)
    }
    
    return nil
}
```

### 1.2 High-Level Go API (auth/opaque.go)

**Add new provider interface methods**:

```go
type OPAQUEProvider interface {
    // Existing methods...
    
    // Multi-step registration
    CreateRegistrationResponse(M []byte, serverPrivateKey []byte) ([]byte, []byte, error)
    StoreUserRecord(rsec []byte, rrec []byte) ([]byte, error)
    
    // Multi-step authentication
    CreateCredentialResponse(pub []byte, rec []byte) ([]byte, []byte, []byte, error)
    UserAuth(authUServer []byte, authUClient []byte) error
}
```

**Implement in RealOPAQUEProvider**:

```go
func (r *RealOPAQUEProvider) CreateRegistrationResponse(M []byte, serverPrivateKey []byte) ([]byte, []byte, error) {
    return libopaqueCreateRegistrationResponse(M, serverPrivateKey)
}

func (r *RealOPAQUEProvider) StoreUserRecord(rsec []byte, rrec []byte) ([]byte, error) {
    return libopaqueStoreUserRecord(rsec, rrec)
}

func (r *RealOPAQUEProvider) CreateCredentialResponse(pub []byte, rec []byte) ([]byte, []byte, []byte, error) {
    return libopaqueCreateCredentialResponse(pub, rec)
}

func (r *RealOPAQUEProvider) UserAuth(authUServer []byte, authUClient []byte) error {
    return libopaqueUserAuth(authUServer, authUClient)
}
```

### 1.3 Database Schema Updates (database/unified_schema.sql)

**Add new table for intermediate OPAQUE state**:

```sql
-- Store intermediate server state during multi-step OPAQUE protocols
CREATE TABLE IF NOT EXISTS opaque_sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    protocol_type TEXT NOT NULL, -- 'registration' or 'authentication'
    server_secret BLOB NOT NULL, -- rsec or ssec (encrypted)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Index for cleanup of expired sessions
CREATE INDEX IF NOT EXISTS idx_opaque_sessions_expires 
ON opaque_sessions(expires_at);

-- Index for username lookups
CREATE INDEX IF NOT EXISTS idx_opaque_sessions_username 
ON opaque_sessions(username);
```

**Add session management functions**:

```go
// database/database.go

// StoreOPAQUESession stores intermediate server state for multi-step protocol
func StoreOPAQUESession(db *sql.DB, sessionID, username, protocolType string, serverSecret []byte, expiresAt time.Time) error {
    // Encrypt server secret before storage
    encryptedSecret, err := encryptServerSecret(serverSecret)
    if err != nil {
        return fmt.Errorf("failed to encrypt server secret: %w", err)
    }
    
    _, err = db.Exec(`
        INSERT INTO opaque_sessions (session_id, username, protocol_type, server_secret, expires_at)
        VALUES (?, ?, ?, ?, ?)`,
        sessionID, username, protocolType, encryptedSecret, expiresAt,
    )
    return err
}

// GetOPAQUESession retrieves and decrypts intermediate server state
func GetOPAQUESession(db *sql.DB, sessionID string) (username, protocolType string, serverSecret []byte, err error) {
    var encryptedSecret []byte
    var expiresAt time.Time
    
    err = db.QueryRow(`
        SELECT username, protocol_type, server_secret, expires_at
        FROM opaque_sessions
        WHERE session_id = ?`,
        sessionID,
    ).Scan(&username, &protocolType, &encryptedSecret, &expiresAt)
    
    if err != nil {
        return "", "", nil, err
    }
    
    // Check expiration
    if time.Now().After(expiresAt) {
        DeleteOPAQUESession(db, sessionID)
        return "", "", nil, fmt.Errorf("session expired")
    }
    
    // Decrypt server secret
    serverSecret, err = decryptServerSecret(encryptedSecret)
    if err != nil {
        return "", "", nil, fmt.Errorf("failed to decrypt server secret: %w", err)
    }
    
    return username, protocolType, serverSecret, nil
}

// DeleteOPAQUESession removes a session after use
func DeleteOPAQUESession(db *sql.DB, sessionID string) error {
    _, err := db.Exec("DELETE FROM opaque_sessions WHERE session_id = ?", sessionID)
    return err
}

// CleanupExpiredOPAQUESessions removes expired sessions (run periodically)
func CleanupExpiredOPAQUESessions(db *sql.DB) error {
    _, err := db.Exec("DELETE FROM opaque_sessions WHERE expires_at < ?", time.Now())
    return err
}
```

### 1.4 New API Endpoints (handlers/auth.go)

**Registration Endpoints**:

```go
// Step 1: Client initiates registration (receives M from client WASM)
type OpaqueRegisterStep1Request struct {
    Username string `json:"username"`
    Email    string `json:"email,omitempty"`
    M        string `json:"m"` // base64-encoded registration request from client
}

type OpaqueRegisterStep1Response struct {
    SessionID string `json:"session_id"`
    Rpub      string `json:"rpub"` // base64-encoded registration response
}

func OpaqueRegisterStep1(c echo.Context) error {
    var request OpaqueRegisterStep1Request
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
    }
    
    // Validate username
    if err := utils.ValidateUsername(request.Username); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid username: "+err.Error())
    }
    
    // Check if user already exists
    _, err := models.GetUserByUsername(database.DB, request.Username)
    if err == nil {
        return echo.NewHTTPError(http.StatusConflict, "Username already registered")
    }
    
    // Decode M from client
    M, err := base64.StdEncoding.DecodeString(request.M)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid M format")
    }
    
    // Get server keys
    provider := auth.GetOPAQUEProvider()
    _, serverPrivateKey, err := provider.GetServerKeys()
    if err != nil {
        logging.ErrorLogger.Printf("Failed to get server keys: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Server configuration error")
    }
    
    // Create registration response
    rsec, rpub, err := provider.CreateRegistrationResponse(M, serverPrivateKey)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to create registration response: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Generate session ID
    sessionID := crypto.GenerateRandomString(32)
    
    // Store server secret (rsec) for step 2
    expiresAt := time.Now().Add(5 * time.Minute)
    if err := database.StoreOPAQUESession(database.DB, sessionID, request.Username, "registration", rsec, expiresAt); err != nil {
        logging.ErrorLogger.Printf("Failed to store OPAQUE session: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Clear rsec from memory
    crypto.SecureZeroBytes(rsec)
    
    logging.InfoLogger.Printf("OPAQUE registration step 1 completed for: %s", request.Username)
    
    return c.JSON(http.StatusOK, OpaqueRegisterStep1Response{
        SessionID: sessionID,
        Rpub:      base64.StdEncoding.EncodeToString(rpub),
    })
}

// Step 2: Client completes registration (receives recU from client WASM)
type OpaqueRegisterStep2Request struct {
    SessionID string `json:"session_id"`
    RecU      string `json:"rec_u"` // base64-encoded registration record from client
}

type OpaqueRegisterStep2Response struct {
    Message           string `json:"message"`
    RequiresTOTPSetup bool   `json:"requires_totp_setup"`
    TempToken         string `json:"temp_token"`
}

func OpaqueRegisterStep2(c echo.Context) error {
    var request OpaqueRegisterStep2Request
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
    }
    
    // Retrieve session
    username, protocolType, rsec, err := database.GetOPAQUESession(database.DB, request.SessionID)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to retrieve OPAQUE session: %v", err)
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid or expired session")
    }
    defer crypto.SecureZeroBytes(rsec)
    
    if protocolType != "registration" {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid session type")
    }
    
    // Decode recU from client
    recU, err := base64.StdEncoding.DecodeString(request.RecU)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid recU format")
    }
    
    // Complete registration
    provider := auth.GetOPAQUEProvider()
    rec, err := provider.StoreUserRecord(rsec, recU)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to store user record: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Create user in database
    user := &models.User{
        Username:  username,
        CreatedAt: time.Now(),
    }
    
    // Store OPAQUE record
    userData := auth.OPAQUEUserData{
        Username:         username,
        SerializedRecord: rec,
        CreatedAt:        time.Now(),
    }
    
    if err := auth.storeOPAQUEUserData(database.DB, userData); err != nil {
        logging.ErrorLogger.Printf("Failed to store OPAQUE user data: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Create user record
    if err := models.CreateUser(database.DB, user); err != nil {
        logging.ErrorLogger.Printf("Failed to create user: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration failed")
    }
    
    // Delete session
    database.DeleteOPAQUESession(database.DB, request.SessionID)
    
    // Generate temporary token for TOTP setup
    tempToken, err := auth.GenerateTemporaryTOTPToken(username)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to generate temporary TOTP token: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Registration succeeded but setup token creation failed")
    }
    
    database.LogUserAction(username, "registered with zero-knowledge OPAQUE", "")
    logging.InfoLogger.Printf("Zero-knowledge OPAQUE registration completed for: %s", username)
    
    return c.JSON(http.StatusCreated, OpaqueRegisterStep2Response{
        Message:           "Registration successful. TOTP setup required.",
        RequiresTOTPSetup: true,
        TempToken:         tempToken,
    })
}
```

**Authentication Endpoints**:

```go
// Step 1: Client initiates authentication (receives pub from client WASM)
type OpaqueLoginStep1Request struct {
    Username string `json:"username"`
    Pub      string `json:"pub"` // base64-encoded credential request from client
}

type OpaqueLoginStep1Response struct {
    SessionID string `json:"session_id"`
    Resp      string `json:"resp"` // base64-encoded credential response
}

func OpaqueLoginStep1(c echo.Context) error {
    var request OpaqueLoginStep1Request
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
    }
    
    // Validate username
    if request.Username == "" {
        return echo.NewHTTPError(http.StatusBadRequest, "Username is required")
    }
    
    // Get user record
    userData, err := auth.loadOPAQUEUserData(database.DB, request.Username)
    if err != nil {
        logging.ErrorLogger.Printf("User not found: %s", request.Username)
        entityID := logging.GetOrCreateEntityID(c)
        recordAuthFailedAttempt("login_step1", entityID)
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
    }
    
    // Decode pub from client
    pub, err := base64.StdEncoding.DecodeString(request.Pub)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid pub format")
    }
    
    // Create credential response
    provider := auth.GetOPAQUEProvider()
    resp, sk, authUServer, err := provider.CreateCredentialResponse(pub, userData.SerializedRecord)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to create credential response: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
    }
    
    // Clear sk (we don't use it on server side)
    crypto.SecureZeroBytes(sk)
    
    // Generate session ID
    sessionID := crypto.GenerateRandomString(32)
    
    // Store server secret (authUServer) for step 2
    expiresAt := time.Now().Add(5 * time.Minute)
    if err := database.StoreOPAQUESession(database.DB, sessionID, request.Username, "authentication", authUServer, expiresAt); err != nil {
        logging.ErrorLogger.Printf("Failed to store OPAQUE session: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
    }
    
    // Clear authUServer from memory
    crypto.SecureZeroBytes(authUServer)
    
    logging.InfoLogger.Printf("OPAQUE authentication step 1 completed for: %s", request.Username)
    
    return c.JSON(http.StatusOK, OpaqueLoginStep1Response{
        SessionID: sessionID,
        Resp:      base64.StdEncoding.EncodeToString(resp),
    })
}

// Step 2: Client completes authentication (receives authU from client WASM)
type OpaqueLoginStep2Request struct {
    SessionID string `json:"session_id"`
    AuthU     string `json:"auth_u"` // base64-encoded client auth token
}

type OpaqueLoginStep2Response struct {
    RequiresTOTP bool   `json:"requires_totp"`
    TempToken    string `json:"temp_token"`
    Message      string `json:"message"`
}

func OpaqueLoginStep2(c echo.Context) error {
    var request OpaqueLoginStep2Request
    if err := c.Bind(&request); err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
    }
    
    // Retrieve session
    username, protocolType, authUServer, err := database.GetOPAQUESession(database.DB, request.SessionID)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to retrieve OPAQUE session: %v", err)
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid or expired session")
    }
    defer crypto.SecureZeroBytes(authUServer)
    
    if protocolType != "authentication" {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid session type")
    }
    
    // Decode authU from client
    authUClient, err := base64.StdEncoding.DecodeString(request.AuthU)
    if err != nil {
        return echo.NewHTTPError(http.StatusBadRequest, "Invalid authU format")
    }
    
    // Verify authentication
    provider := auth.GetOPAQUEProvider()
    if err := provider.UserAuth(authUServer, authUClient); err != nil {
        logging.ErrorLogger.Printf("OPAQUE authentication failed for %s: %v", username, err)
        entityID := logging.GetOrCreateEntityID(c)
        recordAuthFailedAttempt("login_step2", entityID)
        return echo.NewHTTPError(http.StatusUnauthorized, "Invalid credentials")
    }
    
    // Delete session
    database.DeleteOPAQUESession(database.DB, request.SessionID)
    
    // Check TOTP status
    totpEnabled, err := auth.IsUserTOTPEnabled(database.DB, username)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to check TOTP status: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
    }
    
    if !totpEnabled {
        return echo.NewHTTPError(http.StatusForbidden, "TOTP setup required")
    }
    
    // Generate temporary token for TOTP
    tempToken, err := auth.GenerateTemporaryTOTPToken(username)
    if err != nil {
        logging.ErrorLogger.Printf("Failed to generate temporary TOTP token: %v", err)
        return echo.NewHTTPError(http.StatusInternalServerError, "Authentication failed")
    }
    
    database.LogUserAction(username, "OPAQUE auth completed, awaiting TOTP", "")
    logging.InfoLogger.Printf("Zero-knowledge OPAQUE authentication completed for: %s", username)
    
    return c.JSON(http.StatusOK, OpaqueLoginStep2Response{
        RequiresTOTP: true,
        TempToken:    tempToken,
        Message:      "OPAQUE authentication successful. TOTP code required.",
    })
}
```

### 1.5 Route Configuration (handlers/route_config.go)

**Replace existing routes with new zero-knowledge endpoints**:

```go
// Zero-knowledge OPAQUE endpoints (replace old single-step endpoints)
api.POST("/auth/opaque/register/step1", OpaqueRegisterStep1)
api.POST("/auth/opaque/register/step2", OpaqueRegisterStep2)
api.POST("/auth/opaque/login/step1", OpaqueLoginStep1)
api.POST("/auth/opaque/login/step2", OpaqueLoginStep2)

// Remove old insecure endpoints:
// api.POST("/auth/opaque/register", OpaqueRegister) // REMOVED - sent password to server
// api.POST("/auth/opaque/login", OpaqueLogin)       // REMOVED - sent password to server
```

## Phase 2: WASM/Crypto Layer

### 2.1 WASM Exports (crypto/wasm_shim.go)

**Add client-side OPAQUE functions**:

```go
//export opaqueCreateRegistrationRequest
func opaqueCreateRegistrationRequest(passwordPtr, passwordLen uint32) uint32 {
    password := readBytes(passwordPtr, passwordLen)
    defer SecureZeroMemory(password)
    
    // Call libopaque via CGO
    usrCtx, M, err := libopaqueCreateRegistrationRequest(password)
    if err != nil {
        return writeError(err.Error())
    }
    
    // Return both usrCtx and M as JSON
    result := map[string]string{
        "usr_ctx": base64.StdEncoding.EncodeToString(usrCtx),
        "m":       base64.StdEncoding.EncodeToString(M),
    }
    
    return writeJSON(result)
}

//export opaqueFinalizeRequest
func opaqueFinalizeRequest(usrCtxPtr, usrCtxLen, rpubPtr, rpubLen uint32) uint32 {
    usrCtx := readBytes(usrCtxPtr, usrCtxLen)
    defer SecureZeroMemory(usrCtx)
    
    rpub := readBytes(rpubPtr, rpubLen)
    
    // Call libopaque via CGO
    recU, exportKey, err := libopaqueFinalize Request(usrCtx, rpub)
    if err != nil {
        return writeError(err.Error())
    }
    
    // Return both recU and exportKey as JSON
    result := map[string]string{
        "rec_u":      base64.StdEncoding.EncodeToString(recU),
        "export_key": base64.StdEncoding.EncodeToString(exportKey),
    }
    
    return writeJSON(result)
}

//export opaqueCreateCredentialRequest
func opaqueCreateCredentialRequest(passwordPtr, passwordLen uint32) uint32 {
    password := readBytes(passwordPtr, passwordLen)
    defer SecureZeroMemory(password)
    
    // Call libopaque via CGO
    sec, pub, err := libopaqueCreateCredentialRequest(password)
    if err != nil {
        return writeError(err.Error())
    }
    
    // Return both sec and pub as JSON
    result := map[string]string{
        "sec": base64.StdEncoding.EncodeToString(sec),
        "pub": base64.StdEncoding.EncodeToString(pub),
    }
    
    return writeJSON(result)
}

//export opaqueRecoverCredentials
func opaqueRecoverCredentials(respPtr, respLen, secPtr, secLen uint32) uint32 {
    resp := readBytes(respPtr, respLen)
    sec := readBytes(secPtr, secLen)
    defer SecureZeroMemory(sec)
    
    // Call libopaque via CGO
    sk, authU, exportKey, err := libopaqueRecoverCredentials(resp, sec)
    if err != nil {
        return writeError(err.Error())
    }
    
    // Return sk, authU, and exportKey as JSON
    result := map[string]string{
        "sk":         base64.StdEncoding.EncodeToString(sk),
        "auth_u":     base64.StdEncoding.EncodeToString(authU),
        "export_key": base64.StdEncoding.EncodeToString(exportKey),
    }
    
    return writeJSON(result)
}
```

### 2.2 TypeScript WASM Interface (client/static/js/src/types/wasm.d.ts)

**Add new WASM function declarations**:

```typescript
export interface WasmExports {
    // Existing exports...
    
    // Zero-knowledge OPAQUE - Registration
    opaqueCreateRegistrationRequest(
        passwordPtr: number,
        passwordLen: number
    ): number;
    
    opaqueFinalizeRequest(
        usrCtxPtr: number,
        usrCtxLen: number,
        rpubPtr: number,
        rpubLen: number
    ): number;
    
    // Zero-knowledge OPAQUE - Authentication
    opaqueCreateCredentialRequest(
        passwordPtr: number,
        passwordLen: number
    ): number;
    
    opaqueRecoverCredentials(
        respPtr: number,
        respLen: number,
        secPtr: number,
        secLen: number
    ): number;
}

export interface OpaqueRegistrationStep1Result {
    usr_ctx: string; // base64
    m: string;       // base64
}

export interface OpaqueRegistrationStep2Result {
    rec_u: string;      // base64
    export_key: string; // base64
}

export interface OpaqueAuthStep1Result {
    sec: string; // base64
    pub: string; // base64
}

export interface OpaqueAuthStep2Result {
    sk: string;         // base64
    auth_u: string;     // base64
    export_key: string; // base64
}
```

### 2.3 WASM Utility Functions (client/static/js/src/utils/wasm.ts)

**Add high-level WASM wrapper functions**:

```typescript
// Registration Step 1: Create registration request
export async function createOpaqueRegistrationRequest(
    password: string
): Promise<OpaqueRegistrationStep1Result> {
    const wasm = await getWasmInstance();
    const passwordBytes = new TextEncoder().encode(password);
    
    try {
        const resultPtr = wasm.opaqueCreateRegistrationRequest(
            allocateBytes(passwordBytes),
            passwordBytes.length
        );
        
        const result = readWasmResult<OpaqueRegistrationStep1Result>(resultPtr);
        
        if ('error' in result) {
            throw new Error(result.error);
        }
        
        return result;
    } finally {
        // Securely zero password from memory
        passwordBytes.fill(0);
    }
}

// Registration Step 2: Finalize registration
export async function finalizeOpaqueRegistration(
    usrCtx: string,
    rpub: string
): Promise<OpaqueRegistrationStep2Result> {
    const wasm = await getWasmInstance();
    const usrCtxBytes = base64ToBytes(usrCtx);
    const rpubBytes = base64ToBytes(rpub);
    
    try {
        const resultPtr = wasm.opaqueFinalizeRequest(
            allocateBytes(usrCtxBytes),
            usrCtxBytes.length,
            allocateBytes(rpubBytes),
            rpubBytes.length
        );
        
        const result = readWasmResult<OpaqueRegistrationStep2Result>(resultPtr);
        
        if ('error' in result) {
            throw new Error(result.error);
        }
        
        return result;
    } finally {
        // Securely zero sensitive data
        usrCtxBytes.fill(0);
    }
}

// Authentication Step 1: Create credential request
export async function createOpaqueCredentialRequest(
    password: string
): Promise<OpaqueAuthStep1Result> {
    const wasm = await getWasmInstance();
    const passwordBytes = new TextEncoder().encode(password);
    
    try {
        const resultPtr = wasm.opaqueCreateCredentialRequest(
            allocateBytes(passwordBytes),
            passwordBytes.length
        );
        
        const result = readWasmResult<OpaqueAuthStep1Result>(resultPtr);
        
        if ('error' in result) {
            throw new Error(result.error);
        }
        
        return result;
    } finally {
        // Securely zero password from memory
        passwordBytes.fill(0);
    }
}

// Authentication Step 2: Recover credentials
export async function recoverOpaqueCredentials(
    resp: string,
    sec: string
): Promise<OpaqueAuthStep2Result> {
    const wasm = await getWasmInstance();
    const respBytes = base64ToBytes(resp);
    const secBytes = base64ToBytes(sec);
    
    try {
        const resultPtr = wasm.opaqueRecoverCredentials(
            allocateBytes(respBytes),
            respBytes.length,
            allocateBytes(secBytes),
            secBytes.length
        );
        
        const result = readWasmResult<OpaqueAuthStep2Result>(resultPtr);
        
        if ('error' in result) {
            throw new Error(result.error);
        }
        
        return result;
    } finally {
        // Securely zero sensitive data
        secBytes.fill(0);
    }
}

// Helper: Store export key securely in sessionStorage
export function storeExportKey(exportKey: string): void {
    // In a real implementation, consider using IndexedDB with encryption
    // For now, use sessionStorage (cleared on tab close)
    sessionStorage.setItem('opaque_export_key', exportKey);
}

// Helper: Retrieve export key
export function getExportKey(): string | null {
    return sessionStorage.getItem('opaque_export_key');
}

// Helper: Clear export key
export function clearExportKey(): void {
    sessionStorage.removeItem('opaque_export_key');
}
```

## Phase 3: Browser Client Updates

### 3.1 Registration Flow (client/static/js/src/auth/register.ts)

**Complete rewrite for zero-knowledge protocol**:

```typescript
import {
    createOpaqueRegistrationRequest,
    finalizeOpaqueRegistration,
    storeExportKey
} from '../utils/wasm.js';

async function handleRegistration(event: Event): Promise<void> {
    event.preventDefault();
    
    const form = event.target as HTMLFormElement;
    const username = (form.querySelector('#username') as HTMLInputElement).value;
    const email = (form.querySelector('#email') as HTMLInputElement).value;
    const password = (form.querySelector('#password') as HTMLInputElement).value;
    
    try {
        showStatus('Creating registration request...', 'info');
        
        // STEP 1: Client creates registration request (password never sent!)
        const step1Result = await createOpaqueRegistrationRequest(password);
        
        // Send M to server
        const step1Response = await fetch('/api/auth/opaque/register/step1', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                email,
                m: step1Result.m
            })
        });
        
        if (!step1Response.ok) {
            const error = await step1Response.json();
            throw new Error(error.message || 'Registration step 1 failed');
        }
        
        const step1Data = await step1Response.json();
        
        showStatus('Finalizing registration...', 'info');
        
        // STEP 2: Client finalizes registration
        const step2Result = await finalizeOpaqueRegistration(
            step1Result.usr_ctx,
            step1Data.rpub
        );
        
        // Store export key locally (CRITICAL - needed for session)
        storeExportKey(step2Result.export_key);
        
        // Send recU to server
        const step2Response = await fetch('/api/auth/opaque/register/step2', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: step1Data.session_id,
                rec_u: step2Result.rec_u
            })
        });
        
        if (!step2Response.ok) {
            const error = await step2Response.json();
            throw new Error(error.message || 'Registration step 2 failed');
        }
        
        const step2Data = await step2Response.json();
        
        // Store temp token for TOTP setup
        sessionStorage.setItem('temp_token', step2Data.temp_token);
        
        showStatus('Registration successful! Setting up 2FA...', 'success');
        
        // Redirect to TOTP setup
        window.location.href = '/totp-setup.html';
        
    } catch (error) {
        console.error('Registration error:', error);
        showStatus(error.message || 'Registration failed', 'error');
    }
}
```

### 3.2 Login Flow (client/static/js/src/auth/login.ts)

**Complete rewrite for zero-knowledge protocol**:

```typescript
import {
    createOpaqueCredentialRequest,
    recoverOpaqueCredentials,
    storeExportKey
} from '../utils/wasm.js';

async function handleLogin(event: Event): Promise<void> {
    event.preventDefault();
    
    const form = event.target as HTMLFormElement;
    const username = (form.querySelector('#username') as HTMLInputElement).value;
    const password = (form.querySelector('#password') as HTMLInputElement).value;
    
    try {
        showStatus('Authenticating...', 'info');
        
        // STEP 1: Client creates credential request (password never sent!)
        const step1Result = await createOpaqueCredentialRequest(password);
        
        // Send pub to server
        const step1Response = await fetch('/api/auth/opaque/login/step1', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                pub: step1Result.pub
            })
        });
        
        if (!step1Response.ok) {
            const error = await step1Response.json();
            throw new Error(error.message || 'Authentication step 1 failed');
        }
        
        const step1Data = await step1Response.json();
        
        showStatus('Recovering credentials...', 'info');
        
        // STEP 2: Client recovers credentials
        const step2Result = await recoverOpaqueCredentials(
            step1Data.resp,
            step1Result.sec
        );
        
        // Store export key locally (CRITICAL - needed for session)
        storeExportKey(step2Result.export_key);
        
        // Send authU to server
        const step2Response = await fetch('/api/auth/opaque/login/step2', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: step1Data.session_id,
                auth_u: step2Result.auth_u
            })
        });
        
        if (!step2Response.ok) {
            const error = await step2Response.json();
            throw new Error(error.message || 'Authentication step 2 failed');
        }
        
        const step2Data = await step2Response.json();
        
        // Store temp token for TOTP
        sessionStorage.setItem('temp_token', step2Data.temp_token);
        
        showStatus('Authentication successful! Enter 2FA code...', 'success');
        
        // Redirect to TOTP verification
        window.location.href = '/totp-verify.html';
        
    } catch (error) {
        console.error('Login error:', error);
        showStatus(error.message || 'Login failed', 'error');
    }
}
```

## Phase 4: TOTP Integration

### 4.1 TOTP Setup Flow

After successful OPAQUE registration (Phase 1-3), users must set up TOTP for two-factor authentication.

**API Endpoint**: `POST /api/totp/setup`

**Request**:
```json
{
    "temp_token": "eyJhbGc..."
}
```

**Response**:
```json
{
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code_url": "otpauth://totp/Arkfile:username?secret=JBSWY3DPEHPK3PXP&issuer=Arkfile",
    "backup_codes": ["code1", "code2", "code3", "code4", "code5"],
    "manual_entry": "JBSW Y3DP EHPK 3PXP"
}
```

### 4.2 TOTP Verification Flow

**API Endpoint**: `POST /api/totp/verify`

**Request**:
```json
{
    "code": "123456",
    "temp_token": "eyJhbGc...",
    "is_backup": false
}
```

**Response (Success)**:
```json
{
    "message": "TOTP setup completed successfully",
    "enabled": true,
    "access_token": "eyJhbGc...",
    "refresh_token": "refresh_token_here",
    "user": {
        "username": "user.name",
        "email": "user@example.com",
        "is_approved": false,
        "is_admin": false,
        "total_storage": 0,
        "storage_limit": 10737418240,
        "storage_used_pc": 0
    }
}
```

### 4.3 TypeScript TOTP Interfaces

**File**: `client/static/js/src/auth/totp.ts`

```typescript
interface TOTPSetupRequest {
    temp_token: string;
}

interface TOTPSetupResponse {
    secret: string;
    qr_code_url: string;
    backup_codes: string[];
    manual_entry: string;
}

interface TOTPVerifyRequest {
    code: string;
    temp_token: string;
    is_backup?: boolean;
}

interface TOTPVerifyResponse {
    message: string;
    enabled: boolean;
    access_token: string;
    refresh_token: string;
    user: {
        username: string;
        email: string | null;
        is_approved: boolean;
        is_admin: boolean;
        total_storage: number;
        storage_limit: number;
        storage_used_pc: number;
    };
}

async function setupTOTP(tempToken: string): Promise<TOTPSetupResponse> {
    const response = await fetch('/api/totp/setup', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${tempToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ temp_token: tempToken })
    });
    
    if (!response.ok) {
        throw new Error('TOTP setup failed');
    }
    
    return await response.json();
}

async function verifyTOTP(code: string, tempToken: string, isBackup: boolean = false): Promise<TOTPVerifyResponse> {
    const response = await fetch('/api/totp/verify', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${tempToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            code,
            temp_token: tempToken,
            is_backup: isBackup
        })
    });
    
    if (!response.ok) {
        throw new Error('TOTP verification failed');
    }
    
    return await response.json();
}
```

### 4.4 Integration with Registration Flow

After OPAQUE registration completes (Phase 3), automatically initiate TOTP setup:

```typescript
// In register.ts, after step 2 completes:
const step2Data = await step2Response.json();

// Store temp token
sessionStorage.setItem('temp_token', step2Data.temp_token);

// Automatically initiate TOTP setup
const totpData = await setupTOTP(step2Data.temp_token);

// Display QR code and backup codes (see Phase 5 for UI)
displayTOTPSetup(totpData);
```

### 4.5 Integration with Login Flow

After OPAQUE authentication completes (Phase 3), require TOTP verification:

```typescript
// In login.ts, after step 2 completes:
const step2Data = await step2Response.json();

// Store temp token
sessionStorage.setItem('temp_token', step2Data.temp_token);

// Redirect to TOTP verification page
window.location.href = '/totp-verify.html';
```

## Phase 5: UI Components

### 5.1 TOTP Setup Page Components

**QR Code Display**:
```html
<div id="totp-setup-container">
    <h2>Set Up Two-Factor Authentication</h2>
    
    <div class="qr-code-section">
        <h3>Scan QR Code</h3>
        <img id="qr-code" src="" alt="TOTP QR Code">
        <p>Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)</p>
    </div>
    
    <div class="manual-entry-section">
        <h3>Or Enter Manually</h3>
        <code id="manual-entry"></code>
        <button onclick="copyManualEntry()">Copy</button>
    </div>
    
    <div class="backup-codes-section">
        <h3>Backup Codes</h3>
        <p>Save these backup codes in a secure location. Each can be used once if you lose access to your authenticator.</p>
        <ul id="backup-codes-list"></ul>
        <button onclick="downloadBackupCodes()">Download Codes</button>
    </div>
    
    <div class="verification-section">
        <h3>Verify Setup</h3>
        <input type="text" id="totp-code" placeholder="Enter 6-digit code" maxlength="6">
        <button onclick="verifyTOTPSetup()">Verify & Complete Setup</button>
    </div>
</div>
```

**TypeScript for TOTP Setup Display**:
```typescript
function displayTOTPSetup(data: TOTPSetupResponse): void {
    // Display QR code
    const qrImg = document.getElementById('qr-code') as HTMLImageElement;
    qrImg.src = data.qr_code_url;
    
    // Display manual entry
    const manualEntry = document.getElementById('manual-entry') as HTMLElement;
    manualEntry.textContent = data.manual_entry;
    
    // Display backup codes
    const backupCodesList = document.getElementById('backup-codes-list') as HTMLUListElement;
    backupCodesList.innerHTML = '';
    data.backup_codes.forEach(code => {
        const li = document.createElement('li');
        li.textContent = code;
        backupCodesList.appendChild(li);
    });
    
    // Store for download
    sessionStorage.setItem('backup_codes', JSON.stringify(data.backup_codes));
}

function copyManualEntry(): void {
    const manualEntry = document.getElementById('manual-entry') as HTMLElement;
    navigator.clipboard.writeText(manualEntry.textContent || '');
    showNotification('Manual entry code copied to clipboard');
}

function downloadBackupCodes(): void {
    const codes = JSON.parse(sessionStorage.getItem('backup_codes') || '[]');
    const content = 'Arkfile Backup Codes\n\n' + codes.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'arkfile-backup-codes.txt';
    a.click();
    URL.revokeObjectURL(url);
}

async function verifyTOTPSetup(): Promise<void> {
    const code = (document.getElementById('totp-code') as HTMLInputElement).value;
    const tempToken = sessionStorage.getItem('temp_token');
    
    if (!tempToken) {
        showError('Session expired. Please register again.');
        return;
    }
    
    try {
        const result = await verifyTOTP(code, tempToken);
        
        // Store final tokens
        localStorage.setItem('access_token', result.access_token);
        localStorage.setItem('refresh_token', result.refresh_token);
        localStorage.setItem('username', result.user.username);
        
        // Clear temporary data
        sessionStorage.clear();
        
        showSuccess('Setup complete! Redirecting...');
        setTimeout(() => {
            window.location.href = '/';
        }, 2000);
        
    } catch (error) {
        showError('Invalid code. Please try again.');
    }
}
```

### 5.2 TOTP Verification Page Components

**TOTP Verification Form**:
```html
<div id="totp-verify-container">
    <h2>Two-Factor Authentication</h2>
    
    <div class="totp-input-section">
        <p>Enter the 6-digit code from your authenticator app</p>
        <input type="text" id="totp-code" placeholder="000000" maxlength="6" autocomplete="off">
        <button onclick="verifyTOTPLogin()">Verify</button>
    </div>
    
    <div class="backup-code-section">
        <p>Lost your device? <a href="#" onclick="showBackupCodeInput()">Use a backup code</a></p>
        <div id="backup-code-input" style="display: none;">
            <input type="text" id="backup-code" placeholder="Enter backup code">
            <button onclick="verifyBackupCode()">Verify Backup Code</button>
        </div>
    </div>
</div>
```

**TypeScript for TOTP Verification**:
```typescript
async function verifyTOTPLogin(): Promise<void> {
    const code = (document.getElementById('totp-code') as HTMLInputElement).value;
    const tempToken = sessionStorage.getItem('temp_token');
    
    if (!tempToken) {
        showError('Session expired. Please log in again.');
        window.location.href = '/login.html';
        return;
    }
    
    try {
        const result = await verifyTOTP(code, tempToken, false);
        
        // Store tokens
        localStorage.setItem('access_token', result.access_token);
        localStorage.setItem('refresh_token', result.refresh_token);
        localStorage.setItem('username', result.user.username);
        
        // Clear temporary data
        sessionStorage.clear();
        
        showSuccess('Login successful! Redirecting...');
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
        
    } catch (error) {
        showError('Invalid code. Please try again.');
    }
}

function showBackupCodeInput(): void {
    const backupInput = document.getElementById('backup-code-input');
    if (backupInput) {
        backupInput.style.display = 'block';
    }
}

async function verifyBackupCode(): Promise<void> {
    const code = (document.getElementById('backup-code') as HTMLInputElement).value;
    const tempToken = sessionStorage.getItem('temp_token');
    
    if (!tempToken) {
        showError('Session expired. Please log in again.');
        window.location.href = '/login.html';
        return;
    }
    
    try {
        const result = await verifyTOTP(code, tempToken, true);
        
        // Store tokens
        localStorage.setItem('access_token', result.access_token);
        localStorage.setItem('refresh_token', result.refresh_token);
        localStorage.setItem('username', result.user.username);
        
        // Clear temporary data
        sessionStorage.clear();
        
        showSuccess('Login successful! Redirecting...');
        setTimeout(() => {
            window.location.href = '/';
        }, 1000);
        
    } catch (error) {
        showError('Invalid backup code. Please try again.');
    }
}
```

### 5.3 Progress Indicators

**Registration Progress**:
```html
<div class="progress-indicator">
    <div class="step" data-step="1">
        <div class="step-number">1</div>
        <div class="step-label">Create Account</div>
    </div>
    <div class="step" data-step="2">
        <div class="step-number">2</div>
        <div class="step-label">Set Up 2FA</div>
    </div>
    <div class="step" data-step="3">
        <div class="step-number">3</div>
        <div class="step-label">Complete</div>
    </div>
</div>
```

**CSS for Progress Indicator**:
```css
.progress-indicator {
    display: flex;
    justify-content: space-between;
    margin: 2rem 0;
}

.step {
    flex: 1;
    text-align: center;
    position: relative;
}

.step::after {
    content: '';
    position: absolute;
    top: 20px;
    left: 50%;
    width: 100%;
    height: 2px;
    background: #ddd;
    z-index: -1;
}

.step:last-child::after {
    display: none;
}

.step.active .step-number {
    background: #007bff;
    color: white;
}

.step.completed .step-number {
    background: #28a745;
    color: white;
}

.step-number {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: #ddd;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    margin-bottom: 0.5rem;
}
```

### 5.4 UI Components Checklist

- [ ] QR code display component
- [ ] Manual entry code display with copy button
- [ ] Backup codes list with download button
- [ ] TOTP code input field (6 digits)
- [ ] Backup code input field
- [ ] Progress indicators for registration flow
- [ ] Error/success message displays
- [ ] Loading spinners for async operations
- [ ] Responsive design for mobile devices
- [ ] Accessibility features (ARIA labels, keyboard navigation)

## Phase 6: CLI Tools Updates

### 4.1 CLI Client (cmd/arkfile-client/main.go)

**Update registration command**:

```go
func registerCommand() error {
    username := promptUsername()
    password := promptPassword()
    
    fmt.Println("Starting zero-knowledge OPAQUE registration...")
    
    // Step 1: Create registration request
    provider := auth.GetOPAQUEProvider()
    usrCtx, M, err := libopaqueCreateRegistrationRequest([]byte(password))
    if err != nil {
        return fmt.Errorf("failed to create registration request: %w", err)
    }
    defer crypto.SecureZeroBytes(usrCtx)
    
    // Send M to server
    step1Req := map[string]string{
        "username": username,
        "m":        base64.StdEncoding.EncodeToString(M),
    }
    
    step1Resp, err := sendRequest("POST", "/api/auth/opaque/register/step1", step1Req)
    if err != nil {
        return fmt.Errorf("registration step 1 failed: %w", err)
    }
    
    sessionID := step1Resp["session_id"].(string)
    rpubB64 := step1Resp["rpub"].(string)
    rpub, _ := base64.StdEncoding.DecodeString(rpubB64)
    
    fmt.Println("Finalizing registration...")
    
    // Step 2: Finalize registration
    recU, exportKey, err := libopaqueFinalize Request(usrCtx, rpub)
    if err != nil {
        return fmt.Errorf("failed to finalize registration: %w", err)
    }
    defer crypto.SecureZeroBytes(exportKey)
    
    // Send recU to server
    step2Req := map[string]string{
        "session_id": sessionID,
        "rec_u":      base64.StdEncoding.EncodeToString(recU),
    }
    
    step2Resp, err := sendRequest("POST", "/api/auth/opaque/register/step2", step2Req)
    if err != nil {
        return fmt.Errorf("registration step 2 failed: %w", err)
    }
    
    fmt.Println("Registration successful!")
    fmt.Println("Temp token:", step2Resp["temp_token"])
    fmt.Println("Please complete TOTP setup")
    
    return nil
}
```

**Update login command**:

```go
func loginCommand() error {
    username := promptUsername()
    password := promptPassword()
    
    fmt.Println("Starting zero-knowledge OPAQUE authentication...")
    
    // Step 1: Create credential request
    sec, pub, err := libopaqueCreateCredentialRequest([]byte(password))
    if err != nil {
        return fmt.Errorf("failed to create credential request: %w", err)
    }
    defer crypto.SecureZeroBytes(sec)
    
    // Send pub to server
    step1Req := map[string]string{
        "username": username,
        "pub":      base64.StdEncoding.EncodeToString(pub),
    }
    
    step1Resp, err := sendRequest("POST", "/api/auth/opaque/login/step1", step1Req)
    if err != nil {
        return fmt.Errorf("authentication step 1 failed: %w", err)
    }
    
    sessionID := step1Resp["session_id"].(string)
    respB64 := step1Resp["resp"].(string)
    resp, _ := base64.StdEncoding.DecodeString(respB64)
    
    fmt.Println("Recovering credentials...")
    
    // Step 2: Recover credentials
    sk, authU, exportKey, err := libopaqueRecoverCredentials(resp, sec)
    if err != nil {
        return fmt.Errorf("failed to recover credentials: %w", err)
    }
    defer crypto.SecureZeroBytes(sk)
    defer crypto.SecureZeroBytes(exportKey)
    
    // Send authU to server
    step2Req := map[string]string{
        "session_id": sessionID,
        "auth_u":     base64.StdEncoding.EncodeToString(authU),
    }
    
    step2Resp, err := sendRequest("POST", "/api/auth/opaque/login/step2", step2Req)
    if err != nil {
        return fmt.Errorf("authentication step 2 failed: %w", err)
    }
    
    fmt.Println("Authentication successful!")
    fmt.Println("Temp token:", step2Resp["temp_token"])
    fmt.Println("Please enter TOTP code")
    
    return nil
}
```

### 4.2 Test Script (scripts/testing/test-app-curl.sh)

**Update test script for new endpoints**:

```bash
#!/bin/bash

# Test zero-knowledge OPAQUE registration

echo "=== Testing Zero-Knowledge OPAQUE Registration ==="

# Step 1: Create registration request (simulated client-side)
# In real implementation, this would be done by WASM
# For testing, we'll use a mock M value
M_BASE64="mock_registration_request_base64"

echo "Step 1: Sending registration request..."
STEP1_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/opaque/register/step1 \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"testuser\",\"m\":\"$M_BASE64\"}")

echo "Step 1 Response: $STEP1_RESPONSE"

SESSION_ID=$(echo $STEP1_RESPONSE | jq -r '.session_id')
RPUB=$(echo $STEP1_RESPONSE | jq -r '.rpub')

echo "Session ID: $SESSION_ID"

# Step 2: Finalize registration (simulated client-side)
# In real implementation, this would be done by WASM
REC_U_BASE64="mock_registration_record_base64"

echo "Step 2: Finalizing registration..."
STEP2_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/opaque/register/step2 \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$SESSION_ID\",\"rec_u\":\"$REC_U_BASE64\"}")

echo "Step 2 Response: $STEP2_RESPONSE"

echo ""
echo "=== Testing Zero-Knowledge OPAQUE Authentication ==="

# Step 1: Create credential request (simulated client-side)
PUB_BASE64="mock_credential_request_base64"

echo "Step 1: Sending credential request..."
AUTH_STEP1_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/opaque/login/step1 \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"testuser\",\"pub\":\"$PUB_BASE64\"}")

echo "Auth Step 1 Response: $AUTH_STEP1_RESPONSE"

AUTH_SESSION_ID=$(echo $AUTH_STEP1_RESPONSE | jq -r '.session_id')
RESP=$(echo $AUTH_STEP1_RESPONSE | jq -r '.resp')

# Step 2: Complete authentication (simulated client-side)
AUTH_U_BASE64="mock_auth_token_base64"

echo "Step 2: Completing authentication..."
AUTH_STEP2_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/opaque/login/step2 \
  -H "Content-Type: application/json" \
  -d "{\"session_id\":\"$AUTH_SESSION_ID\",\"auth_u\":\"$AUTH_U_BASE64\"}")

echo "Auth Step 2 Response: $AUTH_STEP2_RESPONSE"
```

## Phase 7: Testing & Validation

### 7.1 Registration Phase Testing

**Checklist**:
- [ ] Password validation works (entropy check)
- [ ] OPAQUE registration step 1 succeeds
- [ ] Server returns session_id and rpub
- [ ] OPAQUE registration step 2 succeeds
- [ ] Server returns temp_token
- [ ] Password never sent in plaintext
- [ ] Export key stored in WASM memory
- [ ] No password in localStorage or sessionStorage

### 7.2 TOTP Setup Phase Testing

**Checklist**:
- [ ] TOTP setup request succeeds with temp_token
- [ ] QR code displays correctly
- [ ] Backup codes displayed and stored
- [ ] Manual entry format shown correctly
- [ ] TOTP code verification works
- [ ] Invalid codes rejected properly
- [ ] Backup codes work for verification
- [ ] Final tokens received (access_token, refresh_token)

### 7.3 Authentication Phase Testing

**Checklist**:
- [ ] OPAQUE authentication step 1 succeeds
- [ ] Server returns session_id and resp
- [ ] OPAQUE authentication step 2 succeeds
- [ ] Server returns temp_token
- [ ] TOTP verification required
- [ ] TOTP code verification works
- [ ] Session established correctly
- [ ] Redirect to dashboard works

### 7.4 Unit Tests

**Test CGO wrappers** (auth/opaque_cgo_test.go):

```go
func TestMultiStepRegistration(t *testing.T) {
    password := []byte("TestPassword123!")
    
    // Step 1: Create registration request
    usrCtx, M, err := libopaqueCreateRegistrationRequest(password)
    require.NoError(t, err)
    require.NotNil(t, usrCtx)
    require.NotNil(t, M)
    
    // Step 2: Create registration response
    serverPrivateKey := make([]byte, 32) // Mock key
    rsec, rpub, err := libopaqueCreateRegistrationResponse(M, serverPrivateKey)
    require.NoError(t, err)
    require.NotNil(t, rsec)
    require.NotNil(t, rpub)
    
    // Step 3: Finalize request
    recU, exportKey, err := libopaqueFinalize Request(usrCtx, rpub)
    require.NoError(t, err)
    require.NotNil(t, recU)
    require.NotNil(t, exportKey)
    
    // Step 4: Store user record
    rec, err := libopaqueStoreUserRecord(rsec, recU)
    require.NoError(t, err)
    require.NotNil(t, rec)
}

func TestMultiStepAuthentication(t *testing.T) {
    // Assume we have a user record from registration
    password := []byte("TestPassword123!")
    userRecord := []byte{} // From registration
    
    // Step 1: Create credential request
    sec, pub, err := libopaqueCreateCredentialRequest(password)
    require.NoError(t, err)
    require.NotNil(t, sec)
    require.NotNil(t, pub)
    
    // Step 2: Create credential response
    resp, sk, authUServer, err := libopaqueCreateCredentialResponse(pub, userRecord)
    require.NoError(t, err)
    require.NotNil(t, resp)
    require.NotNil(t, sk)
    require.NotNil(t, authUServer)
    
    // Step 3: Recover credentials
    skClient, authUClient, exportKey, err := libopaqueRecoverCredentials(resp, sec)
    require.NoError(t, err)
    require.NotNil(t, skClient)
    require.NotNil(t, authUClient)
    require.NotNil(t, exportKey)
    
    // Step 4: Authenticate
    err = libopaqueUserAuth(authUServer, authUClient)
    require.NoError(t, err)
}
```

### 5.2 Integration Tests

**Test full registration flow** (handlers/auth_test.go):

```go
func TestZeroKnowledgeOPAQUERegistration(t *testing.T) {
    // Test Step 1
    step1Req := map[string]interface{}{
        "username": "zktest",
        "m":        base64.StdEncoding.EncodeToString(mockM),
    }
    
    step1Resp := testRequest(t, "POST", "/api/auth/opaque/register/step1", step1Req)
    assert.Equal(t, http.StatusOK, step1Resp.Code)
    
    var step1Data map[string]interface{}
    json.Unmarshal(step1Resp.Body.Bytes(), &step1Data)
    
    sessionID := step1Data["session_id"].(string)
    assert.NotEmpty(t, sessionID)
    
    // Test Step 2
    step2Req := map[string]interface{}{
        "session_id": sessionID,
        "rec_u":      base64.StdEncoding.EncodeToString(mockRecU),
    }
    
    step2Resp := testRequest(t, "POST", "/api/auth/opaque/register/step2", step2Req)
    assert.Equal(t, http.StatusCreated, step2Resp.Code)
}
```

### 7.5 Security Audit Checklist

- [ ] Password never sent to server in plaintext
- [ ] All sensitive data cleared from memory after use
- [ ] Session IDs are cryptographically random
- [ ] Sessions expire after 5 minutes
- [ ] Server secrets encrypted in database
- [ ] Export keys stored securely on client
- [ ] TOTP still required after OPAQUE
- [ ] Rate limiting on all endpoints
- [ ] Proper error messages (no information leakage)
- [ ] All crypto operations use libopaque (no custom crypto)

### 7.6 Zero-Knowledge Verification

After implementation, verify these critical security properties:

**Password Handling**:
- [ ] Password sent ZERO times to server (not even once)
- [ ] Password stored only in WASM memory
- [ ] Password cleared from memory after use
- [ ] No password in localStorage
- [ ] No password in sessionStorage
- [ ] No password in cookies

**File Encryption**:
- [ ] All encryption happens client-side in WASM
- [ ] Only encrypted data sent to server
- [ ] Server cannot decrypt files
- [ ] Server cannot see original filenames
- [ ] Server cannot access file content

**Token Management**:
- [ ] temp_token used only for TOTP setup/verification
- [ ] access_token used for API calls
- [ ] refresh_token used for token renewal
- [ ] Export key managed entirely client-side
- [ ] Session keys never exposed to server

**Protocol Verification**:
- [ ] Multi-step OPAQUE protocol implemented correctly
- [ ] Client-side crypto operations use WASM
- [ ] Server-side crypto operations use libopaque
- [ ] No custom crypto implementations
- [ ] All sensitive data properly zeroed after use

## Phase 8: Deployment Strategy

### 8.1 No Backward Compatibility Needed

Since this is a **greenfield application with no production deployments**, we can:

1. **Remove old insecure endpoints completely** - No deprecation period needed
2. **Implement zero-knowledge OPAQUE directly** - No migration path required
3. **Clean implementation** - No legacy code to maintain

### 8.2 Deployment Steps

**Step 1**: Implement all backend changes (Go wrappers, API endpoints, database)
**Step 2**: Implement WASM layer (client-side crypto functions)
**Step 3**: Implement browser client (registration, login flows)
**Step 4**: Update CLI tools
**Step 5**: Run complete test suite
**Step 6**: Deploy to production

### 8.3 Testing Before Deployment

- [ ] All unit tests passing
- [ ] All integration tests passing
- [ ] Security audit completed
- [ ] Manual testing of registration flow
- [ ] Manual testing of authentication flow
- [ ] CLI tools tested
- [ ] Browser client tested in multiple browsers

## Phase 9: Documentation Updates

### 9.1 API Documentation (docs/api.md)

Add comprehensive documentation for new endpoints with examples.

### 9.2 Security Documentation (docs/security.md)

Update to reflect true zero-knowledge OPAQUE implementation.

### 9.3 Setup Guide (docs/setup.md)

Update setup instructions for new protocol.

## Implementation Timeline

**Week 1-2**: Backend infrastructure (Go wrappers, database, API endpoints)
**Week 3**: WASM layer (exports, TypeScript interfaces)
**Week 4**: Browser client (registration, login flows)
**Week 5**: CLI tools updates
**Week 6**: Testing and security audit
**Week 7**: Documentation updates
**Week 8**: Final testing and deployment

## Success Criteria

- [ ] Password never transmitted to server
- [ ] All tests passing
- [ ] Security audit completed
- [ ] Documentation updated
- [ ] CLI tools working with new protocol
- [ ] Browser client working with new protocol
- [ ] Performance acceptable (< 500ms per step)
- [ ] Zero regressions in existing functionality

## Risk Mitigation

**Risk**: Performance degradation
**Mitigation**: Benchmark each step, optimize if needed

**Risk**: Complexity in client-side code
**Mitigation**: Comprehensive error handling, clear user feedback

**Risk**: Session management issues
**Mitigation**: Proper expiration, cleanup jobs, monitoring

## Conclusion

This refactoring will transform Arkfile from an "OPAQUE-inspired" system to a true zero-knowledge OPAQUE implementation, ensuring passwords never leave the client device. The multi-phase approach ensures backward compatibility during migration while maintaining security and reliability.

**Remember**: NEVER roll our own crypto. All cryptographic operations rely on the battle-tested libopaque C library.


</INITIAL_PLAN>

---

## FEEDBACK ON THE ABOVE PLAN FROM GPT-5 LLM

"""
Findings: gaps in the “fix-opaque.md” plan to reach truly zero-knowledge OPAQUE auth

Protocol and cryptographic correctness
- Channel/context binding omitted: The plan’s CGO prototypes do not include IdU/IdS or “context” inputs (server identity, application context) that OPAQUE uses to prevent unknown key-share/mix-ups. Add explicit parameters and ensure both sides inject and verify them consistently.
- Server key generation/handling unspecified: The plan relies on GetServerKeys but does not define correct public key derivation from the private key nor rotation policy for oprf_seed. Define:
  - Correct derivation for server_public_key (not random bytes).
  - Storage and rotation policy for (server_secret_key, server_public_key, oprf_seed), including operational risk of rotation (invalidates registrations) and migration steps.
- Replay and misuse resistance of step payloads: Define strict size checks and base64 validation for M/pub/resp/authU; reject duplicates; bind step responses to the session_id and username; ensure one-time use.

Client-side WASM feasibility (critical)
- CGO in the browser is not viable: The plan calls libopaque via CGO from crypto/wasm_shim.go and TypeScript. Go’s WASM target does not support cgo to native C in the browser. You must instead:
  - Compile libopaque to WebAssembly via Emscripten, export a JS/WASM API, and call it from TS, or
  - Use a Rust OPAQUE implementation compiled to WASM.
- Memory hygiene at the JS boundary: “Password only in WASM memory” is not strictly achievable with DOM strings. Mitigations to include in the plan:
  - Immediately copy from the input field to a Uint8Array, set input.value = '' and call form.reset().
  - Avoid logging; never serialize to JSON.
  - Ensure TypedArrays passed to WASM are zeroed after use.
  - Keep all OPAQUE state (usr_ctx/sec) inside the WASM module when possible; only pass base64-encoded messages to/from server.

Export key lifecycle and storage
- Export key storage policy too weak: Storing export_key in sessionStorage exposes it to XSS. Strengthen:
  - Keep export_key in-memory only (not in any Web Storage).
  - If persistence is absolutely needed, wrap with WebCrypto using a non-extractable CryptoKey and gated user gesture, or use in-memory Web Worker to isolate.
  - Define lifecycle: when created, how long kept, cleared on tab close, logout, or after TOTP verification.
- Clarify usage: The plan says “use export_key for session” but does not specify derivations (e.g., HKDF contexts for different app keys). Add a key schedule section:
  - export_key -> HKDF(“auth-session”) for local state only; never transmitted.
  - Derive separate subkeys for file-metadata encryption, ephemeral UI secrets, etc., with context labels to avoid cross-use.

Server-side state (opaque_sessions)
- Encryption-at-rest design missing: The plan references encryptServerSecret/decryptServerSecret but doesn’t specify the master key source, algorithm, or rotation. Specify:
  - Algorithm: XChaCha20-Poly1305 with random 24-byte nonce; include session_id and username as AAD.
  - Master key provisioning via systemd-credentials (preferred) or KMS; document rotation and startup checks.
  - Immediate zeroization of decrypted buffers; use runtime.KeepAlive and avoid Go copies when possible.
- Expiry/cleanup: Plan includes expires_at; add guaranteed cleanup path (cron, background job on startup), and unique constraints to prevent reuse.

Data model consistency
- Dual storage paths for account records: Align on a single authoritative table for account auth:
  - Prefer opaque_user_data (username PRIMARY KEY, serialized_record BLOB).
  - Restrict opaque_password_records to file-specific custom passwords only; update record_type enumeration and all code paths accordingly.
- BLOB vs TEXT: The schema specifies BLOB but some code hex-encodes to TEXT. Standardize on raw BLOB for OPAQUE records/keys to avoid silent bugs with rqlite.

API and flow mechanics
- Finalize endpoint contract details:
  - Enforce content sizes: reject oversized base64 inputs to avoid C/WASM buffer overflows.
  - Strong rate limiting on both steps; per entity_id and per username.
  - Return bodies must never include any intermediate OPAQUE secrets; keep messages minimal.
- CSRF and token scoping:
  - If tokens are in cookies, protect step endpoints with CSRF defenses or make them purely bearer-based with explicit short-lived session_id-only authorization.
  - temp_token must be audience-limited to TOTP endpoints only, with <= 5–10 minute expiry.
- Remove all plaintext password fields: The plan states this principle, but explicitly forbid any legacy paths in the API docs and add tests that fail if a password field appears.

TOTP alignment with zero-knowledge goals
- Decide and document a single design:
  - Recommended: Server-managed TOTP root with per-user derivation (HKDF), encrypted at rest with a server master key. This keeps auth zero-knowledge for passwords/files while making 2FA operationally robust and does not require sending export_key to server.
  - If you instead bind TOTP to export_key, explicitly update the “zero-knowledge” claims to allow limited key provisioning to the server for TOTP only, or move verification client-side (impractical).
- Scope and lifecycle of temp_token: Document TTL, scope (“totp:*”), single-use, and revocation on success/failure.

Build, toolchain, and tests
- Add a concrete browser-WASM toolchain plan:
  - Emscripten build of libopaque -> wasm + glue JS; expose minimal stable API; integrate with TS types.
  - CI step to build artifacts deterministically; verify symbol sizes.
- Replace “mock M/recU/authU base64” in tests with real vectors produced by the WASM build.
- Add negative tests: malformed base64, wrong sizes, expired session, replayed session, wrong username/session binding.
- Fuzz CGO/WASM boundary for size misreports (where applicable on server-side).

Operational/privacy hardening
- XSS hardening: Mandate CSP (script-src 'self'; object-src 'none'; enable Trusted Types), no inline scripts, no eval, COOP/COEP for WASM performance and memory isolation. Document this in the plan because export_key and OPAQUE state live client-side.
- Logging policy: Absolutely no logging of OPAQUE messages, session IDs, or any base64 payloads; log only high-level event types and entity IDs.
- Documentation corrections:
  - State clearly that passwords never leave the client; export_key never leaves client; server never derives or receives session keys.
  - Adjust docs/api.md and docs/security.md to the final TOTP design and endpoint names.

Spec-level details to add to the plan
- Explicitly include IdU/IdS and context in all OPAQUE steps; define what values are used (e.g., IdS = “Arkfile v1”, IdU = username, context = domain + API version).
- Define precise buffer sizes and constants from libopaque headers for each message; include validation tables in the plan to prevent off-by-one errors when marshalling.
- Define key schedules (HKDF labels) for any derivations from export_key used by the client.

Typos/compile pitfalls in the plan
- Function name typos (“libopaqueFinalize Request” with a space); fix all prototype names and ensure they map to real symbols.
- Handlers reference unexported helpers (store/load) and mismatched CreateUser signatures; adjust when implementing.

Decisions needed to finalize the plan
- TOTP design: server-managed master key (recommended) vs export_key-bound.
- Single source of truth for OPAQUE account record: choose opaque_user_data and restrict opaque_password_records to file-scoped passwords.
- Server key provisioning: systemd-credentials/KMS vs DB at rest (with encryption). Set a rotation policy.
- Client export_key storage: in-memory only vs wrapped CryptoKey in IndexedDB; default should be in-memory only for zero-knowledge posture.
- API paths: lock /api/auth/opaque/register|login/(step1|step2).
- WASM toolchain: Emscripten libopaque or alternate OPAQUE WASM library.

With these additions and clarifications incorporated into fix-opaque.md, the plan will align tightly with a truly zero-knowledge OPAQUE authentication model while remaining implementable in a browser WASM environment.
"""