# Admin Bootstrap Design Specification

This document outlines the design and implementation plan for bootstrapping an administrator account on a new Arkfile deployment. This process allows for secure, local creation of the initial admin user without exposing insecure endpoints or requiring manual database manipulation.

## 1. Security Constraints & Requirements

To ensure the security of the deployment, the bootstrap process adheres to the following strict constraints:

*   **Localhost Only:** The bootstrap API endpoints (`/api/admin/bootstrap/*`) MUST only accept requests from `127.0.0.1` or `::1`. Any external access attempts will be rejected.
*   **Single-Outcome Token:** The process relies on a high-entropy `BOOTSTRAP_TOKEN` generated at server startup. This token is valid for **exactly one successful admin creation**.
    *   *Note:* Since the OPAQUE protocol is a two-step process, the token must be presented and validated **twice** (once for `/init`, once for `/finalize`). It is NOT invalidated after the first use.
*   **Atomic Invalidation:** Upon successful creation of the admin user (completion of `/finalize`), the token is immediately cleared from memory, disabling the bootstrap endpoints permanently for the lifetime of the process.
*   **Conditional Activation:** The bootstrap mechanism is **disabled by default** if any administrator accounts already exist in the database. This prevents accidental or malicious re-initialization.
    *   *Override:* This check can be bypassed by setting the environment variable `ARKFILE_FORCE_ADMIN_BOOTSTRAP=true` at startup, allowing for emergency recovery.
*   **Admin-Only Tool:** The client-side operations are encapsulated in the `arkfile-admin` utility, which is designed to be run by a system administrator with shell access to the host.

## 2. Architecture

The solution consists of three main components:

1.  **Server-Side (`handlers/admin_bootstrap.go`):**
    *   Manages the lifecycle of the `BOOTSTRAP_TOKEN`.
    *   Exposes endpoints for the OPAQUE registration flow (Init/Finalize).
    *   Enforces IP restrictions and token validation.
2.  **Client-Side (`cmd/arkfile-admin`):**
    *   Implements the `bootstrap` command.
    *   Handles the client-side OPAQUE cryptography (hashing, blinding).
    *   Interacts with the local API to register the user.
3.  **Shared (`auth` package):**
    *   Provides the underlying cryptographic primitives for OPAQUE and TOTP.

## 3. Implementation Plan

### Step 1: Server Startup & Token Generation
*   **File:** `main.go`
*   **Logic:**
    1.  Check environment variable `ARKFILE_FORCE_ADMIN_BOOTSTRAP`.
    2.  Query database for existing admins (`SELECT COUNT(*) FROM users WHERE is_admin = true`).
    3.  **Decision:**
        *   IF `ARKFILE_FORCE_ADMIN_BOOTSTRAP == "true"` OR `AdminCount == 0`:
            *   Generate random 32-byte hex string (`BOOTSTRAP_TOKEN`).
            *   Log token to `stdout` (INFO level).
            *   Store in `handlers` package.
        *   ELSE:
            *   Log "Admin users detected. Bootstrap mode disabled."
            *   Do not generate token (endpoints will reject requests).

### Step 2: API Endpoints
*   **File:** `handlers/route_config.go`
*   **Endpoints:**
    *   `POST /api/admin/bootstrap/init`: Accepts OPAQUE registration request.
    *   `POST /api/admin/bootstrap/finalize`: Accepts OPAQUE record and creates user.

### Step 3: Request Handling Logic
*   **File:** `handlers/admin_bootstrap.go`
*   **Validation:**
    ```go
    func validateBootstrapRequest(c echo.Context, token string) error {
        // 1. IP Check
        if c.RealIP() != "127.0.0.1" && c.RealIP() != "::1" { return Forbidden }
        
        // 2. Token Check
        if token != currentBootstrapToken { return Forbidden }
        
        return nil
    }
    ```
*   **Completion (Invalidation):**
    ```go
    func completeBootstrap() {
        currentBootstrapToken = "" // Atomic clear
        // Clear any pending sessions
    }
    ```

### Step 4: Client Implementation
*   **File:** `cmd/arkfile-admin/main.go`
*   **Command:** `arkfile-admin bootstrap --username <user> --token <token>`
*   **Flow:**
    1.  Prompt for password (secure input).
    2.  Generate OPAQUE request (`auth.ClientCreateRegistrationRequest`).
    3.  POST to `/init` (Token Use #1).
    4.  Process response (`auth.ClientFinalizeRegistration`).
    5.  POST to `/finalize` (Token Use #2).
    6.  Display success message and TOTP secret/QR code URL.

## 4. Code Specifications

### 4.1. `handlers/admin_bootstrap.go`

```go
package handlers

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/84adam/Arkfile/auth"
	"github.com/84adam/Arkfile/crypto"
	"github.com/84adam/Arkfile/database"
	"github.com/84adam/Arkfile/logging"
	"github.com/84adam/Arkfile/models"
)

var (
	bootstrapToken      string
	bootstrapTokenMutex sync.RWMutex
	// Temporary storage for OPAQUE secrets between Init and Finalize steps
	// Key: username, Value: server_secret (rsec)
	bootstrapSessions      = make(map[string][]byte)
	bootstrapSessionsMutex sync.Mutex
)

// SetBootstrapToken sets the one-time token for admin creation
func SetBootstrapToken(token string) {
	bootstrapTokenMutex.Lock()
	defer bootstrapTokenMutex.Unlock()
	bootstrapToken = token
}

// ClearBootstrapToken removes the token, disabling the endpoints
func ClearBootstrapToken() {
	bootstrapTokenMutex.Lock()
	defer bootstrapTokenMutex.Unlock()
	bootstrapToken = ""
	
	// Clear sessions too
	bootstrapSessionsMutex.Lock()
	bootstrapSessions = make(map[string][]byte)
	bootstrapSessionsMutex.Unlock()
}

// validateBootstrapRequest checks IP and token
func validateBootstrapRequest(c echo.Context, providedToken string) error {
	// 1. Check Localhost
	ip := c.RealIP()
	// Allow IPv4 localhost and IPv6 localhost
	if ip != "127.0.0.1" && ip != "::1" {
		logging.SecurityLogger.Printf("Security Alert: Bootstrap attempt from non-local IP: %s", ip)
		return echo.NewHTTPError(http.StatusForbidden, "Access denied")
	}

	// 2. Check Token
	bootstrapTokenMutex.RLock()
	currentToken := bootstrapToken
	bootstrapTokenMutex.RUnlock()

	if currentToken == "" {
		return echo.NewHTTPError(http.StatusForbidden, "Bootstrap disabled")
	}

	if subtle.ConstantTimeCompare([]byte(providedToken), []byte(currentToken)) != 1 {
		logging.SecurityLogger.Printf("Security Alert: Invalid bootstrap token attempt from %s", ip)
		return echo.NewHTTPError(http.StatusForbidden, "Invalid token")
	}

	return nil
}

type BootstrapInitRequest struct {
	Username       string `json:"username"`
	OpaqueRequest  string `json:"opaque_request"` // Base64
	BootstrapToken string `json:"bootstrap_token"`
}

type BootstrapInitResponse struct {
	OpaqueResponse string `json:"opaque_response"` // Base64
}

// AdminBootstrapInit handles the first step of OPAQUE registration
func AdminBootstrapInit(c echo.Context) error {
	var req BootstrapInitRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if err := validateBootstrapRequest(c, req.BootstrapToken); err != nil {
		return err
	}

	// Decode OPAQUE request
	requestBytes, err := base64.StdEncoding.DecodeString(req.OpaqueRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid OPAQUE request encoding")
	}

	// Generate OPAQUE response
	responsePublic, responseSecret, err := auth.CreateRegistrationResponse(requestBytes)
	if err != nil {
		logging.ErrorLogger.Printf("Bootstrap OPAQUE error: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to process OPAQUE request")
	}

	// Store secret for next step
	bootstrapSessionsMutex.Lock()
	bootstrapSessions[req.Username] = responseSecret
	bootstrapSessionsMutex.Unlock()

	return c.JSON(http.StatusOK, BootstrapInitResponse{
		OpaqueResponse: base64.StdEncoding.EncodeToString(responsePublic),
	})
}

type BootstrapFinalizeRequest struct {
	Username       string `json:"username"`
	OpaqueRecord   string `json:"opaque_record"` // Base64
	BootstrapToken string `json:"bootstrap_token"`
}

type BootstrapFinalizeResponse struct {
	Success    bool   `json:"success"`
	TOTPSecret string `json:"totp_secret"`
	TOTPURL    string `json:"totp_url"`
}

// AdminBootstrapFinalize handles the final step of registration
func AdminBootstrapFinalize(c echo.Context) error {
	var req BootstrapFinalizeRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request format")
	}

	if err := validateBootstrapRequest(c, req.BootstrapToken); err != nil {
		return err
	}

	// Retrieve secret
	bootstrapSessionsMutex.Lock()
	serverSecret, ok := bootstrapSessions[req.Username]
	delete(bootstrapSessions, req.Username) // One-time use
	bootstrapSessionsMutex.Unlock()

	if !ok {
		return echo.NewHTTPError(http.StatusBadRequest, "Session expired or invalid")
	}

	// Decode OPAQUE record
	clientRecord, err := base64.StdEncoding.DecodeString(req.OpaqueRecord)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid OPAQUE record encoding")
	}

	// Create final user record
	userRecord, err := auth.StoreUserRecord(serverSecret, clientRecord)
	if err != nil {
		logging.ErrorLogger.Printf("Bootstrap OPAQUE store error: %v", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create user record")
	}

	// 1. Create User Model
	user := &models.User{
		Username:   req.Username,
		IsAdmin:    true,
		IsApproved: true,
		CreatedAt:  time.Now(),
	}
	
	// Insert user
	res, err := database.DB.Exec(`
		INSERT INTO users (username, is_approved, is_admin, created_at)
		VALUES (?, ?, ?, ?)`,
		user.Username, user.IsApproved, user.IsAdmin, user.CreatedAt,
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create user")
	}
	uid, _ := res.LastInsertId()
	user.ID = uid

	// 2. Save OPAQUE Data
	if err := auth.SaveOPAQUEUser(database.DB, req.Username, userRecord); err != nil {
		// Rollback
		models.DeleteUser(database.DB, user.ID)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to save auth data")
	}

	// 3. Setup TOTP
	totpSetup, err := auth.GenerateTOTPSetup(req.Username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to generate TOTP")
	}

	// Manually store TOTP as enabled/completed since this is a trusted bootstrap
	totpKey, err := crypto.DeriveTOTPUserKey(req.Username)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to derive TOTP key")
	}
	defer crypto.SecureZeroTOTPKey(totpKey)

	// Encrypt secret
	secretEncrypted, err := crypto.EncryptGCM([]byte(totpSetup.Secret), totpKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to encrypt TOTP secret")
	}

	// Encrypt backup codes
	backupCodesJSON, _ := json.Marshal(totpSetup.BackupCodes)
	backupCodesEncrypted, err := crypto.EncryptGCM(backupCodesJSON, totpKey)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to encrypt backup codes")
	}

	// Store
	_, err = database.DB.Exec(`
		INSERT OR REPLACE INTO user_totp (
			username, secret_encrypted, backup_codes_encrypted, 
			enabled, setup_completed, created_at
		) VALUES (?, ?, ?, ?, ?, ?)`,
		req.Username, secretEncrypted, backupCodesEncrypted,
		true, true, time.Now(),
	)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to store TOTP")
	}

	// 4. Clear Token (Invalidate)
	ClearBootstrapToken()
	logging.InfoLogger.Printf("Bootstrap complete. Admin '%s' created.", req.Username)

	return c.JSON(http.StatusOK, BootstrapFinalizeResponse{
		Success:    true,
		TOTPSecret: totpSetup.Secret,
		TOTPURL:    totpSetup.QRCodeURL,
	})
}
```

### 4.2. `auth/opaque.go`

```go
// SaveOPAQUEUser saves the OPAQUE user record to the database
// This is an exported wrapper for storeOPAQUEUserData
func SaveOPAQUEUser(db *sql.DB, username string, record []byte) error {
	return storeOPAQUEUserData(db, OPAQUEUserData{
		Username:         username,
		SerializedRecord: record,
		CreatedAt:        time.Now(),
	})
}
```

### 4.3. `cmd/arkfile-admin/main.go`

```go
// Add to main() switch case:
case "bootstrap":
    bootstrapCmd := flag.NewFlagSet("bootstrap", flag.ExitOnError)
    username := bootstrapCmd.String("username", "admin", "Admin username")
    token := bootstrapCmd.String("token", "", "Bootstrap token (required)")
    
    bootstrapCmd.Parse(args)
    if *token == "" {
        fmt.Println("Error: --token is required")
        os.Exit(1)
    }
    
    // Use existing config for server URL if available, or default
    runBootstrap(config.ServerURL, *username, *token)

// Implementation of runBootstrap...
// (Follows the flow described in Architecture section)
```

### 4.4. `main.go` (Server Startup Logic)

```go
// In main() function, before starting server:

// Check for existing admins
var adminCount int
err := database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = true").Scan(&adminCount)
if err != nil {
    logging.ErrorLogger.Printf("Failed to check admin count: %v", err)
}

// Check environment override
forceBootstrap := os.Getenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP") == "true"

if adminCount == 0 || forceBootstrap {
    // Generate Bootstrap Token
    bootstrapToken := crypto.GenerateRandomString(32)
    handlers.SetBootstrapToken(bootstrapToken)
    
    logging.InfoLogger.Println("==================================================")
    logging.InfoLogger.Printf("ADMIN BOOTSTRAP TOKEN: %s", bootstrapToken)
    logging.InfoLogger.Println("Use this token with 'arkfile-admin bootstrap' to create the first admin user.")
    logging.InfoLogger.Println("==================================================")
} else {
    logging.InfoLogger.Println("Admin users detected. Bootstrap mode disabled.")
}
