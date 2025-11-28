# Admin Bootstrap Design Specification

This document outlines the design and implementation plan for bootstrapping an administrator account on a new Arkfile deployment. This process allows for secure, local creation of the initial admin user without exposing insecure endpoints or requiring manual database manipulation.

## 1. Security Constraints & Requirements

To ensure the security of the deployment, the bootstrap process adheres to the following strict constraints:

*   **Localhost Only:** The bootstrap API endpoints (`/api/admin/bootstrap/*`) MUST only accept requests from `127.0.0.1` or `::1`. Any external access attempts will be rejected.
    *   *Container Strategy:* In containerized environments (Docker/Podman), the bootstrap tool MUST be run **inside the container** (e.g., `docker exec -it ...`). This guarantees the request originates from the container's internal loopback interface (`127.0.0.1`), bypassing the need for complex trusted proxy configuration for this specific feature.
*   **Single-Outcome Token:** The process relies on a high-entropy `BOOTSTRAP_TOKEN` generated at server startup. This token is valid for **exactly one successful admin creation**.
    *   *Note:* Since the OPAQUE protocol is a two-step process, the token must be presented and validated **twice** (once for `/response`, once for `/finalize`). It is NOT invalidated after the first use.
*   **Atomic Invalidation:** Upon successful creation of the admin user (completion of `/finalize`), the token is immediately cleared from memory, disabling the bootstrap endpoints permanently for the lifetime of the process.
*   **Conditional Activation:** The bootstrap mechanism is **disabled by default** if any administrator accounts already exist in the database. This prevents accidental or malicious re-initialization.
    *   *Override:* This check can be bypassed by setting the environment variable `ARKFILE_FORCE_ADMIN_BOOTSTRAP=true` at startup, allowing for emergency recovery.
*   **Proof of Life (Loopback Verification):** The bootstrap process is NOT complete until the created admin successfully logs in. The `arkfile-admin` tool MUST perform a full authentication flow immediately after creation. The server records this by updating the `last_login` timestamp. A non-null `last_login` is the cryptographic proof that the admin credentials were correctly generated, stored, and are usable.

## 2. Architecture

The solution consists of three main components:

1.  **Server-Side (`handlers/admin_bootstrap.go`):**
    *   Manages the lifecycle of the `BOOTSTRAP_TOKEN`.
    *   Exposes endpoints for the OPAQUE registration flow (Response/Finalize).
    *   Enforces IP restrictions and token validation.
2.  **Client-Side (`cmd/arkfile-admin`):**
    *   Implements the `bootstrap` command.
    *   Handles the client-side OPAQUE cryptography (hashing, blinding).
    *   Interacts with the local API to register the user.
    *   **Performs "Loopback Login" to verify credentials.**
3.  **Shared (`auth` package):**
    *   Provides the underlying cryptographic primitives for OPAQUE and TOTP.

## 3. Implementation Plan

### Step 1: Server Startup & Token Generation
*   **File:** `main.go`
*   **Logic:**
    1.  Check environment variable `ARKFILE_FORCE_ADMIN_BOOTSTRAP`.
    2.  Query database for existing **active** admins (`SELECT COUNT(*) FROM users WHERE is_admin = true AND last_login IS NOT NULL`).
        *   *Rationale:* If an admin exists but has `last_login` as NULL, it is considered a "Zombie Admin" (failed bootstrap). We should allow re-bootstrapping in this case to recover.
    3.  **Decision:**
        *   IF `ARKFILE_FORCE_ADMIN_BOOTSTRAP == "true"` OR `ActiveAdminCount == 0`:
            *   Generate random 32-byte hex string (`BOOTSTRAP_TOKEN`).
            *   Log token to `stdout` (INFO level).
            *   Store in `handlers` package.
        *   ELSE:
            *   Log "Admin users detected. Bootstrap mode disabled."
            *   Do not generate token (endpoints will reject requests).

### Step 2: API Endpoints
*   **File:** `handlers/route_config.go`
*   **Endpoints:**
    *   `POST /api/admin/bootstrap/response`: Accepts OPAQUE registration request.
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

### Step 4: Client Implementation (The "Proof of Life")
*   **File:** `cmd/arkfile-admin/main.go`
*   **Command:** `arkfile-admin bootstrap --username <user> --token <token>`
*   **Flow:**
    1.  Prompt for password (secure input).
    2.  Generate OPAQUE request (`auth.ClientCreateRegistrationRequest`).
    3.  POST to `/response` (Token Use #1).
    4.  Process response (`auth.ClientFinalizeRegistration`).
    5.  POST to `/finalize` (Token Use #2).
    6.  **Receive TOTP Secret.**
    7.  **VERIFICATION PHASE:**
        *   Generate TOTP code using the secret.
        *   Perform OPAQUE Login (`/api/admin/login/response` -> `/finalize`).
        *   Perform TOTP Login (`/api/totp/auth`).
    8.  **Success:** If login succeeds, display success message and TOTP QR code URL. If login fails, display error and exit with non-zero status (indicating "Zombie Admin" state).

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
	// Temporary storage for OPAQUE secrets between Response and Finalize steps
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
	// We strictly check the direct remote IP. In containerized setups, 
	// the admin tool must be run INSIDE the container (docker exec) 
	// to appear as 127.0.0.1. We do NOT rely on X-Forwarded-For here 
	// to avoid misconfiguration risks.
	ip := c.RealIP()
	
	// Allow IPv4 localhost and IPv6 localhost
	if ip != "127.0.0.1" && ip != "::1" {
		logging.SecurityLogger.Printf("Security Alert: Bootstrap attempt from non-local IP: %s", ip)
		return echo.NewHTTPError(http.StatusForbidden, "Access denied. Non-local IP detected.")
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

type BootstrapResponseRequest struct {
	Username       string `json:"username"`
	OpaqueRequest  string `json:"opaque_request"` // Base64
	BootstrapToken string `json:"bootstrap_token"`
}

type BootstrapResponse struct {
	OpaqueResponse string `json:"opaque_response"` // Base64
}

// AdminBootstrapResponse handles the first step of OPAQUE registration
func AdminBootstrapResponse(c echo.Context) error {
	var req BootstrapResponseRequest
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

	return c.JSON(http.StatusOK, BootstrapResponse{
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
		// LastLogin remains NULL here - it is set only upon successful login
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
	logging.InfoLogger.Printf("Bootstrap complete. Admin '%s' created. Awaiting proof-of-life login.", req.Username)

	return c.JSON(http.StatusOK, BootstrapFinalizeResponse{
		Success:    true,
		TOTPSecret: totpSetup.Secret,
		TOTPURL:    totpSetup.QRCodeURL,
	})
}
```

### 4.2. `models/user.go` (Update)

```go
type User struct {
	ID         int64      `json:"id"`
	Username   string     `json:"username"`
	IsApproved bool       `json:"is_approved"`
	IsAdmin    bool       `json:"is_admin"`
	CreatedAt  time.Time  `json:"created_at"`
	LastLogin  *time.Time `json:"last_login"` // Pointer to allow NULL
}
```

### 4.3. `handlers/auth.go` (Update Logic)

```go
// In TOTPAuth function (Login Handler):

// ... after successful TOTP validation ...

// Update Last Login
now := time.Now()
_, err = database.DB.Exec("UPDATE users SET last_login = ? WHERE username = ?", now, username)
if err != nil {
    logging.ErrorLogger.Printf("Failed to update last_login for %s: %v", username, err)
    // Non-critical error, proceed
}

// ... proceed to issue JWT ...
```

### 4.4. `cmd/arkfile-admin/main.go`

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
// 1. Perform OPAQUE Registration (Response/Finalize)
// 2. Get TOTP Secret
// 3. fmt.Println("Verifying credentials...")
// 4. Perform OPAQUE Login (Init/Finalize)
// 5. Perform TOTP Login
// 6. If Success:
//    fmt.Println("SUCCESS: Admin user created and verified.")
//    fmt.Printf("TOTP Secret: %s\n", secret)
// Else:
//    fmt.Println("CRITICAL ERROR: Admin created but login failed. Credentials may be invalid.")
//    os.Exit(1)
```

### 4.5. `main.go` (Server Startup Logic)

```go
// In main() function, before starting server:

// Check for existing ACTIVE admins (Proof of Life check)
// We only count admins who have successfully logged in at least once.
// This prevents "Zombie Admins" (failed bootstraps) from locking out the system.
var activeAdminCount int
err := database.DB.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = true AND last_login IS NOT NULL").Scan(&activeAdminCount)
if err != nil {
    logging.ErrorLogger.Printf("Failed to check admin count: %v", err)
}

// Check environment override
forceBootstrap := os.Getenv("ARKFILE_FORCE_ADMIN_BOOTSTRAP") == "true"

if activeAdminCount == 0 || forceBootstrap {
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
