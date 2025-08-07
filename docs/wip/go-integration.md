# Arkfile Go-Based Complete Integration Test

## Project Overview & Objectives

### Purpose
Create a comprehensive Go-based integration test (`test-complete-integration.go`) that validates the entire Arkfile system end-to-end, including OPAQUE authentication, file operations, and anonymous file sharing capabilities.

### Key Objectives
1. **Complete Authentication Flow**: Username-based OPAQUE registration → TOTP setup → login with 2FA
2. **Large File Operations**: 50MB file upload/download with integrity verification
3. **Share System Validation**: Create shares → anonymous access → file download
4. **Security Validation**: Rate limiting, timing protection, encryption round-trip
5. **Database Integration**: Direct database operations and validation
6. **MinIO Storage Testing**: Verify S3-compatible storage backend

### Why Go vs Existing Bash Scripts
- **Complex Crypto Operations**: OPAQUE client implementation requires Go packages
- **Binary Data Handling**: 50MB files, encryption, and decryption operations
- **JSON API Interaction**: Complex request/response handling with proper error parsing
- **Concurrent Operations**: Chunked upload handling and parallel validation
- **Database Integration**: Direct SQL operations with proper connection management
- **Performance Testing**: Precise timing and resource usage measurement

## Technical Architecture

### System Integration Points

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Integration   │    │    Arkfile       │    │    External     │
│   Test (Go)     │    │    Server        │    │    Services     │
│                 │    │                  │    │                 │
│ • OPAQUE Client │◄──►│ • Auth APIs      │    │ • MinIO S3      │
│ • TOTP Generator│    │ • File APIs      │    │ • rqlite DB     │
│ • Crypto Ops    │    │ • Share APIs     │    │ • TLS Certs     │
│ • HTTP Client   │    │ • Static Files   │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Test Architecture

```
main()
├── Phase1: UserSetupAndAuthentication()
│   ├── RegisterUser()
│   ├── ApproveInDatabase()
│   ├── SetupTOTP()
│   ├── LoginUser()
│   └── ValidateTokens()
├── Phase2: FileOperations()
│   ├── GenerateTestFile()
│   ├── UploadFile()
│   ├── ListFiles()
│   ├── DownloadFile()
│   └── VerifyIntegrity()
├── Phase3: FileSharingOperations()
│   ├── CreateShareLink()
│   ├── ValidateShareInDatabase()
│   ├── LogoutUser()
│   ├── AnonymousShareAccess()
│   ├── AnonymousDownload()
│   └── VerifySharedFileIntegrity()
└── Phase4: ComprehensiveCleanup()
    ├── CleanupUser()
    ├── ValidateCleanup()
    └── GenerateReport()
```

## Implementation Specifications

### Phase 1: User Setup & Authentication

#### Step 1: RegisterUser()
```go
type RegistrationRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
    Email    string `json:"email,omitempty"` // Optional field
}

func (t *IntegrationTest) RegisterUser() error {
    // Use existing OPAQUE client implementation
    req := RegistrationRequest{
        Username: t.config.TestUsername,
        Password: t.config.TestPassword,
        Email:    t.config.TestEmail, // Optional
    }
    
    resp, err := t.httpClient.Post("/api/opaque/register", req)
    if err != nil {
        return fmt.Errorf("registration failed: %w", err)
    }
    
    // Extract temp token and session key for TOTP setup
    t.tempToken = resp.TempToken
    t.sessionKey = resp.SessionKey
    t.requiresTOTPSetup = resp.RequiresTOTPSetup
    
    return t.validateRegistrationResponse(resp)
}
```

#### Step 2: ApproveInDatabase()
```go
func (t *IntegrationTest) ApproveInDatabase() error {
    query := "UPDATE users SET is_approved = 1, approved_by = 'integration-test', approved_at = CURRENT_TIMESTAMP WHERE username = ?"
    
    result, err := t.dbClient.Execute(query, t.config.TestUsername)
    if err != nil {
        return fmt.Errorf("database approval failed: %w", err)
    }
    
    if result.RowsAffected == 0 {
        return fmt.Errorf("no user found to approve: %s", t.config.TestUsername)
    }
    
    return t.verifyUserApproval()
}
```

#### Step 3: SetupTOTP()
```go
type TOTPSetupRequest struct {
    SessionKey string `json:"sessionKey"`
}

func (t *IntegrationTest) SetupTOTP() error {
    // Initiate TOTP setup
    req := TOTPSetupRequest{SessionKey: t.sessionKey}
    resp, err := t.httpClient.PostWithAuth("/api/totp/setup", req, t.tempToken)
    if err != nil {
        return fmt.Errorf("TOTP setup failed: %w", err)
    }
    
    // Store TOTP secret and backup codes
    t.totpSecret = resp.Secret
    t.backupCodes = resp.BackupCodes
    
    // Generate real TOTP code using existing totp-generator logic
    totpCode, err := t.generateTOTPCode(t.totpSecret)
    if err != nil {
        return fmt.Errorf("TOTP code generation failed: %w", err)
    }
    
    // Verify TOTP setup
    verifyReq := TOTPVerifyRequest{
        Code:       totpCode,
        SessionKey: t.sessionKey,
    }
    
    _, err = t.httpClient.PostWithAuth("/api/totp/verify", verifyReq, t.tempToken)
    return err
}
```

#### Step 4: LoginUser()
```go
func (t *IntegrationTest) LoginUser() error {
    // OPAQUE login
    loginReq := LoginRequest{
        Username: t.config.TestUsername,
        Password: t.config.TestPassword,
    }
    
    loginResp, err := t.httpClient.Post("/api/opaque/login", loginReq)
    if err != nil {
        return fmt.Errorf("OPAQUE login failed: %w", err)
    }
    
    // Should require TOTP
    if !loginResp.RequiresTOTP {
        return fmt.Errorf("expected TOTP requirement, got: %v", loginResp.RequiresTOTP)
    }
    
    t.loginTempToken = loginResp.TempToken
    t.loginSessionKey = loginResp.SessionKey
    
    // TOTP authentication
    totpCode, err := t.generateTOTPCode(t.totpSecret)
    if err != nil {
        return fmt.Errorf("TOTP generation failed: %w", err)
    }
    
    totpReq := TOTPAuthRequest{
        Code:       totpCode,
        SessionKey: t.loginSessionKey,
        IsBackup:   false,
    }
    
    totpResp, err := t.httpClient.PostWithAuth("/api/totp/auth", totpReq, t.loginTempToken)
    if err != nil {
        return fmt.Errorf("TOTP authentication failed: %w", err)
    }
    
    // Store final tokens
    t.jwtToken = totpResp.Token
    t.refreshToken = totpResp.RefreshToken
    t.finalSessionKey = totpResp.SessionKey
    
    return nil
}
```

### Phase 2: File Operations

#### Step 6: GenerateTestFile()
```go
func (t *IntegrationTest) GenerateTestFile() error {
    const fileSize = 50 * 1024 * 1024 // 50MB
    
    // Create deterministic test data for consistent hashing
    data := make([]byte, fileSize)
    seed := []byte("ArkFile Integration Test File Content")
    
    // Fill with pseudo-random but deterministic data
    for i := 0; i < len(data); i += len(seed) {
        copy(data[i:], seed)
    }
    
    // Calculate SHA-256 hash for integrity verification
    hash := sha256.Sum256(data)
    t.originalFileHash = hex.EncodeToString(hash[:])
    
    // Save to temporary file
    t.testFilePath = filepath.Join(os.TempDir(), "arkfile-test-50mb.dat")
    err := os.WriteFile(t.testFilePath, data, 0644)
    if err != nil {
        return fmt.Errorf("failed to create test file: %w", err)
    }
    
    t.logger.Printf("Generated 50MB test file: %s", t.testFilePath)
    t.logger.Printf("Original file hash: %s", t.originalFileHash)
    
    return nil
}
```

#### Step 7: UploadFile()
```go
func (t *IntegrationTest) UploadFile() error {
    // Read test file
    fileData, err := os.ReadFile(t.testFilePath)
    if err != nil {
        return fmt.Errorf("failed to read test file: %w", err)
    }
    
    // Generate File Encryption Key (FEK)
    fek := make([]byte, 32)
    _, err = rand.Read(fek)
    if err != nil {
        return fmt.Errorf("failed to generate FEK: %w", err)
    }
    
    // Encrypt file with FEK
    encryptedFile, err := t.encryptFile(fileData, fek)
    if err != nil {
        return fmt.Errorf("file encryption failed: %w", err)
    }
    
    // Encrypt FEK with session key
    encryptedFEK, err := t.encryptFEK(fek, t.finalSessionKey)
    if err != nil {
        return fmt.Errorf("FEK encryption failed: %w", err)
    }
    
    // Chunked upload implementation
    const chunkSize = 1024 * 1024 // 1MB chunks
    totalChunks := (len(encryptedFile) + chunkSize - 1) / chunkSize
    
    // Initialize upload session
    uploadReq := InitUploadRequest{
        Filename:     "integration-test-file.dat",
        FileSize:     int64(len(encryptedFile)),
        ContentType:  "application/octet-stream",
        EncryptedFEK: base64.StdEncoding.EncodeToString(encryptedFEK),
        TotalChunks:  totalChunks,
    }
    
    uploadResp, err := t.httpClient.PostWithAuth("/api/upload/init", uploadReq, t.jwtToken)
    if err != nil {
        return fmt.Errorf("upload initialization failed: %w", err)
    }
    
    t.uploadSessionID = uploadResp.SessionID
    t.fileID = uploadResp.FileID
    
    // Upload chunks with progress tracking
    for chunkIndex := 0; chunkIndex < totalChunks; chunkIndex++ {
        start := chunkIndex * chunkSize
        end := start + chunkSize
        if end > len(encryptedFile) {
            end = len(encryptedFile)
        }
        
        chunkData := encryptedFile[start:end]
        
        err := t.uploadChunk(chunkIndex, chunkData)
        if err != nil {
            return fmt.Errorf("chunk %d upload failed: %w", chunkIndex, err)
        }
        
        // Progress logging
        progress := float64(chunkIndex+1) / float64(totalChunks) * 100
        t.logger.Printf("Upload progress: %.1f%% (%d/%d chunks)", progress, chunkIndex+1, totalChunks)
    }
    
    // Finalize upload
    finalizeReq := FinalizeUploadRequest{
        SessionID: t.uploadSessionID,
    }
    
    _, err = t.httpClient.PostWithAuth("/api/upload/finalize", finalizeReq, t.jwtToken)
    if err != nil {
        return fmt.Errorf("upload finalization failed: %w", err)
    }
    
    t.logger.Printf("File upload completed successfully - FileID: %s", t.fileID)
    return nil
}
```

### Phase 3: File Sharing Operations

#### Step 11: CreateShareLink()
```go
func (t *IntegrationTest) CreateShareLink() error {
    sharePassword := t.config.SharePassword
    
    // Generate 32-byte random salt
    salt := make([]byte, 32)
    _, err := rand.Read(salt)
    if err != nil {
        return fmt.Errorf("salt generation failed: %w", err)
    }
    
    // Derive Argon2id key (same parameters as production)
    shareKey := argon2.IDKey([]byte(sharePassword), salt, 4, 128*1024, 4, 32)
    
    // Download and decrypt FEK using user's session key
    encryptedFEK, err := t.downloadEncryptedFEK(t.fileID)
    if err != nil {
        return fmt.Errorf("failed to download encrypted FEK: %w", err)
    }
    
    fek, err := t.decryptFEK(encryptedFEK, t.finalSessionKey)
    if err != nil {
        return fmt.Errorf("FEK decryption failed: %w", err)
    }
    
    // Re-encrypt FEK with share key
    encryptedFEKForShare, err := t.encryptFEK(fek, shareKey)
    if err != nil {
        return fmt.Errorf("FEK re-encryption failed: %w", err)
    }
    
    // Create share via API
    createShareReq := CreateShareRequest{
        Salt:          base64.StdEncoding.EncodeToString(salt),
        EncryptedFEK:  base64.StdEncoding.EncodeToString(encryptedFEKForShare),
        ExpiresInDays: 30,
    }
    
    shareResp, err := t.httpClient.PostWithAuth(
        fmt.Sprintf("/api/files/%s/share", t.fileID), 
        createShareReq, 
        t.jwtToken,
    )
    if err != nil {
        return fmt.Errorf("share creation failed: %w", err)
    }
    
    t.shareID = shareResp.ShareID
    t.shareURL = shareResp.ShareURL
    t.shareExpiresAt = shareResp.ExpiresAt
    
    t.logger.Printf("Share created successfully:")
    t.logger.Printf("  Share ID: %s", t.shareID)
    t.logger.Printf("  Share URL: %s", t.shareURL)
    t.logger.Printf("  Expires: %s", t.shareExpiresAt)
    
    return nil
}
```

#### Step 14: AnonymousShareAccess()
```go
func (t *IntegrationTest) AnonymousShareAccess() error {
    sharePassword := t.config.SharePassword
    
    // Access share without authentication (anonymous)
    shareAccessReq := ShareAccessRequest{
        Password: sharePassword,
    }
    
    // Test timing protection (should take ~1000ms)
    startTime := time.Now()
    shareResp, err := t.httpClient.Post(fmt.Sprintf("/api/share/%s", t.shareID), shareAccessReq)
    duration := time.Since(startTime)
    
    if err != nil {
        return fmt.Errorf("anonymous share access failed: %w", err)
    }
    
    // Validate timing protection
    if duration < 900*time.Millisecond {
        return fmt.Errorf("timing protection not working: duration %v < 900ms", duration)
    }
    
    // Extract salt and encrypted FEK from response
    salt, err := base64.StdEncoding.DecodeString(shareResp.Salt)
    if err != nil {
        return fmt.Errorf("invalid salt in share response: %w", err)
    }
    
    encryptedFEKFromShare, err := base64.StdEncoding.DecodeString(shareResp.EncryptedFEK)
    if err != nil {
        return fmt.Errorf("invalid encrypted FEK in share response: %w", err)
    }
    
    // Store for anonymous download
    t.anonymousDownloadURL = shareResp.DownloadURL
    t.shareResponseSalt = salt
    t.shareResponseEncryptedFEK = encryptedFEKFromShare
    
    t.logger.Printf("Anonymous share access successful:")
    t.logger.Printf("  Timing protection: %v", duration)
    t.logger.Printf("  Download URL: %s", t.anonymousDownloadURL)
    
    return nil
}
```

#### Step 15: AnonymousDownload()
```go
func (t *IntegrationTest) AnonymousDownload() error {
    sharePassword := t.config.SharePassword
    
    // Derive share key again (anonymous client-side operation)
    shareKey := argon2.IDKey([]byte(sharePassword), t.shareResponseSalt, 4, 128*1024, 4, 32)
    
    // Decrypt FEK using share key
    fek, err := t.decryptFEK(t.shareResponseEncryptedFEK, shareKey)
    if err != nil {
        return fmt.Errorf("FEK decryption with share key failed: %w", err)
    }
    
    // Download encrypted file using download URL (no auth required)
    encryptedFileData, err := t.httpClient.GetRaw(t.anonymousDownloadURL)
    if err != nil {
        return fmt.Errorf("anonymous file download failed: %w", err)
    }
    
    // Decrypt file with FEK
    decryptedFileData, err := t.decryptFile(encryptedFileData, fek)
    if err != nil {
        return fmt.Errorf("anonymous file decryption failed: %w", err)
    }
    
    // Save decrypted file for integrity verification
    t.anonymousDownloadPath = filepath.Join(os.TempDir(), "arkfile-anonymous-download.dat")
    err = os.WriteFile(t.anonymousDownloadPath, decryptedFileData, 0644)
    if err != nil {
        return fmt.Errorf("failed to save anonymous download: %w", err)
    }
    
    t.logger.Printf("Anonymous download completed: %s", t.anonymousDownloadPath)
    return nil
}
```

## Code Structure Design

### Main Test Structure
```go
type IntegrationTest struct {
    config   *TestConfig
    logger   *log.Logger
    
    // HTTP client for API calls
    httpClient *HTTPClient
    
    // Database client for direct operations
    dbClient *DatabaseClient
    
    // Test state tracking
    tempToken         string
    sessionKey        string
    jwtToken          string
    refreshToken      string
    finalSessionKey   string
    
    // TOTP data
    totpSecret    string
    backupCodes   []string
    
    // File data
    testFilePath         string
    originalFileHash     string
    fileID              string
    uploadSessionID     string
    authenticatedDownloadPath string
    
    // Share data
    shareID              string
    shareURL             string
    shareExpiresAt       time.Time
    anonymousDownloadURL string
    shareResponseSalt    []byte
    shareResponseEncryptedFEK []byte
    anonymousDownloadPath string
    
    // Test results
    startTime    time.Time
    phaseResults map[string]PhaseResult
}

type TestConfig struct {
    ServerURL     string `default:"https://localhost:4443"`
    TestUsername  string `default:"integration.test.user.2025"`
    TestEmail     string `default:"integration-test@example.com"` // Optional
    TestPassword  string `default:"IntegrationTestPassword123456789!"`
    SharePassword string `default:"TestSharePassword2025_SecureAndLong!"`
    TestFileSize  int64  `default:"52428800"` // 50MB
    DatabaseURL   string `default:"http://demo-user:TestPassword123_Secure@localhost:4001"`
    TLSInsecure   bool   `default:"true"`     // For local testing with self-signed certs
    Verbose       bool   `default:"false"`
    CleanupOnFail bool   `default:"true"`
}

type PhaseResult struct {
    PhaseName   string
    StartTime   time.Time
    EndTime     time.Time
    Duration    time.Duration
    Success     bool
    Error       error
    Steps       []StepResult
}

type StepResult struct {
    StepName    string
    Duration    time.Duration
    Success     bool
    Error       error
    Details     map[string]interface{}
}
```

### Helper Functions and Utilities

#### HTTP Client Implementation
```go
type HTTPClient struct {
    client      *http.Client
    baseURL     string
    tlsInsecure bool
    logger      *log.Logger
}

func NewHTTPClient(baseURL string, tlsInsecure bool, logger *log.Logger) *HTTPClient {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: tlsInsecure,
        },
    }
    
    return &HTTPClient{
        client:      &http.Client{Transport: tr, Timeout: 30 * time.Second},
        baseURL:     strings.TrimSuffix(baseURL, "/"),
        tlsInsecure: tlsInsecure,
        logger:      logger,
    }
}

func (c *HTTPClient) Post(endpoint string, request interface{}) (*Response, error) {
    return c.makeRequest("POST", endpoint, request, "")
}

func (c *HTTPClient) PostWithAuth(endpoint string, request interface{}, token string) (*Response, error) {
    return c.makeRequest("POST", endpoint, request, token)
}

func (c *HTTPClient) Get(endpoint string) (*Response, error) {
    return c.makeRequest("GET", endpoint, nil, "")
}

func (c *HTTPClient) GetWithAuth(endpoint string, token string) (*Response, error) {
    return c.makeRequest("GET", endpoint, nil, token)
}

func (c *HTTPClient) GetRaw(url string) ([]byte, error) {
    resp, err := c.client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
    }
    
    return io.ReadAll(resp.Body)
}
```

#### Database Client Implementation
```go
type DatabaseClient struct {
    baseURL string
    auth    string
    client  *http.Client
    logger  *log.Logger
}

func NewDatabaseClient(dbURL string, logger *log.Logger) (*DatabaseClient, error) {
    // Parse URL to extract auth and base URL
    u, err := url.Parse(dbURL)
    if err != nil {
        return nil, fmt.Errorf("invalid database URL: %w", err)
    }
    
    auth := ""
    if u.User != nil {
        auth = base64.StdEncoding.EncodeToString([]byte(u.User.String()))
        u.User = nil
    }
    
    return &DatabaseClient{
        baseURL: u.String(),
        auth:    auth,
        client:  &http.Client{Timeout: 10 * time.Second},
        logger:  logger,
    }, nil
}

func (db *DatabaseClient) Execute(query string, args ...interface{}) (*DatabaseResult, error) {
    // Format query with arguments
    formattedQuery := fmt.Sprintf(query, args...)
    
    reqBody := []string{formattedQuery}
    jsonData, _ := json.Marshal(reqBody)
    
    req, err := http.NewRequest("POST", db.baseURL+"/db/execute", bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Content-Type", "application/json")
    if db.auth != "" {
        req.Header.Set("Authorization", "Basic "+db.auth)
    }
    
    resp, err := db.client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result DatabaseResult
    err = json.NewDecoder(resp.Body).Decode(&result)
    return &result, err
}
```

#### Crypto Operations
```go
// Reuse existing crypto packages from the Arkfile project
func (t *IntegrationTest) encryptFile(data []byte, fek []byte) ([]byte, error) {
    // Use crypto/gcm.go functions
    return EncryptWithGCM(data, fek)
}

func (t *IntegrationTest) decryptFile(encryptedData []byte, fek []byte) ([]byte, error) {
    // Use crypto/gcm.go functions
    return DecryptWithGCM(encryptedData, fek)
}

func (t *IntegrationTest) encryptFEK(fek []byte, sessionKey string) ([]byte, error) {
    // Convert session key to bytes and encrypt FEK
    keyBytes := []byte(sessionKey)
    if len(keyBytes) > 32 {
        keyBytes = keyBytes[:32]
    }
    return EncryptWithGCM(fek, keyBytes)
}

func (t *IntegrationTest) decryptFEK(encryptedFEK []byte, sessionKey string) ([]byte, error) {
    // Convert session key to bytes and decrypt FEK
    keyBytes := []byte(sessionKey)
    if len(keyBytes) > 32 {
        keyBytes = keyBytes[:32]
    }
    return DecryptWithGCM(encryptedFEK, keyBytes)
}

func (t *IntegrationTest) generateTOTPCode(secret string) (string, error) {
    // Reuse the existing totp-generator logic
    return totp.GenerateCodeCustom(secret, time.Now(), totp.ValidateOpts{
        Period:    30,
        Skew:      0,
        Digits:    otp.DigitsSix,
        Algorithm: otp.AlgorithmSHA1,
    })
}
```

## Security & Validation Requirements

### Authentication Security
- **OPAQUE Protocol**: Zero-knowledge authentication with no password exposure
- **TOTP Verification**: Real 6-digit codes generated with production parameters
- **JWT Validation**: Proper token format and expiration handling
- **Session Management**: Secure session key derivation and usage

### File Security
- **End-to-End Encryption**: File encrypted client-side before upload
- **FEK Protection**: File Encryption Keys encrypted with session keys
- **Integrity Verification**: SHA-256 hash comparison for all file operations
- **Secure Transport**: All operations over HTTPS with proper certificate handling

### Share Security
- **Argon2id Parameters**: 128MB memory, 4 iterations, 4 threads (production settings)
- **Anonymous Access**: No authentication required for share access
- **Timing Protection**: Minimum 1-second response times for security endpoints
- **Rate Limiting**: Exponential backoff for failed share access attempts
- **EntityID Privacy**: Anonymous user identification without personal data

### Database Security
- **SQL Injection Prevention**: Parameterized queries for all database operations
- **Data Cleanup**: Complete removal of test data after execution
- **Access Validation**: Proper database permissions and authentication

## Integration Points

### Existing Arkfile Components to Reuse

#### Authentication System
```go
import (
    "github.com/yourorg/arkfile/auth"
    "github.com/yourorg/arkfile/models"
)

// Use existing OPAQUE implementation
opaqueProvider := auth.NewOPAQUEProvider()
```

#### Crypto System
```go
import (
    "github.com/yourorg/arkfile/crypto"
)

// Use existing encryption functions
encryptedData, err := crypto.EncryptWithGCM(plaintext, key)
```

#### Database Models
```go
import (
    "github.com/yourorg/arkfile/models"
    "github.com/yourorg/arkfile/database"
)

// Use existing user and file models
user := &models.User{
    Username: testUsername,
    Email:    &testEmail, // Optional field
    // ... other fields
}
```

### New Components Required

#### Chunked Upload Client
```go
type ChunkedUploader struct {
    httpClient  *HTTPClient
    sessionID   string
    totalChunks int
    chunkSize   int
}

func (cu *ChunkedUploader) UploadChunk(index int, data []byte) error {
    // Implementation for chunked upload
}
```

#### MinIO Integration Testing
```go
type MinIOTester struct {
    endpoint   string
    accessKey  string
    secretKey  string
    bucketName string
}

func (mt *MinIOTester) VerifyObjectExists(objectKey string) error {
    // Direct MinIO object verification
}
```

## Testing Scenarios & Edge Cases

### Success Path Validation
1. **Happy Path**: All operations succeed without errors
2. **Performance Validation**: Operations complete within acceptable timeframes
3. **Data Integrity**: All hash comparisons pass
4. **Security Compliance**: All security measures active and working

### Error Condition Handling
1. **Network Failures**: Graceful handling of connection timeouts
2. **Authentication Errors**: Proper error messages for auth failures
3. **File Upload Failures**: Chunked upload retry and recovery
4. **Database Errors**: Transaction rollback and cleanup

### Security Boundary Testing
1. **Invalid TOTP Codes**: Rejection of incorrect 2FA codes
2. **Expired Tokens**: Proper handling of JWT expiration
3. **Rate Limiting Triggers**: Verification of rate limiting activation
4. **Share Password Attacks**: Timing protection under load

### Edge Case Scenarios
1. **Large File Handling**: 50MB upload performance and reliability
2. **Concurrent Operations**: Multiple simultaneous test executions
3. **Resource Cleanup**: Proper cleanup after partial failures
4. **System Resource Usage**: Memory and disk space management

## Implementation Timeline

### Phase 1: Foundation (Days 1-2)
- **Day 1**: Project structure, configuration, and basic HTTP client
- **Day 2**: Database client and TOTP generation integration

### Phase 2: Authentication & File Operations (Days 3-4)
- **Day 3**: OPAQUE authentication flow and TOTP integration
- **Day 4**: File upload/download with chunked operations

### Phase 3: Share System (Days 5-6)
- **Day 5**: Share creation and anonymous access implementation
- **Day 6**: End-to-end testing and validation

### Phase 4: Polish & Documentation (Day 7)
- **Day 7**: Error handling, edge cases, and comprehensive documentation

## Expected Output & Usage

### Command Line Interface
```bash
# Basic execution
go run scripts/testing/test-complete-integration.go

# With custom configuration
go run scripts/testing/test-complete-integration.go \
    --server-url https://arkfile.example.com \
    --test-username integration.user.custom \
    --test-email integration@example.com \
    --verbose

# Specific phase testing
go run scripts/testing/test-complete-integration.go --phase auth
go run scripts/testing/test-complete-integration.go --phase files
go run scripts/testing/test-complete-integration.go --phase sharing

# Skip cleanup for debugging
go run scripts/testing/test-complete-integration.go --no-cleanup
```

### Expected Console Output
```
🧪 ARKFILE COMPLETE INTEGRATION TEST
Configuration:
  Server URL: https://localhost:4443
  Test Username: integration.test.user.2025
  Test Email: integration-test@example.com (optional)
  Test File Size: 50MB
  Database URL: http://localhost:4001
  TLS Insecure: true

📋 Phase 1: User Setup & Authentication
  ✅ Step 1: RegisterUser (2.1s)
      - OPAQUE registration successful (username: integration.test.user.2025)
      - Optional email provided: integration-test@example.com
      - Temp token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
      - Session key: 64 bytes
      - Requires TOTP setup: true
      
  ✅ Step 2: ApproveInDatabase (0.3s)
      - Database query executed successfully (username: integration.test.user.2025)
      - Rows affected: 1
      - User approval verified
      
  ✅ Step 3: SetupTOTP (4.2s)
      - TOTP secret: JBSWY3DPEHPK3PXP... (32 chars)
      - QR code URL generated
      - Backup codes: 12 codes generated
      - TOTP verification: SUCCESS (code: 123456)
      
  ✅ Step 4: LoginUser (3.8s)
      - OPAQUE login successful
      - TOTP authentication successful
      - Final JWT token: 512 bytes
      - Refresh token: 256 bytes
      - Session key: 64 bytes
      
  ✅ Step 5: ValidateTokens (0.5s)
      - JWT format validation: PASSED
      - Token expiration: 1 hour
      - Refresh token valid: true

📋 Phase 2: File Operations
  ✅ Step 6: GenerateTestFile (1.2s)
      - File size: 52,428,800 bytes (50.0 MB)
      - File path: /tmp/arkfile-test-50mb.dat
      - SHA-256: a1b2c3d4e5f6789012345678901234567890abcdef...
      
  ✅ Step 7: UploadFile (45.3s)
      - File encryption: AES-GCM with random FEK
      - FEK encryption: Session key derived encryption
      - Total chunks: 53 (1MB each)
      - Upload progress: 100% (53/53 chunks)
      - File ID: file_abc123def456
      
  ✅ Step 8: ListFiles (0.8s)
      - Files in account: 1
      - Target file found: ✓
      - File metadata verified: ✓
      
  ✅ Step 9: DownloadFile (12.4s)
      - Encrypted file download: 52.4MB
      - FEK decryption: SUCCESS
      - File decryption: SUCCESS
      - Save path: /tmp/arkfile-authenticated-download.dat
      
  ✅ Step 10: VerifyIntegrity (0.9s)
      - Original hash:  a1b2c3d4e5f6789012345678901234567890abcdef...
      - Downloaded hash: a1b2c3d4e5f6789012345678901234567890abcdef...
      - Hash match: ✅ PERFECT INTEGRITY

📋 Phase 3: File Sharing Operations
  ✅ Step 11: CreateShareLink (3.7s)
      - Share password: TestSharePassword2025_SecureAndLong!
      - Argon2id salt: 32 bytes (random)
      - Share key derivation: 128MB memory, 4 iterations
      - FEK re-encryption: SUCCESS
      - Share ID: share_xyz789abc123
      - Share URL: https://localhost:4443/shared/share_xyz789abc123
      - Expires: 2025-09-05T08:11:37Z
      
  ✅ Step 12: ValidateShareInDatabase (0.4s)
      - file_share_keys table: 1 entry found
      - Share ID match: ✓
      - Salt length: 32 bytes ✓
      - Encrypted FEK length: 48 bytes ✓
      
  ✅ Step 13: LogoutUser (0.6s)
      - JWT token invalidated
      - Session terminated
      - Verification: protected endpoints inaccessible ✓
      
  ✅ Step 14: AnonymousShareAccess (1.8s)
      - Share access request: POST /api/share/share_xyz789abc123
      - Timing protection: 1,015ms (✅ > 900ms)
      - Response: salt + encrypted FEK received
      - Download URL: https://storage.localhost:9000/files/obj_abc123...
      
  ✅ Step 15: AnonymousDownload (15.2s)
      - Argon2id key derivation: 128MB operation completed
      - FEK decryption with share key: SUCCESS
      - File download (no auth): 52.4MB
      - File decryption with FEK: SUCCESS
      - Save path: /tmp/arkfile-anonymous-download.dat
      
  ✅ Step 16: VerifySharedFileIntegrity (0.7s)
      - Original hash:    a1b2c3d4e5f6789012345678901234567890abcdef...
      - Auth download:    a1b2c3d4e5f6789012345678901234567890abcdef...
      - Anonymous hash:   a1b2c3d4e5f6789012345678901234567890abcdef...
      - Triple integrity: ✅ PERFECT MATCH

📋 Phase 4: Comprehensive Cleanup
  ✅ Step 17: CleanupUser (1.2s)
      - User removed from users table (username: integration.test.user.2025)
      - OPAQUE data removed
      - TOTP data removed  
      - File metadata removed
      - Share data removed
      - MinIO objects deleted: 1
      
  ✅ Step 18: ValidateCleanup (0.8s)
      - Database queries: 0 test records found ✓
      - Temporary files removed ✓
      - System state clean ✓

🎉 ALL TESTS COMPLETED SUCCESSFULLY

📊 Test Summary:
   Total Duration: 2 minutes 34 seconds
   Total Steps: 18
   Success Rate: 100% (18/18)
   
📈 Performance Metrics:
   File Upload: 45.3s (50MB → ~1.1MB/s)
   Authenticated Download: 12.4s (~4.0MB/s)  
   Anonymous Download: 15.2s (~3.3MB/s)
   Share Access Timing: 1,015ms (security compliant)
   
🔐 Security Validation:
   ✅ OPAQUE zero-knowledge authentication
   ✅ TOTP two-factor authentication  
   ✅ End-to-end file encryption
   ✅ Argon2id share password protection
   ✅ Timing protection (>900ms)
   ✅ Anonymous access privacy
   ✅ Perfect file integrity (3x verified)
   
🗄️ System Integration:
   ✅ Database operations (rqlite)
   ✅ Storage backend (MinIO S3)
   ✅ TLS certificate handling
   ✅ JWT token management
   ✅ Rate limiting validation
   
💾 File Operations Summary:
   Original file:         52,428,800 bytes
   Authenticated round-trip: PERFECT (100% integrity)
   Anonymous share access:   PERFECT (100% integrity)
   Total data transferred:   ~157MB (3x file size)

✨ ARKFILE SYSTEM VALIDATION: COMPLETE SUCCESS
Your secure file sharing system is fully operational and production-ready!

Cleanup completed - all test data removed
Test artifacts saved to: /tmp/arkfile-integration-test-20250806-081137/
```

### Configuration File Support
```yaml
# config/integration-test.yaml
server:
  url: "https://localhost:4443"
  tls_insecure: true
  
test:
  username: "integration.test.user.2025"
  email: "integration-test@example.com"  # Optional
  password: "IntegrationTestPassword123456789!"
  share_password: "TestSharePassword2025_SecureAndLong!"
  file_size: 52428800  # 50MB
  
database:
  url: "http://demo-user:TestPassword123_Secure@localhost:4001"
  
options:
  verbose: false
  cleanup_on_fail: true
  save_artifacts: true
  performance_mode: true
```

## File Structure

### Project Organization
```
scripts/testing/
├── test-complete-integration.go      # Main integration test
├── integration/                      # Support packages
│   ├── config.go                    # Configuration management
│   ├── client/                      # HTTP and database clients
│   │   ├── http.go                 # HTTP client implementation
│   │   └── database.go             # Database client implementation
│   ├── crypto/                      # Crypto operations
│   │   ├── encryption.go           # File encryption/decryption
│   │   ├── totp.go                 # TOTP generation
│   │   └── argon2.go               # Argon2id operations
│   ├── models/                      # Request/response models
│   │   ├── auth.go                 # Authentication models
│   │   ├── files.go                # File operation models
│   │   └── shares.go               # Share operation models
│   └── utils/                       # Utility functions
│       ├── logging.go              # Structured logging
│       ├── validation.go           # Response validation
│       └── cleanup.go              # Resource cleanup
└── go.mod                           # Go module definition
```

### Dependencies
```go
module arkfile-integration-test

go 1.21

require (
    github.com/pquerna/otp v1.4.0
    golang.org/x/crypto v0.17.0
    github.com/stretchr/testify v1.8.4
)
```

## Success Criteria & Validation

### Completion Criteria
1. **✅ All 18 steps complete without errors**
2. **✅ Triple file integrity verification passes**
3. **✅ Security measures validated (timing, rate limiting)**
4. **✅ Database operations successful**
5. **✅ Anonymous access working correctly**
6. **✅ Complete cleanup verification**

### Performance Benchmarks
- **File Upload**: < 60 seconds for 50MB
- **File Download**: < 20 seconds for 50MB  
- **Share Creation**: < 5 seconds
- **Anonymous Access**: 900ms - 1500ms (timing protection)
- **Total Test Duration**: < 5 minutes

### Security Validation
- **OPAQUE Authentication**: Zero password exposure
- **TOTP Verification**: Real 6-digit codes accepted
- **Encryption Round-trip**: Perfect integrity preservation  
- **Share Password Security**: Argon2id with 128MB memory requirement
- **Timing Protection**: Consistent >900ms response times
- **Anonymous Privacy**: No user information disclosure

### Integration Validation
- **Database Consistency**: All operations properly recorded/cleaned
- **Storage Backend**: MinIO objects created and deleted correctly
- **TLS Handling**: Self-signed certificates accepted in test mode
- **API Compatibility**: All endpoints responding as expected
- **Error Handling**: Graceful failure and cleanup on errors

## Next Steps for Implementation

### Ready for Development
This comprehensive planning document provides:

1. **✅ Complete technical specification**
2. **✅ Detailed implementation examples** 
3. **✅ Integration architecture**
4. **✅ Expected output format**
5. **✅ Success criteria definition**
6. **✅ Timeline and milestones**

### Implementation Priority
1. **Start with foundation** (HTTP client, config, basic structure)
2. **Implement authentication flow** (leverage existing auth patterns)
3. **Add file operations** (chunked upload/download)
4. **Complete share system** (anonymous access testing)
5. **Polish and validate** (error handling, edge cases)

### Estimated Development Time
- **Full implementation**: 5-7 days
- **Basic functionality**: 2-3 days  
- **Production ready**: 7-10 days

This Go-based integration test will provide **definitive validation** that your Phase 6F implementation is complete and production-ready, covering all critical workflows with real 50MB files and comprehensive security validation.
