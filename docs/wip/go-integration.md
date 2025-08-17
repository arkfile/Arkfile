# Arkfile Go Integration Test Framework

## Overview

This document outlines the implementation of `scripts/testing/integration-test.go` - a Go-based integration test framework that orchestrates existing Go tools (arkfile-client, arkfile-admin, cryptocli) to validate end-to-end workflows.

`NOTE: Complete go-utils-project.md before starting this project.`

**Core Philosophy**: Tool orchestration, not reimplementation. Execute existing binaries via `os/exec` to test real-world workflows that complement `test-app-curl.sh`.

## Project Structure

### File Location
```
scripts/testing/integration-test.go
```

### Execution Model
```bash
# From project root:
go run scripts/testing/integration-test.go full-suite
go run scripts/testing/integration-test.go auth-flow --verbose
go run scripts/testing/integration-test.go file-ops --performance
```

### Integration with Existing Workflow
```bash
sudo ./scripts/dev-reset.sh                                    # Reset environment  
./scripts/testing/test-app-curl.sh                             # API endpoint validation
go run scripts/testing/integration-test.go full-suite          # Tool orchestration validation
```

## Implementation Phases

### Phase 1: Core Infrastructure

**Goal**: Build foundation for tool orchestration and test management.

#### 1.1 Command Line Interface
```go
package main

import (
    "flag"
    "fmt"
    "os"
    "os/exec" 
    "path/filepath"
    "time"
)

const Usage = `integration-test - Go tool orchestration testing

USAGE:
    go run integration-test.go [global options] command [command options]

COMMANDS:
    full-suite      Run all 5 phases of integration testing
    env-check       Phase 1: Environment validation only
    auth-flow       Phase 2: Authentication workflow only
    file-ops        Phase 3: File operations workflow only
    share-ops       Phase 4: Share operations workflow only
    admin-ops       Phase 5: Admin operations workflow only

GLOBAL OPTIONS:
    --server-url URL     Server URL (default: https://localhost:4443)
    --verbose, -v        Verbose output with command details
    --performance        Enable performance timing and benchmarks
    --cleanup            Cleanup test files after completion
    --test-file-size     Size for test files (default: 100MB)
    --help, -h           Show help

EXAMPLES:
    go run integration-test.go full-suite --verbose
    go run integration-test.go file-ops --performance --test-file-size 50MB
`

type Config struct {
    ServerURL    string
    Verbose      bool
    Performance  bool
    Cleanup      bool
    TestFileSize string
    BaseDir      string
    TestUser     string
}

func main() {
    config := &Config{
        ServerURL:    "https://localhost:4443",
        TestFileSize: "100MB",
        BaseDir:      ".",
        TestUser:     "testuser",
    }
    
    // Parse command line arguments
    parseArgs(config)
    
    // Create integration suite
    suite := NewIntegrationSuite(config)
    
    // Execute requested command
    if err := suite.Run(); err != nil {
        fmt.Printf("❌ Integration testing failed: %v\n", err)
        os.Exit(1)
    }
    
    fmt.Printf("✅ Integration testing completed successfully\n")
}
```

#### 1.2 Tool Execution Framework
```go
type ExecResult struct {
    Stdout   string
    Stderr   string
    ExitCode int
    Duration time.Duration
}

type IntegrationSuite struct {
    config    *Config
    testDir   string
    startTime time.Time
    results   map[string]bool
}

func (s *IntegrationSuite) executeCommand(tool string, args ...string) (*ExecResult, error) {
    var binPath string
    switch tool {
    case "arkfile-client":
        binPath = "./cmd/arkfile-client/arkfile-client"
    case "arkfile-admin":
        binPath = "./cmd/arkfile-admin/arkfile-admin"
    case "cryptocli":
        binPath = "./cmd/cryptocli/cryptocli"
    default:
        return nil, fmt.Errorf("unknown tool: %s", tool)
    }
    
    startTime := time.Now()
    cmd := exec.Command(binPath, args...)
    cmd.Dir = s.config.BaseDir
    
    // Set environment
    cmd.Env = append(os.Environ(),
        "ARKFILE_SERVER_URL="+s.config.ServerURL,
        "ARKFILE_VERBOSE="+fmt.Sprintf("%v", s.config.Verbose),
    )
    
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr
    
    if s.config.Verbose {
        fmt.Printf("🔧 Executing: %s %s\n", binPath, strings.Join(args, " "))
    }
    
    err := cmd.Run()
    duration := time.Since(startTime)
    
    result := &ExecResult{
        Stdout:   stdout.String(),
        Stderr:   stderr.String(),
        ExitCode: 0,
        Duration: duration,
    }
    
    if err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            result.ExitCode = exitError.ExitCode()
        }
    }
    
    if s.config.Performance {
        fmt.Printf("⏱️  Command completed in: %v\n", duration)
    }
    
    return result, err
}

func (s *IntegrationSuite) runTest(name string, testFunc func() error) {
    fmt.Printf("🧪 Running: %s\n", name)
    
    if err := testFunc(); err != nil {
        fmt.Printf("❌ FAILED: %s - %v\n", name, err)
        s.results[name] = false
        return
    }
    
    fmt.Printf("✅ PASSED: %s\n", name)
    s.results[name] = true
}
```

### Phase 2: Environment Validation (Test Phase 1)

**Goal**: Verify all tools are available and server is accessible.

```go
func (s *IntegrationSuite) runEnvironmentValidation() error {
    fmt.Printf("📋 Phase 1: Environment Validation\n")
    
    s.runTest("Tool Availability - arkfile-client", func() error {
        result, err := s.executeCommand("arkfile-client", "--help")
        if err != nil {
            return fmt.Errorf("arkfile-client not available: %v", err)
        }
        if !strings.Contains(result.Stdout, "arkfile-client - Secure file sharing client") {
            return fmt.Errorf("arkfile-client help output invalid")
        }
        return nil
    })
    
    s.runTest("Tool Availability - arkfile-admin", func() error {
        result, err := s.executeCommand("arkfile-admin", "--version")
        if err != nil {
            return fmt.Errorf("arkfile-admin not available: %v", err)
        }
        if !strings.Contains(result.Stdout, "1.0.0") {
            return fmt.Errorf("arkfile-admin version output invalid")
        }
        return nil
    })
    
    s.runTest("Tool Availability - cryptocli", func() error {
        result, err := s.executeCommand("cryptocli", "--help")
        if err != nil {
            return fmt.Errorf("cryptocli not available: %v", err)
        }
        return nil
    })
    
    s.runTest("Server Connectivity", func() error {
        // Test basic HTTPS connectivity
        client := &http.Client{
            Timeout: 10 * time.Second,
            Transport: &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
            },
        }
        
        resp, err := client.Get(s.config.ServerURL + "/")
        if err != nil {
            return fmt.Errorf("server not accessible: %v", err)
        }
        defer resp.Body.Close()
        
        if resp.StatusCode != 200 {
            return fmt.Errorf("server returned status %d", resp.StatusCode)
        }
        
        return nil
    })
    
    fmt.Printf("✅ Environment validation completed\n\n")
    return nil
}
```

### Phase 3: Authentication Workflow (Test Phase 2)

**Goal**: Test authentication and session management across tools.

```go
func (s *IntegrationSuite) runAuthenticationWorkflow() error {
    fmt.Printf("📋 Phase 2: Authentication Workflow\n")
    
    var opaqueExportKey string
    var sessionToken string
    
    s.runTest("User Authentication", func() error {
        result, err := s.executeCommand("arkfile-client", "login", "--username", s.config.TestUser)
        if err != nil {
            return fmt.Errorf("login failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        // Parse login output for session data
        if strings.Contains(result.Stdout, "Login successful") {
            sessionToken = extractSessionToken(result.Stdout)
            opaqueExportKey = extractOPAQUEExportKey(result.Stdout)
            
            if opaqueExportKey == "" {
                return fmt.Errorf("OPAQUE export key not found in login output")
            }
            
            // Store for later phases
            s.setSessionData("opaque_export_key", opaqueExportKey)
            s.setSessionData("session_token", sessionToken)
            
            return nil
        }
        
        return fmt.Errorf("login output invalid: %s", result.Stdout)
    })
    
    s.runTest("Session Persistence", func() error {
        // Test that session persists across command invocations
        result, err := s.executeCommand("arkfile-client", "list-files")
        if err != nil {
            return fmt.Errorf("session not persisting: %v", err)
        }
        
        if strings.Contains(result.Stderr, "authentication required") {
            return fmt.Errorf("session not properly persisted")
        }
        
        return nil
    })
    
    s.runTest("OPAQUE Export Key Validation", func() error {
        // Verify export key format and length
        if len(opaqueExportKey) < 64 {
            return fmt.Errorf("OPAQUE export key too short: %d bytes", len(opaqueExportKey))
        }
        
        // Test key with cryptocli
        result, err := s.executeCommand("cryptocli", "validate-export-key", "--key", opaqueExportKey)
        if err != nil {
            // If validate command doesn't exist, just check format
            if !isValidHexString(opaqueExportKey) {
                return fmt.Errorf("OPAQUE export key not valid hex: %s", opaqueExportKey[:20]+"...")
            }
        }
        
        return nil
    })
    
    fmt.Printf("✅ Authentication workflow completed\n\n")
    return nil
}

// Helper functions
func extractSessionToken(output string) string {
    // Parse session token from arkfile-client output
    lines := strings.Split(output, "\n")
    for _, line := range lines {
        if strings.Contains(line, "Session token:") {
            parts := strings.Split(line, ":")
            if len(parts) > 1 {
                return strings.TrimSpace(parts[1])
            }
        }
    }
    return ""
}

func extractOPAQUEExportKey(output string) string {
    // Parse OPAQUE export key from arkfile-client output
    lines := strings.Split(output, "\n")
    for _, line := range lines {
        if strings.Contains(line, "OPAQUE export key:") {
            parts := strings.Split(line, ":")
            if len(parts) > 1 {
                return strings.TrimSpace(parts[1])
            }
        }
    }
    return ""
}
```

### Phase 4: File Operations Workflow (Test Phase 3)

**Goal**: Test complete file encrypt→upload→download→decrypt cycle.

```go
func (s *IntegrationSuite) runFileOperationsWorkflow() error {
    fmt.Printf("📋 Phase 3: File Operations Workflow\n")
    
    var testFileName = "integration-test.dat"
    var encryptedFileName = "integration-test.enc"
    var downloadedFileName = "integration-test-downloaded.enc"
    var decryptedFileName = "integration-test-decrypted.dat"
    var originalHash string
    var fileID string
    
    s.runTest("Test File Generation", func() error {
        result, err := s.executeCommand("cryptocli", "generate-test-file",
            "--size", s.config.TestFileSize,
            "--pattern", "sequential",
            "--output", testFileName,
            "--hash-output", testFileName+".hash")
        if err != nil {
            return fmt.Errorf("test file generation failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        // Read original file hash
        hashBytes, err := os.ReadFile(testFileName + ".hash")
        if err != nil {
            return fmt.Errorf("failed to read hash file: %v", err)
        }
        originalHash = strings.TrimSpace(string(hashBytes))
        
        return nil
    })
    
    s.runTest("File Encryption with OPAQUE Keys", func() error {
        opaqueKey := s.getSessionData("opaque_export_key")
        if opaqueKey == "" {
            return fmt.Errorf("OPAQUE export key not available")
        }
        
        result, err := s.executeCommand("cryptocli", "encrypt-file-opaque",
            "--input", testFileName,
            "--output", encryptedFileName,
            "--export-key", opaqueKey,
            "--username", s.config.TestUser,
            "--file-id", testFileName)
        if err != nil {
            return fmt.Errorf("file encryption failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        // Verify encrypted file exists and is larger than original
        if !fileExists(encryptedFileName) {
            return fmt.Errorf("encrypted file not created")
        }
        
        return nil
    })
    
    s.runTest("Chunked File Upload", func() error {
        result, err := s.executeCommand("arkfile-client", "upload",
            "--file", encryptedFileName,
            "--description", "Integration test file")
        if err != nil {
            return fmt.Errorf("file upload failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        // Parse file ID from upload output
        fileID = extractFileID(result.Stdout)
        if fileID == "" {
            return fmt.Errorf("file ID not found in upload output")
        }
        
        s.setSessionData("file_id", fileID)
        
        return nil
    })
    
    s.runTest("File Download", func() error {
        result, err := s.executeCommand("arkfile-client", "download",
            "--file-id", fileID,
            "--output", downloadedFileName)
        if err != nil {
            return fmt.Errorf("file download failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        if !fileExists(downloadedFileName) {
            return fmt.Errorf("downloaded file not created")
        }
        
        return nil
    })
    
    s.runTest("File Decryption and Integrity", func() error {
        opaqueKey := s.getSessionData("opaque_export_key")
        
        result, err := s.executeCommand("cryptocli", "decrypt-file-opaque",
            "--input", downloadedFileName,
            "--output", decryptedFileName,
            "--export-key", opaqueKey,
            "--username", s.config.TestUser)
        if err != nil {
            return fmt.Errorf("file decryption failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        // Verify file integrity through hash comparison
        finalHash, err := calculateFileHash(decryptedFileName)
        if err != nil {
            return fmt.Errorf("failed to calculate final hash: %v", err)
        }
        
        if finalHash != originalHash {
            return fmt.Errorf("file integrity check failed: original=%s, final=%s", 
                originalHash[:16]+"...", finalHash[:16]+"...")
        }
        
        fmt.Printf("✅ Perfect file integrity maintained through complete cycle\n")
        return nil
    })
    
    fmt.Printf("✅ File operations workflow completed\n\n")
    return nil
}
```

### Phase 5: Share Operations Workflow (Test Phase 4)

**Goal**: Test anonymous sharing with proper session isolation and security validation.

```go
func (s *IntegrationSuite) runShareOperationsWorkflow() error {
    fmt.Printf("📋 Phase 4: Share Operations Workflow\n")
    
    var shareURL string
    var sharePassword = "integration-test-share-pass"
    var sharedFileName = "integration-test-shared.dat"
    var originalFileHash string
    
    s.runTest("Share Creation (Authenticated User)", func() error {
        fileID := s.getSessionData("file_id")
        if fileID == "" {
            return fmt.Errorf("file ID not available from previous phase")
        }
        
        // Capture original file hash for later verification
        if hashData := s.getSessionData("original_hash"); hashData != "" {
            originalFileHash = hashData
        } else {
            // Calculate hash from decrypted file if not stored
            hash, err := calculateFileHash("integration-test-decrypted.dat")
            if err != nil {
                return fmt.Errorf("failed to get original file hash: %v", err)
            }
            originalFileHash = hash
        }
        
        result, err := s.executeCommand("arkfile-client", "create-share",
            "--file-id", fileID,
            "--password", sharePassword,
            "--description", "Integration test share")
        if err != nil {
            return fmt.Errorf("share creation failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        // Parse share URL from output
        shareURL = extractShareURL(result.Stdout)
        if shareURL == "" {
            return fmt.Errorf("share URL not found in output")
        }
        
        s.setSessionData("share_url", shareURL)
        s.setSessionData("share_password", sharePassword)
        s.setSessionData("original_file_hash", originalFileHash)
        
        fmt.Printf("✅ Share created successfully with URL: %s\n", shareURL[:50]+"...")
        
        return nil
    })
    
    s.runTest("User Logout (Session Isolation)", func() error {
        // Critical: Log out the authenticated user to test anonymous access
        result, err := s.executeCommand("arkfile-client", "logout")
        if err != nil {
            return fmt.Errorf("user logout failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        if !strings.Contains(result.Stdout, "Logout successful") {
            return fmt.Errorf("logout output invalid: %s", result.Stdout)
        }
        
        // Verify session is actually cleared
        listResult, listErr := s.executeCommand("arkfile-client", "list-files")
        if listErr == nil || !strings.Contains(listResult.Stderr, "authentication required") {
            return fmt.Errorf("session not properly cleared after logout")
        }
        
        fmt.Printf("✅ User logged out, session cleared for anonymous testing\n")
        
        return nil
    })
    
    s.runTest("Anonymous Share Access", func() error {
        // Extract share data from URL
        shareSalt, shareContent, err := parseShareURL(shareURL)
        if err != nil {
            return fmt.Errorf("failed to parse share URL: %v", err)
        }
        
        // Use cryptocli to decrypt as anonymous visitor with only share URL + password
        result, err := s.executeCommand("cryptocli", "decrypt-share-file",
            "--input", shareContent,
            "--output", sharedFileName,
            "--share-password", sharePassword,
            "--salt", shareSalt)
        if err != nil {
            return fmt.Errorf("anonymous share decryption failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        if !fileExists(sharedFileName) {
            return fmt.Errorf("shared file not created by anonymous access")
        }
        
        fmt.Printf("✅ Anonymous visitor successfully accessed and decrypted shared file\n")
        
        return nil
    })
    
    s.runTest("Anonymous Share Integrity Verification", func() error {
        // Second SHA256 verification: compare anonymously decrypted file against original
        sharedHash, err := calculateFileHash(sharedFileName)
        if err != nil {
            return fmt.Errorf("failed to calculate anonymously decrypted file hash: %v", err)
        }
        
        originalHash := s.getSessionData("original_file_hash")
        if originalHash == "" {
            return fmt.Errorf("original file hash not available for comparison")
        }
        
        if sharedHash != originalHash {
            return fmt.Errorf("anonymous share integrity check FAILED: original=%s, anonymous=%s", 
                originalHash[:16]+"...", sharedHash[:16]+"...")
        }
        
        fmt.Printf("✅ Perfect integrity: Anonymous decryption matches original file\n")
        fmt.Printf("   Original hash:  %s\n", originalHash[:32]+"...")
        fmt.Printf("   Anonymous hash: %s\n", sharedHash[:32]+"...")
        
        return nil
    })
    
    s.runTest("Session Isolation Validation", func() error {
        // Verify that anonymous access truly worked without authentication
        // Try to access authenticated endpoints (should fail)
        result, err := s.executeCommand("arkfile-client", "list-files")
        if err == nil {
            return fmt.Errorf("authenticated endpoint accessible without login - session isolation failed")
        }
        
        if !strings.Contains(result.Stderr, "authentication required") {
            return fmt.Errorf("unexpected error from authenticated endpoint: %s", result.Stderr)
        }
        
        fmt.Printf("✅ Session isolation confirmed: Anonymous access only, no authenticated access\n")
        
        return nil
    })
    
    fmt.Printf("✅ Share operations workflow completed with proper anonymous access testing\n\n")
    return nil
}
```

### Phase 6: Admin Operations Workflow (Test Phase 5)

**Goal**: Test administrative tools and user management.

```go
func (s *IntegrationSuite) runAdminOperationsWorkflow() error {
    fmt.Printf("📋 Phase 5: Admin Operations Workflow\n")
    
    s.runTest("Admin Authentication", func() error {
        result, err := s.executeCommand("arkfile-admin", "login", "--username", "admin")
        if err != nil {
            return fmt.Errorf("admin login failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        if !strings.Contains(result.Stdout, "Admin login successful") {
            return fmt.Errorf("admin login output invalid")
        }
        
        return nil
    })
    
    s.runTest("User Management - List Users", func() error {
        result, err := s.executeCommand("arkfile-admin", "list-users")
        if err != nil {
            return fmt.Errorf("list users failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        if !strings.Contains(result.Stdout, s.config.TestUser) {
            return fmt.Errorf("test user not found in user list")
        }
        
        return nil
    })
    
    s.runTest("User Management - Storage Management", func() error {
        result, err := s.executeCommand("arkfile-admin", "set-storage",
            "--username", s.config.TestUser,
            "--credits", "2000")
        if err != nil {
            return fmt.Errorf("set storage failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        return nil
    })
    
    s.runTest("System Operations - Health Check", func() error {
        result, err := s.executeCommand("arkfile-admin", "health-check")
        if err != nil {
            // Expected if server endpoints not implemented yet
            if strings.Contains(result.Stderr, "server endpoint not yet available") {
                fmt.Printf("ℹ️  Health check endpoint not yet implemented (expected)\n")
                return nil
            }
            return fmt.Errorf("health check failed: %v\nStderr: %s", err, result.Stderr)
        }
        
        return nil
    })
    
    fmt.Printf("✅ Admin operations workflow completed\n\n")
    return nil
}
```

### Phase 7: Performance and Integration (Final Validation)

**Goal**: End-to-end validation and performance benchmarking.

```go
func (s *IntegrationSuite) runPerformanceValidation() error {
    if !s.config.Performance {
        return nil
    }
    
    fmt.Printf("📋 Performance Benchmarking\n")
    
    // Benchmark file operations with different sizes
    sizes := []string{"1MB", "10MB", "50MB"}
    
    for _, size := range sizes {
        s.runTest(fmt.Sprintf("Performance - %s File Operations", size), func() error {
            startTime := time.Now()
            
            // Complete file cycle with timing
            if err := s.benchmarkFileCycle(size); err != nil {
                return err
            }
            
            duration := time.Since(startTime)
            fmt.Printf("📊 %s file cycle completed in: %v\n", size, duration)
            
            return nil
        })
    }
    
    return nil
}

func (s *IntegrationSuite) cleanup() error {
    if !s.config.Cleanup {
        return nil
    }
    
    fmt.Printf("🧹 Cleaning up test files\n")
    
    testFiles := []string{
        "integration-test.dat",
        "integration-test.enc", 
        "integration-test-downloaded.enc",
        "integration-test-decrypted.dat",
        "integration-test-shared.dat",
        "integration-test.dat.hash",
    }
    
    for _, file := range testFiles {
        if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
            fmt.Printf("⚠️  Failed to remove %s: %v\n", file, err)
        }
    }
    
    return nil
}
```

## Success Criteria

### Functional Requirements
- ✅ All 5 test phases pass with existing Go tools
- ✅ File integrity maintained through complete encrypt→upload→download→decrypt cycle
- ✅ OPAQUE export keys work seamlessly between arkfile-client and cryptocli
- ✅ Session management works correctly across tool invocations
- ✅ Share operations produce correct decrypted files
- ✅ Admin operations integrate correctly with user workflows

### Performance Requirements
- ✅ 100MB file operations complete within reasonable time (<2 minutes)
- ✅ Authentication workflow completes quickly (<10 seconds)
- ✅ Memory usage stays reasonable during large file operations
- ✅ Performance meets or exceeds test-app-curl.sh baseline

### Integration Requirements
- ✅ Clean integration with existing `dev-reset.sh` + `test-app-curl.sh` workflow
- ✅ Proper error handling and cleanup on failures
- ✅ Structured output with clear pass/fail reporting
- ✅ Zero regressions in existing functionality

## Usage Examples

### Basic Testing
```bash
# Run all integration tests
go run scripts/testing/integration-test.go full-suite

# Run specific phase with verbose output
go run scripts/testing/integration-test.go file-ops --verbose

# Run with performance benchmarking
go run scripts/testing/integration-test.go full-suite --performance --cleanup
```

### Development Workflow
```bash
# Complete development testing cycle
sudo ./scripts/dev-reset.sh                           # Reset environment
./scripts/testing/test-app-curl.sh                    # API endpoint tests
go run scripts/testing/integration-test.go full-suite # Tool integration tests
```

### Troubleshooting
```bash
# Test environment only
go run scripts/testing/integration-test.go env-check --verbose

# Test specific workflow
go run scripts/testing/integration-test.go auth-flow --verbose
```

## Implementation Status

**Phase 1: Foundation** - ⏳ Ready to implement
**Phase 2: Environment** - ⏳ Ready to implement  
**Phase 3: Authentication** - ⏳ Ready to implement
**Phase 4: File Operations** - ⏳ Ready to implement
**Phase 5: Share Operations** - ⏳ Ready to implement
**Phase 6: Admin Operations** - ⏳ Ready to implement
**Phase 7: Performance** - ⏳ Ready to implement

**Estimated Implementation Time**: 13-16 hours total

This framework provides comprehensive testing of the Go tool ecosystem while maintaining clean separation from API endpoint testing handled by `test-app-curl.sh`.
