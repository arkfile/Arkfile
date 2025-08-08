# Test App Refactoring: Secure Admin API Implementation

## Project Overview

This document outlines the complete refactoring of the `test-app-curl.sh` script to eliminate direct database access and implement a secure admin API system. The project addresses connection consistency issues and security concerns while maintaining comprehensive testing capabilities.

## Problem Statement

### Current Issues

1. **Connection Inconsistency**: Test script uses direct HTTP calls to rqlite (`http://localhost:4001/db/execute`) while the application uses Go's `database/sql` connection pool, causing state inconsistencies.

2. **Direct Database Manipulation**: Test script performs raw SQL operations on 9+ database tables, bypassing application logic and security controls.

3. **"Username already registered" Bug**: Cleanup shows `users(0)` (no users exist) but registration fails because different connection methods see different database states.

4. **Security Risk**: Direct database access bypasses authentication, authorization, and audit logging.

### Current Direct Database Access Cases

#### Phase 1 & 10: Cleanup Operations
```bash
execute_db_query "DELETE FROM users WHERE username = '$TEST_USERNAME'"
execute_db_query "DELETE FROM opaque_user_data WHERE username = '$TEST_USERNAME'" 
execute_db_query "DELETE FROM opaque_password_records WHERE record_identifier = '$TEST_USERNAME'"
execute_db_query "DELETE FROM user_totp WHERE username = '$TEST_USERNAME'"
execute_db_query "DELETE FROM refresh_tokens WHERE username = '$TEST_USERNAME'"
execute_db_query "DELETE FROM totp_usage_log WHERE username = '$TEST_USERNAME'"
execute_db_query "DELETE FROM totp_backup_usage WHERE username = '$TEST_USERNAME'"
execute_db_query "DELETE FROM revoked_tokens WHERE username = '$TEST_USERNAME'"
execute_db_query "DELETE FROM user_activity WHERE username = '$TEST_USERNAME'"
```

#### Phase 3: User Approval
```bash
execute_db_query "UPDATE users SET is_approved = 1, approved_by = 'auth-test', approved_at = CURRENT_TIMESTAMP WHERE username = '$TEST_USERNAME'"
```

#### Verification Queries (Multiple phases)
```bash
query_db "SELECT COUNT(*) FROM users WHERE username = '$TEST_USERNAME'"
query_db "SELECT username, is_approved FROM users WHERE username = '$TEST_USERNAME'"
query_db "SELECT enabled, setup_completed FROM user_totp WHERE username = '$TEST_USERNAME'"
```

#### Manual TOTP Override (Fallback)
```bash
execute_db_query "UPDATE user_totp SET enabled = 1, setup_completed = 1 WHERE username = '$TEST_USERNAME'"
```

## Solution Architecture

### Core Principle
Replace all direct database access with secure admin API endpoints that use the same connection pool and transaction scope as the main application.

### New Secure Admin API Endpoints

#### 1. `POST /api/admin/test-user/cleanup`
**Purpose**: Clean up all test user data across all tables
**Request**: 
```json
{
  "username": "arkfile-dev-test-user",
  "confirm": true
}
```
**Response**:
```json
{
  "success": true,
  "tables_cleaned": {
    "users": 1,
    "opaque_user_data": 1,
    "opaque_password_records": 2,
    "user_totp": 1,
    "refresh_tokens": 3,
    "totp_usage_log": 0,
    "totp_backup_usage": 0,
    "revoked_tokens": 0,
    "user_activity": 5
  },
  "total_rows_affected": 13
}
```

#### 2. `POST /api/admin/user/{username}/approve`
**Purpose**: Approve a specific user for testing
**Request**:
```json
{
  "approved_by": "arkfile-dev-admin"
}
```
**Response**:
```json
{
  "success": true,
  "username": "arkfile-dev-test-user",
  "is_approved": true,
  "approved_by": "arkfile-dev-admin",
  "approved_at": "2025-08-08T10:30:00Z"
}
```

#### 3. `GET /api/admin/user/{username}/status`
**Purpose**: Get comprehensive user status for verification
**Response**:
```json
{
  "exists": true,
  "username": "arkfile-dev-test-user",
  "is_approved": true,
  "is_admin": false,
  "totp": {
    "enabled": true,
    "setup_completed": true
  },
  "opaque": {
    "has_account": true,
    "records_count": 1
  },
  "tokens": {
    "active_refresh_tokens": 1,
    "revoked_tokens": 0
  }
}
```

#### 4. ~~Force TOTP Setup~~ **ELIMINATED**
**Rationale**: With proper API-based approach, the normal TOTP setup flow should work correctly without manual database overrides.

### Security Framework

#### Multi-Layer Access Control

1. **Admin User Validation**: Check `user.IsAdmin` flag from JWT token
2. **Localhost Restriction**: Validate request originates from `127.0.0.1` or `::1`
3. **Special Admin Token**: Require admin-level JWT token with admin privileges
4. **Rate Limiting**: Aggressive rate limiting (e.g., 10 requests/minute per IP)
5. **Audit Logging**: Log all admin operations to security audit trail

#### Security Implementation
```go
func AdminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        // 1. Localhost only
        if !isLocalhostRequest(c) {
            return echo.NewHTTPError(http.StatusForbidden, "Admin endpoints only available from localhost")
        }
        
        // 2. Valid admin JWT
        username := auth.GetUsernameFromToken(c)
        if username == "" {
            return echo.NewHTTPError(http.StatusUnauthorized, "Admin authentication required")
        }
        
        // 3. Admin privileges
        user, err := models.GetUserByUsername(database.DB, username)
        if err != nil || !user.HasAdminPrivileges() {
            return echo.NewHTTPError(http.StatusForbidden, "Admin privileges required")
        }
        
        // 4. Block dev admin accounts in production
        if isProductionEnvironment() && isDevAdminAccount(username) {
            logging.ErrorLogger.Printf("SECURITY: Blocked dev admin account '%s' in production", username)
            return echo.NewHTTPError(http.StatusForbidden, "Dev admin accounts blocked in production")
        }
        
        // 5. Audit log
        logging.InfoLogger.Printf("Admin API access: user=%s endpoint=%s ip=%s", username, c.Request().URL.Path, c.RealIP())
        
        return next(c)
    }
}
```

### Production Safeguards

#### Multi-Layer Defense Against Dev Admin Accounts in Production

##### 1. Runtime Environment Detection
```go
func isProductionEnvironment() bool {
    envVars := []string{"ENVIRONMENT", "NODE_ENV", "GO_ENV"}
    
    for _, envVar := range envVars {
        value := strings.ToLower(os.Getenv(envVar))
        if value == "production" || value == "prod" {
            return true
        }
    }
    
    return isDomainProduction() || isPortProduction()
}

func isDomainProduction() bool {
    // Check if running on production domain
    hostname, _ := os.Hostname()
    return strings.Contains(hostname, "prod") || 
           strings.Contains(hostname, "production")
}

func isPortProduction() bool {
    // Production typically runs on port 443/80
    port := os.Getenv("PORT")
    return port == "443" || port == "80"
}
```

##### 2. Dev Admin Account Blocking
**Location**: `models/user.go` in `isAdminUsername()` function
```go
func isAdminUsername(username string) bool {
    // Block dev admin accounts in production
    if isProductionEnvironment() {
        devAdminAccounts := []string{
            "arkfile-dev-admin", 
            "admin.dev.user", 
            "admin.demo.user"
        }
        for _, devAdmin := range devAdminAccounts {
            if username == devAdmin {
                logging.ErrorLogger.Printf("SECURITY WARNING: Blocked dev admin account '%s' in production", username)
                return false
            }
        }
    }
    
    // Normal admin username check
    adminUsernames := strings.Split(getEnvOrDefault("ADMIN_USERNAMES", ""), ",")
    for _, adminUsername := range adminUsernames {
        if strings.TrimSpace(adminUsername) == username {
            return true
        }
    }
    return false
}
```

##### 3. Startup Validation
**Location**: Application startup in `config/config.go`
```go
func ValidateProductionConfig() error {
    if isProductionEnvironment() {
        adminUsernames := os.Getenv("ADMIN_USERNAMES")
        devAccounts := []string{"arkfile-dev-admin", "admin.dev.user", "admin.demo.user"}
        
        for _, devAccount := range devAccounts {
            if strings.Contains(adminUsernames, devAccount) {
                return fmt.Errorf("FATAL: Dev admin account '%s' found in production ADMIN_USERNAMES - deployment blocked", devAccount)
            }
        }
    }
    return nil
}
```

##### 4. Deployment Script Safeguards
**Location**: `scripts/setup/deploy.sh`
```bash
#!/bin/bash
# Production deployment safeguards

# Check for dev admin accounts
if echo "$ADMIN_USERNAMES" | grep -E "(arkfile-dev-admin|admin\.dev\.user|admin\.demo\.user)"; then
    echo "ERROR: Dev admin accounts found in ADMIN_USERNAMES:"
    echo "$ADMIN_USERNAMES"
    echo "Remove dev accounts before production deployment!"
    exit 1
fi

echo "✅ Admin configuration validated for production"
```

##### 5. Environment Variable Template
**Location**: `.env.example`
```bash
# ============================================================================
# ADMIN CONFIGURATION
# ============================================================================

# SECURITY WARNING: These are DEV-ONLY admin accounts!
# NEVER use arkfile-dev-admin, admin.dev.user, or admin.demo.user in production!

# For development:
# ADMIN_USERNAMES=arkfile-dev-admin

# For production (replace with your actual admin usernames):
ADMIN_USERNAMES=your-production-admin-username,second-admin-username

# The application will BLOCK dev admin accounts if ENVIRONMENT=production
ENVIRONMENT=development
```

##### 6. Documentation Safeguards
**Location**: `docs/setup.md`
```markdown
## ⚠️ CRITICAL PRODUCTION SECURITY NOTICE

### Dev Admin Accounts
The following accounts are **DEVELOPMENT ONLY** and are automatically blocked in production:
- `arkfile-dev-admin`
- `admin.dev.user` 
- `admin.demo.user`

### Production Deployment Checklist
- [ ] Set `ENVIRONMENT=production`
- [ ] Update `ADMIN_USERNAMES` with production admin accounts only
- [ ] Remove all dev admin accounts from environment variables
- [ ] Verify deployment scripts pass admin validation
- [ ] Test admin functionality with production accounts
```

### User Naming Convention

#### Updated Names
- **Admin User**: `arkfile-dev-admin` (was `arkfile-test-admin`)
- **Test User**: `arkfile-dev-test-user` (was `auth-test-user-12345`)

#### Rationale
- Clear "dev" prefix indicates development/testing usage
- Consistent naming convention across the project
- Easier to identify and block in production environments

### Pre-Approved Admin Account System

#### Implementation in `scripts/dev-reset.sh`
```bash
#!/bin/bash

# Admin Configuration - DEV ONLY
ADMIN_USERNAMES=arkfile-dev-admin

# Ensure dev admin is created and approved during setup
create_dev_admin_user() {
    echo "Creating development admin user: arkfile-dev-admin"
    
    # This would integrate with the existing user creation process
    # The admin user gets auto-approved due to being in ADMIN_USERNAMES
}

export ADMIN_USERNAMES
```

#### Integration with Test Script
The test script will authenticate as `arkfile-dev-admin` to perform administrative operations via the new API endpoints.

## Implementation Plan

### Phase 1: Foundation (Security & Environment Detection)
**Files to create/modify**:
- `models/user.go`: Add production detection and dev admin blocking
- `config/config.go`: Add startup validation
- `handlers/middleware.go`: Create admin middleware
- `.env.example`: Update with security warnings

**Deliverables**:
- Production environment detection working
- Dev admin accounts blocked in production
- Admin middleware enforcing security policies
- Startup validation preventing prod deployment with dev accounts

### Phase 2: Admin API Endpoints
**Files to create/modify**:
- `handlers/admin.go`: New admin API handlers
- `handlers/route_config.go`: Register admin routes
- `models/admin.go`: Admin-specific database operations

**Deliverables**:
- All 3 admin endpoints implemented and tested
- Comprehensive error handling and logging
- API documentation and examples
- Unit tests for admin endpoints

### Phase 3: Script Updates
**Files to modify**:
- `scripts/dev-reset.sh`: Update `ADMIN_USERNAMES=arkfile-dev-admin`
- `scripts/testing/test-app-curl.sh`: Replace direct DB calls with API calls
- `scripts/testing/test-app-curl.sh`: Update `TEST_USERNAME=arkfile-dev-test-user`

**Deliverables**:
- Test script uses admin APIs instead of direct database access
- Admin user creation integrated into setup process
- All test functionality preserved with new approach

### Phase 4: Production Safeguards
**Files to create/modify**:
- `scripts/setup/deploy.sh`: Add production deployment validation
- `docs/setup.md`: Add production security warnings
- `scripts/quick-start.sh`: Update for consistency

**Deliverables**:
- Deployment scripts validate admin configuration
- Documentation clearly separates dev vs production setup
- Multiple layers of protection against dev account usage in production

### Phase 5: Testing & Validation
**Files to test**:
- Full end-to-end test with new admin API approach
- Production deployment simulation with safeguard testing
- Performance validation of API vs direct database access

**Deliverables**:
- Test suite passing with new admin API system
- Performance benchmarks showing no significant degradation
- Security validation of all admin endpoints
- Production deployment process tested and documented

## File Changes Summary

### New Files
- `handlers/admin.go`: Admin API endpoint implementations
- `models/admin.go`: Admin-specific database operations
- `utils/environment.go`: Production environment detection
- `scripts/setup/deploy.sh`: Production deployment validation

### Modified Files
- `models/user.go`: Add production safeguards and dev admin blocking
- `config/config.go`: Add startup validation
- `handlers/middleware.go`: Add admin middleware
- `handlers/route_config.go`: Register admin routes
- `scripts/dev-reset.sh`: Update admin usernames
- `scripts/testing/test-app-curl.sh`: Replace DB calls with API calls
- `.env.example`: Add security warnings
- `docs/setup.md`: Add production security documentation

## Benefits

### Technical Benefits
1. **Connection Consistency**: All operations use the same database connection pool as the main application
2. **Transaction Integrity**: Admin operations participate in the same transaction scopes
3. **Error Handling**: Consistent error handling and logging across all operations
4. **Performance**: No additional database connections or connection pool overhead

### Security Benefits
1. **Authentication**: All admin operations require proper authentication
2. **Authorization**: Proper admin privilege validation for all operations
3. **Audit Trail**: Complete logging of all administrative actions
4. **Production Protection**: Multiple layers prevent dev accounts in production
5. **Principle of Least Privilege**: Localhost-only access for admin endpoints

### Maintenance Benefits
1. **Schema Independence**: Changes to database schema automatically reflected in APIs
2. **Code Reuse**: Admin operations reuse existing model methods and validation
3. **Testing**: Admin endpoints can be unit tested like any other API
4. **Documentation**: Self-documenting through OpenAPI/Swagger integration

## Testing Strategy

### Unit Tests
- Admin middleware security validation
- Production environment detection logic
- Dev admin account blocking functionality
- Individual admin endpoint functionality

### Integration Tests
- Full admin authentication flow
- Database operations through admin APIs
- Error handling and edge cases
- Production safeguard validation

### End-to-End Tests
- Complete test-app-curl.sh execution with new admin APIs
- Production deployment simulation
- Security penetration testing of admin endpoints

## Migration Timeline

**Week 1**: Phase 1 (Foundation)
**Week 2**: Phase 2 (Admin APIs) 
**Week 3**: Phase 3 (Script Updates)
**Week 4**: Phase 4 (Production Safeguards)
**Week 5**: Phase 5 (Testing & Validation)

## Success Criteria

1. ✅ **No Direct Database Access**: Test script uses only admin APIs
2. ✅ **Connection Consistency**: "Username already registered" bug resolved
3. ✅ **Security Compliance**: All admin operations properly authenticated and authorized
4. ✅ **Production Safety**: Dev admin accounts cannot be used in production
5. ✅ **Functionality Preserved**: All existing test capabilities maintained
6. ✅ **Performance**: No significant performance degradation
7. ✅ **Documentation**: Clear separation between dev and production procedures

## Risk Mitigation

### High Risk: Production Security
**Mitigation**: Multiple independent layers of protection against dev admin accounts

### Medium Risk: API Performance
**Mitigation**: Performance benchmarking and optimization of admin endpoints

### Low Risk: Test Functionality
**Mitigation**: Comprehensive testing to ensure all current test scenarios work with new approach

---

*This document serves as the complete specification for refactoring the test-app-curl.sh system to use secure admin APIs instead of direct database access.*
