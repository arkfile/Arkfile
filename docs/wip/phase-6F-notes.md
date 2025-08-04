# Phase 6F Development Reset & Deployment Notes

## Purpose & Context

This document tracks the development of an improved dev-reset workflow and database schema consolidation for the Arkfile project during Phase 6F implementation. The primary purpose is to create a reliable deployment and testing environment that will validate the complete Phase 6F functionality when it becomes fully operational.

## Dev-Reset Script Improvements

### Schema Consolidation Implementation

**Problem Addressed**: The application previously used separate schema files (`schema_extensions.sql` and `schema_rate_limiting.sql`) which caused complexity in database setup scripts and parsing issues.

**Solution Implemented**:
- ✅ **Consolidated single schema file**: Merged all schema components into `database/schema_extensions.sql`
- ✅ **Removed separate rate limiting schema**: Deleted `database/schema_rate_limiting.sql` 
- ✅ **Updated database.go**: Modified `ApplyRateLimitingSchema()` to be backwards-compatible no-op
- ✅ **Simplified setup script**: Database setup now creates base tables then delegates extended schema to application startup

**Benefits**:
- Single authoritative source for complete database schema
- Eliminates complex SQL parsing in bash scripts
- Allows application's native schema handling to manage complex statements
- Reduces setup script complexity and potential parsing errors

### Enhanced Dev-Reset Workflow

**Script**: `scripts/dev-reset.sh`

**Complete Reset Process**:
1. **Service Shutdown**: Aggressively stops all arkfile services (arkfile, minio, rqlite, caddy)
2. **Data Destruction**: Completely removes all user data, database, logs, secrets, and cryptographic keys
3. **Fresh Build**: Rebuilds application directly in current directory including:
   - TypeScript frontend compilation with Bun
   - WebAssembly build for crypto operations
   - Go application build with proper library linking
4. **Secret Generation**: Creates fresh JWT secrets, rqlite authentication, and configuration
5. **Service Startup**: Starts MinIO, rqlite with leader establishment verification
6. **Database Schema**: Applies base schema via improved setup script
7. **Application Launch**: Attempts to start arkfile service

**Key Improvements**:
- ✅ **Direct build approach**: Builds in development directory instead of complex deployment
- ✅ **Complete secret regeneration**: Fresh secrets on every reset
- ✅ **Comprehensive data wipe**: Ensures no state persists between resets
- ✅ **Service verification**: Waits for rqlite leadership establishment
- ✅ **Improved error handling**: Better feedback during each phase

## Current Deployment Issues

### Application Startup Failure

**Status**: Application build completes successfully but service fails to start.

**Root Cause**: Environment configuration issues preventing proper initialization.

**Symptoms Observed**:
```
2025/08/04 16:57:03 Warning: Could not load .env file: open .env: no such file or directory
2025/08/04 16:57:03 Continuing with environment variables from system/systemd
2025/08/04 16:57:03 Failed to load configuration: JWT_SECRET is required
```

**Analysis**:
- Application cannot locate `.env` file in working directory `/opt/arkfile`
- Missing `JWT_SECRET` environment variable in systemd environment
- Application attempts to fall back to systemd environment but required variables not set

### SystemD Service Configuration Issues

**Service File**: `systemd/arkfile.service`

**Current Configuration**:
- Uses `EnvironmentFile=-/opt/arkfile/etc/secrets.env` for configuration
- Loads systemd credentials from key files
- Working directory set to `/opt/arkfile`

**Identified Issues**:
1. **Environment Variable Mismatch**: Application expects `JWT_SECRET` but secrets.env may use different variable names
2. **Working Directory Conflict**: Service runs from `/opt/arkfile` but development build in project directory
3. **Library Path Issues**: LD_LIBRARY_PATH may not properly point to built libraries

## Next Steps for Resolution

### Immediate Actions Required

**1. Environment Configuration Audit**
- Examine `/opt/arkfile/etc/secrets.env` contents to verify variable names
- Ensure JWT_SECRET is properly set in secrets.env
- Validate all required environment variables are present

**2. Service Configuration Fix**
- Update systemd service to properly load environment variables
- Verify working directory and binary paths are correct
- Ensure library path points to correct shared libraries

**3. Application Configuration Review**
- Check `config/config.go` for required environment variable names
- Ensure application properly handles missing .env file scenario
- Validate fallback to systemd environment variables works correctly

**4. Database Schema Validation**
- Verify consolidated schema applies correctly on application startup
- Test that all required tables are created properly
- Ensure no missing tables cause application crashes

### Validation Testing Plan

**When Issues Resolved**:
1. **Complete Reset Test**: Run `dev-reset.sh` and verify clean startup
2. **Service Stability**: Ensure arkfile service starts and remains running
3. **Database Verification**: Confirm all tables exist and are properly indexed
4. **API Functionality**: Test basic endpoints respond correctly
5. **Phase 6F Integration Test**: Run complete share workflow validation

**Success Criteria**:
- `dev-reset.sh` completes without errors
- Arkfile service starts successfully and remains stable
- All database tables created and accessible
- Ready for Phase 6F user interface testing

## Schema Components Successfully Consolidated

**Base Tables** (created by setup script):
- `users` - User account management
- `file_metadata` - File information and metadata
- `user_activity` - User action logging
- `access_logs` - Access logging
- `admin_logs` - Administrative action logs

**Extended Tables** (created by application on startup):
- `file_share_keys` - Anonymous share system with Argon2id protection
- `share_access_attempts` - EntityID-based rate limiting
- `security_events` - Security event logging with privacy protection
- `rate_limit_state` - Rate limiting state management
- `opaque_server_keys` - OPAQUE authentication server keys
- `opaque_user_data` - OPAQUE user registration data
- `upload_sessions` - Chunked upload session management
- `file_encryption_keys` - File encryption key management
- `refresh_tokens` - JWT refresh token management
- `revoked_tokens` - JWT token revocation list

**Additional Components**:
- Complete index set for performance optimization
- Triggers for automatic timestamp updates
- Views for monitoring rate limiting activity
- Foreign key relationships for data integrity

## Integration with Phase 6F

**Purpose**: This dev-reset workflow will be essential for Phase 6F validation because:

1. **Clean Testing Environment**: Provides guaranteed clean state for each test cycle
2. **Complete Functionality Validation**: Will test entire system including database schema, authentication, and share system
3. **Deployment Readiness**: Ensures production deployment process works correctly
4. **Regression Prevention**: Allows testing that Phase 6F changes don't break existing functionality

**Next Phase**: Once the current environment/service issues are resolved, this reset workflow will enable comprehensive Phase 6F testing and validation of the complete user interface implementation.
