# Arkfile Filename and Storage Architecture

## Overview

This document explains how filenames are handled in the Arkfile system, from client-side upload through storage in the backend.

## Architecture Components

### 1. Client-Side Handling

**Filename Preservation:**
- Users select files with their original filenames
- The client sends the original filename to the server in upload requests
- Filenames are displayed to users in the UI with their original names

**Upload Process:**
- Regular uploads: Send filename in JSON request body
- Chunked uploads: Send filename when creating upload session

### 2. Server-Side Storage

**Database Storage (RQLite):**
- **file_metadata table**: Stores the original filename along with:
  - `filename`: Original filename as provided by user
  - `storage_id`: UUID v4 that serves as the actual storage identifier
  - `owner_email`: File owner
  - `size_bytes`: Original file size
  - `padded_size`: Size after privacy-preserving padding
  - Other metadata (password hints, upload date, etc.)

- **upload_sessions table**: For chunked uploads, stores:
  - `filename`: Original filename
  - `storage_id`: UUID v4 for storage backend
  - Session tracking information

**Storage Backend (MinIO/S3-compatible):**
- Files are stored using the `storage_id` (UUID) as the object name
- Original filenames are NOT used in the storage backend
- This provides:
  - Privacy: Storage admins cannot see meaningful filenames
  - Security: Prevents filename-based attacks
  - Uniqueness: No filename collision issues

### 3. Storage Flow

```
User uploads "document.pdf"
    ↓
Server generates UUID: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    ↓
Database stores:
  - filename: "document.pdf"
  - storage_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    ↓
MinIO stores object as: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
```

### 4. Retrieval Process

**Download Flow:**
1. User requests file by original filename
2. Server queries database for storage_id
3. Server retrieves object from storage using storage_id
4. File is returned to user with original filename

**File Listing:**
- ListFiles returns original filenames from database
- Each file entry includes the storage_id for internal tracking

### 5. Privacy Features

**Padding:**
- Files are padded to obscure their actual size
- Tiered padding system:
  - < 1MB: 64KB blocks
  - < 100MB: 1MB blocks  
  - < 1GB: 10MB blocks
  - ≥ 1GB: 100MB blocks
- Random padding (0-10% of block size) added for additional privacy

**Storage Identifier:**
- UUIDs prevent correlation between files
- No metadata leakage through filenames
- Storage backend sees only anonymous identifiers

### 6. Current User Experience

**What Users See:**
- Original filenames in file listings
- Original filenames when downloading
- File sizes (original, not padded)
- Upload dates and other metadata

**What Users Don't See:**
- Storage IDs (UUIDs)
- Padded sizes
- Internal storage structure

### 7. Security Benefits

1. **Filename Attack Prevention**: Malicious filenames cannot affect storage
2. **Privacy**: Storage layer has no knowledge of actual filenames
3. **Deduplication Prevention**: Same file uploaded twice gets different UUIDs
4. **Access Control**: Files accessed only through proper authentication

### 8. Implementation Details

**Key Functions:**
- `models.GenerateStorageID()`: Creates UUID v4 for storage
- `utils.CalculatePaddedSize()`: Determines padded size
- `storage.PutObjectWithPadding()`: Stores with padding
- `storage.GetObjectWithoutPadding()`: Retrieves and strips padding

**Database Schema:**
```sql
CREATE TABLE file_metadata (
    filename TEXT NOT NULL,          -- User's original filename
    storage_id VARCHAR(36) UNIQUE,   -- UUID for storage backend
    owner_email TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,      -- Original size
    padded_size BIGINT NOT NULL,     -- Size with padding
    -- ... other fields
);
```

### 9. Future Considerations

- Filename encryption in database for additional privacy
- Metadata stripping from files before storage
- Enhanced padding algorithms
- Client-side filename obfuscation options

## Summary

The Arkfile system maintains a clear separation between user-facing filenames and storage-layer identifiers. Users interact with their original filenames while the backend uses anonymous UUIDs, providing both usability and privacy. The padding system further enhances privacy by obscuring file sizes in the storage layer.
