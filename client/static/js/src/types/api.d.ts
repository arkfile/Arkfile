/**
 * TypeScript definitions for ArkFile API requests and responses
 */

// Common API response structure
interface ApiResponse<T = any> {
  success?: boolean;
  error?: string;
  message?: string;
  data?: T;
}

// Authentication types
interface LoginRequest {
  email: string;
  password: string;
}

interface LoginResponse {
  token: string;
  refreshToken: string;
  sessionKey: string;
  authMethod: 'OPAQUE';
  requiresTOTP?: boolean;
}

interface RegisterRequest {
  email: string;
  password: string;
}

interface RegisterResponse {
  token: string;
  refreshToken: string;
  sessionKey: string;
  authMethod: 'OPAQUE';
  message: string;
}

interface TOTPLoginRequest {
  email: string;
  code: string;
  tempToken: string;
  sessionKey: string;
}

interface TOTPVerifyRequest {
  code: string;
  sessionKey: string;
}

interface TOTPSetupRequest {
  code: string;
  sessionKey: string;
}

interface TOTPSetupResponse {
  secret: string;
  qrCodeUrl: string;
  manualEntry: string;
  backupCodes: string[];
}

// File operation types
interface FileMetadata {
  id: string;
  fileId: string;
  storageId: string;
  // Encrypted metadata fields (base64 encoded)
  encryptedFilename: string;
  filenameNonce: string;
  encryptedSha256sum: string;
  sha256sumNonce: string;
  // Decrypted fields (populated client-side)
  filename?: string;
  sha256sum?: string;
  size: number;
  uploadedAt: string;
  contentType: string;
  encrypted: boolean;
  keyType?: 'account' | 'custom';
  hasCustomPassword?: boolean;
  multiKey?: boolean;
  sharedWith?: string[];
  downloadCount?: number;
  maxDownloads?: number;
  expiresAt?: string;
}
// File operation types for client-side display (after decryption)
interface DecryptedFileMetadata {
  id: string;
  fileId: string;
  storageId: string;
  filename: string;
  sha256sum: string;
  size: number;
  uploadedAt: string;
  contentType: string;
  encrypted: boolean;
  keyType?: 'account' | 'custom';
  hasCustomPassword?: boolean;
  multiKey?: boolean;
  sharedWith?: string[];
  downloadCount?: number;
  maxDownloads?: number;
  expiresAt?: string;
}

interface FileListResponse {
  files: FileMetadata[];
  totalCount: number;
  hasMore: boolean;
}

interface FileUploadRequest {
  // Encrypted metadata fields (base64 encoded)
  encryptedFilename: string;
  filenameNonce: string;
  encryptedSha256sum: string;
  sha256sumNonce: string;
  contentType: string;
  size: number;
  encrypted: boolean;
  keyType: 'account' | 'custom';
  hasCustomPassword?: boolean;
  passwordHint?: string;
  multiKey?: boolean;
  additionalKeys?: Array<{ id: string; hint?: string }>;
}

interface FileUploadResponse {
  fileId: string;
  uploadUrl: string;
  chunkSize: number;
  totalChunks: number;
}

interface ChunkUploadRequest {
  fileId: string;
  chunkIndex: number;
  totalChunks: number;
  chunkData: string; // Base64 encoded chunk data
  chunkHash: string; // SHA256 hash of chunk
}

interface ChunkUploadResponse {
  uploaded: boolean;
  nextChunk?: number;
  completed?: boolean;
}

interface FileDownloadRequest {
  fileId: string;
  password?: string; // For custom password files
}

interface FileDownloadResponse {
  // Encrypted metadata fields (base64 encoded)
  encryptedFilename: string;
  filenameNonce: string;
  encryptedSha256sum: string;
  sha256sumNonce: string;
  // Decrypted fields (populated client-side)
  filename?: string;
  sha256sum?: string;
  contentType: string;
  size: number;
  encrypted: boolean;
  keyType: 'account' | 'custom';
  multiKey?: boolean;
  chunks: Array<{
    index: number;
    url: string;
    hash: string;
  }>;
}

interface FileShareRequest {
  fileId: string;
  maxDownloads?: number;
  expiresInHours?: number;
  password?: string;
}

interface FileShareResponse {
  shareId: string;
  shareUrl: string;
  expiresAt?: string;
  maxDownloads?: number;
}

// Admin types
interface AdminStatsResponse {
  totalUsers: number;
  totalFiles: number;
  totalStorageUsed: number;
  activeUsers: number;
  recentUploads: number;
  systemHealth: {
    status: 'healthy' | 'warning' | 'error';
    uptime: number;
    memoryUsage: number;
    diskUsage: number;
  };
}

interface UserManagementRequest {
  action: 'suspend' | 'unsuspend' | 'delete' | 'resetPassword';
  userId: string;
  reason?: string;
}

// Error types
interface ApiError {
  error: string;
  details?: string;
  field?: string; // For validation errors
  code?: string; // Error code for client handling
}

interface ValidationError extends ApiError {
  field: string;
  code: 'VALIDATION_ERROR';
}

interface AuthenticationError extends ApiError {
  code: 'AUTH_ERROR' | 'TOKEN_EXPIRED' | 'INVALID_CREDENTIALS';
}

interface FileError extends ApiError {
  code: 'FILE_NOT_FOUND' | 'FILE_TOO_LARGE' | 'ENCRYPTION_ERROR' | 'UPLOAD_FAILED';
}

// Utility types
type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';

interface FetchOptions {
  method: HttpMethod;
  headers?: Record<string, string>;
  body?: string | FormData;
  credentials?: RequestCredentials;
}

interface AuthenticatedFetchOptions extends FetchOptions {
  requiresAuth: true;
  token?: string;
}

// Progress tracking types
interface ProgressCallback {
  (progress: {
    loaded: number;
    total: number;
    percentage: number;
    stage: 'uploading' | 'encrypting' | 'processing' | 'complete';
  }): void;
}

interface ChunkedUploadProgress {
  fileId: string;
  filename: string; // This can be the original filename client-side
  totalSize: number;
  uploadedSize: number;
  currentChunk: number;
  totalChunks: number;
  percentage: number;
  speed: number; // bytes per second
  remainingTime: number; // seconds
  stage: 'encrypting' | 'uploading' | 'complete' | 'error';
  error?: string;
}

// Export all types
export type {
  ApiResponse,
  LoginRequest,
  LoginResponse,
  RegisterRequest,
  RegisterResponse,
  TOTPLoginRequest,
  TOTPVerifyRequest,
  TOTPSetupRequest,
  TOTPSetupResponse,
  FileMetadata,
  DecryptedFileMetadata,
  FileListResponse,
  FileUploadRequest,
  FileUploadResponse,
  ChunkUploadRequest,
  ChunkUploadResponse,
  FileDownloadRequest,
  FileDownloadResponse,
  FileShareRequest,
  FileShareResponse,
  AdminStatsResponse,
  UserManagementRequest,
  ApiError,
  ValidationError,
  AuthenticationError,
  FileError,
  HttpMethod,
  FetchOptions,
  AuthenticatedFetchOptions,
  ProgressCallback,
  ChunkedUploadProgress
};
