/**
 * Account Key Cache Module
 * 
 * Manages caching of the user's Account Key (derived from account password + username)
 * in sessionStorage for convenient file encryption/decryption operations.
 *
 * Security features:
 * - **Ephemeral wrapping key**: The account key is never stored as plaintext in
 *   sessionStorage. Instead, it is AES-GCM encrypted with a random 32-byte
 *   wrapping key held only in a module-level variable (JS heap). If sessionStorage
 *   is read by an attacker (XSS, browser extension), they get only ciphertext.
 * - **Session binding**: The cached key is bound to a specific JWT access token
 *   via SHA-256 hash. If the session changes, the cache auto-locks.
 * - **Inactivity auto-lock**: After a configurable idle period (default 15 min),
 *   the cache is automatically locked and the wrapping key wiped.
 * - **Integrity HMAC**: Each cache entry includes an HMAC-SHA256 of the stored
 *   ciphertext, verified on every read to detect tampering.
 * - **Configurable expiration**: 1-4 hours (default 1 hour).
 * - **User must explicitly opt-in** to caching.
 * - **Lock function** to manually clear cached keys.
 * - **Automatic cleanup** on logout and page unload.
 */

import {
  encryptAESGCM,
  decryptAESGCM,
  randomBytes,
  secureWipe,
  toBase64,
  fromBase64,
  hash256,
  toHex,
} from './primitives.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

// ============================================================================
// Types (Unified shape — matches Go agent's accountKeyEntry)
// ============================================================================

/**
 * Cache duration options in hours
 */
export type CacheDurationHours = 1 | 2 | 3 | 4;

/**
 * Configuration for Account Key caching
 */
export interface AccountKeyCacheConfig {
  /** Whether caching is enabled for this session */
  enabled: boolean;
  /** Cache duration in hours (1-4) */
  durationHours: CacheDurationHours;
  /** Inactivity timeout in minutes (0 = disabled) */
  inactivityTimeoutMinutes: number;
}

/**
 * Cached Account Key data structure (unified shape with Go agent).
 * Stored in sessionStorage as JSON.
 *
 * Note: `account_key` is AES-GCM ciphertext, NOT the raw key.
 * The wrapping key needed to decrypt it exists only in JS heap memory.
 */
interface AccountKeyCache {
  /** Base64-encoded AES-GCM ciphertext of the account key */
  account_key: string;
  /** Base64-encoded IV used for wrapping encryption */
  wrapping_iv: string;
  /** Base64-encoded GCM auth tag from wrapping encryption */
  wrapping_tag: string;
  /** HMAC-SHA256 hex of the ciphertext (integrity check) */
  integrity_hmac: string;
  /** SHA-256 hex of the bound session access token */
  token_hash: string;
  /** Username this key belongs to */
  username: string;
  /** Context (always 'account' for Account Keys) */
  context: 'account';
  /** ISO 8601 timestamp when the key was stored */
  stored_at: string;
  /** ISO 8601 timestamp when the key expires */
  expires_at: string;
  /** TTL in hours */
  ttl_hours: number;
}

// ============================================================================
// Constants
// ============================================================================

/** Storage key prefix for Account Key cache */
const ACCOUNT_KEY_PREFIX = 'arkfile_account_key_';

/** Storage key for cache configuration */
const ACCOUNT_KEY_CONFIG = 'arkfile_account_key_config';

/** Storage key for locked state */
const ACCOUNT_KEY_LOCKED = 'arkfile_account_key_locked';

/** Default cache duration in hours */
const DEFAULT_DURATION_HOURS: CacheDurationHours = 1;

/** Maximum cache duration in hours */
const MAX_DURATION_HOURS: CacheDurationHours = 4;

/** Milliseconds per hour */
const MS_PER_HOUR = 3600000;

/** Default inactivity timeout in minutes */
const DEFAULT_INACTIVITY_TIMEOUT_MINUTES = 15;

/** Inactivity check interval in milliseconds */
const INACTIVITY_CHECK_INTERVAL_MS = 60_000; // 1 minute

// ============================================================================
// Module-level ephemeral state (never persisted)
// ============================================================================

/**
 * Ephemeral wrapping key — exists only in JS heap memory.
 * Used to encrypt/decrypt the account key in sessionStorage.
 * On page unload this variable is lost; on lock/clear it is securely wiped.
 */
let wrappingKey: Uint8Array | null = null;

/**
 * Timestamp of last user activity (mouse/keyboard/click).
 * Used for inactivity auto-lock.
 */
let lastActivityTimestamp: number = Date.now();

/**
 * Interval ID for the inactivity checker.
 */
let inactivityIntervalId: ReturnType<typeof setInterval> | null = null;

/**
 * Whether activity listeners have been registered.
 */
let activityListenersRegistered = false;

// ============================================================================
// Configuration Functions
// ============================================================================

/**
 * Gets the current Account Key cache configuration
 * 
 * @returns Current configuration or default if not set
 */
export function getAccountKeyCacheConfig(): AccountKeyCacheConfig {
  try {
    const stored = sessionStorage.getItem(ACCOUNT_KEY_CONFIG);
    if (stored) {
      const config = JSON.parse(stored) as AccountKeyCacheConfig;
      // Validate duration is within bounds
      if (config.durationHours >= 1 && config.durationHours <= MAX_DURATION_HOURS) {
        return {
          enabled: config.enabled,
          durationHours: config.durationHours,
          inactivityTimeoutMinutes: config.inactivityTimeoutMinutes ?? DEFAULT_INACTIVITY_TIMEOUT_MINUTES,
        };
      }
    }
  } catch {
    // Fall through to default
  }
  
  // Return default configuration (disabled until user opts in)
  return {
    enabled: false,
    durationHours: DEFAULT_DURATION_HOURS,
    inactivityTimeoutMinutes: DEFAULT_INACTIVITY_TIMEOUT_MINUTES,
  };
}

/**
 * Sets the Account Key cache configuration
 * 
 * @param config - New configuration to apply
 */
export function setAccountKeyCacheConfig(config: AccountKeyCacheConfig): void {
  try {
    // Validate duration
    const validDuration = Math.min(
      Math.max(Math.round(config.durationHours), 1),
      MAX_DURATION_HOURS
    ) as CacheDurationHours;
    
    const validConfig: AccountKeyCacheConfig = {
      enabled: config.enabled,
      durationHours: validDuration,
      inactivityTimeoutMinutes: Math.max(0, Math.round(config.inactivityTimeoutMinutes ?? DEFAULT_INACTIVITY_TIMEOUT_MINUTES)),
    };
    
    sessionStorage.setItem(ACCOUNT_KEY_CONFIG, JSON.stringify(validConfig));
  } catch (error) {
    console.warn('Failed to save Account Key cache config:', error);
  }
}

// ============================================================================
// Session Binding Helpers
// ============================================================================

/**
 * Computes SHA-256 hex hash of a session access token.
 * Matches the Go agent's hashToken() function.
 */
function hashToken(token: string): string {
  const encoder = new TextEncoder();
  const tokenBytes = encoder.encode(token);
  const digest = hash256(tokenBytes);
  return toHex(digest);
}

/**
 * Computes HMAC-SHA256 of data using the wrapping key.
 * Used for integrity verification of stored ciphertext.
 */
function computeIntegrityHMAC(data: Uint8Array, key: Uint8Array): string {
  const mac = hmac(sha256, key, data);
  return toHex(mac);
}

// ============================================================================
// Cache Functions
// ============================================================================

/**
 * Caches an Account Key in sessionStorage, encrypted with an ephemeral wrapping key.
 * 
 * The account key is AES-GCM encrypted with a random 32-byte wrapping key that
 * exists only in a module-level JS variable. The ciphertext goes to sessionStorage;
 * the wrapping key stays in heap memory only.
 * 
 * @param username - The user's username
 * @param key - The derived Account Key (32 bytes)
 * @param accessToken - The current JWT access token (for session binding)
 * @param durationHours - Optional override for cache duration (1-4 hours)
 */
export async function cacheAccountKey(
  username: string,
  key: Uint8Array,
  accessToken: string,
  durationHours?: CacheDurationHours
): Promise<void> {
  try {
    // Get configured duration or use provided override
    const config = getAccountKeyCacheConfig();
    const duration = durationHours ?? config.durationHours;
    
    // Validate duration
    const validDuration = Math.min(
      Math.max(Math.round(duration), 1),
      MAX_DURATION_HOURS
    );
    
    // Generate ephemeral wrapping key (or reuse existing)
    if (wrappingKey !== null) {
      secureWipe(wrappingKey);
    }
    wrappingKey = randomBytes(32);
    
    // Encrypt the account key with the wrapping key
    const encrypted = await encryptAESGCM({
      key: wrappingKey,
      data: key,
    });
    
    // Compute integrity HMAC over the ciphertext
    const integrityHMAC = computeIntegrityHMAC(encrypted.ciphertext, wrappingKey);
    
    const now = new Date();
    const expiresAt = new Date(now.getTime() + (validDuration * MS_PER_HOUR));
    
    const cached: AccountKeyCache = {
      account_key: toBase64(encrypted.ciphertext),
      wrapping_iv: toBase64(encrypted.iv),
      wrapping_tag: toBase64(encrypted.tag),
      integrity_hmac: integrityHMAC,
      token_hash: hashToken(accessToken),
      username: username.trim(),
      context: 'account',
      stored_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      ttl_hours: validDuration,
    };
    
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    sessionStorage.setItem(storageKey, JSON.stringify(cached));
    
    // Clear locked state since we just cached a key
    sessionStorage.removeItem(ACCOUNT_KEY_LOCKED);
    
    // Update config to reflect that caching is now enabled
    if (!config.enabled) {
      setAccountKeyCacheConfig({
        enabled: true,
        durationHours: validDuration as CacheDurationHours,
        inactivityTimeoutMinutes: config.inactivityTimeoutMinutes,
      });
    }
    
    // Start inactivity monitoring
    startInactivityMonitor();
    
  } catch (error) {
    console.warn('Failed to cache Account Key:', error);
  }
}

/**
 * Retrieves a cached Account Key from sessionStorage.
 * 
 * Performs expiration check, session binding validation, and integrity HMAC
 * verification before decrypting with the ephemeral wrapping key.
 * 
 * @param username - The user's username
 * @param accessToken - Optional current access token for session binding check
 * @returns The cached Account Key, or null if not cached/expired/locked/invalid
 */
export async function getCachedAccountKey(
  username: string,
  accessToken?: string
): Promise<Uint8Array | null> {
  try {
    // Check if session is locked
    if (isAccountKeyLocked()) {
      return null;
    }
    
    // Wrapping key must exist in memory
    if (wrappingKey === null) {
      return null;
    }
    
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    const stored = sessionStorage.getItem(storageKey);
    
    if (!stored) {
      return null;
    }
    
    const cached: AccountKeyCache = JSON.parse(stored);
    
    // Check if expired
    const expiresAt = new Date(cached.expires_at).getTime();
    if (Date.now() > expiresAt) {
      // Clean up expired key
      sessionStorage.removeItem(storageKey);
      return null;
    }
    
    // Verify username matches
    if (cached.username !== username.trim()) {
      sessionStorage.removeItem(storageKey);
      return null;
    }
    
    // Verify context is 'account'
    if (cached.context !== 'account') {
      sessionStorage.removeItem(storageKey);
      return null;
    }
    
    // Session binding: verify token hash if provided
    if (accessToken && accessToken !== '') {
      const currentTokenHash = hashToken(accessToken);
      if (currentTokenHash !== cached.token_hash) {
        // Session mismatch — auto-lock for security
        console.warn('Session mismatch detected. Locking account key cache.');
        lockAccountKey();
        return null;
      }
    }
    
    // Integrity HMAC verification
    const ciphertextBytes = fromBase64(cached.account_key);
    const expectedHMAC = computeIntegrityHMAC(ciphertextBytes, wrappingKey);
    if (expectedHMAC !== cached.integrity_hmac) {
      // Tampering detected — force lock and alert
      console.error('⚠️ Account key cache integrity check failed! Possible tampering detected. Locking.');
      lockAccountKey();
      return null;
    }
    
    // Decrypt the account key using the ephemeral wrapping key
    const iv = fromBase64(cached.wrapping_iv);
    const tag = fromBase64(cached.wrapping_tag);
    
    const result = await decryptAESGCM({
      ciphertext: ciphertextBytes,
      iv,
      tag,
      key: wrappingKey,
    });
    
    return result.plaintext;
  } catch (error) {
    console.warn('Failed to retrieve cached Account Key:', error);
    return null;
  }
}

/**
 * Clears a cached Account Key for a specific user.
 * Overwrites the sessionStorage entry before removing it.
 * 
 * @param username - The user's username
 */
export function clearCachedAccountKey(username: string): void {
  try {
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    // Overwrite with random data before removing (defense-in-depth)
    const existing = sessionStorage.getItem(storageKey);
    if (existing) {
      const overwrite = toBase64(randomBytes(existing.length));
      sessionStorage.setItem(storageKey, overwrite);
    }
    sessionStorage.removeItem(storageKey);
  } catch (error) {
    console.warn('Failed to clear cached Account Key:', error);
  }
}

/**
 * Clears all cached Account Keys.
 * Overwrites each entry before removing it.
 */
export function clearAllCachedAccountKeys(): void {
  try {
    const keysToRemove: string[] = [];
    
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(ACCOUNT_KEY_PREFIX)) {
        keysToRemove.push(key);
      }
    }
    
    for (const key of keysToRemove) {
      // Overwrite with random data before removing
      const existing = sessionStorage.getItem(key);
      if (existing) {
        const overwrite = toBase64(randomBytes(existing.length));
        sessionStorage.setItem(key, overwrite);
      }
      sessionStorage.removeItem(key);
    }
  } catch (error) {
    console.warn('Failed to clear all cached Account Keys:', error);
  }
}

/**
 * Checks if an Account Key is currently cached for a user
 * 
 * @param username - The user's username
 * @returns True if a valid (non-expired) key is cached and wrapping key exists
 */
export function isAccountKeyCached(username: string): boolean {
  if (isAccountKeyLocked() || wrappingKey === null) {
    return false;
  }
  
  try {
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    const stored = sessionStorage.getItem(storageKey);
    if (!stored) return false;
    
    const cached: AccountKeyCache = JSON.parse(stored);
    const expiresAt = new Date(cached.expires_at).getTime();
    return Date.now() <= expiresAt;
  } catch {
    return false;
  }
}

/**
 * Gets the expiration time of a cached Account Key
 * 
 * @param username - The user's username
 * @returns Expiration timestamp in milliseconds, or null if not cached
 */
export function cachedAccountKeyExpiresAt(username: string): number | null {
  try {
    if (isAccountKeyLocked() || wrappingKey === null) {
      return null;
    }
    
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    const stored = sessionStorage.getItem(storageKey);
    
    if (!stored) {
      return null;
    }
    
    const cached: AccountKeyCache = JSON.parse(stored);
    const expiresAt = new Date(cached.expires_at).getTime();
    
    // Check if expired
    if (Date.now() > expiresAt) {
      sessionStorage.removeItem(storageKey);
      return null;
    }
    
    return expiresAt;
  } catch {
    return null;
  }
}

/**
 * Gets the remaining time until the cached Account Key expires
 * 
 * @param username - The user's username
 * @returns Remaining time in milliseconds, or null if not cached
 */
export function cachedAccountKeyTimeRemaining(username: string): number | null {
  const expiresAt = cachedAccountKeyExpiresAt(username);
  if (expiresAt === null) {
    return null;
  }
  
  const remaining = expiresAt - Date.now();
  return remaining > 0 ? remaining : null;
}

// ============================================================================
// Lock Functions
// ============================================================================

/**
 * Locks the Account Key cache, clearing all cached keys and wiping the wrapping key.
 * 
 * After locking, the wrapping key is destroyed — even if sessionStorage still
 * contains ciphertext, it cannot be decrypted without the wrapping key.
 * Users must re-enter their password for file operations.
 */
export function lockAccountKey(): void {
  try {
    // Securely wipe the ephemeral wrapping key
    if (wrappingKey !== null) {
      secureWipe(wrappingKey);
      wrappingKey = null;
    }
    
    // Clear all cached Account Keys from sessionStorage
    clearAllCachedAccountKeys();
    
    // Set locked state
    sessionStorage.setItem(ACCOUNT_KEY_LOCKED, 'true');
    
    // Disable caching in config
    const config = getAccountKeyCacheConfig();
    setAccountKeyCacheConfig({
      ...config,
      enabled: false,
    });
    
    // Stop inactivity monitoring
    stopInactivityMonitor();
  } catch (error) {
    console.warn('Failed to lock Account Key:', error);
  }
}

/**
 * Unlocks the Account Key cache.
 * 
 * This is called when a user successfully enters their password
 * and opts to cache their Account Key again.
 */
export function unlockAccountKey(): void {
  try {
    sessionStorage.removeItem(ACCOUNT_KEY_LOCKED);
  } catch (error) {
    console.warn('Failed to unlock Account Key:', error);
  }
}

/**
 * Checks if the Account Key cache is currently locked
 * 
 * @returns True if locked (user must re-enter password)
 */
export function isAccountKeyLocked(): boolean {
  try {
    return sessionStorage.getItem(ACCOUNT_KEY_LOCKED) === 'true';
  } catch {
    return false;
  }
}

// ============================================================================
// Inactivity Auto-Lock
// ============================================================================

/**
 * Records user activity (called by event listeners).
 */
function recordActivity(): void {
  lastActivityTimestamp = Date.now();
}

/**
 * Checks if the inactivity timeout has been exceeded and auto-locks if so.
 */
function checkInactivityTimeout(): void {
  const config = getAccountKeyCacheConfig();
  const timeoutMinutes = config.inactivityTimeoutMinutes;
  
  // 0 = disabled
  if (timeoutMinutes <= 0) {
    return;
  }
  
  const idleMs = Date.now() - lastActivityTimestamp;
  const timeoutMs = timeoutMinutes * 60_000;
  
  if (idleMs >= timeoutMs) {
    console.warn(`Account key auto-locked after ${timeoutMinutes} minutes of inactivity.`);
    lockAccountKey();
  }
}

/**
 * Starts the inactivity monitor (activity event listeners + periodic check).
 */
function startInactivityMonitor(): void {
  // Register activity listeners (only once)
  if (!activityListenersRegistered) {
    const events: Array<keyof WindowEventMap> = ['mousemove', 'keydown', 'click', 'touchstart', 'scroll'];
    
    // Debounced activity recorder — update at most once per second
    let debounceTimer: ReturnType<typeof setTimeout> | null = null;
    const debouncedRecord = (): void => {
      if (debounceTimer === null) {
        recordActivity();
        debounceTimer = setTimeout(() => { debounceTimer = null; }, 1000);
      }
    };
    
    for (const event of events) {
      window.addEventListener(event, debouncedRecord, { passive: true });
    }
    
    activityListenersRegistered = true;
  }
  
  // Start periodic inactivity check
  if (inactivityIntervalId === null) {
    inactivityIntervalId = setInterval(checkInactivityTimeout, INACTIVITY_CHECK_INTERVAL_MS);
  }
  
  // Reset activity timestamp
  lastActivityTimestamp = Date.now();
}

/**
 * Stops the inactivity monitor.
 */
function stopInactivityMonitor(): void {
  if (inactivityIntervalId !== null) {
    clearInterval(inactivityIntervalId);
    inactivityIntervalId = null;
  }
}

// ============================================================================
// Cleanup Functions
// ============================================================================

/**
 * Performs full cleanup of Account Key cache.
 * 
 * Called on logout or when user explicitly clears session data.
 * Wipes the wrapping key, all cached data, and config.
 */
export function cleanupAccountKeyCache(): void {
  try {
    // Wipe wrapping key
    if (wrappingKey !== null) {
      secureWipe(wrappingKey);
      wrappingKey = null;
    }
    
    clearAllCachedAccountKeys();
    sessionStorage.removeItem(ACCOUNT_KEY_CONFIG);
    sessionStorage.removeItem(ACCOUNT_KEY_LOCKED);
    
    stopInactivityMonitor();
  } catch (error) {
    console.warn('Failed to cleanup Account Key cache:', error);
  }
}

/**
 * Registers cleanup handlers for automatic key clearing.
 * 
 * Sets up event listeners for:
 * - beforeunload (tab/browser close) — locks and wipes wrapping key
 */
export function registerAccountKeyCleanupHandlers(): void {
  // Clear on tab/browser close
  window.addEventListener('beforeunload', () => {
    lockAccountKey();
  });
  
  // Note: sessionStorage is automatically cleared on tab close,
  // but we explicitly lock to ensure the wrapping key is wiped.
}

// ============================================================================
// Exports
// ============================================================================

export const accountKeyCache = {
  // Configuration
  getAccountKeyCacheConfig,
  setAccountKeyCacheConfig,
  
  // Caching
  cacheAccountKey,
  getCachedAccountKey,
  clearCachedAccountKey,
  clearAllCachedAccountKeys,
  isAccountKeyCached,
  cachedAccountKeyExpiresAt,
  cachedAccountKeyTimeRemaining,
  
  // Session binding
  hashToken,
  
  // Locking
  lockAccountKey,
  unlockAccountKey,
  isAccountKeyLocked,
  
  // Cleanup
  cleanupAccountKeyCache,
  registerAccountKeyCleanupHandlers,
};
