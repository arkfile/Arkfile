/**
 * Account Key Cache Module
 * 
 * Manages caching of the user's Account Key (derived from account password + username)
 * in sessionStorage for convenient file encryption/decryption operations.
 * 
 * Security features:
 * - Keys are stored in sessionStorage (cleared on tab/browser close)
 * - Configurable expiration (1-4 hours, default 1 hour)
 * - User must explicitly opt-in to caching
 * - Lock function to manually clear cached keys
 * - Automatic cleanup on logout
 */

import { toBase64, fromBase64, secureWipe } from './primitives.js';

// ============================================================================
// Types
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
}

/**
 * Cached Account Key data structure
 */
interface AccountKeyCache {
  /** Base64-encoded Account Key */
  key: string;
  /** Expiration timestamp (milliseconds since epoch) */
  expiresAt: number;
  /** Username this key belongs to */
  username: string;
  /** Context (always 'account' for Account Keys) */
  context: 'account';
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
        return config;
      }
    }
  } catch {
    // Fall through to default
  }
  
  // Return default configuration (disabled until user opts in)
  return {
    enabled: false,
    durationHours: DEFAULT_DURATION_HOURS,
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
    };
    
    sessionStorage.setItem(ACCOUNT_KEY_CONFIG, JSON.stringify(validConfig));
  } catch (error) {
    console.warn('Failed to save Account Key cache config:', error);
  }
}

// ============================================================================
// Cache Functions
// ============================================================================

/**
 * Caches an Account Key in sessionStorage
 * 
 * @param username - The user's username
 * @param key - The derived Account Key (32 bytes)
 * @param durationHours - Optional override for cache duration (1-4 hours)
 */
export function cacheAccountKey(
  username: string,
  key: Uint8Array,
  durationHours?: CacheDurationHours
): void {
  try {
    // Get configured duration or use provided override
    const config = getAccountKeyCacheConfig();
    const duration = durationHours ?? config.durationHours;
    
    // Validate duration
    const validDuration = Math.min(
      Math.max(Math.round(duration), 1),
      MAX_DURATION_HOURS
    );
    
    const cached: AccountKeyCache = {
      key: toBase64(key),
      expiresAt: Date.now() + (validDuration * MS_PER_HOUR),
      username: username.trim(),
      context: 'account',
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
      });
    }
  } catch (error) {
    console.warn('Failed to cache Account Key:', error);
  }
}

/**
 * Retrieves a cached Account Key from sessionStorage
 * 
 * @param username - The user's username
 * @returns The cached Account Key, or null if not cached/expired/locked
 */
export function getCachedAccountKey(username: string): Uint8Array | null {
  try {
    // Check if session is locked
    if (isAccountKeyLocked()) {
      return null;
    }
    
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    const stored = sessionStorage.getItem(storageKey);
    
    if (!stored) {
      return null;
    }
    
    const cached: AccountKeyCache = JSON.parse(stored);
    
    // Check if expired
    if (Date.now() > cached.expiresAt) {
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
    
    return fromBase64(cached.key);
  } catch (error) {
    console.warn('Failed to retrieve cached Account Key:', error);
    return null;
  }
}

/**
 * Clears a cached Account Key for a specific user
 * 
 * @param username - The user's username
 */
export function clearCachedAccountKey(username: string): void {
  try {
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    sessionStorage.removeItem(storageKey);
  } catch (error) {
    console.warn('Failed to clear cached Account Key:', error);
  }
}

/**
 * Clears all cached Account Keys
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
 * @returns True if a valid (non-expired) key is cached
 */
export function isAccountKeyCached(username: string): boolean {
  return getCachedAccountKey(username) !== null;
}

/**
 * Gets the expiration time of a cached Account Key
 * 
 * @param username - The user's username
 * @returns Expiration timestamp in milliseconds, or null if not cached
 */
export function cachedAccountKeyExpiresAt(username: string): number | null {
  try {
    if (isAccountKeyLocked()) {
      return null;
    }
    
    const storageKey = ACCOUNT_KEY_PREFIX + username.trim();
    const stored = sessionStorage.getItem(storageKey);
    
    if (!stored) {
      return null;
    }
    
    const cached: AccountKeyCache = JSON.parse(stored);
    
    // Check if expired
    if (Date.now() > cached.expiresAt) {
      sessionStorage.removeItem(storageKey);
      return null;
    }
    
    return cached.expiresAt;
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
 * Locks the Account Key cache, clearing all cached keys
 * 
 * This is the "Lock" function that users can trigger manually.
 * After locking, users must re-enter their password for file operations.
 */
export function lockAccountKey(): void {
  try {
    // Clear all cached Account Keys
    clearAllCachedAccountKeys();
    
    // Set locked state
    sessionStorage.setItem(ACCOUNT_KEY_LOCKED, 'true');
    
    // Disable caching in config
    const config = getAccountKeyCacheConfig();
    setAccountKeyCacheConfig({
      ...config,
      enabled: false,
    });
  } catch (error) {
    console.warn('Failed to lock Account Key:', error);
  }
}

/**
 * Unlocks the Account Key cache
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
// Cleanup Functions
// ============================================================================

/**
 * Performs full cleanup of Account Key cache
 * 
 * Called on logout or when user explicitly clears session data.
 */
export function cleanupAccountKeyCache(): void {
  try {
    clearAllCachedAccountKeys();
    sessionStorage.removeItem(ACCOUNT_KEY_CONFIG);
    sessionStorage.removeItem(ACCOUNT_KEY_LOCKED);
  } catch (error) {
    console.warn('Failed to cleanup Account Key cache:', error);
  }
}

/**
 * Registers cleanup handlers for automatic key clearing
 * 
 * This sets up event listeners for:
 * - beforeunload (tab/browser close)
 * - visibilitychange (optional, for aggressive cleanup)
 */
export function registerAccountKeyCleanupHandlers(): void {
  // Clear on tab/browser close
  window.addEventListener('beforeunload', () => {
    lockAccountKey();
  });
  
  // Note: sessionStorage is automatically cleared on tab close,
  // but we explicitly lock to ensure clean state
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
  
  // Locking
  lockAccountKey,
  unlockAccountKey,
  isAccountKeyLocked,
  
  // Cleanup
  cleanupAccountKeyCache,
  registerAccountKeyCleanupHandlers,
};
