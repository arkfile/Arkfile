/**
 * Password Modal Component
 * 
 * A modal dialog for prompting users to enter their password when:
 * - Their cached Account Key has expired
 * - They need to re-authenticate for file operations
 * - They want to cache their Account Key with a specific duration
 */

import type { CacheDurationHours } from '../crypto/account-key-cache.js';

// ============================================================================
// Types
// ============================================================================

/**
 * Options for the password prompt modal
 */
export interface PasswordPromptOptions {
  /** Modal title */
  title: string;
  /** Message to display to the user */
  message: string;
  /** Whether to show the cache duration selector */
  showCacheDuration: boolean;
  /** Default cache duration (if showCacheDuration is true) */
  defaultDuration?: CacheDurationHours;
  /** Label for the submit button */
  submitLabel?: string;
  /** Label for the cancel button */
  cancelLabel?: string;
}

/**
 * Result from the password prompt
 */
export interface PasswordPromptResult {
  /** The entered password */
  password: string;
  /** Selected cache duration (if showCacheDuration was true) */
  cacheDuration?: CacheDurationHours | undefined;
  /** Whether to remember the cache duration preference */
  rememberDuration?: boolean | undefined;
}

// ============================================================================
// Constants
// ============================================================================

const MODAL_ID = 'arkfile-password-modal';
const MODAL_OVERLAY_ID = 'arkfile-password-modal-overlay';

// ============================================================================
// Modal HTML Template
// ============================================================================

function createModalHTML(options: PasswordPromptOptions): string {
  const submitLabel = options.submitLabel || 'Continue';
  const cancelLabel = options.cancelLabel || 'Cancel';
  const defaultDuration = options.defaultDuration || 1;

  const durationSelector = options.showCacheDuration ? `
    <div class="password-modal-duration">
      <label for="password-modal-duration">Remember Account Key for:</label>
      <select id="password-modal-duration" class="password-modal-select">
        <option value="1" ${defaultDuration === 1 ? 'selected' : ''}>1 hour</option>
        <option value="2" ${defaultDuration === 2 ? 'selected' : ''}>2 hours</option>
        <option value="3" ${defaultDuration === 3 ? 'selected' : ''}>3 hours</option>
        <option value="4" ${defaultDuration === 4 ? 'selected' : ''}>4 hours</option>
        <option value="0">Don't remember</option>
      </select>
    </div>
  ` : '';

  return `
    <div id="${MODAL_OVERLAY_ID}" class="password-modal-overlay">
      <div id="${MODAL_ID}" class="password-modal" role="dialog" aria-modal="true" aria-labelledby="password-modal-title">
        <div class="password-modal-header">
          <h2 id="password-modal-title">${escapeHtml(options.title)}</h2>
          <button type="button" class="password-modal-close" aria-label="Close" id="password-modal-close-btn">
            <span aria-hidden="true">&times;</span>
          </button>
        </div>
        <div class="password-modal-body">
          <p class="password-modal-message">${escapeHtml(options.message)}</p>
          <form id="password-modal-form" class="password-modal-form">
            <div class="password-modal-field">
              <label for="password-modal-input">Account Password</label>
              <input 
                type="password" 
                id="password-modal-input" 
                class="password-modal-input"
                autocomplete="current-password"
                required
                autofocus
              />
            </div>
            ${durationSelector}
          </form>
        </div>
        <div class="password-modal-footer">
          <button type="button" class="password-modal-btn password-modal-btn-cancel" id="password-modal-cancel-btn">
            ${escapeHtml(cancelLabel)}
          </button>
          <button type="submit" form="password-modal-form" class="password-modal-btn password-modal-btn-submit" id="password-modal-submit-btn">
            ${escapeHtml(submitLabel)}
          </button>
        </div>
      </div>
    </div>
  `;
}

// ============================================================================
// Modal CSS (injected once)
// ============================================================================

const MODAL_STYLES = `
  .password-modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    animation: password-modal-fade-in 0.2s ease-out;
  }

  @keyframes password-modal-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  .password-modal {
    background: var(--bg-primary, #1a1a2e);
    border: 1px solid var(--border-color, #333);
    border-radius: 8px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    max-width: 400px;
    width: 90%;
    max-height: 90vh;
    overflow: auto;
    animation: password-modal-slide-in 0.2s ease-out;
  }

  @keyframes password-modal-slide-in {
    from { transform: translateY(-20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }

  .password-modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color, #333);
  }

  .password-modal-header h2 {
    margin: 0;
    font-size: 1.25rem;
    color: var(--text-primary, #fff);
  }

  .password-modal-close {
    background: none;
    border: none;
    font-size: 1.5rem;
    color: var(--text-secondary, #888);
    cursor: pointer;
    padding: 0;
    line-height: 1;
    transition: color 0.2s;
  }

  .password-modal-close:hover {
    color: var(--text-primary, #fff);
  }

  .password-modal-body {
    padding: 20px;
  }

  .password-modal-message {
    margin: 0 0 20px 0;
    color: var(--text-secondary, #ccc);
    line-height: 1.5;
  }

  .password-modal-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .password-modal-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .password-modal-field label {
    font-size: 0.875rem;
    color: var(--text-secondary, #ccc);
  }

  .password-modal-input,
  .password-modal-select {
    padding: 10px 12px;
    border: 1px solid var(--border-color, #333);
    border-radius: 4px;
    background: var(--bg-secondary, #252540);
    color: var(--text-primary, #fff);
    font-size: 1rem;
    transition: border-color 0.2s;
  }

  .password-modal-input:focus,
  .password-modal-select:focus {
    outline: none;
    border-color: var(--accent-color, #6366f1);
  }

  .password-modal-duration {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .password-modal-duration label {
    font-size: 0.875rem;
    color: var(--text-secondary, #ccc);
  }

  .password-modal-footer {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    padding: 16px 20px;
    border-top: 1px solid var(--border-color, #333);
  }

  .password-modal-btn {
    padding: 10px 20px;
    border-radius: 4px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
  }

  .password-modal-btn-cancel {
    background: transparent;
    border: 1px solid var(--border-color, #333);
    color: var(--text-secondary, #ccc);
  }

  .password-modal-btn-cancel:hover {
    background: var(--bg-secondary, #252540);
    color: var(--text-primary, #fff);
  }

  .password-modal-btn-submit {
    background: var(--accent-color, #6366f1);
    border: 1px solid var(--accent-color, #6366f1);
    color: #fff;
  }

  .password-modal-btn-submit:hover {
    background: var(--accent-hover, #5558e3);
    border-color: var(--accent-hover, #5558e3);
  }

  .password-modal-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }
`;

let stylesInjected = false;

function injectStyles(): void {
  if (stylesInjected) return;
  
  const styleElement = document.createElement('style');
  styleElement.id = 'arkfile-password-modal-styles';
  styleElement.textContent = MODAL_STYLES;
  document.head.appendChild(styleElement);
  
  stylesInjected = true;
}

// ============================================================================
// Utility Functions
// ============================================================================

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ============================================================================
// Modal Functions
// ============================================================================

let currentResolve: ((result: PasswordPromptResult | null) => void) | null = null;
let currentReject: ((error: Error) => void) | null = null;

/**
 * Shows the password prompt modal
 * 
 * @param options - Modal configuration options
 * @returns Promise that resolves with the password and options, or null if cancelled
 */
export function showPasswordPrompt(options: PasswordPromptOptions): Promise<PasswordPromptResult | null> {
  return new Promise((resolve, reject) => {
    // Close any existing modal
    hidePasswordPrompt();
    
    // Inject styles if needed
    injectStyles();
    
    // Store resolve/reject for later
    currentResolve = resolve;
    currentReject = reject;
    
    // Create and insert modal
    const modalContainer = document.createElement('div');
    modalContainer.innerHTML = createModalHTML(options);
    document.body.appendChild(modalContainer.firstElementChild!);
    
    // Get elements
    const overlay = document.getElementById(MODAL_OVERLAY_ID);
    const form = document.getElementById('password-modal-form') as HTMLFormElement;
    const input = document.getElementById('password-modal-input') as HTMLInputElement;
    const cancelBtn = document.getElementById('password-modal-cancel-btn');
    const closeBtn = document.getElementById('password-modal-close-btn');
    const durationSelect = document.getElementById('password-modal-duration') as HTMLSelectElement | null;
    
    if (!overlay || !form || !input || !cancelBtn || !closeBtn) {
      reject(new Error('Failed to create password modal'));
      return;
    }
    
    // Focus input
    setTimeout(() => input.focus(), 100);
    
    // Handle form submission
    const handleSubmit = (e: Event) => {
      e.preventDefault();
      
      const password = input.value;
      if (!password) {
        input.focus();
        return;
      }
      
      let cacheDuration: CacheDurationHours | undefined;
      if (durationSelect) {
        const value = parseInt(durationSelect.value, 10);
        if (value >= 1 && value <= 4) {
          cacheDuration = value as CacheDurationHours;
        }
        // value of 0 means "don't remember" - cacheDuration stays undefined
      }
      
      hidePasswordPrompt();
      
      if (currentResolve) {
        currentResolve({
          password,
          cacheDuration,
        });
        currentResolve = null;
      }
    };
    
    // Handle cancel
    const handleCancel = () => {
      hidePasswordPrompt();
      
      if (currentResolve) {
        currentResolve(null);
        currentResolve = null;
      }
    };
    
    // Handle overlay click (close on background click)
    const handleOverlayClick = (e: Event) => {
      if (e.target === overlay) {
        handleCancel();
      }
    };
    
    // Handle escape key
    const handleKeydown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        handleCancel();
      }
    };
    
    // Add event listeners
    form.addEventListener('submit', handleSubmit);
    cancelBtn.addEventListener('click', handleCancel);
    closeBtn.addEventListener('click', handleCancel);
    overlay.addEventListener('click', handleOverlayClick);
    document.addEventListener('keydown', handleKeydown);
    
    // Store cleanup function
    (overlay as any)._cleanup = () => {
      form.removeEventListener('submit', handleSubmit);
      cancelBtn.removeEventListener('click', handleCancel);
      closeBtn.removeEventListener('click', handleCancel);
      overlay.removeEventListener('click', handleOverlayClick);
      document.removeEventListener('keydown', handleKeydown);
    };
  });
}

/**
 * Hides the password prompt modal
 */
export function hidePasswordPrompt(): void {
  const overlay = document.getElementById(MODAL_OVERLAY_ID);
  
  if (overlay) {
    // Run cleanup
    if ((overlay as any)._cleanup) {
      (overlay as any)._cleanup();
    }
    
    // Remove from DOM
    overlay.remove();
  }
  
  // Clear any pending promise
  if (currentResolve) {
    currentResolve(null);
    currentResolve = null;
  }
}

/**
 * Checks if the password modal is currently visible
 */
export function isPasswordPromptVisible(): boolean {
  return document.getElementById(MODAL_OVERLAY_ID) !== null;
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Shows a password prompt for Account Key re-entry (cache expired)
 * 
 * @returns Promise that resolves with password and cache duration, or null if cancelled
 */
export function promptForAccountKeyPassword(): Promise<PasswordPromptResult | null> {
  return showPasswordPrompt({
    title: 'Account Key Required',
    message: 'Your cached Account Key has expired. Please enter your account password again to continue.',
    showCacheDuration: true,
    defaultDuration: 1,
    submitLabel: 'Continue',
    cancelLabel: 'Cancel',
  });
}

/**
 * Shows a password prompt for initial Account Key caching (after login)
 * 
 * @returns Promise that resolves with cache duration preference, or null if cancelled
 */
export function promptForAccountKeyCaching(): Promise<PasswordPromptResult | null> {
  return showPasswordPrompt({
    title: 'Remember Account Key?',
    message: 'Remember your Account Key for this session? This allows you to encrypt and decrypt files without re-entering your password.',
    showCacheDuration: true,
    defaultDuration: 1,
    submitLabel: 'Remember',
    cancelLabel: 'Skip',
  });
}

/**
 * Result from the cache opt-in prompt (no password needed)
 */
export interface CacheOptInResult {
  /** Selected cache duration, or undefined if user declined */
  cacheDuration?: CacheDurationHours;
}

/**
 * Shows a lightweight opt-in dialog for Account Key caching after login.
 * Unlike showPasswordPrompt, this does NOT ask for a password — the caller
 * already has the password from the login flow.
 *
 * @returns Promise resolving to the chosen duration, or null if user skipped
 */
export function promptForCacheOptIn(): Promise<CacheOptInResult | null> {
  return new Promise((resolve) => {
    // Inject styles if needed
    injectStyles();

    const overlayId = 'arkfile-cache-optin-overlay';

    // Remove any existing overlay
    const existing = document.getElementById(overlayId);
    if (existing) existing.remove();

    const html = `
      <div id="${overlayId}" class="password-modal-overlay">
        <div class="password-modal" role="dialog" aria-modal="true" aria-labelledby="cache-optin-title">
          <div class="password-modal-header">
            <h2 id="cache-optin-title">Cache Account Key?</h2>
            <button type="button" class="password-modal-close" aria-label="Close" id="cache-optin-close-btn">
              <span aria-hidden="true">&times;</span>
            </button>
          </div>
          <div class="password-modal-body">
            <p class="password-modal-message">
              Cache your Account Key for this session so you can encrypt and
              decrypt files without re-entering your password each time.
              The key is protected in memory and cleared on logout or tab close.
            </p>
            <div class="password-modal-duration">
              <label for="cache-optin-duration">Remember for:</label>
              <select id="cache-optin-duration" class="password-modal-select">
                <option value="1" selected>1 hour</option>
                <option value="2">2 hours</option>
                <option value="3">3 hours</option>
                <option value="4">4 hours</option>
              </select>
            </div>
          </div>
          <div class="password-modal-footer">
            <button type="button" class="password-modal-btn password-modal-btn-cancel" id="cache-optin-skip-btn">
              Skip
            </button>
            <button type="button" class="password-modal-btn password-modal-btn-submit" id="cache-optin-ok-btn">
              Cache Key
            </button>
          </div>
        </div>
      </div>
    `;

    const container = document.createElement('div');
    container.innerHTML = html;
    document.body.appendChild(container.firstElementChild!);

    const overlay = document.getElementById(overlayId)!;
    const durationSelect = document.getElementById('cache-optin-duration') as HTMLSelectElement;
    const okBtn = document.getElementById('cache-optin-ok-btn')!;
    const skipBtn = document.getElementById('cache-optin-skip-btn')!;
    const closeBtn = document.getElementById('cache-optin-close-btn')!;

    const cleanup = () => { overlay.remove(); };

    const handleOk = () => {
      const val = parseInt(durationSelect.value, 10) as CacheDurationHours;
      cleanup();
      resolve({ cacheDuration: val });
    };

    const handleSkip = () => {
      cleanup();
      resolve(null);
    };

    okBtn.addEventListener('click', handleOk);
    skipBtn.addEventListener('click', handleSkip);
    closeBtn.addEventListener('click', handleSkip);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) handleSkip(); });
    document.addEventListener('keydown', function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        document.removeEventListener('keydown', onKey);
        handleSkip();
      }
    });
  });
}

// ============================================================================
// Exports
// ============================================================================

export const passwordModal = {
  showPasswordPrompt,
  hidePasswordPrompt,
  isPasswordPromptVisible,
  promptForAccountKeyPassword,
  promptForAccountKeyCaching,
};
