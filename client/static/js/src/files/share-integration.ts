/**
 * Share Integration Module
 * Phase 6F: Integrates share creation with file list
 */

import { ShareCreator, type ShareCreationRequest, type FileInfo } from '../shares/share-creation.js';
import { ShareCrypto } from '../shares/share-crypto.js';
import { authenticatedFetch } from '../utils/auth.js';
import { showError, showSuccess } from '../ui/messages.js';

let currentShareForm: HTMLElement | null = null;
let currentShareCreator: ShareCreator | null = null;

/**
 * Shows inline share creation form for a file
 */
export async function showShareForm(filename: string, fileId: string): Promise<void> {
  try {
    // Hide any existing share form
    hideCurrentShareForm();

    // Find the file item in the DOM
    const fileItems = document.querySelectorAll('.file-item');
    let targetFileItem: HTMLElement | null = null;

    for (const item of fileItems) {
      const fileInfo = item.querySelector('.file-info strong');
      if (fileInfo && fileInfo.textContent === filename) {
        targetFileItem = item as HTMLElement;
        break;
      }
    }

    if (!targetFileItem) {
      showError('Could not find file in list');
      return;
    }

    // Get file encryption key for share creation
    const fileInfo = await getFileInfo(filename, fileId);
    if (!fileInfo) {
      showError('Could not retrieve file information');
      return;
    }

    // Create share form
    const shareForm = createShareForm(filename, fileId);
    
    // Insert form after the file item
    targetFileItem.insertAdjacentElement('afterend', shareForm);
    currentShareForm = shareForm;

    // Initialize share creator
    currentShareCreator = new ShareCreator(fileInfo);

    // Focus on password input
    const passwordInput = shareForm.querySelector('#share-password') as HTMLInputElement;
    if (passwordInput) {
      passwordInput.focus();
    }

  } catch (error) {
    console.error('Error showing share form:', error);
    showError('Failed to show share form');
  }
}

/**
 * Creates the inline share form HTML
 */
function createShareForm(filename: string, fileId: string): HTMLElement {
  const formDiv = document.createElement('div');
  formDiv.className = 'share-form-container';
  formDiv.innerHTML = `
    <div class="card">
      <h3>Share "${escapeHtml(filename)}"</h3>
      
      <div class="form-group">
        <label for="share-password">Share Password:</label>
        <input type="password" id="share-password" placeholder="Enter a strong password (18+ characters)" 
               minlength="18" required>
        <div id="password-strength" class="password-strength"></div>
        <small>This password will be required to access the shared file.</small>
      </div>

      <div class="form-actions">
        <button type="button" id="create-share-btn" class="btn primary" disabled>
          Create Share
        </button>
        <button type="button" id="cancel-share-btn" class="btn secondary">
          Cancel
        </button>
      </div>

      <div id="share-status" class="hidden"></div>
      <div id="share-progress" class="hidden">
        <div class="progress-bar">
          <div class="progress-bar-fill"></div>
        </div>
        <span>Creating secure share...</span>
      </div>
    </div>
  `;

  // Set up event listeners
  setupShareFormEventListeners(formDiv, fileId);

  return formDiv;
}

/**
 * Sets up event listeners for the share form
 */
function setupShareFormEventListeners(formDiv: HTMLElement, fileId: string): void {
  const passwordInput = formDiv.querySelector('#share-password') as HTMLInputElement;
  const createButton = formDiv.querySelector('#create-share-btn') as HTMLButtonElement;
  const cancelButton = formDiv.querySelector('#cancel-share-btn') as HTMLButtonElement;

  // Password input validation
  passwordInput?.addEventListener('input', () => {
    handlePasswordInput(formDiv);
  });

  // Create share button
  createButton?.addEventListener('click', () => {
    handleCreateShare(formDiv, fileId);
  });

  // Cancel button
  cancelButton?.addEventListener('click', () => {
    hideCurrentShareForm();
  });
}

/**
 * Handles real-time password validation
 */
function handlePasswordInput(formDiv: HTMLElement): void {
  if (!currentShareCreator) return;

  const passwordInput = formDiv.querySelector('#share-password') as HTMLInputElement;
  const strengthDiv = formDiv.querySelector('#password-strength') as HTMLElement;
  const createButton = formDiv.querySelector('#create-share-btn') as HTMLButtonElement;

  const password = passwordInput.value;

  if (!password) {
    strengthDiv.innerHTML = '';
    createButton.disabled = true;
    return;
  }

  const validation = currentShareCreator.validatePassword(password);
  
  // Update strength indicator
  const strengthClass = getStrengthClass(validation.strength_score);
  const strengthText = getStrengthText(validation.strength_score);
  
  strengthDiv.innerHTML = `
    <div class="strength-meter ${strengthClass}">
      ${strengthText}
    </div>
    ${validation.feedback.length > 0 ? `<div class="feedback">${validation.feedback.join('. ')}</div>` : ''}
  `;

  // Update create button state
  createButton.disabled = !validation.meets_requirements;
}

/**
 * Handles share creation
 */
async function handleCreateShare(formDiv: HTMLElement, fileId: string): Promise<void> {
  if (!currentShareCreator) return;

  const passwordInput = formDiv.querySelector('#share-password') as HTMLInputElement;
  const createButton = formDiv.querySelector('#create-share-btn') as HTMLButtonElement;
  const statusDiv = formDiv.querySelector('#share-status') as HTMLElement;
  const progressDiv = formDiv.querySelector('#share-progress') as HTMLElement;

  const password = passwordInput.value;

  // Show progress
  progressDiv.classList.remove('hidden');
  statusDiv.classList.add('hidden');
  createButton.disabled = true;

  try {
    const shareRequest: ShareCreationRequest = {
      fileId: fileId,
      sharePassword: password
    };

    const result = await currentShareCreator.createShare(shareRequest);

    progressDiv.classList.add('hidden');

    if (result.success && result.shareUrl) {
      showShareSuccess(formDiv, result.shareUrl);
    } else {
      showShareError(formDiv, result.error || 'Failed to create share');
    }

  } catch (error) {
    progressDiv.classList.add('hidden');
    showShareError(formDiv, 'Network error occurred');
    console.error('Share creation error:', error);
  } finally {
    createButton.disabled = false;
  }
}

/**
 * Shows share creation success with copyable URL
 */
function showShareSuccess(formDiv: HTMLElement, shareUrl: string): void {
  const statusDiv = formDiv.querySelector('#share-status') as HTMLElement;
  
  statusDiv.innerHTML = `
    <div class="success-message">
      <h4>Share Created Successfully!</h4>
      <div class="share-url-group">
        <label>Share URL:</label>
        <div class="url-copy-container">
          <input type="text" value="${shareUrl}" readonly id="share-url-input">
          <button type="button" id="copy-url-btn">Copy</button>
        </div>
      </div>
      <p><small><strong>Important:</strong> Save this URL and password. They cannot be recovered if lost.</small></p>
    </div>
  `;
  
  statusDiv.classList.remove('hidden');

  // Set up copy button
  const copyButton = statusDiv.querySelector('#copy-url-btn') as HTMLButtonElement;
  const urlInput = statusDiv.querySelector('#share-url-input') as HTMLInputElement;

  copyButton?.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(shareUrl);
      copyButton.textContent = 'Copied!';
      setTimeout(() => {
        copyButton.textContent = 'Copy';
      }, 2000);
    } catch (error) {
      // Fallback for older browsers
      urlInput.select();
      document.execCommand('copy');
      copyButton.textContent = 'Copied!';
      setTimeout(() => {
        copyButton.textContent = 'Copy';
      }, 2000);
    }
  });
}

/**
 * Shows share creation error
 */
function showShareError(formDiv: HTMLElement, error: string): void {
  const statusDiv = formDiv.querySelector('#share-status') as HTMLElement;
  
  statusDiv.innerHTML = `
    <div class="error-message">
      <p><strong>Error:</strong> ${escapeHtml(error)}</p>
    </div>
  `;
  
  statusDiv.classList.remove('hidden');
}

/**
 * Retrieves file information needed for share creation
 */
async function getFileInfo(filename: string, fileId: string): Promise<FileInfo | null> {
  try {
    // Get the file's FEK by downloading it (but we only need the key)
    const response = await authenticatedFetch(`/api/files/${encodeURIComponent(filename)}/download`);
    
    if (!response.ok) {
      throw new Error(`Failed to get file info: ${response.status}`);
    }

    const data = await response.json();
    
    if (!data.encryptedFEK) {
      throw new Error('File encryption key not available');
    }

    return {
      filename: filename,
      fek: data.encryptedFEK
    };

  } catch (error) {
    console.error('Error getting file info:', error);
    return null;
  }
}

/**
 * Hides the current share form
 */
function hideCurrentShareForm(): void {
  if (currentShareForm) {
    currentShareForm.remove();
    currentShareForm = null;
  }
  currentShareCreator = null;
}

/**
 * Gets CSS class for password strength
 */
function getStrengthClass(score: number): string {
  if (score === 0) return 'very-weak';
  if (score === 1) return 'weak';
  if (score === 2) return 'moderate';
  if (score === 3) return 'strong';
  return 'very-strong';
}

/**
 * Gets text description for password strength
 */
function getStrengthText(score: number): string {
  if (score === 0) return 'Very Weak';
  if (score === 1) return 'Weak';
  if (score === 2) return 'Moderate';
  if (score === 3) return 'Strong';
  return 'Very Strong';
}

/**
 * Escapes HTML to prevent XSS
 */
function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
