/**
 * Share List UI Module
 * 
 * Manages the display and interaction with file shares.
 * Provides UI for viewing share status, copying URLs, and revoking shares.
 */

import { getToken, getUsernameFromToken } from '../utils/auth.js';
import { showError, showSuccess } from '../ui/messages.js';
import { getCachedAccountKey } from '../crypto/file-encryption.js';
import { decryptMetadataField } from '../crypto/metadata-helpers.js';

// ============================================================================
// Types
// ============================================================================

interface Share {
  share_id: string;
  file_id: string;
  share_url: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
  access_count: number;
  max_accesses: number | null;
  size: number | null;
  is_active: boolean;

  // Added client-side during enrichment
  filename_local?: string;
  sha256_local?: string;
  password_type?: string;
  metadata_decrypted?: boolean;
}

interface ShareListResponse {
  shares: Share[];
}

interface MetadataBatchResponse {
  files: Record<string, {
    file_id: string;
    password_type: string;
    filename_nonce: string;
    encrypted_filename: string;
    sha256sum_nonce: string;
    encrypted_sha256sum: string;
    size_bytes: number;
    upload_date: string;
  }>;
  missing: string[];
}

// ============================================================================
// Share List UI Class
// ============================================================================

export class ShareListUI {
  private container: HTMLElement;
  private shares: Share[] = [];

  constructor(containerId: string) {
    const container = document.getElementById(containerId);
    if (!container) {
      throw new Error(`Container element with id '${containerId}' not found`);
    }
    this.container = container;
  }


  /**
   * Loads and displays the share list
   */
  async loadShares(): Promise<void> {
    try {
      const response = await fetch('/api/shares', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${getToken()}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Authentication required. Please log in.');
        }
        throw new Error(`Failed to load shares: ${response.statusText}`);
      }

      const data: ShareListResponse = await response.json();
      
      // Enrich the shares with batched file metadata
      const rawShares = data.shares || [];
      this.shares = await this.enrichShares(rawShares);
      
      this.renderShares();
    } catch (error) {
      console.error('Failed to load shares:', error);
      showError(error instanceof Error ? error.message : 'Failed to load shares');
      this.container.innerHTML = '<p class="error">Failed to load shares. Please try again.</p>';
    }
  }

  /**
   * Enrich share records with batch metadata lookup and local decryption
   */
  private async enrichShares(shares: Share[]): Promise<Share[]> {
    if (!shares || shares.length === 0) return shares;

    // Extract unique file IDs
    const fileIds = [...new Set(shares.map(s => s.file_id))].filter(Boolean);
    if (fileIds.length === 0) return shares;

    try {
      // Fetch batch metadata
      const token = getToken();
      const response = await fetch('/api/files/metadata/batch', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ file_ids: fileIds }),
      });

      if (!response.ok) {
        console.warn('Failed to fetch batch metadata:', response.status);
        return shares;
      }

      const data: MetadataBatchResponse = await response.json();
      const metadataMap = data.files || {};

      // Get account key for local decryption
      const username = getUsernameFromToken();
      let accountKey: Uint8Array | null = null;
      if (username && token) {
        accountKey = await getCachedAccountKey(username, token);
      }

      // Merge and decrypt
      return await Promise.all(shares.map(async share => {
        const enrichedShare = { ...share };
        const meta = metadataMap[share.file_id];

        if (meta) {
          enrichedShare.password_type = meta.password_type;
          if (meta.size_bytes > 0) enrichedShare.size = meta.size_bytes;

          if (accountKey) {
            try {
              enrichedShare.filename_local = await decryptMetadataField(meta.encrypted_filename, meta.filename_nonce, accountKey);
              enrichedShare.sha256_local = await decryptMetadataField(meta.encrypted_sha256sum, meta.sha256sum_nonce, accountKey);
              enrichedShare.metadata_decrypted = true;
            } catch (err) {
              console.warn(`Failed to decrypt metadata for file ${share.file_id}`, err);
            }
          }
        }
        return enrichedShare;
      }));
    } catch (err) {
      console.warn('Failed to enrich shares:', err);
      return shares;
    }
  }

  /**
   * Renders the share list
   */
  private renderShares(): void {
    if (!this.shares || this.shares.length === 0) {
      this.container.innerHTML = `
        <div class="empty-state">
          <p>No shares found</p>
          <p class="hint">Create a share to get started</p>
        </div>
      `;
      return;
    }

    const html = `
      <div class="share-list">
        ${this.shares.map(share => this.renderShareItem(share)).join('')}
      </div>
    `;
    
    this.container.innerHTML = html;
    this.attachEventListeners();
  }

  /**
   * Renders a single share item
   */
  private renderShareItem(share: Share): string {
    const statusClass = share.is_active ? 'status-active' : 'status-revoked';
    const statusText = share.is_active ? 'Active' : `Revoked: ${share.revoked_reason || 'Unknown'}`;
    
    const accessText = share.max_accesses !== null
      ? `${share.access_count} / ${share.max_accesses} downloads`
      : `${share.access_count} downloads (unlimited)`;
    
    const expiresText = share.expires_at
      ? `Expires: ${new Date(share.expires_at).toLocaleString()}`
      : 'Never expires';
    
    const createdText = `Created: ${new Date(share.created_at).toLocaleString()}`;
    
    const sizeText = share.size !== null
      ? `Size: ${this.formatFileSize(share.size)}`
      : '';

    const filenameDisplay = share.filename_local 
      ? share.filename_local 
      : '<span class="status-encrypted">[Encrypted]</span>';

    const isExhausted = share.max_accesses !== null && share.access_count >= share.max_accesses && share.max_accesses > 0;
    const isExpired = share.expires_at !== null && new Date(share.expires_at) < new Date();
    const inactiveBadge = !share.is_active
      ? `<span class="share-inactive-badge">${share.revoked_at ? 'Revoked' : 'Expired'}</span>`
      : isExhausted
        ? `<span class="share-inactive-badge">Exhausted</span>`
        : isExpired
          ? `<span class="share-inactive-badge">Expired</span>`
          : '';
      
    const sha256Display = share.sha256_local
      ? `<div class="stat-item stat-item-hash">
           <span class="stat-label">SHA-256:</span>
           <span class="stat-value hash-value" title="${share.sha256_local}">${share.sha256_local}</span>
           <button class="btn-copy-hash" data-hash="${share.sha256_local}" title="Copy SHA-256 to clipboard">Copy</button>
         </div>`
      : '';
      
    const pwdTypeDisplay = share.password_type
      ? `<div class="stat-item"><span class="stat-label">Key Type:</span><span class="stat-value type-badge ${share.password_type === 'custom' ? 'type-custom' : 'type-account'}">${share.password_type}</span></div>`
      : '';

    // Truncate share_id for display
    const shareIdShort = share.share_id.substring(0, 8);

    return `
      <div class="share-item" data-share-id="${share.share_id}">
        <div class="share-header">
          <div class="share-title">
            <h3>${filenameDisplay}${inactiveBadge}</h3>
          </div>
          <div class="share-status-badge ${statusClass}">${statusText}</div>
        </div>
        
        <div class="share-details">
          <div class="share-url-section">
            <label>Share URL:</label>
            <div class="url-input-group">
              <input 
                type="text" 
                readonly 
                value="${share.share_url}" 
                class="share-url-input"
                id="url-${share.share_id}"
                onclick="this.select()"
              />
              <button 
                class="btn-copy" 
                data-share-id="${share.share_id}"
                title="Copy to clipboard"
              >
                Copy
              </button>
            </div>
          </div>
          
          <div class="share-stats">
            <div class="stat-item">
              <span class="stat-label">Downloads:</span>
              <span class="stat-value">${accessText}</span>
            </div>
            <div class="stat-item">
              <span class="stat-label">Expiration:</span>
              <span class="stat-value">${expiresText}</span>
            </div>
            <div class="stat-item">
              <span class="stat-label">Created:</span>
              <span class="stat-value">${createdText}</span>
            </div>
            ${sizeText ? `
              <div class="stat-item">
                <span class="stat-label">${sizeText}</span>
              </div>
            ` : ''}
            ${pwdTypeDisplay}
            ${sha256Display}
            <div class="stat-item"><span class="stat-label">ID:</span><span class="stat-value" title="${share.share_id}">${shareIdShort}...</span></div>
          </div>
        </div>
        
        ${share.is_active ? `
          <div class="share-actions">
            <button 
              class="btn-revoke" 
              data-share-id="${share.share_id}"
            >
              Revoke Share
            </button>
          </div>
        ` : ''}
      </div>
    `;
  }

  /**
   * Attaches event listeners to share items
   */
  private attachEventListeners(): void {
    // Copy button listeners
    const copyButtons = this.container.querySelectorAll('.btn-copy');
    copyButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        const shareId = (e.target as HTMLElement).getAttribute('data-share-id');
        if (shareId) {
          this.copyShareURL(shareId);
        }
      });
    });

    // Copy hash button listeners
    const copyHashButtons = this.container.querySelectorAll('.btn-copy-hash');
    copyHashButtons.forEach(button => {
      button.addEventListener('click', async (e) => {
        const hash = (e.target as HTMLElement).getAttribute('data-hash');
        if (hash) {
          try {
            await navigator.clipboard.writeText(hash);
            showSuccess('SHA-256 copied to clipboard!');
          } catch {
            showError('Please copy the hash manually');
          }
        }
      });
    });

    // Revoke button listeners
    const revokeButtons = this.container.querySelectorAll('.btn-revoke');
    revokeButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        const shareId = (e.target as HTMLElement).getAttribute('data-share-id');
        if (shareId) {
          this.revokeShare(shareId);
        }
      });
    });
  }

  /**
   * Copies share URL to clipboard
   */
  private async copyShareURL(shareId: string): Promise<void> {
    const input = document.getElementById(`url-${shareId}`) as HTMLInputElement;
    if (!input) return;

    try {
      await navigator.clipboard.writeText(input.value);
      showSuccess('Share URL copied to clipboard!');
    } catch (error) {
      console.error('Failed to copy URL:', error);
      // Fallback: select the text
      input.select();
      showError('Please copy the URL manually (Ctrl+C)');
    }
  }

  /**
   * Revokes a share
   */
  private async revokeShare(shareId: string): Promise<void> {
    const confirmed = confirm(
      'Are you sure you want to revoke this share?\n\n' +
      'This will immediately prevent anyone from accessing the file using this share link.\n\n' +
      'This action cannot be undone.'
    );

    if (!confirmed) {
      return;
    }

    try {
      const response = await fetch(`/api/shares/${shareId}/revoke`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${getToken()}`,
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Authentication required. Please log in.');
        }
        if (response.status === 403) {
          throw new Error('You do not have permission to revoke this share.');
        }
        if (response.status === 404) {
          throw new Error('Share not found.');
        }
        throw new Error(`Failed to revoke share: ${response.statusText}`);
      }

      showSuccess('Share revoked successfully');
      
      // Reload the share list to reflect changes
      await this.loadShares();
    } catch (error) {
      console.error('Failed to revoke share:', error);
      showError(error instanceof Error ? error.message : 'Failed to revoke share. Please try again.');
    }
  }

  /**
   * Formats file size for display
   */
  private formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  }

  /**
   * Refreshes the share list
   */
  async refresh(): Promise<void> {
    await this.loadShares();
  }
}

// ============================================================================
// Initialization Function
// ============================================================================

/**
 * Initialize the share list UI
 */
export async function initializeShareList(): Promise<void> {
  const shareList = new ShareListUI('sharesList');
  await shareList.loadShares();
  
  // Set up refresh button
  const refreshBtn = document.getElementById('refresh-shares-btn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      await shareList.refresh();
    });
  }
}

// ============================================================================
// Exports
// ============================================================================

export default ShareListUI;
