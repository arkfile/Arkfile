/**
 * Download integrity UX helpers shared by owner download and anonymous share.
 *
 * Post-write verification limits (document for maintainers):
 *
 * - SW streaming: whole-file SHA-256 is computed as plaintext flows to the
 *   browser download manager. A mismatch is often known only after bytes may
 *   already be on disk. The app cannot un-download without buffering the full
 *   file first, which defeats streaming. Per-chunk AES-GCM still authenticates
 *   each chunk during decrypt. Same class of limit as CLI computeStreamingSHA256
 *   after write and offline decrypt-blob post-write checks.
 *
 * - Blob fallback: full plaintext is retained in browser Blob storage before
 *   trigger. Hash is checked before triggerBrowserDownloadFromUrl; on mismatch
 *   the Blob URL is revoked and download is not triggered. There is no
 *   Arkfile-imposed size cap; browser resources may still be insufficient.
 *
 * - CLI: verifies after writing to the output path; on mismatch returns an
 *   error but the file may already exist on disk.
 */

import { showError, showSuccess, showWarning, showInfo, dismissToast } from '../ui/messages.js';
import { closeNavInlinePanelsExcept } from '../ui/sections.js';
import { openVerifyFilePanel } from './verify-file.js';

export type HashVerification = 'skipped' | 'match' | 'mismatch' | 'unavailable';

export interface DownloadIntegrityResult {
  filename: string;
  /** Expected SHA-256 from decrypted metadata or share envelope. */
  expectedSha256?: string | undefined;
  /** Computed digest when available from inline verification. */
  computedSha256?: string | undefined;
  hashVerification?: HashVerification | undefined;
  streamedViaSw: boolean;
}

/** Blob-buffer warning only when SW is unavailable and the file is this large or larger. */
export const BLOB_BUFFER_WARN_BYTES = 250 * 1024 * 1024;

const MATCH_AUTO_HIDE_MS = 11000;

const STREAMING_TIP =
  'This file streams to your download folder with chunk-bounded memory. Whole-file SHA-256 is checked as data flows, but a problem may only be detected after the file is saved. Use Verify File afterward if you need to re-check the saved copy.';

const BLOB_BUFFER_WARNING =
  'Service Worker streaming is unavailable. This large download will buffer the complete decrypted file in the browser before saving, which may fail under memory or storage limits. Prefer a browser with Service Worker support, or use the arkfile-client CLI.';

const PARTIAL_DOWNLOAD_TIP =
  'Download was interrupted after streaming began. A partial file may already be in your downloads folder. Delete it if incomplete, then try again.';

const SW_MISMATCH_TIP =
  'SHA-256 verification failed after the file was streamed to disk. Delete the downloaded file. Use Verify File with the expected digest below, or re-download.';

let activeBlobWarningToast: HTMLElement | null = null;
const matchHideTimers = new Map<string, number>();

/**
 * True when Blob callers must not trigger a browser download.
 */
export function shouldBlockBlobDownload(hashVerification: HashVerification | undefined): boolean {
  return hashVerification === 'mismatch';
}

/** Whether a Blob-path size warrants a sticky buffer warning. */
export function shouldShowBlobBufferWarning(fileSizeBytes: number): boolean {
  return Number.isFinite(fileSizeBytes) && fileSizeBytes >= BLOB_BUFFER_WARN_BYTES;
}

/** Surface SW streaming limits before/during a large SW download. */
export function showSwStreamingTip(): void {
  showInfo(STREAMING_TIP, 12000);
}

/**
 * Warn that Blob path buffers full plaintext. Only for large files when size
 * is known. Sticky until dismissBlobBufferWarning or the user closes the toast.
 */
export function showBlobBufferWarning(fileSizeBytes?: number): void {
  if (fileSizeBytes !== undefined && !shouldShowBlobBufferWarning(fileSizeBytes)) {
    return;
  }
  dismissBlobBufferWarning();
  activeBlobWarningToast = showWarning(BLOB_BUFFER_WARNING);
}

/** Clear the Blob buffer warning toast if it is still showing. */
export function dismissBlobBufferWarning(): void {
  if (activeBlobWarningToast) {
    dismissToast(activeBlobWarningToast);
    activeBlobWarningToast = null;
  }
}

/** Mid-stream SW/transport failure: partial file may exist. */
export function showPartialDownloadWarning(): void {
  showWarning(PARTIAL_DOWNLOAD_TIP);
}

/** Hide and clear an integrity panel. */
export function hideDownloadIntegrityPanel(panelId: string): void {
  const existingTimer = matchHideTimers.get(panelId);
  if (existingTimer !== undefined) {
    window.clearTimeout(existingTimer);
    matchHideTimers.delete(panelId);
  }
  const panel = document.getElementById(panelId);
  if (!panel) return;
  panel.classList.add('hidden');
  panel.innerHTML = '';
}

function scheduleMatchAutoHide(panelId: string, isMatch: boolean): void {
  const existingTimer = matchHideTimers.get(panelId);
  if (existingTimer !== undefined) {
    window.clearTimeout(existingTimer);
    matchHideTimers.delete(panelId);
  }
  if (!isMatch) return;
  const timerId = window.setTimeout(() => {
    hideDownloadIntegrityPanel(panelId);
  }, MATCH_AUTO_HIDE_MS);
  matchHideTimers.set(panelId, timerId);
}

function checksumStatusText(hv: HashVerification | undefined): { text: string; className: string } {
  if (hv === 'match') {
    return { text: 'File checksum: OK', className: 'success-message' };
  }
  if (hv === 'mismatch') {
    return { text: 'File checksum: Warning', className: 'error-message' };
  }
  if (hv === 'skipped') {
    return { text: 'File checksum: Not checked (no expected digest).', className: '' };
  }
  if (hv === 'unavailable') {
    return { text: 'File checksum: Not checked (download incomplete).', className: '' };
  }
  return { text: 'File checksum: Not reported.', className: '' };
}

/**
 * Render or update an inline integrity panel (expected digest, inline result,
 * Verify File entry). Works for main app (#download-integrity-panel) and share
 * page (#share-integrity-panel).
 */
export function renderDownloadIntegrityPanel(
  panelId: string,
  result: DownloadIntegrityResult,
): void {
  const panel = document.getElementById(panelId);
  if (!panel) return;

  panel.classList.remove('hidden');
  // Main-app integrity panel shares absolute positioning with other nav panels.
  if (panelId === 'download-integrity-panel') {
    closeNavInlinePanelsExcept('download-integrity-panel');
  }
  panel.innerHTML = '';

  const header = document.createElement('div');
  header.style.display = 'flex';
  header.style.alignItems = 'center';
  header.style.justifyContent = 'space-between';
  header.style.gap = '0.5rem';
  header.style.marginBottom = '0.5rem';

  const heading = document.createElement('h3');
  heading.textContent = 'Download integrity';
  heading.style.margin = '0';
  header.appendChild(heading);

  const closeBtn = document.createElement('button');
  closeBtn.type = 'button';
  closeBtn.className = 'password-modal-close';
  closeBtn.setAttribute('aria-label', 'Close');
  closeBtn.innerHTML = '&times;';
  closeBtn.style.background = 'none';
  closeBtn.style.border = 'none';
  closeBtn.style.color = 'var(--foam-2)';
  closeBtn.style.fontSize = '1.5rem';
  closeBtn.style.lineHeight = '1';
  closeBtn.style.cursor = 'pointer';
  closeBtn.style.padding = '0 0.25rem';
  closeBtn.addEventListener('click', () => {
    hideDownloadIntegrityPanel(panelId);
  });
  header.appendChild(closeBtn);
  panel.appendChild(header);

  const nameP = document.createElement('p');
  nameP.textContent = `File: ${result.filename}`;
  panel.appendChild(nameP);

  if (result.expectedSha256) {
    const digestRow = document.createElement('div');
    digestRow.className = 'setting-item';
    const label = document.createElement('p');
    label.innerHTML = '<strong>Expected SHA-256</strong>';
    digestRow.appendChild(label);

    const code = document.createElement('code');
    code.id = `${panelId}-expected-digest`;
    code.style.wordBreak = 'break-all';
    code.style.fontSize = '0.85rem';
    code.textContent = result.expectedSha256;
    digestRow.appendChild(code);

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn-copy-hash';
    copyBtn.textContent = 'copy';
    copyBtn.style.marginLeft = '0.5rem';
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(result.expectedSha256!);
        showSuccess('SHA-256 copied to clipboard!');
      } catch {
        showError('Could not copy to clipboard.');
      }
    });
    digestRow.appendChild(copyBtn);
    panel.appendChild(digestRow);
  }

  const hv = result.hashVerification;
  const status = checksumStatusText(hv);
  const statusP = document.createElement('p');
  if (status.className) {
    statusP.className = status.className;
  }
  statusP.textContent = status.text;
  panel.appendChild(statusP);

  if (hv === 'mismatch' && result.computedSha256) {
    const computed = document.createElement('p');
    computed.style.fontFamily = 'monospace';
    computed.style.wordBreak = 'break-all';
    computed.style.fontSize = '0.85rem';
    computed.textContent = `Computed: ${result.computedSha256}`;
    panel.appendChild(computed);
  }

  if (result.streamedViaSw && hv === 'mismatch') {
    const tip = document.createElement('p');
    tip.className = 'warning-note';
    tip.textContent = SW_MISMATCH_TIP;
    panel.appendChild(tip);
  } else if (result.streamedViaSw) {
    const tip = document.createElement('p');
    tip.className = 'warning-note';
    tip.textContent =
      'Service Worker path: if you need certainty about the file on disk, compare this expected digest with Verify File or an offline tool.';
    panel.appendChild(tip);
  }

  if (result.expectedSha256) {
    const verifyBtn = document.createElement('button');
    verifyBtn.type = 'button';
    verifyBtn.className = 'secondary-button';
    verifyBtn.id = `${panelId}-open-verify-btn`;
    verifyBtn.textContent = 'Verify File...';
    verifyBtn.addEventListener('click', (e) => {
      e.preventDefault();
      openVerifyFilePanel(result.expectedSha256);
      const mainPanel = document.getElementById('verify-file-panel');
      if (mainPanel) {
        mainPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    });
    panel.appendChild(verifyBtn);
  }

  scheduleMatchAutoHide(panelId, hv === 'match');
}

/**
 * Finalize owner/share download messaging after a successful stream or Blob assemble.
 * Callers must check Blob mismatch and revoke before calling trigger when blocked.
 *
 * Returns true if the caller may claim success (and for Blob, may trigger download).
 */
export function finalizeDownloadIntegrity(
  result: DownloadIntegrityResult,
  panelId: string,
): { allowSuccess: boolean; blockBlobTrigger: boolean } {
  renderDownloadIntegrityPanel(panelId, result);

  if (result.streamedViaSw) {
    if (result.hashVerification === 'mismatch') {
      // Never showSuccess on SW mismatch.
      showError(
        `Integrity check failed for ${result.filename}. Delete the downloaded file and verify or re-download.`,
      );
      showWarning(SW_MISMATCH_TIP);
      return { allowSuccess: false, blockBlobTrigger: false };
    }
    showSuccess(`Downloaded: ${result.filename}`);
    return { allowSuccess: true, blockBlobTrigger: false };
  }

  // Blob path
  if (shouldBlockBlobDownload(result.hashVerification)) {
    showError(
      `Integrity check failed for ${result.filename}. Download was not started. The decrypted data did not match the expected SHA-256.`,
    );
    return { allowSuccess: false, blockBlobTrigger: true };
  }

  showSuccess(`Downloaded: ${result.filename}`);
  return { allowSuccess: true, blockBlobTrigger: false };
}
