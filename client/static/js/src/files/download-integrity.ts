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

import { showError, showSuccess, showWarning, showInfo } from '../ui/messages.js';
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

const STREAMING_TIP =
  'This file streams to your download folder with chunk-bounded memory. Whole-file SHA-256 is checked as data flows, but a problem may only be detected after the file is saved. Use Verify File afterward if you need to re-check the saved copy.';

const BLOB_BUFFER_WARNING =
  'Service Worker streaming is unavailable. This download will buffer the complete decrypted file in the browser before saving. Large files may fail under browser memory or storage limits. Prefer a browser with Service Worker support, or use the arkfile-client CLI.';

const PARTIAL_DOWNLOAD_TIP =
  'Download was interrupted after streaming began. A partial file may already be in your downloads folder — delete it if incomplete, then try again.';

const SW_MISMATCH_TIP =
  'SHA-256 verification failed after the file was streamed to disk. Delete the downloaded file. Use Verify File with the expected digest below, or re-download.';

/**
 * True when Blob callers must not trigger a browser download.
 */
export function shouldBlockBlobDownload(hashVerification: HashVerification | undefined): boolean {
  return hashVerification === 'mismatch';
}

/** Surface SW streaming limits before/during a large SW download. */
export function showSwStreamingTip(): void {
  showInfo(STREAMING_TIP, 12000);
}

/** Warn that Blob path buffers full plaintext (no app size cap). */
export function showBlobBufferWarning(): void {
  showWarning(BLOB_BUFFER_WARNING);
}

/** Mid-stream SW/transport failure: partial file may exist. */
export function showPartialDownloadWarning(): void {
  showWarning(PARTIAL_DOWNLOAD_TIP);
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

  const heading = document.createElement('h3');
  heading.textContent = 'Download integrity';
  panel.appendChild(heading);

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
  const statusP = document.createElement('p');
  if (hv === 'match') {
    statusP.className = 'success-message';
    statusP.textContent = 'Inline verification: match';
  } else if (hv === 'mismatch') {
    statusP.className = 'error-message';
    statusP.textContent = 'Inline verification: mismatch';
  } else if (hv === 'skipped') {
    statusP.textContent = 'Inline verification: skipped (no expected digest).';
  } else if (hv === 'unavailable') {
    statusP.textContent = 'Inline verification: unavailable (stream did not complete).';
  } else {
    statusP.textContent = 'Inline verification: not reported.';
  }
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
    verifyBtn.textContent = 'Verify File…';
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
