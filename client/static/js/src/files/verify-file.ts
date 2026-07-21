/**
 * Verify File tool — hash a local file and compare to an expected SHA-256.
 *
 * Uses computeStreamingSHA256 so peak memory stays near one chunk regardless of
 * file size. Works offline once the expected digest is known. Does not log
 * digest values in production info paths.
 */

import { computeStreamingSHA256, normalizeSha256Hex, constantTimeHexEqual } from '../crypto/streaming-hash.js';
import { getChunkingParams } from '../crypto/constants.js';
import { showError, showSuccess } from '../ui/messages.js';
import { showProgress, updateProgress, hideProgress } from '../ui/progress.js';

export type VerifyFileOutcome = 'match' | 'mismatch' | 'invalid_expected' | 'cancelled' | 'error';

export interface VerifyLocalFileDigestResult {
  outcome: VerifyFileOutcome;
  computedHex?: string;
  expectedHex?: string;
  error?: string;
}

/**
 * Hash a user-picked File and compare to an expected SHA-256 hex digest.
 */
export async function verifyLocalFileDigest(
  file: File,
  expectedDigest: string,
  options?: {
    onProgress?: (bytesHashed: number, totalBytes: number) => void;
    chunkSize?: number;
  },
): Promise<VerifyLocalFileDigestResult> {
  const expectedHex = normalizeSha256Hex(expectedDigest);
  if (!expectedHex) {
    return { outcome: 'invalid_expected' };
  }

  try {
    let chunkSize = options?.chunkSize;
    if (!chunkSize) {
      const cfg = await getChunkingParams();
      chunkSize = cfg.plaintextChunkSizeBytes;
    }

    const computedHex = await computeStreamingSHA256(file, chunkSize, options?.onProgress);
    const match = constantTimeHexEqual(computedHex, expectedHex);
    return {
      outcome: match ? 'match' : 'mismatch',
      computedHex,
      expectedHex,
    };
  } catch (err) {
    return {
      outcome: 'error',
      error: err instanceof Error ? err.message : 'Verification failed',
    };
  }
}

/** Close sibling nav panels except the given id. */
function closeSiblingPanels(keep: string): void {
  for (const id of ['security-settings', 'contact-info-panel', 'billing-panel', 'verify-file-panel']) {
    if (id === keep) continue;
    const el = document.getElementById(id);
    if (el && !el.classList.contains('hidden')) {
      el.classList.add('hidden');
    }
  }
}

/**
 * Open the Verify File panel, optionally pre-filling the expected digest
 * (e.g. from a download completion panel).
 */
export function openVerifyFilePanel(expectedDigest?: string): void {
  const panel = document.getElementById('verify-file-panel');
  if (!panel) return;

  panel.classList.remove('hidden');
  closeSiblingPanels('verify-file-panel');

  const expectedInput = document.getElementById('verify-file-expected') as HTMLInputElement | null;
  if (expectedInput && expectedDigest) {
    const normalized = normalizeSha256Hex(expectedDigest);
    expectedInput.value = normalized ?? expectedDigest.trim();
  }

  const resultEl = document.getElementById('verify-file-result');
  if (resultEl) {
    resultEl.textContent = '';
    resultEl.className = '';
  }
}

/** Toggle the Verify File panel. */
export function toggleVerifyFilePanel(): void {
  const panel = document.getElementById('verify-file-panel');
  if (!panel) return;
  const opening = panel.classList.contains('hidden');
  panel.classList.toggle('hidden');
  if (opening) {
    closeSiblingPanels('verify-file-panel');
  }
}

/**
 * Wire Verify File panel controls. Safe to call once at app init.
 */
export function wireVerifyFilePanel(): void {
  const runBtn = document.getElementById('verify-file-run-btn');
  if (!runBtn || (runBtn as HTMLElement).dataset['wired'] === '1') return;
  (runBtn as HTMLElement).dataset['wired'] = '1';

  runBtn.addEventListener('click', async (e) => {
    e.preventDefault();
    await runVerifyFromPanel();
  });
}

async function runVerifyFromPanel(): Promise<void> {
  const fileInput = document.getElementById('verify-file-input') as HTMLInputElement | null;
  const expectedInput = document.getElementById('verify-file-expected') as HTMLInputElement | null;
  const resultEl = document.getElementById('verify-file-result');

  const file = fileInput?.files?.[0];
  if (!file) {
    showError('Choose a local file to verify.');
    return;
  }
  const expectedRaw = expectedInput?.value ?? '';
  if (!expectedRaw.trim()) {
    showError('Paste the expected SHA-256 hex digest.');
    return;
  }

  if (resultEl) {
    resultEl.textContent = 'Hashing…';
    resultEl.className = '';
  }

  showProgress({
    title: 'Verifying File',
    message: 'Computing SHA-256…',
    percentage: 0,
  });

  const result = await verifyLocalFileDigest(file, expectedRaw, {
    onProgress: (bytesHashed, totalBytes) => {
      const pct = totalBytes > 0 ? (bytesHashed / totalBytes) * 100 : 100;
      updateProgress({
        title: 'Verifying File',
        message: `Hashing… ${Math.round(pct)}%`,
        percentage: pct,
      });
    },
  });

  hideProgress();

  if (result.outcome === 'invalid_expected') {
    if (resultEl) {
      resultEl.textContent = 'Expected digest must be 64 hexadecimal characters.';
      resultEl.className = 'error-message';
    }
    showError('Expected SHA-256 must be 64 hex characters.');
    return;
  }

  if (result.outcome === 'error') {
    if (resultEl) {
      resultEl.textContent = result.error || 'Verification failed.';
      resultEl.className = 'error-message';
    }
    showError(result.error || 'Verification failed.');
    return;
  }

  if (result.outcome === 'match') {
    if (resultEl) {
      resultEl.textContent = 'Match: the local file SHA-256 matches the expected digest.';
      resultEl.className = 'success-message';
    }
    showSuccess('File digest matches.');
    return;
  }

  // mismatch — show digests in the panel only (not in toast text that might linger)
  if (resultEl) {
    resultEl.innerHTML = '';
    const title = document.createElement('p');
    title.textContent = 'Mismatch: the local file does not match the expected digest.';
    title.className = 'error-message';
    resultEl.appendChild(title);
    if (result.expectedHex) {
      const exp = document.createElement('p');
      exp.style.fontFamily = 'monospace';
      exp.style.wordBreak = 'break-all';
      exp.style.fontSize = '0.85rem';
      exp.textContent = `Expected: ${result.expectedHex}`;
      resultEl.appendChild(exp);
    }
    if (result.computedHex) {
      const got = document.createElement('p');
      got.style.fontFamily = 'monospace';
      got.style.wordBreak = 'break-all';
      got.style.fontSize = '0.85rem';
      got.textContent = `Computed: ${result.computedHex}`;
      resultEl.appendChild(got);
    }
  }
  showError('File digest does not match the expected SHA-256.');
}
