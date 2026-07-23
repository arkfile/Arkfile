import { showAuthSection, toggleAuthForm } from '../ui/sections';

async function handleTOTPVerify(
  code: string,
  completeTOTPSetup: (code: string) => Promise<Record<string, any> | null>
): Promise<void> {
  if (code.length !== 6) return;
  const verifyResult = await completeTOTPSetup(code);
  if (verifyResult) {
    const { hideProgress } = await import('../ui/progress');
    hideProgress();
  }
}

/** TOTP setup UI listeners and verify handler. */
export function setupTOTPListeners(): void {
  const generateTotpBtn = document.getElementById('generate-totp-btn');
  if (generateTotpBtn) {
    generateTotpBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const { generateAndDisplayTOTPSetup } = await import('../auth/totp');
      await generateAndDisplayTOTPSetup();
    });
  }

  const copyTotpSecretBtn = document.getElementById('copy-totp-secret-btn') as HTMLButtonElement | null;
  if (copyTotpSecretBtn) {
    copyTotpSecretBtn.addEventListener('click', () => {
      const secretEl = document.getElementById('manual-entry-code');
      const secret = secretEl?.textContent?.trim() ?? '';
      if (!secret) return;
      navigator.clipboard.writeText(secret).then(() => {
        const original = copyTotpSecretBtn.textContent;
        copyTotpSecretBtn.textContent = 'copied!';
        setTimeout(() => {
          copyTotpSecretBtn.textContent = original;
        }, 2000);
      }).catch(() => {
        // Clipboard API unavailable -- silently ignore; user can still select manually
      });
    });
  }

  const totpVerifyCode = document.getElementById('totp-verify-code') as HTMLInputElement | null;
  const verifyTotpBtn = document.getElementById('verify-totp-btn') as HTMLButtonElement | null;
  if (totpVerifyCode && verifyTotpBtn) {
    totpVerifyCode.addEventListener('input', () => {
      totpVerifyCode.value = totpVerifyCode.value.replace(/[^0-9]/g, '');
      verifyTotpBtn.disabled = totpVerifyCode.value.length !== 6;
    });
    totpVerifyCode.addEventListener('keypress', async (e) => {
      if (e.key === 'Enter' && totpVerifyCode.value.length === 6) {
        const { completeTOTPSetup } = await import('../auth/totp');
        await handleTOTPVerify(totpVerifyCode.value, completeTOTPSetup);
      }
    });
  }

  if (verifyTotpBtn) {
    verifyTotpBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      const code = (document.getElementById('totp-verify-code') as HTMLInputElement)?.value || '';
      const { completeTOTPSetup } = await import('../auth/totp');
      await handleTOTPVerify(code, completeTOTPSetup);
    });
  }

  const cancelRegistrationBtn = document.getElementById('cancel-registration-btn');
  if (cancelRegistrationBtn) {
    cancelRegistrationBtn.addEventListener('click', () => {
      showAuthSection();
      toggleAuthForm();
    });
  }

  const downloadBackupCodesBtn = document.getElementById('download-backup-codes-btn');
  if (downloadBackupCodesBtn) {
    downloadBackupCodesBtn.addEventListener('click', async () => {
      const { downloadBackupCodes } = await import('../auth/totp');
      downloadBackupCodes();
    });
  }
}
