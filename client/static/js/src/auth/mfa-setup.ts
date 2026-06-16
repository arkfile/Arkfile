/**
 * Unified MFA enrollment entry point after OPAQUE registration or login resume.
 */

import { handleTOTPSetupFlow } from './totp-setup.js';
import { handleWebAuthnSetupFlow } from './webauthn.js';
import {
  showMFAMethodPicker,
  type MFASetupFlowData,
  type MFAMethod,
} from './mfa-method.js';

export type { MFASetupFlowData, MFAMethod };

/**
 * Begin MFA enrollment. Shows a method picker unless the server or caller
 * already specified totp or webauthn (e.g. pending enrollment resume).
 */
export function handleMFASetupFlow(data: MFASetupFlowData): void {
  const method = (data.mfaMethod || '').trim() as MFAMethod | '';

  if (method === 'totp') {
    handleTOTPSetupFlow({ tempToken: data.tempToken, username: data.username });
    return;
  }

  if (method === 'webauthn') {
    handleWebAuthnSetupFlow(data);
    return;
  }

  showMFAMethodPicker((selected) => {
    if (selected === 'totp') {
      handleTOTPSetupFlow({ tempToken: data.tempToken, username: data.username });
    } else {
      handleWebAuthnSetupFlow({ ...data, mfaMethod: 'webauthn' });
    }
  });
}
